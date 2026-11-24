"""Command-line interface: ``redscan scan | validate | report | list``."""

from __future__ import annotations

import argparse
import os
import sys
from pathlib import Path

from . import converters as conv
from . import datasets, report
from .pair import Turn, run_pair, run_replay
from .storage import Store
from .targets import GANDALF_LEVELS, GandalfTarget, MockTarget, OpenAIChatTarget, Target
from .taxonomy import TECHNIQUES


def _levels(spec: str) -> list[int]:
    out: list[int] = []
    for part in spec.split(","):
        if "-" in part:
            a, b = part.split("-")
            out.extend(range(int(a), int(b) + 1))
        elif part.strip():
            out.append(int(part))
    return out


def _targets(args: argparse.Namespace) -> list[Target]:
    if args.target == "gandalf":
        return [GandalfTarget(level) for level in _levels(args.level)]
    if args.target == "openai":
        if not args.model:
            sys.exit("--model is required for --target openai")
        return [OpenAIChatTarget(args.model, system_prompt=args.system_prompt, secret=args.secret,
                                 base_url=args.target_base_url)]
    return [MockTarget()]


def _llm(model: str, offline: bool):
    if offline:
        from .offline import ScriptedLLM

        return ScriptedLLM()
    from .llm import ChatLLM

    return ChatLLM(model)


def _print_turn(t: Turn) -> None:
    tag = "VERIFIED" if t.verified else ("rejected" if t.verified is False else "")
    print(f"    [{t.iteration:>2}] score {t.score:>2}/10 {tag:<8} {t.attacker_prompt[:70]!r}")
    if t.improvement and t.iteration > 1:
        print(f"         change: {t.improvement[:100]}")


def cmd_scan(args: argparse.Namespace) -> int:
    seeds = datasets.load(args.seeds, limit=args.limit, technique=args.technique)
    if not seeds:
        sys.exit("No seeds loaded.")
    pipeline = conv.Pipeline(args.converters.split(",") if args.converters else [])
    offline = args.target == "mock"
    attacker = _llm(args.attacker_model, offline)
    judge = _llm(args.judge_model, offline)
    store = Store(args.db)

    for target in _targets(args):
        scan_id = store.new_scan("pair", target.name, {"seeds": args.seeds, "converters": pipeline.label(),
                                                       "max_iters": args.max_iters})
        print(f"\n== {target.describe()} | {len(seeds)} seeds | converters: {pipeline.label()} | scan {scan_id}")
        for seed in seeds:
            print(f"  seed {seed.id} ({seed.technique})")
            res = run_pair(seed, target, attacker, judge, converters=pipeline, max_iters=args.max_iters,
                           on_turn=_print_turn)
            store.save(scan_id, res)
            status = f"SUCCESS -> {res.secret}" if res.success else f"failed (best {res.best_score}/10)"
            print(f"  => {status}")
            if res.success and args.stop_on_success:
                break
    print(f"\nResults saved to {args.db}. Run `redscan report` for the summary.")
    return 0


def cmd_validate(args: argparse.Namespace) -> int:
    seeds = datasets.load(args.dataset, limit=args.limit)
    pipeline = conv.Pipeline(args.converters.split(",") if args.converters else [])
    judge = None if args.no_judge else _llm(args.judge_model, args.target == "mock")
    store = Store(args.db)
    for target in _targets(args):
        scan_id = store.new_scan("validate", target.name, {"dataset": args.dataset})
        wins = 0
        for seed in seeds:
            res = run_replay(seed, target, judge, pipeline)
            store.save(scan_id, res)
            wins += res.success
        print(f"{target.describe()}: {wins}/{len(seeds)} dataset prompts succeeded as-is (scan {scan_id})")
    return 0


def cmd_report(args: argparse.Namespace) -> int:
    store = Store(args.db)
    scan_id = None if args.all else (args.scan_id or store.latest_scan())
    md = report.to_markdown(store.attacks(scan_id), title=f"redscan report ({scan_id or 'all scans'})")
    if args.out:
        Path(args.out).write_text(md, encoding="utf-8")
        print(f"Wrote {args.out}")
    else:
        print(md)
    return 0


def cmd_list(args: argparse.Namespace) -> int:
    if args.what == "levels":
        for n, d in GANDALF_LEVELS.items():
            print(f"{n}: {d}")
    elif args.what == "converters":
        print("\n".join(sorted(conv.BUILTIN)) + "\n(plus any PyRIT text converter as pyrit:<ClassName>)")
    else:
        for t in TECHNIQUES.values():
            print(f"{t.name:<26} ATLAS {', '.join(t.atlas):<28} OWASP {', '.join(t.owasp)}")
    return 0


def _add_target_args(p: argparse.ArgumentParser) -> None:
    p.add_argument("--target", choices=["gandalf", "openai", "mock"], default="gandalf")
    p.add_argument("--level", default="1", help="Gandalf level(s): 1 | 1,3 | 1-8")
    p.add_argument("--model", help="model for --target openai (e.g. gpt-4o-mini, llama3.1)")
    p.add_argument("--target-base-url", help="OpenAI-compatible URL for the target (Ollama: http://localhost:11434/v1)")
    p.add_argument("--system-prompt", help="system prompt for --target openai")
    p.add_argument("--secret", help="ground-truth secret for --target openai (enables verification)")
    p.add_argument("--converters", default="", help="comma-separated stack, e.g. base64_instruct,pyrit:AtbashConverter")
    p.add_argument("--judge-model", default=os.getenv("REDSCAN_JUDGE_MODEL", "gpt-4o-mini"))
    p.add_argument("--db", default="results/redscan.sqlite")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="redscan", description="LLM red-teaming scanner (PAIR-style).")
    sub = parser.add_subparsers(dest="cmd", required=True)

    s = sub.add_parser("scan", help="run the attacker/judge refinement loop over seed prompts")
    _add_target_args(s)
    s.add_argument("--seeds", default="data/seeds/gandalf_starter.yaml", help="file path or hf:<repo>[@split][#col]")
    s.add_argument("--technique", help="only seeds with this technique label")
    s.add_argument("--limit", type=int, help="max number of seeds")
    s.add_argument("--max-iters", type=int, default=10)
    s.add_argument("--attacker-model", default=os.getenv("REDSCAN_ATTACKER_MODEL", "gpt-4o-mini"))
    s.add_argument("--stop-on-success", action="store_true", help="move to next level after first success")
    s.set_defaults(func=cmd_scan)

    v = sub.add_parser("validate", help="replay a benchmark dataset as-is (no refinement)")
    _add_target_args(v)
    v.add_argument("--dataset", default="hf:Lakera/gandalf_ignore_instructions@validation#text")
    v.add_argument("--limit", type=int, default=50)
    v.add_argument("--no-judge", action="store_true")
    v.set_defaults(func=cmd_validate)

    r = sub.add_parser("report", help="print an ASR report (markdown)")
    r.add_argument("--db", default="results/redscan.sqlite")
    r.add_argument("--scan-id")
    r.add_argument("--all", action="store_true", help="aggregate every scan in the DB")
    r.add_argument("--out", help="write markdown to this file")
    r.set_defaults(func=cmd_report)

    li = sub.add_parser("list", help="list levels, converters or techniques")
    li.add_argument("what", choices=["levels", "converters", "techniques"])
    li.set_defaults(func=cmd_list)
    return parser


def main(argv: list[str] | None = None) -> int:
    try:
        from dotenv import load_dotenv

        load_dotenv()
    except ImportError:
        pass
    args = build_parser().parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
