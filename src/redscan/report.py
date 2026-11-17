"""Aggregate results into an attack-success-rate (ASR) report, tagged with ATLAS / OWASP IDs."""

from __future__ import annotations

from collections import defaultdict

from .taxonomy import get_technique


def _group(rows: list[dict], key: str) -> dict[str, dict]:
    out: dict[str, dict] = defaultdict(lambda: {"attacks": 0, "success": 0, "turns_to_success": []})
    for r in rows:
        g = out[r[key]]
        g["attacks"] += 1
        if r["success"]:
            g["success"] += 1
            g["turns_to_success"].append(r["n_turns"])
    return dict(out)


def _asr(g: dict) -> str:
    return f"{100 * g['success'] / g['attacks']:.0f}%" if g["attacks"] else "-"


def _avg_turns(g: dict) -> str:
    t = g["turns_to_success"]
    return f"{sum(t) / len(t):.1f}" if t else "-"


def to_markdown(rows: list[dict], title: str = "Scan report") -> str:
    if not rows:
        return f"# {title}\n\nNo results.\n"
    total = len(rows)
    wins = sum(r["success"] for r in rows)
    lines = [f"# {title}", "", f"**Overall ASR:** {wins}/{total} ({100 * wins / total:.0f}%)", ""]

    lines += ["## By target", "", "| Target | Attacks | Successes | ASR | Avg turns to success |",
              "|---|---|---|---|---|"]
    for name, g in sorted(_group(rows, "target").items()):
        lines.append(f"| {name} | {g['attacks']} | {g['success']} | {_asr(g)} | {_avg_turns(g)} |")

    lines += ["", "## By technique", "",
              "| Technique | MITRE ATLAS | OWASP LLM | Attacks | ASR | Avg turns |", "|---|---|---|---|---|---|"]
    for name, g in sorted(_group(rows, "technique").items()):
        t = get_technique(name)
        lines.append(f"| {name} | {', '.join(t.atlas)} | {', '.join(t.owasp)} | {g['attacks']} | "
                     f"{_asr(g)} | {_avg_turns(g)} |")

    lines += ["", "## By converter stack", "", "| Converters | Attacks | ASR |", "|---|---|---|"]
    for name, g in sorted(_group(rows, "converters").items()):
        lines.append(f"| {name} | {g['attacks']} | {_asr(g)} |")

    found = sorted({(r["target"], r["secret"]) for r in rows if r["success"] and r["secret"]})
    if found:
        lines += ["", "## Recovered secrets", ""] + [f"- **{t}**: `{s}`" for t, s in found]
    return "\n".join(lines) + "\n"
