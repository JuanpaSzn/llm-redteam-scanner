"""Load seed prompts from local files or Hugging Face datasets into a common ``Seed`` shape.

Supported sources:
  path/to/file.yaml | .yml   list of seeds, or {"seeds": [...]}
  path/to/file.jsonl         one JSON object per line
  path/to/file.json          list of objects
  path/to/file.csv           header row; prompt column auto-detected
  path/to/file.txt           one prompt per line
  hf:<repo>[@split][#column] Hugging Face dataset (needs ``pip install -e .[hf]``)

Each record may carry ``technique`` (see taxonomy.py) and ``id``. Unknown fields are kept in ``meta``.
"""

from __future__ import annotations

import csv
import json
from collections.abc import Iterable
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

PROMPT_KEYS = ("prompt", "text", "jailbreak", "attack", "user_input", "input", "query", "goal")


@dataclass
class Seed:
    id: str
    prompt: str
    technique: str = "unknown"
    source: str = ""
    meta: dict[str, Any] = field(default_factory=dict)


def _pick_prompt(row: dict[str, Any], column: str | None) -> str | None:
    if column:
        return row.get(column)
    for key in PROMPT_KEYS:
        if isinstance(row.get(key), str) and row[key].strip():
            return row[key]
    return None


def _to_seeds(rows: Iterable[Any], source: str, column: str | None = None) -> list[Seed]:
    seeds: list[Seed] = []
    for i, row in enumerate(rows):
        if isinstance(row, str):
            row = {"prompt": row}
        if not isinstance(row, dict):
            continue
        prompt = _pick_prompt(row, column)
        if not prompt or not str(prompt).strip():
            continue
        meta = {k: v for k, v in row.items() if k not in {"id", "technique", column or "prompt"}}
        seeds.append(
            Seed(
                id=str(row.get("id", f"{Path(source).stem}-{i}")),
                prompt=str(prompt).strip(),
                technique=str(row.get("technique", "unknown")),
                source=source,
                meta=meta,
            )
        )
    return seeds


def _load_hf(spec: str) -> list[Seed]:
    try:
        from datasets import load_dataset
    except ImportError as err:
        raise ImportError("Hugging Face loading needs: pip install -e '.[hf]'") from err
    repo, column = (spec.split("#", 1) + [None])[:2]
    repo, split = (repo.split("@", 1) + ["train"])[:2]
    ds = load_dataset(repo, split=split)
    return _to_seeds((dict(r) for r in ds), source=f"hf:{repo}", column=column)


def load(source: str, *, limit: int | None = None, technique: str | None = None) -> list[Seed]:
    if source.startswith("hf:"):
        seeds = _load_hf(source[3:])
    else:
        path = Path(source)
        if not path.exists():
            raise FileNotFoundError(source)
        suffix = path.suffix.lower()
        text = path.read_text(encoding="utf-8")
        if suffix in {".yaml", ".yml"}:
            data = yaml.safe_load(text) or []
            rows = data.get("seeds", []) if isinstance(data, dict) else data
        elif suffix == ".jsonl":
            rows = [json.loads(line) for line in text.splitlines() if line.strip()]
        elif suffix == ".json":
            data = json.loads(text)
            rows = data.get("seeds", data) if isinstance(data, dict) else data
        elif suffix == ".csv":
            rows = list(csv.DictReader(text.splitlines()))
        else:
            rows = [line for line in text.splitlines() if line.strip() and not line.startswith("#")]
        seeds = _to_seeds(rows, source=str(path))
    if technique:
        seeds = [s for s in seeds if s.technique == technique]
    return seeds[:limit] if limit else seeds
