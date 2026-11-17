"""Map attack techniques to MITRE ATLAS and the OWASP Top 10 for LLM Applications (2025).

Every seed prompt carries a ``technique`` label. Results are aggregated per technique and
reported with these framework IDs so findings read like a real red-team report.

References:
  - MITRE ATLAS: https://atlas.mitre.org/techniques
  - OWASP Top 10 for LLM Applications 2025: https://genai.owasp.org/llm-top-10/
"""

from __future__ import annotations

from dataclasses import dataclass, field

ATLAS = {
    "AML.T0051": "LLM Prompt Injection",
    "AML.T0051.000": "LLM Prompt Injection: Direct",
    "AML.T0051.001": "LLM Prompt Injection: Indirect",
    "AML.T0054": "LLM Jailbreak",
    "AML.T0056": "LLM Meta Prompt Extraction",
    "AML.T0057": "LLM Data Leakage",
}

OWASP_LLM = {
    "LLM01": "Prompt Injection",
    "LLM02": "Sensitive Information Disclosure",
    "LLM07": "System Prompt Leakage",
}


@dataclass(frozen=True)
class Technique:
    name: str
    description: str
    atlas: tuple[str, ...] = field(default_factory=tuple)
    owasp: tuple[str, ...] = field(default_factory=tuple)


_BASE_ATLAS = ("AML.T0051.000",)
_BASE_OWASP = ("LLM01",)

TECHNIQUES: dict[str, Technique] = {
    t.name: t
    for t in [
        Technique("direct_request", "Plainly asks for the protected data.",
                  ("AML.T0051.000", "AML.T0057"), ("LLM01", "LLM02")),
        Technique("instruction_override", "'Ignore previous instructions' style override.",
                  ("AML.T0051.000",), ("LLM01",)),
        Technique("system_prompt_extraction", "Asks the model to reveal/repeat its hidden instructions.",
                  ("AML.T0051.000", "AML.T0056"), ("LLM01", "LLM07")),
        Technique("roleplay", "Wraps the request in a persona or fictional frame (DAN, grandma...).",
                  ("AML.T0051.000", "AML.T0054"), ("LLM01",)),
        Technique("obfuscation", "Hides intent/output via encodings (base64, rot13, leetspeak, spelling).",
                  ("AML.T0051.000", "AML.T0054"), ("LLM01", "LLM02")),
        Technique("indirect_leak", "Leaks the secret through side channels (riddles, acrostics, hints).",
                  ("AML.T0051.000", "AML.T0057"), ("LLM01", "LLM02")),
        Technique("context_manipulation", "Fake context / authority / time shifts (e.g. 'Time Bandit').",
                  ("AML.T0051.000", "AML.T0054"), ("LLM01",)),
        Technique("multi_turn", "Escalates gradually across turns (e.g. Crescendo).",
                  ("AML.T0051.000", "AML.T0054"), ("LLM01",)),
        Technique("translation", "Switches language to evade filters.",
                  ("AML.T0051.000", "AML.T0054"), ("LLM01",)),
        Technique("unknown", "Unlabelled technique (imported dataset without metadata).",
                  _BASE_ATLAS, _BASE_OWASP),
    ]
}


def get_technique(name: str | None) -> Technique:
    return TECHNIQUES.get((name or "unknown").strip().lower(), TECHNIQUES["unknown"])


def describe(ids: tuple[str, ...]) -> str:
    names = {**ATLAS, **OWASP_LLM}
    return ", ".join(f"{i} ({names.get(i, '?')})" for i in ids)
