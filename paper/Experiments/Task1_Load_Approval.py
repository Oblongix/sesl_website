"""
Task 1 – Loan approval comparison between GPT-5.1 and SESL.

This script:
- Loads applicant data from JSON.
- Extracts the loan policy text (PDF or text file).
- Asks GPT to: (a) turn the policy into SESL rules, and (b) give an
  approve/decline decision plus rationale for each applicant via a
  simple prompt.
- Runs the SESL engine against the same applicants using the generated
  SESL rules to produce a deterministic decision/rationale.
- Writes both outputs into a single JSON file for side-by-side review.

Requirements:
- `openai` Python SDK (>=1.0) with an `OPENAI_API_KEY` env var.
- SESL engine available at `SESL_HOME` (defaults to the local repo under
  OneDrive). If PyYAML or SESL deps are only in a venv, run the script
  inside that venv.
- For PDF extraction install `pypdf` or `PyPDF2` (`pip install pypdf`).
"""

from __future__ import annotations

import argparse
import copy
import json
import os
import sys
import re
import subprocess
import tempfile
from pathlib import Path
from typing import Any, Dict, List, Tuple

import yaml


DEFAULT_DATASET = Path("Loan_dataset.json")
DEFAULT_POLICY = Path("Loan_Approval_SOP.pdf")
DEFAULT_OUTPUT = Path("Task1_Load_Approval_results.json")
DEFAULT_SESL_HOME = Path.home() / "OneDrive" / "Documents" / "sesl"
DEFAULT_SESL_RULES_FILE = Path("Task1_Load_Approval_rules.sesl")
DEFAULT_GPT_CACHE = Path("Task1_Load_Approval_gpt.json")
DEFAULT_SESL_CACHE = Path("Task1_Load_Approval_sesl.json")
DEFAULT_SESL_PROMPT = (
    Path.home() / "OneDrive" / "Documents" / "sesl-mcp" / "src" / "sesl_mcp" / "sesl_prompt.txt"
)
DEFAULT_MODEL = os.getenv("OPENAI_GPT_MODEL", "gpt-4.1") 


def load_applicants(path: Path) -> List[Dict[str, Any]]:
    data = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(data, list):
        raise ValueError("Applicant dataset must be a JSON list of records")
    return data


def _json_default(o: Any):
    if isinstance(o, set):
        return list(o)
    return str(o)


def extract_policy_text(path: Path) -> str:
    suffix = path.suffix.lower()

    if suffix == ".pdf":
        try:
            from pypdf import PdfReader  # type: ignore
        except ImportError:
            try:
                from PyPDF2 import PdfReader  # type: ignore
            except ImportError as exc:
                raise RuntimeError(
                    "Install pypdf or PyPDF2 to extract text from PDF policy documents"
                ) from exc

        reader = PdfReader(str(path))
        pages = [page.extract_text() or "" for page in reader.pages]
        return "\n".join(pages)

    # Fallback for txt/markdown or other small text files
    return path.read_text(encoding="utf-8", errors="ignore")


def load_sesl_prompt_template(path: Path | None) -> str:
    fallback = (
        """YYou are an expert SESL rule-writer. Convert the policy below into SESL YAML only.
SESL syntax rules (follow exactly):
- Top-level keys: const (optional), rules (list). Do NOT emit facts unless explicitly asked.
- Rule keys: rule, priority, let, if, then, because, stop.
- Use the because: key for a short justification on every rule; also set result.reason in then.
- Logic keys: all/and, any/or, not. Operators: ==, !=, >, <, >=, <=, in, not in.
- No markdown fences. Indent with 2 spaces. No extra keys or commentary.
- Do NOT use any function calls (no min/max/sum). Do NOT put arithmetic in conditions; put arithmetic in LET, then compare LET variables in the if.
- LET supports literals and arithmetic; conditions must be simple comparisons of identifiers/literals.
- Do NOT reuse names: facts/LET variables must not shadow const names or rule names.
- Actions write under result.*. Use quoted strings; booleans true/false; numbers unquoted.
- Avoid inventing fields not present in the policy; use only provided fields.
Use only SESL YAML with top-level keys const, rules, facts.
Emit only valid SESL YAML.
Generate SESL code for the prompt: {prompt}\n"""
        
    )
    if path and path.exists():
        return path.read_text(encoding="utf-8")
    return fallback


def build_policy_prompt(policy_text: str, applicant_fields: List[str]) -> str:
    field_list = ", ".join(applicant_fields)
    return (
        "Loan approval policy:\n"
        f"{policy_text}\n\n"
        "Applicant fields available (top-level facts): "
        f"{field_list}.\n"
        'Set result.decision to "APPROVED" or "DECLINED" and result.reason to a short justification.'
        " Add any helpful derived fields (e.g., computed DTI thresholds) under result.*."
    )


def get_openai_client():
    try:
        from openai import OpenAI
    except ImportError as exc:
        raise RuntimeError(
            "openai package not installed. Install with `pip install openai`."
        ) from exc
    return OpenAI()


def call_chat_json(client, model: str, system_prompt: str, user_prompt: str, temperature: float = 0.0) -> Dict[str, Any]:
    response = client.chat.completions.create(
        model=model,
        messages=[
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": user_prompt},
        ],
        response_format={"type": "json_object"},
        temperature=temperature,
    )
    content = response.choices[0].message.content or "{}"
    return json.loads(content)


def generate_sesl_rules(
    client,
    model: str,
    sesl_prompt_template: str,
    policy_prompt: str,
    temperature: float = 0.0,
) -> str:
    system_prompt = "You convert policies into precise SESL YAML."
    user_prompt = sesl_prompt_template.format(prompt=policy_prompt)
    response = client.chat.completions.create(
        model=model,
        messages=[
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": user_prompt},
        ],
        temperature=temperature,
    )
    return response.choices[0].message.content or ""


def ask_gpt_for_decision(client, model: str, policy_text: str, applicant: Dict[str, Any]) -> Dict[str, Any]:
    system_prompt = (
        "You are an independent credit underwriter. Read the policy and applicant data, "
        "then decide APPROVED or DECLINED. Return JSON with decision and rationale."
    )
    user_prompt = json.dumps(
        {
            "policy": policy_text,
            "applicant": applicant,
            "response_format": {"decision": "APPROVED|DECLINED", "reason": "short text"},
        },
        indent=2,
    )
    return call_chat_json(client, model, system_prompt, user_prompt)


def import_sesl_engine(sesl_home: Path):
    sys.path.insert(0, str(sesl_home))
    try:
        from sesl.engine import load_model_from_yaml, forward_chain, Monitor  # type: ignore
        from sesl.engine import rule_engine  # type: ignore
        from sesl.tools.linter_core import lint_model_from_yaml  # type: ignore
    except Exception as exc:  # pragma: no cover - import guard
        raise RuntimeError(
            f"Could not import SESL engine from {sesl_home}. "
            "Set SESL_HOME or run inside the SESL virtual environment."
        ) from exc
    return load_model_from_yaml, forward_chain, Monitor, rule_engine, lint_model_from_yaml


def sanitize_yaml_block(text: str) -> str:
    """
    Remove Markdown fences (```yaml ... ```), trim whitespace, and return raw YAML.
    """
    stripped = text.strip()
    if stripped.startswith("```"):
        # Drop first line fence
        lines = stripped.splitlines()
        # Skip the opening fence (may be ``` or ```yaml)
        lines = lines[1:]
        # Remove trailing fence if present
        if lines and lines[-1].strip().startswith("```"):
            lines = lines[:-1]
        stripped = "\n".join(lines).strip()
    return stripped


_TRUE_CMP = re.compile(r"\(\s*([A-Za-z_][\w\.]*)\s*==\s*true\s*\)", re.IGNORECASE)
_FALSE_CMP = re.compile(r"\(\s*([A-Za-z_][\w\.]*)\s*==\s*false\s*\)", re.IGNORECASE)


def normalize_let_expr(expr: str) -> str:
    """
    Normalize LET expressions that GPT sometimes emits with '(x == true) + ...' patterns.
    Converts them to 'x + ...' or '(not x) + ...' so they pass AST validation.
    """
    s = str(expr).strip()
    s = _TRUE_CMP.sub(r"\1", s)
    s = _FALSE_CMP.sub(r"(not \1)", s)

    # Strip a single layer of outer parens if they wrap the whole expression
    def _strip_once(text: str) -> str:
        if text.startswith("(") and text.endswith(")"):
            inner = text[1:-1].strip()
            # only strip if parentheses are balanced after removal
            if inner.count("(") == inner.count(")"):
                return inner
        return text

    s = _strip_once(s)
    return s


def normalize_not_paren_blocks(sesl_yaml: str) -> str:
    """
    Convert lines like '- not (' / ')' into proper YAML 'not:' blocks.
    This handles the common GPT pattern:
      - not (
          all:
            - ...
        )
    """
    new_lines = []
    for line in sesl_yaml.splitlines():
        stripped = line.strip()
        if stripped in ("- not (", "- not("):
            new_lines.append(line.replace("- not (", "- not:").replace("- not(", "- not:"))
            continue
        if stripped == ")":
            # drop stray closing parens
            continue
        new_lines.append(line)
    return "\n".join(new_lines)


def normalize_sesl_lets(sesl_yaml: str) -> str:
    """
    Load SESL YAML, normalize LET expressions, and return YAML text.
    If parsing fails, return the original YAML.
    """
    try:
        data = yaml.safe_load(sesl_yaml)
    except Exception:
        return sesl_yaml

    if not isinstance(data, dict):
        return sesl_yaml

    changed = False
    for rule in data.get("rules", []):
        if not isinstance(rule, dict):
            continue
        lets = rule.get("let")
        if not isinstance(lets, dict):
            continue
        for k, v in list(lets.items()):
            if isinstance(v, str):
                new_v = normalize_let_expr(v)
                if new_v != v:
                    lets[k] = new_v
                    changed = True

    if not changed:
        return sesl_yaml

    return yaml.safe_dump(data, sort_keys=False)


def extract_consts(rule_engine_module, sesl_yaml: str) -> Dict[str, Any]:
    try:
        data = rule_engine_module.yaml.safe_load(sesl_yaml)  # type: ignore
    except Exception:
        return {}

    if isinstance(data, dict):
        consts = data.get("const") or {}
        return consts if isinstance(consts, dict) else {}
    return {}


def run_sesl_against_applicants(
    sesl_yaml: str,
    applicants: List[Dict[str, Any]],
    sesl_home: Path,
) -> List[Dict[str, Any]]:
    load_model_from_yaml, forward_chain, Monitor, rule_engine, _ = import_sesl_engine(sesl_home)
    rules, _ = load_model_from_yaml(sesl_yaml)
    # Build lookup with all common rule name attributes
    rules_by_name: Dict[str, Any] = {}
    for r in rules:
        for key in (
            getattr(r, "rule_name", None),
            getattr(r, "name", None),
            getattr(r, "rule", None),
        ):
            if key:
                rules_by_name[key] = r
    consts = extract_consts(rule_engine, sesl_yaml)

    results = []
    for applicant in applicants:
        print(f"[SESL] Evaluating applicant {applicant.get('id')} - {applicant.get('name')}")
        facts = copy.deepcopy(applicant)
        if consts:
            facts["_const"] = consts

        monitor = Monitor(theme="plain")
        forward_chain(rules, facts, monitor=monitor)

        result_block = facts.get("result", {})
        decision = result_block.get("decision") or facts.get("decision")
        reason = result_block.get("reason") or result_block.get("because") or facts.get("because")

        # If reason is missing, try to pull the 'because' text from the fired rule captured in the monitor.
        if not reason:
            fired_rule = None
            for step in monitor.steps:
                msg = step.get("message", "")
                if msg.startswith("Rule ") and " FIRED" in msg:
                    fired_rule = msg.replace("Rule ", "").replace(" FIRED", "").strip()
                    break
            if fired_rule:
                rule_obj = rules_by_name.get(fired_rule)
                if rule_obj:
                    reason = getattr(rule_obj, "because", None) or reason
        if not reason:
            # Try to find the rule that set result.decision in the monitor steps
            for step in reversed(monitor.steps):
                msg = step.get("message", "")
                if msg.startswith("Rule ") and "sets result.decision" in msg:
                    parts = msg.split()
                    if len(parts) >= 2:
                        rule_name = parts[1]
                        rule_obj = rules_by_name.get(rule_name)
                        if rule_obj:
                            reason = getattr(rule_obj, "because", None)
                            if reason:
                                break
        if not reason and decision:
            reason = f"No SESL reason captured for decision '{decision}'"

        print(f"[SESL] Applicant {applicant.get('id')} decision: {decision} | reason: {reason}")
        results.append(
            {
                "id": applicant.get("id"),
                "name": applicant.get("name"),
                "decision": decision,
                "reason": reason,
                "facts_after": facts,
                "monitor": monitor.steps,
            }
        )
    return results


def write_results(path: Path, payload: Dict[str, Any]) -> None:
    path.write_text(json.dumps(payload, indent=2, default=_json_default), encoding="utf-8")


def main(argv: List[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Compare GPT vs SESL on loan approvals.")
    parser.add_argument("--dataset", type=Path, default=DEFAULT_DATASET)
    parser.add_argument("--policy", type=Path, default=DEFAULT_POLICY)
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT)
    parser.add_argument("--sesl-home", type=Path, default=DEFAULT_SESL_HOME)
    parser.add_argument("--sesl-rules", type=Path, default=DEFAULT_SESL_RULES_FILE, help="Path to save/load generated SESL rules.")
    parser.add_argument("--batch-file", type=Path, default=Path("Task1_Load_Approval_batch.sesl"), help="Path for CLI batch run model (rules + facts).")
    parser.add_argument("--gpt-cache", type=Path, default=DEFAULT_GPT_CACHE, help="Cache file for GPT applicant evaluations.")
    parser.add_argument("--sesl-cache", type=Path, default=DEFAULT_SESL_CACHE, help="Cache file for SESL evaluations.")
    parser.add_argument("--sesl-prompt", type=Path, default=DEFAULT_SESL_PROMPT)
    parser.add_argument("--model", default=DEFAULT_MODEL)
    parser.add_argument("--temperature", type=float, default=0.0)
    parser.add_argument(
        "--applicants",
        type=int,
        default=0,
        help="Limit the number of applicants evaluated (0 = all).",
    )
    parser.add_argument(
        "--max-policy-chars",
        type=int,
        default=18000,
        help="Truncate policy text to this many characters for prompts (0 disables truncation).",
    )
    args = parser.parse_args(argv)

    print("[INIT] Loading applicants and policy...")
    applicants = load_applicants(args.dataset)
    if args.applicants and args.applicants > 0:
        applicants = applicants[: args.applicants]
        print(f"[INIT] Applicant list truncated to first {len(applicants)} records")
    print(f"[INIT] Loaded {len(applicants)} applicant(s)")

    applicant_fields = sorted(applicants[0].keys())

    policy_text = extract_policy_text(args.policy)
    print(f"[INIT] Policy text length: {len(policy_text)} chars (source: {args.policy})")
    if args.max_policy_chars and len(policy_text) > args.max_policy_chars:
        policy_text = policy_text[: args.max_policy_chars]
        print(f"[INIT] Policy text truncated to {len(policy_text)} chars for prompt budget")

    sesl_prompt_template = load_sesl_prompt_template(args.sesl_prompt)
    policy_prompt = build_policy_prompt(policy_text, applicant_fields)

    client = get_openai_client()

    # 1) Generate SESL YAML from the policy (reuse file if present)
    if args.sesl_rules.exists():
        print(f"[SESL] Reusing existing SESL rules file: {args.sesl_rules}")
        sesl_rules_yaml = args.sesl_rules.read_text(encoding="utf-8")
        sesl_rules_yaml = sanitize_yaml_block(sesl_rules_yaml)
        sesl_rules_yaml = normalize_sesl_lets(sesl_rules_yaml)
        sesl_rules_yaml = normalize_not_paren_blocks(sesl_rules_yaml)
    else:
        print("[GPT] Generating SESL rules from policy...")
        sesl_rules_yaml = generate_sesl_rules(
            client=client,
            model=args.model,
            sesl_prompt_template=sesl_prompt_template,
            policy_prompt=policy_prompt,
            temperature=args.temperature,
        )
        sesl_rules_yaml = sanitize_yaml_block(sesl_rules_yaml)
        sesl_rules_yaml = normalize_sesl_lets(sesl_rules_yaml)
        sesl_rules_yaml = normalize_not_paren_blocks(sesl_rules_yaml)
        args.sesl_rules.write_text(sesl_rules_yaml, encoding="utf-8")
        print(f"[GPT] SESL rules generated and saved to {args.sesl_rules} ({len(sesl_rules_yaml)} chars)")

    # 2) GPT decision for each applicant (cached if available)
    if args.gpt_cache.exists():
        print(f"[GPT] Reusing cached GPT evaluations from {args.gpt_cache}")
        gpt_results = json.loads(args.gpt_cache.read_text(encoding="utf-8"))
    else:
        gpt_results = []
        for app in applicants:
            print(f"[GPT] Evaluating applicant {app.get('id')} - {app.get('name')}")
            resp = ask_gpt_for_decision(client, args.model, policy_prompt, app)
            decision = resp.get("decision")
            reason = resp.get("reason")
            print(f"[GPT] Applicant {app.get('id')} decision: {decision} | reason: {reason}")
            gpt_results.append(
                {
                    "id": app.get("id"),
                    "name": app.get("name"),
                    **resp,
                }
            )
        args.gpt_cache.write_text(json.dumps(gpt_results, indent=2), encoding="utf-8")
        print(f"[GPT] Cached GPT evaluations written to {args.gpt_cache}")

    # 3) SESL engine decision for each applicant (cached if available)
    if args.sesl_cache.exists():
        print(f"[SESL] Reusing cached SESL evaluations from {args.sesl_cache}")
        sesl_results = json.loads(args.sesl_cache.read_text(encoding="utf-8"))
    else:
        sesl_results = run_sesl_against_applicants(
            sesl_yaml=sesl_rules_yaml,
            applicants=applicants,
            sesl_home=args.sesl_home,
        )
        args.sesl_cache.write_text(json.dumps(sesl_results, indent=2, default=_json_default), encoding="utf-8")
        print(f"[SESL] Cached SESL evaluations written to {args.sesl_cache}")

    output = {
        "policy_prompt": policy_prompt,
        "sesl_rules": sesl_rules_yaml,
        "gpt_model": args.model,
        "gpt_results": gpt_results,
        "sesl_results": sesl_results,
    }

    write_results(args.output, output)
    print(f"[DONE] Wrote combined results to {args.output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
