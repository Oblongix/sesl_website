"""
Task 1 – Loan approval comparison (Simplified Version)

Simplified workflow:
1. Load applicant data and policy text
2. Get GPT decisions for each applicant
3. Use SESL CLI in batch mode for deterministic decisions
4. Compare results

Requirements:
- openai package with OPENAI_API_KEY env var
- SESL CLI available on PATH or at SESL_HOME
- pypdf or PyPDF2 for PDF extraction
"""

import copy
import json
import sys
from pathlib import Path
from typing import Any, Dict, List

# === Configuration ===
DATASET = Path("Loan_dataset.json")
POLICY = Path("Loan_Approval_SOP.pdf")
SESL_RULES = Path("Task1_Load_Approval_rules.sesl")

# Default run suffix (can be overridden via command-line)
RUN_SUFFIX = "run_0"

def get_output_paths(run_suffix: str):
    """Generate output file paths for a given run suffix."""
    return {
        "output": Path(f"Task1_Load_Approval_results_{run_suffix}.json"),
        "gpt_cache": Path(f"Task1_Load_Approval_gpt_{run_suffix}.json"),
        "sesl_cache": Path(f"Task1_Load_Approval_sesl_{run_suffix}.json")
    }

SESL_HOME = Path.home() / "OneDrive" / "Documents" / "sesl"  # Path to SESL Python package


# === Utility Functions ===

def load_json(path: Path) -> Any:
    """Load JSON file."""
    return json.loads(path.read_text(encoding="utf-8"))


def save_json(path: Path, data: Any):
    """Save data as JSON."""
    path.write_text(json.dumps(data, indent=2, default=str), encoding="utf-8")


def extract_policy_text(path: Path) -> str:
    """Extract text from PDF or text file."""
    if path.suffix.lower() == ".pdf":
        try:
            from pypdf import PdfReader
        except ImportError:
            from PyPDF2 import PdfReader
        reader = PdfReader(str(path))
        return "\n".join(page.extract_text() or "" for page in reader.pages)
    return path.read_text(encoding="utf-8", errors="ignore")


# === GPT Integration ===

SESL_PROMPT_TEMPLATE = """You are an expert SESL rule-writer. Convert the policy below into SESL YAML only.

CRITICAL SESL SYNTAX RULES (follow exactly):

1. TOP-LEVEL STRUCTURE:
   - const: (optional) define reusable constants
   - rules: (required) list of rules
   - facts: (optional) test scenarios

2. RULE STRUCTURE - Each rule must have:
   - rule: unique_name
   - priority: number (higher fires first)
   - let: (optional) derived variables
   - if: list of conditions
   - then: list of actions (write to result.*)
   - because: "explanation text"
   - stop: true/false

3. LET BLOCK RULES (CRITICAL - prevents circular dependencies):
   - LET variables are evaluated in ORDER from top to bottom
   - A LET variable can ONLY reference:
     * Input facts (from applicant data)
     * Constants (from const section)
     * LET variables defined EARLIER in the SAME let block
   - NEVER reference a LET variable that is defined later
   - NEVER use function calls (no min, max, sum, len, etc.)
   - Use only arithmetic: +, -, *, /, parentheses
   - Use boolean expressions for complex logic: and, or, == (do NOT use standalone 'not')
   
   EXAMPLE - CORRECT ordering:
   let:
     base_amount: loan_amount * 0.8        # Uses input fact
     monthly_payment: base_amount / 12     # Uses earlier LET variable
     has_income: monthly_income > 3000     # Boolean expression (OK in LET)
     strong_profile: credit_score >= 720 and income >= 50000  # Complex boolean (OK in LET)
   
   EXAMPLE - WRONG (circular dependency):
   let:
     spread: max_score - min_score  # BAD: references min_score before it's defined
     min_score: bureau_score_1      # BAD: defined after being used
   
   EXAMPLE - WRONG (function calls):
   let:
     min_score: min([score1, score2])  # BAD: no function calls allowed
     max_spread: max(spreads)          # BAD: no function calls allowed

4. AVOIDING CIRCULAR DEPENDENCIES:
   - If you need min/max of multiple values, check each individually in IF conditions
   - Instead of: let: min_val: min([a,b,c])
     Use in IF: if: any: [a < threshold, b < threshold, c < threshold]
   - For spreads between values, calculate ALL differences explicitly:
     spread_1_2: val1 - val2
     spread_2_1: val2 - val1  (for absolute difference)
   - For NOT logic, create a positive LET variable instead:
     Instead of: if: not (score >= 720 and income >= 50000)
     Use: let: strong_profile: credit_score >= 720 and income >= 50000
          if: strong_profile == false

5. CONDITIONS (in IF blocks):
   - Simple comparisons only: ==, !=, >, <, >=, <=, in, not in
   - NO arithmetic in conditions
   - NO standalone boolean variables (always use explicit comparison)
   - Logic combinators: all/and, any/or (do NOT use 'not' operator)
   - Reference: input facts, constants, or LET variables
   - CRITICAL: Boolean LET variables MUST be compared explicitly
     WRONG: if: bureau_1_low
     RIGHT: if: bureau_1_low == true
     BETTER: Skip LET, use direct comparison in IF
   
   EXAMPLE - CORRECT conditions:
   if:
     all:
       - credit_score > 640           # Direct comparison (BEST)
       - income >= 30000              # Direct comparison (BEST)
       - strong_profile == true       # Boolean LET variable with explicit comparison
   
   EXAMPLE - WRONG conditions:
   if:
     all:
       - bureau_1_low                 # BAD: No explicit comparison
       - not (score >= 720)           # BAD: 'not' operator not supported
       - income + bonus > 50000       # BAD: Arithmetic in condition

6. ACTIONS (in THEN blocks):
   - ALL actions write to result.* namespace
   - Example: result.decision: "APPROVED"
   - Example: result.reason: "Credit score meets threshold"
   - Use quoted strings, booleans (true/false), or numbers

7. FIELD NAMES:
   - Use EXACT field names from the provided applicant data
   - Do NOT invent field names or assume naming conventions
   - Common mistakes to avoid:
     * Don't use 'credit_bureau_1' if data has 'bureau_score_1'
     * Don't use 'verified_*' if data has '*_verified'
     * ALWAYS check the provided field list carefully

8. FORMATTING:
   - Valid YAML only (2-space indentation)
   - No markdown fences (```yaml or ```)
   - No comments in output
   - Lists use dashes (-)

Generate SESL code for: {prompt}
"""

def get_gpt_decision(policy_text: str, applicant: Dict[str, Any], model: str = "gpt-4o") -> Dict[str, Any]:
    """Ask GPT for loan decision."""
    from openai import OpenAI
    
    client = OpenAI()
    
    system_prompt = """You are a credit underwriter following a Standard Operating Procedure with ZERO discretion.

RULE EXECUTION ORDER (MANDATORY):
1. Document Verification (FIRST - if fail, DECLINE immediately, no further checks)
2. Credit Score Thresholds (SECOND - apply exact ranges, no judgment)
3. Affordability Checks (THIRD - DTI and disposable income)
4. Employment Stability (FOURTH - tenure requirements)

CRITICAL INSTRUCTIONS:
1. The policy defines THREE decision categories: APPROVED, DECLINED, or MANUAL REVIEW
2. MANUAL REVIEW is a REQUIRED decision category - NOT a suggestion for approval
3. Apply ALL thresholds as EXACT cutoffs - they are NOT guidelines
4. Process rules in the order above - STOP at first failure/flag
5. If multiple conditions apply, the most restrictive takes precedence

ABSOLUTE PROHIBITIONS:
- NEVER approve an applicant with credit score 640-699 (MUST be MANUAL REVIEW)
- NEVER approve an applicant with credit score 620-639 (MUST be MANUAL REVIEW)
- NEVER approve if ANY required document is unverified (MUST check documents FIRST)
- NEVER use compensatory logic (e.g., "high income compensates for credit score")
- NEVER apply judgment to "borderline" cases - use exact policy thresholds
- NEVER aggregate positive factors to override a single policy violation

CREDIT SCORE RULES (NO EXCEPTIONS):
- Below 640: DECLINED (not manual review, not approved)
- 640-699: MANUAL REVIEW (not approved, even with perfect other metrics)
- 620-639: MANUAL REVIEW (not approved, even with perfect other metrics)
- 700+: Can proceed to other checks

DOCUMENT VERIFICATION (CHECK FIRST):
- If ANY required document unverified: DECLINED or MANUAL REVIEW per policy
- Do NOT proceed to credit checks if documents fail
- Strong financial profile does NOT override document failures

OUTPUT REQUIREMENTS:
- Return ONLY valid JSON: {"decision": "APPROVED"|"DECLINED"|"MANUAL REVIEW", "reason": "..."}
- Reason must cite the SPECIFIC policy section/threshold that determined the decision
- Do NOT explain why applicant is "otherwise qualified" - state ONLY the decisive factor
- Be deterministic - same input must always produce same output

Think step-by-step following the rule order above, but output ONLY the final JSON."""

    user_prompt = f"""Policy Document:
{policy_text}

Applicant to Evaluate:
{json.dumps(applicant, indent=2)}

Follow the policy exactly. Check each requirement in sequence. Return your decision as JSON."""
    
    response = client.chat.completions.create(
        model=model,
        messages=[
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": user_prompt}
        ],
        temperature=0.0,
        response_format={"type": "json_object"}
    )
    
    content = response.choices[0].message.content or "{}"
    # Extract JSON from markdown code blocks if present
    if "```json" in content:
        content = content.split("```json")[1].split("```")[0].strip()
    elif "```" in content:
        content = content.split("```")[1].split("```")[0].strip()
    
    return json.loads(content)


def get_all_gpt_decisions(policy_text: str, applicants: List[Dict], cache_file: Path) -> List[Dict]:
    """Get GPT decisions for all applicants (with caching)."""
    if cache_file.exists():
        print(f"[GPT] Loading cached results from {cache_file}")
        return load_json(cache_file)
    
    results = []
    for app in applicants:
        print(f"[GPT] Evaluating applicant {app['id']} - {app['name']}")
        decision = get_gpt_decision(policy_text, app)
        results.append({
            "id": app["id"],
            "name": app["name"],
            "decision": decision.get("decision"),
            "reason": decision.get("reason")
        })
        print(f"      -> {decision.get('decision')}: {decision.get('reason')}")
    
    save_json(cache_file, results)
    return results


def generate_sesl_rules(policy_text: str, applicant_fields: List[str], model: str = "gpt-4") -> str:
    """Generate SESL rules from policy text using GPT."""
    from openai import OpenAI
    
    client = OpenAI()
    
    # Build the policy prompt
    field_list = ", ".join(applicant_fields)
    policy_prompt = (
        f"Loan approval policy:\n{policy_text}\n\n"
        f"Applicant fields available (top-level facts): {field_list}.\n"
        'Set result.decision to "APPROVED" or "DECLINED" and result.reason to a short justification.'
    )
    
    # Format the template with the prompt
    full_prompt = SESL_PROMPT_TEMPLATE.format(prompt=policy_prompt)
    
    response = client.chat.completions.create(
        model=model,
        messages=[
            {"role": "system", "content": "You are an expert SESL rule writer. Generate valid SESL YAML that follows all syntax rules."},
            {"role": "user", "content": full_prompt}
        ],
        temperature=0.0
    )
    
    sesl_yaml = response.choices[0].message.content or ""
    
    # Remove markdown fences if present
    sesl_yaml = sesl_yaml.strip()
    if sesl_yaml.startswith("```"):
        lines = sesl_yaml.split('\n')
        # Remove first and last lines (fences)
        sesl_yaml = '\n'.join(lines[1:-1]) if len(lines) > 2 else sesl_yaml
    
    return sesl_yaml


# === SESL Python Engine Integration ===

def import_sesl_engine():
    """Import SESL engine from the SESL Python package."""
    import sys
    sys.path.insert(0, str(SESL_HOME))
    
    try:
        from sesl.engine import load_model_from_yaml, forward_chain, Monitor
        return load_model_from_yaml, forward_chain, Monitor
    except Exception as exc:
        raise RuntimeError(
            f"Could not import SESL engine from {SESL_HOME}. "
            "Make sure SESL is installed or SESL_HOME is correct."
        ) from exc


def run_sesl_on_facts(sesl_yaml: str, facts: Dict[str, Any]) -> Dict[str, Any]:
    """Run SESL rules on a set of facts using the Python engine."""
    load_model_from_yaml, forward_chain, Monitor = import_sesl_engine()
    
    # Load the rules and constants from YAML string
    import yaml
    model = yaml.safe_load(sesl_yaml)
    consts = model.get("const", {})
    
    # Load rules using the engine
    rules, _ = load_model_from_yaml(sesl_yaml)
    
    # Add result object and constants
    facts = dict(facts)
    facts["result"] = {}
    if consts:
        facts["_const"] = consts
    
    # Run forward chaining
    monitor = Monitor(theme="plain")
    try:
        forward_chain(rules, facts, monitor=monitor)
    except Exception as e:
        return {
            "decision": "ERROR",
            "reason": f"Execution error: {str(e)}",
            "error": str(e)
        }
    
    # Extract results
    result_block = facts.get("result", {})
    decision = result_block.get("decision", "UNKNOWN")
    reason = result_block.get("reason", "No reason provided")
    
    return {
        "decision": decision,
        "reason": reason,
        "facts_after": facts
    }


def get_all_sesl_decisions(rules_file: Path, applicants: List[Dict], cache_file: Path) -> List[Dict]:
    """Get SESL decisions for all applicants (with caching)."""
    if cache_file.exists():
        print(f"[SESL] Loading cached results from {cache_file}")
        return load_json(cache_file)
    
    # Load SESL rules once
    sesl_yaml = rules_file.read_text(encoding="utf-8")
    
    results = []
    for app in applicants:
        print(f"[SESL] Evaluating applicant {app['id']} - {app['name']}")
        
        decision_data = run_sesl_on_facts(sesl_yaml, app)
        results.append({
            "id": app["id"],
            "name": app["name"],
            "decision": decision_data.get("decision"),
            "reason": decision_data.get("reason"),
            "facts_after": decision_data.get("facts_after", {})
        })
        print(f"      -> {decision_data.get('decision')}: {decision_data.get('reason')}")
    
    save_json(cache_file, results)
    return results


# === Main Workflow ===

def main(run_suffix: str = "run_0"):
    """Run the full comparison workflow.
    
    Args:
        run_suffix: Suffix for output files (e.g., 'run_0', 'run_1', etc.)
    """
    print(f"[INIT] Starting experimental run: {run_suffix}")
    print("[INIT] Loading data...")
    applicants = load_json(DATASET)
    policy_text = extract_policy_text(POLICY)
    print(f"[INIT] Loaded {len(applicants)} applicants")
    print(f"[INIT] Policy text: {len(policy_text)} chars\n")
    
    # Get output paths for this run
    paths = get_output_paths(run_suffix)
    OUTPUT = paths["output"]
    GPT_CACHE = paths["gpt_cache"]
    SESL_CACHE = paths["sesl_cache"]
    
    # Get GPT decisions
    print("[GPT] Getting GPT-4 decisions...")
    gpt_results = get_all_gpt_decisions(policy_text, applicants, GPT_CACHE)
    print(f"[GPT] Completed {len(gpt_results)} evaluations\n")
    
    # Get SESL decisions
    print("[SESL] Getting SESL decisions...")
    if not SESL_RULES.exists():
        print(f"[SESL] Rules file not found. Generating from policy...")
        applicant_fields = sorted(applicants[0].keys()) if applicants else []
        sesl_yaml = generate_sesl_rules(policy_text[:10000], applicant_fields)
        SESL_RULES.write_text(sesl_yaml, encoding="utf-8")
        print(f"[SESL] Generated rules saved to {SESL_RULES}")
    
    sesl_results = get_all_sesl_decisions(SESL_RULES, applicants, SESL_CACHE)
    print(f"[SESL] Completed {len(sesl_results)} evaluations\n")
    
    # Save results
    output = {
        "run_suffix": run_suffix,
        "gpt_results": gpt_results,
        "sesl_results": sesl_results,
        "policy_source": str(POLICY),
        "applicants_count": len(applicants)
    }
    
    save_json(OUTPUT, output)
    print(f"[DONE] Results saved to {OUTPUT}")
    
    # Print summary
    gpt_decisions = [r.get("decision") for r in gpt_results]
    sesl_decisions = [r.get("decision") for r in sesl_results]
    
    print(f"\n[STATS] GPT-4 Summary:")
    print(f"  APPROVED: {gpt_decisions.count('APPROVED')}")
    print(f"  DECLINED: {gpt_decisions.count('DECLINED')}")
    print(f"  MANUAL REVIEW: {gpt_decisions.count('MANUAL REVIEW')}")
    print(f"  ERROR: {gpt_decisions.count('ERROR')}")
    
    print(f"\n[STATS] SESL Summary:")
    print(f"  APPROVED: {sesl_decisions.count('APPROVED')}")
    print(f"  DECLINED: {sesl_decisions.count('DECLINED')}")
    print(f"  MANUAL REVIEW: {sesl_decisions.count('MANUAL REVIEW')}")
    print(f"  ERROR: {sesl_decisions.count('ERROR')}")
    
    # Compare agreement
    matches = sum(1 for g, s in zip(gpt_decisions, sesl_decisions) if g == s)
    agreement = (matches / len(applicants) * 100) if applicants else 0
    print(f"\n[COMPARE] Agreement: {matches}/{len(applicants)} ({agreement:.1f}%)")
    print(f"[DONE] Results saved to {OUTPUT}")
    print(f"[DONE] Run '{run_suffix}' completed successfully\n")
    
    return


if __name__ == "__main__":
    # Parse command-line argument for run suffix
    run_suffix = sys.argv[1] if len(sys.argv) > 1 else "run_0"
    raise SystemExit(main(run_suffix))
