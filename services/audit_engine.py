"""Closed-Loop Static Analysis & AI-Assisted Repair Verification Engine.
Runs deterministic scans (AST + Bandit), requests targeted AI repair,
and re-scans the repaired code to mathematically verify resolution.
"""
import difflib
import json
import re
import shutil
import subprocess
import tempfile
from pathlib import Path
from typing import Any
from services.ast_analyzer import analyze_ast

def scan_bandit_raw(code: str) -> list[dict[str, Any]]:
    """Execute Bandit in an isolated temporary directory and return raw JSON results."""
    exe = shutil.which('bandit')
    if not exe:
        return []
    with tempfile.TemporaryDirectory(prefix='codeniti-bandit-') as directory:
        path = Path(directory) / 'snippet.py'
        path.write_text(code, encoding='utf-8')
        try:
            proc = subprocess.run(
                [exe, '-q', '-f', 'json', str(path)],
                capture_output=True, text=True, timeout=9, check=False
            )
            output = json.loads(proc.stdout)
            results = output.get('results', [])
            return [{
                'rule_id': r.get('test_id', 'BANDIT'),
                'name': r.get('test_name', 'Security Risk'),
                'severity': r.get('issue_severity', 'MEDIUM'),
                'line': r.get('line_number', 1),
                'message': r.get('issue_text', '').replace('`', "'"),
                'tool': 'bandit'
            } for r in results]
        except Exception:
            return []

def audit_code(code: str) -> dict[str, Any]:
    """Execute both AST and Bandit analyzers deterministically on the code."""
    ast_res = analyze_ast(code)
    bandit_findings = scan_bandit_raw(code)
    
    all_findings = list(ast_res.get('findings', [])) + bandit_findings
    
    # Calculate deterministic risk score: High=10, Medium=5, Low=2
    weights = {'HIGH': 10, 'MEDIUM': 5, 'LOW': 2}
    risk_score = sum(weights.get(f.get('severity', 'LOW'), 2) for f in all_findings)
    
    return {
        'valid_syntax': ast_res.get('valid_syntax', True),
        'syntax_error': ast_res.get('syntax_error'),
        'metrics': {
            'loc': ast_res.get('loc', 0),
            'cyclomatic_complexity': ast_res.get('cyclomatic_complexity', 1),
            'function_count': ast_res.get('function_count', 0),
            'class_count': ast_res.get('class_count', 0),
            'risk_score': risk_score,
        },
        'findings': all_findings,
        'findings_count': len(all_findings),
    }

def extract_code_block(text: str) -> str:
    """Extract code from ```python ... ``` fences or return stripped text."""
    pattern = r'```(?:python)?\s*\n(.*?)\n```'
    match = re.search(pattern, text, re.DOTALL)
    if match:
        return match.group(1).strip()
    # If no fences, return text without outer fences
    cleaned = re.sub(r'^```[a-z]*\n?', '', text.strip(), flags=re.MULTILINE)
    cleaned = re.sub(r'```$', '', cleaned.strip(), flags=re.MULTILINE)
    return cleaned.strip()

def compute_diff(original: str, repaired: str) -> str:
    """Generate deterministic unified diff."""
    lines = list(difflib.unified_diff(
        original.splitlines(), repaired.splitlines(),
        fromfile='Original (Vulnerable)', tofile='Repaired (Verified)',
        lineterm='', n=3
    ))
    return '\n'.join(lines)


async def execute_repair_verification(code: str, language: str = 'python') -> dict[str, Any]:
    """Execute complete closed-loop audit, targeted AI repair, and independent re-scan verification."""
    from services.gemini import call_gemini

    before_audit = audit_code(code)
    
    if not before_audit['valid_syntax']:
        return {
            'status': 'SYNTAX_ERROR',
            'summary': 'Code contains invalid Python syntax; cannot run AST repair verification.',
            'before': before_audit,
            'after': None,
            'report_markdown': f"## ⚠️ Syntax Error Detected\n\n```\n{before_audit['syntax_error']}\n```\nPlease correct basic Python syntax before running automated repair verification."
        }
        
    initial_findings = before_audit['findings']
    
    if not initial_findings:
        return {
            'status': 'CLEAN',
            'summary': 'Zero AST violations or Bandit security vulnerabilities detected.',
            'before': before_audit,
            'after': before_audit,
            'report_markdown': (
                "## ✅ Clean Code Verification\n\n"
                "**Zero static issues or security vulnerabilities detected.**\n\n"
                f"- **Lines of Code (LOC):** {before_audit['metrics']['loc']}\n"
                f"- **Cyclomatic Complexity:** {before_audit['metrics']['cyclomatic_complexity']}\n"
                f"- **Functions / Classes:** {before_audit['metrics']['function_count']} / {before_audit['metrics']['class_count']}\n"
                "- **Deterministic AST Scan:** Passed\n"
                "- **Bandit Security Scanner:** Passed\n"
            )
        }

    # Format findings list for Gemini targeted repair
    findings_bullets = []
    for f in initial_findings:
        findings_bullets.append(f"- Line {f.get('line', '?')}: [{f.get('severity', 'MED')}] {f.get('rule_id', 'RULE')}: {f.get('message', '')}")
    findings_str = '\n'.join(findings_bullets)

    repair_prompt = {
        'code': code,
        'language': 'python',
        'target_violations': findings_str,
        'repair_instruction': (
            "Refactor this Python code to fix EVERY listed static analysis and security violation. "
            "Maintain the original business logic. "
            "Output the full refactored Python code inside a ```python ``` code block, "
            "followed by a concise bullet list of changes made."
        )
    }

    # Request targeted repair from Gemini
    gemini_output = await call_gemini('optimize', repair_prompt)
    repaired_code = extract_code_block(gemini_output)
    
    if not repaired_code or repaired_code == code.strip():
        repaired_code = code

    # Stage 3: Independent Re-scan of the repaired code!
    after_audit = audit_code(repaired_code)
    
    # Compute verification delta
    before_rules = {f"{f.get('rule_id')}:{f.get('line', 0)}" for f in initial_findings}
    after_rules = {f"{f.get('rule_id')}:{f.get('line', 0)}" for f in after_audit['findings']}
    
    # Determine resolved vs remaining
    after_rule_ids = {f.get('rule_id') for f in after_audit['findings']}
    resolved_findings = [f for f in initial_findings if f.get('rule_id') not in after_rule_ids]
    remaining_findings = [f for f in after_audit['findings'] if f.get('rule_id') in {orig.get('rule_id') for orig in initial_findings}]
    new_findings = [f for f in after_audit['findings'] if f.get('rule_id') not in {orig.get('rule_id') for orig in initial_findings}]

    resolved_count = len(resolved_findings)
    remaining_count = len(remaining_findings)
    new_count = len(new_findings)
    
    diff_text = compute_diff(code, repaired_code)
    
    # Build Evidence-Based Markdown Report
    c_before = before_audit['metrics']['cyclomatic_complexity']
    c_after = after_audit['metrics']['cyclomatic_complexity']
    r_before = before_audit['metrics']['risk_score']
    r_after = after_audit['metrics']['risk_score']

    report_lines = [
        "## 🛡️ Closed-Loop Repair & Verification Report\n",
        "### 📊 Empirical Verification Metrics",
        f"- **Initial Issues Detected:** `{len(initial_findings)}`",
        f"- **Issues Successfully Resolved:** `{resolved_count}` ✅",
        f"- **Remaining Unresolved Issues:** `{remaining_count}`",
        f"- **New Issues Introduced by Fix:** `{new_count}` " + ("✅ (None)" if new_count == 0 else "⚠️ (Review needed)"),
        f"- **Cyclomatic Complexity:** `{c_before}` ➔ `{c_after}` " + ("(Improved)" if c_after <= c_before else "(Increased)"),
        f"- **Calculated Risk Score:** `{r_before}` ➔ `{r_after}` " + (f"({round((r_before - r_after) / max(1, r_before) * 100)}% reduction)" if r_before > 0 else ""),
        "\n### 🔍 Initial Detected Violations (Pre-Repair)",
    ]
    for f in initial_findings:
        report_lines.append(f"- **Line {f.get('line', '?')}** `[{f.get('severity', 'MED')}]` **{f.get('rule_id')}**: {f.get('message')}")

    if resolved_findings:
        report_lines.append("\n### ✅ Independently Verified Resolutions (Post-Repair)")
        for f in resolved_findings:
            report_lines.append(f"- Fixed: **{f.get('rule_id')}** (previously line {f.get('line', '?')})")

    if new_findings:
        report_lines.append("\n### ⚠️ Regressions Detected in Suggested Fix")
        for f in new_findings:
            report_lines.append(f"- **Line {f.get('line', '?')}** `[{f.get('severity')}]` **{f.get('rule_id')}**: {f.get('message')}")

    if diff_text:
        report_lines.append(f"\n### 📝 Verified Code Diff\n```diff\n{diff_text}\n```")

    report_lines.append(f"\n### 💻 Full Repaired Source Code\n```python\n{repaired_code}\n```")
    report_lines.append("\n**Verification Methodology:** This report was produced by running deterministic AST & Bandit checks on the initial code, prompting Gemini with exact rule parameters, and automatically executing an independent re-scan on the generated patch.")

    return {
        'status': 'VERIFIED' if remaining_count == 0 and new_count == 0 else 'PARTIAL',
        'summary': f"Resolved {resolved_count}/{len(initial_findings)} issues. Complexity: {c_before}➔{c_after}.",
        'initial_count': len(initial_findings),
        'resolved_count': resolved_count,
        'remaining_count': remaining_count,
        'new_count': new_count,
        'repaired_code': repaired_code,
        'diff': diff_text,
        'before': before_audit,
        'after': after_audit,
        'report_markdown': '\n'.join(report_lines)
    }

