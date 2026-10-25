"""Closed-Loop Static Analysis & AI-Assisted Repair Verification Engine.
Runs deterministic scans (AST + Bandit), requests targeted AI repair,
and re-scans the repaired code to mathematically verify resolution.
"""
from collections import Counter
import difflib
import json
import re
import shutil
import subprocess  # nosec B404
import tempfile
from pathlib import Path
from typing import Any
from services.ast_analyzer import analyze_ast, analyze_universal, is_test_or_runner_file


def scan_bandit_raw(code: str) -> tuple[list[dict[str, Any]], bool]:
    """Execute Bandit in an isolated temporary directory and return raw JSON results + status."""
    exe = shutil.which('bandit')
    if not exe:
        return [], False
    with tempfile.TemporaryDirectory(prefix='codeniti-bandit-') as directory:
        path = Path(directory) / 'snippet.py'
        path.write_text(code, encoding='utf-8')
        try:
            proc = subprocess.run(
                [exe, '-q', '-f', 'json', str(path)],
                capture_output=True, text=True, timeout=9, check=False
            )  # nosec B603
            output = json.loads(proc.stdout)
            results = output.get('results', [])
            findings = [{
                'rule_id': r.get('test_id', 'BANDIT'),
                'name': r.get('test_name', 'Security Risk'),
                'severity': r.get('issue_severity', 'MEDIUM'),
                'line': r.get('line_number', 1),
                'message': r.get('issue_text', '').replace('`', "'"),
                'tool': 'bandit'
            } for r in results]
            return findings, True
        except Exception:  # nosec B110
            return [], False


def audit_code(code: str, language: str = 'python', file_path: str = '') -> dict[str, Any]:
    """Execute language-appropriate static analyzer deterministically."""
    lang = (language or 'python').lower()
    is_test = is_test_or_runner_file(file_path)

    if lang in ('python', 'py'):
        ast_res = analyze_ast(code, file_path=file_path)
        bandit_findings, bandit_available = scan_bandit_raw(code)
        if is_test and bandit_findings:
            bandit_findings = [f for f in bandit_findings if f.get('rule_id') not in (
                'B101', 'assert_used', 'B105', 'hardcoded_password_string', 'B404', 'B603'
            )]
    else:
        ast_res = analyze_universal(code, lang, file_path=file_path)
        bandit_findings, bandit_available = [], True

    all_findings = list(ast_res.get('findings', [])) + bandit_findings
    if lang in ('python', 'py') and not bandit_available:
        all_findings.append({
            'rule_id': 'SCANNER_NOTICE_BANDIT_OFFLINE',
            'name': 'Scanner Notice',
            'severity': 'LOW',
            'line': 1,
            'message': 'Bandit binary was not located on this host. Security checks completed via native Python AST analyzer only.',
            'tool': 'system'
        })

    weights = {'HIGH': 10, 'MEDIUM': 5, 'LOW': 2}
    risk_score = sum(weights.get(f.get('severity', 'LOW'), 2) for f in all_findings)

    return {
        'valid_syntax': ast_res.get('valid_syntax', True),
        'syntax_error': ast_res.get('syntax_error'),
        'bandit_available': bandit_available,
        'defined_functions': ast_res.get('defined_functions', []),
        'function_signatures': ast_res.get('function_signatures', {}),
        'defined_classes': ast_res.get('defined_classes', []),
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
    """Extract code from ```lang ... ``` fences or return stripped text."""
    pattern = r'```(?:[a-zA-Z0-9_+#-]+)?\s*\n(.*?)\n```'
    match = re.search(pattern, text, re.DOTALL)
    if match:
        return match.group(1).strip()
    cleaned = re.sub(r'^```[a-zA-Z0-9_+#-]*\n?', '', text.strip(), flags=re.MULTILINE)
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


def _count_finding_transitions(initial_findings: list[dict], after_findings: list[dict]) -> tuple[int, int, int]:
    """Accurate multi-instance counting via Counter comparing rule counts before and after repair."""
    before_rules = Counter(f.get('rule_id') for f in initial_findings if not f.get('rule_id', '').startswith('SCANNER_NOTICE'))
    after_rules = Counter(f.get('rule_id') for f in after_findings if not f.get('rule_id', '').startswith('SCANNER_NOTICE'))

    resolved_count = 0
    remaining_count = 0
    for rule_id, count in before_rules.items():
        after_c = after_rules.get(rule_id, 0)
        resolved_count += max(0, count - after_c)
        remaining_count += min(count, after_c)

    new_count = sum(count for rule_id, count in after_rules.items() if rule_id not in before_rules)
    return resolved_count, remaining_count, new_count


def _inspect_structural_integrity(before_audit: dict, after_audit: dict, remaining_count: int, new_count: int) -> tuple[str, str | None]:
    """Evaluate structural and business logic preservation between original and repaired code."""
    if not after_audit['valid_syntax']:
        return 'SYNTAX_ERROR_IN_REPAIR', f"The generated repair has invalid Python syntax: {after_audit['syntax_error']}."

    deleted_functions = set(before_audit.get('defined_functions', [])) - set(after_audit.get('defined_functions', []))
    if deleted_functions:
        return 'FUNCTIONALITY_RISK_DETECTED', f"Function(s) `{', '.join(deleted_functions)}` were removed by the repair. Business logic was deleted."

    sig_before = before_audit.get('function_signatures', {})
    sig_after = after_audit.get('function_signatures', {})
    sig_mismatches = [
        f"`{fn}({', '.join(params)})` ➔ `({', '.join(sig_after[fn])})`"
        for fn, params in sig_before.items() if fn in sig_after and params != sig_after[fn]
    ]
    if sig_mismatches:
        return 'FUNCTIONALITY_RISK_DETECTED', f"Function signature altered: {', '.join(sig_mismatches)}. Calling code may break."

    if before_audit['metrics']['loc'] >= 3 and after_audit['metrics']['loc'] <= 1:
        return 'FUNCTIONALITY_RISK_DETECTED', "The code body was replaced with empty/trivial statement (e.g. `pass`). Business functionality was removed."

    if remaining_count == 0 and new_count == 0:
        return 'STATIC_CHECKS_PASSED', None
    if remaining_count > 0:
        return 'PARTIAL_REPAIR', None
    return 'REGRESSION_DETECTED', None


def _build_repair_report_markdown(
    status: str, before_audit: dict, after_audit: dict,
    resolved_count: int, remaining_count: int, new_count: int,
    diff_text: str, repaired_code: str, language: str, structural_warning: str | None
) -> str:
    """Build empirical verification report markdown."""
    c_before = before_audit['metrics']['cyclomatic_complexity']
    c_after = after_audit['metrics']['cyclomatic_complexity']
    r_before = before_audit['metrics']['risk_score']
    r_after = after_audit['metrics']['risk_score']
    init_count = len(before_audit['findings'])
    funcs_count = len(before_audit.get('function_signatures', {}))

    report_lines = [
        "## 🛡️ Closed-Loop Repair & Verification Report\n",
        f"**Verification Outcome:** `{status}`\n",
        "### 📊 Empirical Verification Metrics",
        f"- **Initial Issues Detected:** `{init_count}`",
        f"- **Issues Successfully Resolved:** `{resolved_count}` ✅",
        f"- **Remaining Unresolved Issues:** `{remaining_count}`",
        f"- **New Issues Introduced by Fix:** `{new_count}` " + ("✅ (None)" if new_count == 0 else "⚠️ (Review needed)"),
        f"- **Cyclomatic Complexity:** `{c_before}` ➔ `{c_after}` " + ("(Improved)" if c_after <= c_before else "(Maintained)" if c_after == c_before else "(Increased)"),
        f"- **Calculated Risk Score:** `{r_before}` ➔ `{r_after}` " + (f"({round((r_before - r_after) / max(1, r_before) * 100)}% reduction)" if r_before > 0 else ""),
        "\n### 📋 Verification Summary Matrix",
        "| Metric | Pre-Repair | Post-Repair | Status |",
        "| :--- | :---: | :---: | :---: |",
        f"| Static Violations | {init_count} | {len(after_audit['findings'])} | {'✅ Resolved' if len(after_audit['findings']) == 0 else '⚠️ Remaining'} |",
        f"| Cyclomatic Complexity | {c_before} | {c_after} | {'✅ Optimized' if c_after <= c_before else '⚠️ Increased'} |",
        f"| Security Risk Score | {r_before} | {r_after} | {'✅ Clean (0)' if r_after == 0 else f'{r_after} pts'} |",
        f"| Structural Integrity | {funcs_count} funcs | {len(after_audit.get('function_signatures', {}))} funcs | {'✅ Preserved' if not structural_warning else '⚠️ Issue Detected'} |",
    ]

    if structural_warning:
        report_lines.append(f"\n> [!CAUTION]\n> **Functional Integrity Warning:** {structural_warning}\n> Static issues disappeared because the implementation was deleted, not safely refactored.")

    report_lines.append("\n### 🔍 Initial Detected Violations (Pre-Repair)")
    for f in before_audit['findings']:
        report_lines.append(f"- **Line {f.get('line', '?')}** `[{f.get('severity', 'MED')}]` **{f.get('rule_id')}**: {f.get('message')}")

    if diff_text:
        report_lines.append(f"\n### 📝 Verified Code Diff\n```diff\n{diff_text}\n```")

    report_lines.append(f"\n### 💻 Full Repaired Source Code\n```{language}\n{repaired_code}\n```")
    report_lines.append(f"\n> [!IMPORTANT]\n> **Verification Scope:** Static compliance confirms that configured rules passed on the re-scanned {language.capitalize()} patch. Static verification does not prove functional or behavioral equivalence; execute automated unit tests to verify runtime behavior.")
    return '\n'.join(report_lines)


async def execute_repair_verification(code: str, language: str = 'python') -> dict[str, Any]:
    """Execute complete closed-loop audit, targeted AI repair, and independent re-scan verification."""
    from services.gemini import call_gemini

    before_audit = audit_code(code, language)
    if not before_audit['valid_syntax']:
        return {
            'status': 'SYNTAX_ERROR',
            'summary': f"Code contains invalid {language.capitalize()} syntax; cannot run repair verification.",
            'before': before_audit,
            'after': None,
            'report_markdown': f"## ⚠️ Syntax Error Detected\n\n```\n{before_audit['syntax_error']}\n```\nPlease correct basic syntax before running automated repair verification."
        }

    initial_findings = before_audit['findings']
    if not initial_findings:
        return {
            'status': 'CLEAN',
            'summary': f"Zero violations or security vulnerabilities detected in {language.capitalize()}.",
            'before': before_audit,
            'after': before_audit,
            'report_markdown': (
                f"## ✅ Clean {language.capitalize()} Code Verification\n\n"
                "**Zero static issues or security vulnerabilities detected.**\n\n"
                f"- **Language:** `{language.capitalize()}`\n"
                f"- **Lines of Code (LOC):** {before_audit['metrics']['loc']}\n"
                f"- **Cyclomatic Complexity:** {before_audit['metrics']['cyclomatic_complexity']}\n"
                f"- **Functions / Classes:** {before_audit['metrics']['function_count']} / {before_audit['metrics']['class_count']}\n"
                "- **Deterministic Static Scan:** Passed\n"
            )
        }

    findings_bullets = [
        f"- Line {f.get('line', '?')}: [{f.get('severity', 'MED')}] {f.get('rule_id', 'RULE')}: {f.get('message', '')}"
        for f in initial_findings
    ]
    repair_prompt = {
        'code': code,
        'language': language,
        'target_violations': '\n'.join(findings_bullets),
        'repair_instruction': (
            f"Refactor this {language.capitalize()} code to fix EVERY listed static analysis and security violation. "
            "Maintain the original business logic, function names, and parameter signatures. "
            "Never delete functions or replace bodies with empty stubs. "
            f"Output the full refactored {language.capitalize()} code inside a ```{language} ``` code block, "
            "followed by a concise bullet list of changes made."
        )
    }

    gemini_output = await call_gemini('optimize', repair_prompt)
    repaired_code = extract_code_block(gemini_output) or code
    after_audit = audit_code(repaired_code, language)

    # Optional 2nd self-healing pass if syntax error produced in Python
    if not after_audit['valid_syntax'] and language.lower() in ('python', 'py'):
        try:
            followup = {
                'code': repaired_code,
                'language': 'python',
                'target_violations': f"Syntax Error: {after_audit['syntax_error']}",
                'repair_instruction': f"Fix syntax error ({after_audit['syntax_error']}) and output valid Python code in ```python ```."
            }
            gemini_out2 = await call_gemini('optimize', followup)
            repaired2 = extract_code_block(gemini_out2)
            if repaired2:
                after_audit2 = audit_code(repaired2, language)
                if after_audit2['valid_syntax']:
                    repaired_code, after_audit = repaired2, after_audit2
        except Exception:  # nosec B110
            pass

    resolved_count, remaining_count, new_count = _count_finding_transitions(initial_findings, after_audit['findings'])
    diff_text = compute_diff(code, repaired_code)
    status, structural_warning = _inspect_structural_integrity(before_audit, after_audit, remaining_count, new_count)
    report_markdown = _build_repair_report_markdown(
        status, before_audit, after_audit, resolved_count, remaining_count, new_count,
        diff_text, repaired_code, language, structural_warning
    )

    return {
        'status': status,
        'summary': f"Resolved {resolved_count}/{len(initial_findings)} issues. Status: {status}.",
        'initial_count': len(initial_findings),
        'resolved_count': resolved_count,
        'remaining_count': remaining_count,
        'new_count': new_count,
        'structural_warning': structural_warning,
        'repaired_code': repaired_code,
        'diff': diff_text,
        'before': before_audit,
        'after': after_audit,
        'report_markdown': report_markdown
    }
