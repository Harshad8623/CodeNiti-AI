"""Deterministic offline developer tools. We NEVER execute submitted source code."""
import difflib
import json
from pathlib import Path
import shutil
import subprocess
import tempfile

class LocalToolError(Exception):
    def __init__(self, status: int, message: str):
        self.status = status
        self.message = message
        super().__init__(message)


def compare(before: str, after: str, language: str) -> str:
    lines = list(difflib.unified_diff(before.splitlines(), after.splitlines(),
                                      fromfile='Original', tofile='Updated', lineterm='', n=3))
    if not lines:
        return '## Comparison\n\nBoth snippets are identical.\n\nA textual diff cannot establish behavioral equivalence.'
    additions = sum(1 for line in lines if line.startswith('+') and not line.startswith('+++'))
    removals = sum(1 for line in lines if line.startswith('-') and not line.startswith('---'))
    body = '\n'.join(lines)
    return (f'## Side-by-side change summary\n\n**{additions} line{"" if additions == 1 else "s"} added · {removals} line{"" if removals == 1 else "s"} removed**\n\n'
            f'```diff\n{body}\n```\n\n**Important:** This is a deterministic textual diff, not a claim that one version is correct.')


def beautify(code: str, language: str) -> str:
    if language != 'python':
        raise LocalToolError(422, 'The offline formatter supports Python. Select Python to use Ruff.')
    exe = shutil.which('ruff')
    if not exe:
        raise LocalToolError(503, 'Ruff is not installed. Run: pip install -r requirements.txt')
    try:
        proc = subprocess.run([exe, 'format', '--stdin-filename', 'snippet.py', '-'],
                              input=code, capture_output=True, text=True, timeout=5, check=False)
    except subprocess.TimeoutExpired as exc:
        raise LocalToolError(504, 'Formatting timed out.') from exc
    if proc.returncode != 0:
        raise LocalToolError(422, 'Ruff could not format this input. Check Python syntax.')
    return ('## Formatted Python\n\n```python\n' + proc.stdout.rstrip() + '\n```\n\n'
            'Formatted by **Ruff**. The code was parsed and formatted, but never executed.')


def security(code: str, language: str) -> str:
    if language != 'python':
        raise LocalToolError(422, 'The offline security scanner supports Python. Select Python to use Bandit.')
    exe = shutil.which('bandit')
    if not exe:
        raise LocalToolError(503, 'Bandit is not installed. Run: pip install -r requirements.txt')
    with tempfile.TemporaryDirectory(prefix='codeniti-') as directory:
        path = Path(directory) / 'snippet.py'
        path.write_text(code, encoding='utf-8')
        try:
            proc = subprocess.run([exe, '-q', '-f', 'json', str(path)],
                                  capture_output=True, text=True, timeout=9, check=False)
        except subprocess.TimeoutExpired as exc:
            raise LocalToolError(504, 'Security scan timed out.') from exc
        try:
            output = json.loads(proc.stdout)
        except (json.JSONDecodeError, TypeError) as exc:
            raise LocalToolError(422, 'Bandit could not analyze this snippet; verify it is valid Python.') from exc
    if output.get('errors'):
        raise LocalToolError(422, 'Bandit could not parse this Python snippet. Fix syntax errors and retry.')
    findings = output.get('results', [])
    if not findings:
        return ('## Static security scan\n\n**No findings from configured Bandit checks.**\n\n'
                'This is not proof the code is secure. Bandit covers a subset of Python security weaknesses. '
                'Review dependencies, secrets, business logic, and runtime behavior separately.')
    rows = [f'## Static security scan\n\nFound **{len(findings)}** potential issue(s) (Bandit).\n']
    for f in findings[:30]:
        severity = f.get('issue_severity', 'UNKNOWN')
        name = f.get('test_name', 'Finding')
        explanation = f.get('issue_text', '').replace('`','\'')
        rows.append(f'### {severity} · {name} · line {f.get("line_number", "?")}\n\n{explanation}\n')
    if len(findings) > 30:
        rows.append(f'\n{len(findings)-30} additional findings not shown.')
    rows.append('\n**Note:** Static findings require human review and may include false positives. Submitted code was not executed.')
    return '\n'.join(rows)
