"""Deterministic Python AST Analysis: Complexity metrics and security/code smell detection."""
import ast
import re
from typing import Any

SENSITIVE_VAR_NAMES = {'password', 'secret', 'api_key', 'token', 'private_key', 'passwd', 'auth_token'}


def is_test_or_runner_file(file_path: str) -> bool:
    """Return True if file is part of automated test suites or verification runners."""
    lower = file_path.lower().replace('\\', '/')
    return any(t in lower for t in (
        '/tests/', 'tests/', 'test_', '_test.py', 'conftest.py',
        '/scripts/', 'scripts/', 'smoke.py', 'benchmark.py', 'e2e_browser.py'
    ))


def _calc_branch_increment(node: ast.AST) -> int:
    """Calculate cyclomatic complexity branch contribution for an AST node."""
    if isinstance(node, (ast.If, ast.For, ast.While, ast.And, ast.Or, ast.ExceptHandler, ast.With, ast.IfExp)):
        return 1
    return 0


def _check_func_metrics(node: ast.FunctionDef | ast.AsyncFunctionDef) -> dict[str, Any] | None:
    """Evaluate cyclomatic complexity for an individual function definition."""
    func_complexity = 1
    for subnode in ast.walk(node):
        if isinstance(subnode, (ast.If, ast.For, ast.While, ast.And, ast.Or, ast.ExceptHandler)):
            func_complexity += 1
    if func_complexity > 10:
        return {
            'rule_id': 'AST_COMPLEXITY_HIGH',
            'severity': 'LOW' if func_complexity <= 20 else 'MEDIUM',
            'line': node.lineno,
            'message': f"Function '{node.name}' has high cyclomatic complexity ({func_complexity} > 10). Consider modularizing.",
            'tool': 'ast'
        }
    return None


def _check_builtin_call(func: ast.Name, lineno: int) -> dict[str, Any] | None:
    """Detect dangerous builtins like eval(), exec(), and legacy system calls."""
    if func.id in ('eval', 'exec'):
        return {
            'rule_id': f'AST_DANGEROUS_{func.id.upper()}',
            'severity': 'HIGH',
            'line': lineno,
            'message': f"Use of '{func.id}()' allows arbitrary code execution. Avoid using dynamic code evaluation.",
            'tool': 'ast'
        }
    if func.id in ('system', 'popen'):
        return {
            'rule_id': 'AST_OS_SYSTEM',
            'severity': 'HIGH',
            'line': lineno,
            'message': f"Use of 'os.{func.id}()' is vulnerable to shell command injection. Use subprocess with an explicit argument list and shell=False.",
            'tool': 'ast'
        }
    return None


def _check_subprocess_call(attr: str, keywords: list[ast.keyword], lineno: int) -> dict[str, Any] | None:
    """Detect subprocess execution with shell=True."""
    if attr in ('run', 'Popen', 'call', 'check_output', 'check_call'):
        for kw in keywords:
            if kw.arg == 'shell' and getattr(kw.value, 'value', None) is True:
                return {
                    'rule_id': 'AST_SUBPROCESS_SHELL_TRUE',
                    'severity': 'HIGH',
                    'line': lineno,
                    'message': "Subprocess call with 'shell=True' detected. This is a critical command injection vector if untrusted input is passed.",
                    'tool': 'ast'
                }
    return None


def _check_sql_injection(attr: str, args: list[ast.expr], lineno: int) -> dict[str, Any] | None:
    """Detect dynamic string interpolation in database execute calls."""
    if attr not in ('execute', 'executemany') or not args:
        return None
    arg0 = args[0]
    is_formatted = isinstance(arg0, ast.JoinedStr) or (
        isinstance(arg0, ast.BinOp) and isinstance(arg0.op, (ast.Add, ast.Mod))
    ) or (
        isinstance(arg0, ast.Call) and isinstance(arg0.func, ast.Attribute) and arg0.func.attr == 'format'
    )
    if is_formatted:
        return {
            'rule_id': 'AST_SQL_INJECTION',
            'severity': 'HIGH',
            'line': lineno,
            'message': "SQL query constructed via dynamic string formatting/concatenation. Use parameterized queries to eliminate SQL injection.",
            'tool': 'ast'
        }
    return None


def _check_deserialization(val_name: str, attr: str, keywords: list[ast.keyword], lineno: int) -> dict[str, Any] | None:
    """Detect unsafe pickle or yaml deserialization."""
    if val_name in ('pickle', '_pickle', 'cPickle', 'dill', 'shelve') and attr in ('load', 'loads'):
        return {
            'rule_id': 'AST_INSECURE_DESERIALIZATION',
            'severity': 'HIGH',
            'line': lineno,
            'message': f"Insecure deserialization via '{val_name}.{attr}()'. Arbitrary code execution can occur when loading untrusted data.",
            'tool': 'ast'
        }
    if val_name == 'yaml' and attr == 'load':
        has_safe = any(kw.arg == 'Loader' and 'SafeLoader' in ast.dump(kw.value) for kw in keywords)
        if not has_safe:
            return {
                'rule_id': 'AST_INSECURE_YAML',
                'severity': 'HIGH',
                'line': lineno,
                'message': "Insecure 'yaml.load()' without SafeLoader. Use 'yaml.safe_load()' to avoid arbitrary code execution.",
                'tool': 'ast'
            }
    return None


def _check_crypto_and_temp(val_name: str, attr: str, lineno: int) -> dict[str, Any] | None:
    """Detect weak cryptographic hashing algorithms and unsafe tempfiles."""
    if val_name == 'hashlib' and attr in ('md5', 'sha1'):
        return {
            'rule_id': 'AST_WEAK_HASH',
            'severity': 'MEDIUM',
            'line': lineno,
            'message': f"Weak cryptographic hash 'hashlib.{attr}()' detected. Vulnerable to collision attacks; use SHA-256 for secure hashing.",
            'tool': 'ast'
        }
    if val_name == 'tempfile' and attr == 'mktemp':
        return {
            'rule_id': 'AST_INSECURE_TEMPFILE',
            'severity': 'HIGH',
            'line': lineno,
            'message': "Insecure 'tempfile.mktemp()' creates file race conditions. Use 'tempfile.NamedTemporaryFile()' or 'tempfile.mkstemp()'.",
            'tool': 'ast'
        }
    return None


def _check_call_node(node: ast.Call) -> dict[str, Any] | None:
    """Dispatch and analyze AST call expressions."""
    if isinstance(node.func, ast.Name):
        return _check_builtin_call(node.func, node.lineno)
    if not isinstance(node.func, ast.Attribute):
        return None
    attr = node.func.attr
    val_name = getattr(node.func.value, 'id', '') if isinstance(getattr(node.func, 'value', None), ast.Name) else ''

    finding = _check_subprocess_call(attr, node.keywords, node.lineno)
    if finding:
        return finding
    finding = _check_sql_injection(attr, node.args, node.lineno)
    if finding:
        return finding
    finding = _check_deserialization(val_name, attr, node.keywords, node.lineno)
    if finding:
        return finding
    return _check_crypto_and_temp(val_name, attr, node.lineno)


def _check_secret_assignment(node: ast.Assign) -> dict[str, Any] | None:
    """Identify hardcoded secrets in variable assignments."""
    for target in node.targets:
        if not isinstance(target, ast.Name):
            continue
        name_lower = target.id.lower()
        if any(s in name_lower for s in SENSITIVE_VAR_NAMES):
            val = getattr(node.value, 'value', None)
            if isinstance(node.value, ast.Constant) and isinstance(val, str) and len(val) >= 8:
                if not any(p in val.lower() for p in ('placeholder', 'your_', 'test_', 'example', 'default', 'demo')):
                    return {
                        'rule_id': 'AST_HARDCODED_SECRET',
                        'severity': 'HIGH',
                        'line': node.lineno,
                        'message': f"Possible hardcoded secret in variable '{target.id}'. Move credentials to environment variables.",
                        'tool': 'ast'
                    }
    return None


def _check_structure_and_imports(node: ast.AST, is_test: bool) -> list[dict[str, Any]]:
    """Inspect AST exception handling, wildcard imports, and assertions."""
    issues: list[dict[str, Any]] = []
    if isinstance(node, ast.ExceptHandler) and node.type is None:
        issues.append({
            'rule_id': 'AST_BARE_EXCEPT',
            'severity': 'MEDIUM',
            'line': node.lineno,
            'message': "Bare 'except:' clause caught. Specify explicit exception classes to avoid masking termination signals.",
            'tool': 'ast'
        })
    elif isinstance(node, ast.ImportFrom):
        for alias in node.names:
            if alias.name == '*':
                issues.append({
                    'rule_id': 'AST_WILDCARD_IMPORT',
                    'severity': 'LOW',
                    'line': node.lineno,
                    'message': f"Wildcard import 'from {node.module} import *' pollutes namespace and obscures variable origin.",
                    'tool': 'ast'
                })
    elif isinstance(node, ast.Assert) and not is_test:
        issues.append({
            'rule_id': 'AST_ASSERT_USED',
            'severity': 'LOW',
            'line': node.lineno,
            'message': "Use of 'assert' detected in application logic. Assertions are ignored when Python runs with optimization flags (-O). Do not use for input validation or authorization.",
            'tool': 'ast'
        })
    return issues


def _evaluate_node_findings(node: ast.AST, is_test: bool) -> list[dict[str, Any]]:
    """Inspect an individual AST node for static issues."""
    node_issues: list[dict[str, Any]] = []
    if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
        f_finding = _check_func_metrics(node)
        if f_finding:
            node_issues.append(f_finding)
    elif isinstance(node, ast.Call):
        call_finding = _check_call_node(node)
        if call_finding:
            node_issues.append(call_finding)
    elif isinstance(node, ast.Assign):
        sec = _check_secret_assignment(node)
        if sec:
            node_issues.append(sec)
    else:
        node_issues.extend(_check_structure_and_imports(node, is_test))
    return node_issues


def analyze_ast(source_code: str, file_path: str = '') -> dict[str, Any]:
    """Parse Python source into AST and extract deterministic metrics and lint findings."""
    lines = source_code.splitlines()
    loc = len([l for l in lines if l.strip() and not l.strip().startswith('#')])
    is_test = is_test_or_runner_file(file_path)

    try:
        tree = ast.parse(source_code)
    except SyntaxError as err:
        return {
            'valid_syntax': False,
            'syntax_error': f"Line {err.lineno}: {err.msg}",
            'loc': loc,
            'cyclomatic_complexity': 0,
            'function_count': 0,
            'class_count': 0,
            'findings': [{
                'rule_id': 'SYNTAX_ERR',
                'severity': 'HIGH',
                'line': err.lineno or 1,
                'message': f"Syntax Error: {err.msg}",
                'tool': 'ast'
            }]
        }

    complexity = 1
    function_count = 0
    class_count = 0
    findings: list[dict[str, Any]] = []

    for node in ast.walk(tree):
        complexity += _calc_branch_increment(node)
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            function_count += 1
        elif isinstance(node, ast.ClassDef):
            class_count += 1

        issues = _evaluate_node_findings(node, is_test)
        if issues:
            findings.extend(issues)

    defined_functions = [n.name for n in ast.walk(tree) if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))]
    function_signatures = {
        n.name: [arg.arg for arg in n.args.args]
        for n in ast.walk(tree) if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))
    }
    defined_classes = [n.name for n in ast.walk(tree) if isinstance(n, ast.ClassDef)]

    return {
        'valid_syntax': True,
        'syntax_error': None,
        'loc': loc,
        'cyclomatic_complexity': complexity,
        'function_count': function_count,
        'class_count': class_count,
        'defined_functions': defined_functions,
        'function_signatures': function_signatures,
        'defined_classes': defined_classes,
        'findings': findings
    }


def _clean_source_lines(lines: list[str]) -> list[str]:
    """Strip comments and return active code lines for universal scanning."""
    clean_lines = []
    in_block = False
    for line in lines:
        s = line.strip()
        if not s:
            continue
        if s.startswith('/*'):
            in_block = True
        if in_block:
            if '*/' in s:
                in_block = False
            continue
        if s.startswith(('//', '#', '--', ';')):
            continue
        clean_lines.append(s)
    return clean_lines


def _extract_universal_symbols(clean_lines: list[str]) -> tuple[list[str], list[str]]:
    """Extract declared functions and classes across programming languages."""
    defined_functions = []
    defined_classes = []
    func_pattern = re.compile(
        r'(?:function\s+([a-zA-Z0-9_$]+)|(?:const|let|var)\s+([a-zA-Z0-9_$]+)\s*=\s*(?:async\s*)?(?:\([^)]*\)|[a-zA-Z0-9_$]+)\s*=>|def\s+([a-zA-Z0-9_]+)|func\s+(?:\([^)]+\)\s+)?([a-zA-Z0-9_]+)|fn\s+([a-zA-Z0-9_]+)|(?:public|private|protected|static|\s)+\s+[a-zA-Z0-9_<>[\]]+\s+([a-zA-Z0-9_$]+)\s*\()'
    )
    class_pattern = re.compile(r'\b(?:class|struct|interface|enum)\s+([a-zA-Z0-9_$]+)\b')

    for line in clean_lines:
        fm = func_pattern.search(line)
        if fm:
            name = next((g for g in fm.groups() if g), None)
            if name and name not in ('if', 'for', 'while', 'switch', 'catch'):
                defined_functions.append(name)
        cm = class_pattern.search(line)
        if cm:
            defined_classes.append(cm.group(1))
    return defined_functions, defined_classes


def _check_universal_injection(idx: int, line: str, language: str) -> list[dict[str, Any]]:
    """Detect code injection, SQL injection, and command execution."""
    issues: list[dict[str, Any]] = []
    if re.search(r'(?<![.\w])eval\s*\(|new\s+Function\s*\(', line):
        issues.append({
            'rule_id': 'SEC_DANGEROUS_EVAL',
            'severity': 'HIGH',
            'line': idx,
            'message': f"Dynamic code evaluation in {language.capitalize()}. Potential arbitrary code execution vector.",
            'tool': 'universal-ast'
        })
    if re.search(r'\b(?:execute|query|raw|prepare)\s*\(\s*(?:`[^`]*\$\{|"[^"]*"\s*\+|[a-zA-Z0-9_]+\s*\+\s*["\'])', line, re.IGNORECASE):
        issues.append({
            'rule_id': 'SEC_SQL_INJECTION',
            'severity': 'HIGH',
            'line': idx,
            'message': "SQL query assembled via dynamic string concatenation/template literals. Use parameterized queries.",
            'tool': 'universal-ast'
        })
    if re.search(r'(?:\b(?:child_process|cp)\.(?:exec|spawn|execSync|spawnSync)\b|\b(?:execSync|spawnSync|system|popen|Runtime\.getRuntime\(\)\.exec)\s*\()', line):
        issues.append({
            'rule_id': 'SEC_CMD_INJECTION',
            'severity': 'HIGH',
            'line': idx,
            'message': f"OS command execution in {language.capitalize()}. Ensure arguments are passed as an array without shell expansion.",
            'tool': 'universal-ast'
        })
    return issues


def _check_universal_hygiene(idx: int, line: str, language: str) -> list[dict[str, Any]]:
    """Detect hardcoded secrets, empty catches, and weak hashes."""
    issues: list[dict[str, Any]] = []
    is_dom = any(w in line.lower() for w in ('autocomplete', 'type=', 'placeholder', 'id=', 'name=', '.value', '.get('))
    if not is_dom and any(s in line.lower() for s in SENSITIVE_VAR_NAMES):
        if re.search(r'\b(?:api_?key|secret|token|private_?key|passwd|password)\s*[:=]\s*["\']([^"\'\s]{12,})["\']', line, re.IGNORECASE):
            val_match = re.search(r'["\']([^"\'\s]{12,})["\']', line)
            if val_match and not any(p in val_match.group(1).lower() for p in ('placeholder', 'your_', 'test_', 'example', 'default', 'demo')):
                issues.append({
                    'rule_id': 'SEC_HARDCODED_SECRET',
                    'severity': 'HIGH',
                    'line': idx,
                    'message': f"Potential hardcoded credential or secret assigned in {language.capitalize()}. Store in environment variables.",
                    'tool': 'universal-ast'
                })
    elif re.search(r'AKIA[0-9A-Z]{16}|BEGIN (?:RSA )?PRIVATE KEY', line):
        issues.append({
            'rule_id': 'SEC_HARDCODED_SECRET',
            'severity': 'HIGH',
            'line': idx,
            'message': "Hardcoded cryptographic key or AWS credential pattern detected.",
            'tool': 'universal-ast'
        })
    if re.search(r'catch\s*(?:\([^)]*\))?\s*\{\s*\}', line):
        issues.append({
            'rule_id': 'SEC_EMPTY_CATCH',
            'severity': 'MEDIUM',
            'line': idx,
            'message': "Empty catch block detected. Swallowing exceptions obscures critical runtime failures.",
            'tool': 'universal-ast'
        })
    if re.search(r'\b(?:createHash\s*\(\s*["\']md5["\']|getInstance\s*\(\s*["\']MD5["\']|MD5_Init)\b', line, re.IGNORECASE):
        issues.append({
            'rule_id': 'SEC_WEAK_HASH',
            'severity': 'MEDIUM',
            'line': idx,
            'message': "Weak MD5 hashing algorithm detected. Use SHA-256 or secure hashing algorithms.",
            'tool': 'universal-ast'
        })
    return issues


def analyze_universal(source_code: str, language: str = 'javascript', file_path: str = '') -> dict[str, Any]:
    """Deterministic static analysis for multi-language source code (JS, TS, Java, C/C++, Go, etc.)."""
    lines = source_code.splitlines()
    clean_lines = _clean_source_lines(lines)
    loc = len(clean_lines)

    branch_regex = re.compile(r'\b(if|else\s+if|elif|for|foreach|while|case|catch|switch)\b|\?|&&|\|\||\band\b|\bor\b')
    complexity = 1 + sum(len(branch_regex.findall(cl)) for cl in clean_lines)

    defined_functions, defined_classes = _extract_universal_symbols(clean_lines)

    findings: list[dict[str, Any]] = []
    for idx, raw_line in enumerate(lines, start=1):
        line = raw_line.strip()
        if not line or line.startswith(('//', '#', '/*', '*')):
            continue
        inj = _check_universal_injection(idx, line, language)
        if inj:
            findings.extend(inj)
        hyg = _check_universal_hygiene(idx, line, language)
        if hyg:
            findings.extend(hyg)

    return {
        'valid_syntax': True,
        'syntax_error': None,
        'loc': loc,
        'cyclomatic_complexity': max(1, complexity),
        'function_count': len(defined_functions),
        'class_count': len(defined_classes),
        'defined_functions': defined_functions,
        'function_signatures': {f: [] for f in defined_functions},
        'defined_classes': defined_classes,
        'findings': findings
    }
