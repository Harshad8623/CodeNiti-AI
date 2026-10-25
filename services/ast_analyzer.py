"""Deterministic Python AST Analysis: Complexity metrics and security/code smell detection."""
import ast
import re
from typing import Any

class ASTAnalysisResult:
    def __init__(self):
        self.cyclomatic_complexity: int = 1
        self.function_count: int = 0
        self.class_count: int = 0
        self.loc: int = 0
        self.findings: list[dict[str, Any]] = []

def analyze_ast(source_code: str) -> dict[str, Any]:
    """Parse Python source into AST and extract deterministic metrics and lint findings."""
    lines = source_code.splitlines()
    loc = len([l for l in lines if l.strip() and not l.strip().startswith('#')])
    
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
    findings = []

    # Check for hardcoded secret naming patterns
    sensitive_var_names = {'password', 'secret', 'api_key', 'token', 'private_key', 'passwd', 'auth_token'}

    for node in ast.walk(tree):
        # Cyclomatic complexity branch points (McCabe)
        if isinstance(node, (ast.If, ast.For, ast.While, ast.And, ast.Or, ast.ExceptHandler, ast.With)):
            complexity += 1
        elif isinstance(node, ast.IfExp):  # ternary operator
            complexity += 1

        # Count functions and classes
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            function_count += 1
            # Check function-level complexity
            func_complexity = 1
            for subnode in ast.walk(node):
                if isinstance(subnode, (ast.If, ast.For, ast.While, ast.And, ast.Or, ast.ExceptHandler)):
                    func_complexity += 1
            if func_complexity > 10:
                findings.append({
                    'rule_id': 'AST_COMPLEXITY_HIGH',
                    'severity': 'MEDIUM' if func_complexity <= 15 else 'HIGH',
                    'line': node.lineno,
                    'message': f"Function '{node.name}' has high cyclomatic complexity ({func_complexity} > 10). Consider modularizing.",
                    'tool': 'ast'
                })

        elif isinstance(node, ast.ClassDef):
            class_count += 1

        # Check for dangerous builtins: eval(), exec(), os.system()
        elif isinstance(node, ast.Call):
            if isinstance(node.func, ast.Name):
                if node.func.id in ('eval', 'exec'):
                    findings.append({
                        'rule_id': f'AST_DANGEROUS_{node.func.id.upper()}',
                        'severity': 'HIGH',
                        'line': node.lineno,
                        'message': f"Use of '{node.func.id}()' allows arbitrary code execution. Avoid using dynamic code evaluation.",
                        'tool': 'ast'
                    })
                elif node.func.id in ('system', 'popen'):
                    findings.append({
                        'rule_id': 'AST_OS_SYSTEM',
                        'severity': 'HIGH',
                        'line': node.lineno,
                        'message': f"Use of 'os.{node.func.id}()' is vulnerable to shell command injection. Use subprocess with an explicit argument list and shell=False.",
                        'tool': 'ast'
                    })
            elif isinstance(node.func, ast.Attribute):
                attr = node.func.attr
                # Subprocess shell=True
                if attr in ('run', 'Popen', 'call', 'check_output', 'check_call'):
                    for kw in node.keywords:
                        if kw.arg == 'shell' and isinstance(kw.value, ast.Constant) and kw.value.value is True:
                            findings.append({
                                'rule_id': 'AST_SUBPROCESS_SHELL_TRUE',
                                'severity': 'HIGH',
                                'line': node.lineno,
                                'message': "Subprocess call with 'shell=True' detected. This is a critical command injection vector if untrusted input is passed.",
                                'tool': 'ast'
                            })
                # SQL Injection detection on .execute() / .executemany()
                elif attr in ('execute', 'executemany') and node.args:
                    arg0 = node.args[0]
                    is_formatted = isinstance(arg0, ast.JoinedStr) or (
                        isinstance(arg0, ast.BinOp) and isinstance(arg0.op, (ast.Add, ast.Mod))
                    ) or (
                        isinstance(arg0, ast.Call) and isinstance(arg0.func, ast.Attribute) and arg0.func.attr == 'format'
                    )
                    if is_formatted:
                        findings.append({
                            'rule_id': 'AST_SQL_INJECTION',
                            'severity': 'HIGH',
                            'line': node.lineno,
                            'message': "SQL query constructed via dynamic string formatting/concatenation. Use parameterized queries to eliminate SQL injection.",
                            'tool': 'ast'
                        })
                # Insecure deserialization via pickle / yaml
                elif attr in ('load', 'loads'):
                    val = getattr(node.func, 'value', None)
                    if isinstance(val, ast.Name) and val.id in ('pickle', '_pickle', 'cPickle', 'dill', 'shelve'):
                        findings.append({
                            'rule_id': 'AST_INSECURE_DESERIALIZATION',
                            'severity': 'HIGH',
                            'line': node.lineno,
                            'message': f"Insecure deserialization via '{val.id}.{attr}()'. Arbitrary code execution can occur when loading untrusted data.",
                            'tool': 'ast'
                        })
                    elif isinstance(val, ast.Name) and val.id == 'yaml' and attr == 'load':
                        has_safe_loader = any(kw.arg == 'Loader' and 'SafeLoader' in ast.dump(kw.value) for kw in node.keywords)
                        if not has_safe_loader:
                            findings.append({
                                'rule_id': 'AST_INSECURE_YAML',
                                'severity': 'HIGH',
                                'line': node.lineno,
                                'message': "Insecure 'yaml.load()' without SafeLoader. Use 'yaml.safe_load()' to avoid arbitrary code execution.",
                                'tool': 'ast'
                            })
                # Weak cryptographic hashing (MD5 / SHA1)
                elif attr in ('md5', 'sha1'):
                    val = getattr(node.func, 'value', None)
                    if isinstance(val, ast.Name) and val.id == 'hashlib':
                        findings.append({
                            'rule_id': 'AST_WEAK_HASH',
                            'severity': 'MEDIUM',
                            'line': node.lineno,
                            'message': f"Weak cryptographic hash 'hashlib.{attr}()' detected. Vulnerable to collision attacks; use SHA-256 for secure hashing.",
                            'tool': 'ast'
                        })
                # Insecure temporary file
                elif attr == 'mktemp':
                    val = getattr(node.func, 'value', None)
                    if isinstance(val, ast.Name) and val.id == 'tempfile':
                        findings.append({
                            'rule_id': 'AST_INSECURE_TEMPFILE',
                            'severity': 'HIGH',
                            'line': node.lineno,
                            'message': "Insecure 'tempfile.mktemp()' creates file race conditions. Use 'tempfile.NamedTemporaryFile()' or 'tempfile.mkstemp()'.",
                            'tool': 'ast'
                        })

        # Check for bare except: (catches KeyboardInterrupt and hides critical bugs)
        elif isinstance(node, ast.ExceptHandler):
            if node.type is None:
                findings.append({
                    'rule_id': 'AST_BARE_EXCEPT',
                    'severity': 'MEDIUM',
                    'line': node.lineno,
                    'message': "Bare 'except:' clause caught. Specify explicit exception classes (e.g., 'except Exception:') to avoid masking termination signals.",
                    'tool': 'ast'
                })

        # Check for wildcard imports: from module import *
        elif isinstance(node, ast.ImportFrom):
            for alias in node.names:
                if alias.name == '*':
                    findings.append({
                        'rule_id': 'AST_WILDCARD_IMPORT',
                        'severity': 'LOW',
                        'line': node.lineno,
                        'message': f"Wildcard import 'from {node.module} import *' pollutes namespace and obscures variable origin.",
                        'tool': 'ast'
                    })

        # Check for assert statements in non-test files (disabled under python -O)
        elif isinstance(node, ast.Assert):
            findings.append({
                'rule_id': 'AST_ASSERT_USED',
                'severity': 'LOW',
                'line': node.lineno,
                'message': "Use of 'assert' detected. Assertions are ignored when Python runs with optimization flags (-O). Do not use for input validation or authorization.",
                'tool': 'ast'
            })

        # Check for hardcoded credentials in assignments: api_key = "..."
        elif isinstance(node, ast.Assign):
            for target in node.targets:
                if isinstance(target, ast.Name):
                    name_lower = target.id.lower()
                    if any(s in name_lower for s in sensitive_var_names):
                        if isinstance(node.value, ast.Constant) and isinstance(node.value.value, str):
                            if len(node.value.value) > 6:  # Non-trivial string
                                findings.append({
                                    'rule_id': 'AST_HARDCODED_SECRET',
                                    'severity': 'HIGH',
                                    'line': node.lineno,
                                    'message': f"Possible hardcoded secret in variable '{target.id}'. Move credentials to environment variables.",
                                    'tool': 'ast'
                                })

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


def analyze_universal(source_code: str, language: str = 'javascript') -> dict[str, Any]:
    """Deterministic static analysis for multi-language source code (JS, TS, Java, C/C++, Go, etc.)."""
    lines = source_code.splitlines()
    clean_lines = []
    in_block_comment = False
    for line in lines:
        stripped = line.strip()
        if not stripped:
            continue
        if stripped.startswith('/*'):
            in_block_comment = True
        if in_block_comment:
            if '*/' in stripped:
                in_block_comment = False
            continue
        if stripped.startswith(('//', '#', '--', ';')):
            continue
        clean_lines.append(stripped)

    loc = len(clean_lines)

    branch_regex = re.compile(
        r'\b(if|else\s+if|elif|for|foreach|while|case|catch|switch)\b|\?|&&|\|\||\band\b|\bor\b'
    )
    complexity = 1
    for cl in clean_lines:
        complexity += len(branch_regex.findall(cl))

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

    findings = []
    sensitive_var_names = {'password', 'secret', 'api_key', 'token', 'private_key', 'passwd', 'auth_token'}

    for idx, raw_line in enumerate(lines, start=1):
        line = raw_line.strip()
        if line.startswith(('//', '#', '/*', '*')):
            continue

        # Dangerous eval / dynamic execution
        if re.search(r'\b(?:eval|exec)\s*\(', line):
            findings.append({
                'rule_id': 'SEC_DANGEROUS_EVAL',
                'severity': 'HIGH',
                'line': idx,
                'message': f"Dynamic code evaluation in {language.capitalize()}. Potential arbitrary code execution vector.",
                'tool': 'universal-ast'
            })

        # SQL Injection via string interpolation / concatenation
        if re.search(r'\b(?:execute|query|raw|prepare)\s*\(\s*(?:`[^`]*\$\{|"[^"]*"\s*\+|[a-zA-Z0-9_]+\s*\+\s*["\'])', line, re.IGNORECASE):
            findings.append({
                'rule_id': 'SEC_SQL_INJECTION',
                'severity': 'HIGH',
                'line': idx,
                'message': "SQL query assembled via dynamic string concatenation/template literals. Use parameterized queries.",
                'tool': 'universal-ast'
            })

        # Command Injection
        if re.search(r'\b(?:exec|execSync|spawn|spawnSync|system|popen|Runtime\.getRuntime\(\)\.exec)\s*\(', line):
            findings.append({
                'rule_id': 'SEC_CMD_INJECTION',
                'severity': 'HIGH',
                'line': idx,
                'message': f"OS command execution in {language.capitalize()}. Ensure arguments are passed as an array without shell expansion.",
                'tool': 'universal-ast'
            })

        # Hardcoded Credentials / Secrets
        if any(s in line.lower() for s in sensitive_var_names):
            if re.search(r'["\'][a-zA-Z0-9_\-]{8,}["\']', line):
                findings.append({
                    'rule_id': 'SEC_HARDCODED_SECRET',
                    'severity': 'HIGH',
                    'line': idx,
                    'message': f"Potential hardcoded credential or secret in variable. Store in environment variables.",
                    'tool': 'universal-ast'
                })
        elif re.search(r'AKIA[0-9A-Z]{16}|BEGIN (?:RSA )?PRIVATE KEY', line):
            findings.append({
                'rule_id': 'SEC_HARDCODED_SECRET',
                'severity': 'HIGH',
                'line': idx,
                'message': "Hardcoded cryptographic key or AWS credential pattern detected.",
                'tool': 'universal-ast'
            })

        # Empty / Bare Catch blocks
        if re.search(r'catch\s*(?:\([^)]*\))?\s*\{\s*\}', line):
            findings.append({
                'rule_id': 'SEC_EMPTY_CATCH',
                'severity': 'MEDIUM',
                'line': idx,
                'message': "Empty catch block detected. Swallowing exceptions obscures critical runtime failures.",
                'tool': 'universal-ast'
            })

        # Weak Cryptographic Hashing (MD5)
        if re.search(r'\b(?:createHash\s*\(\s*["\']md5["\']|getInstance\s*\(\s*["\']MD5["\']|MD5_Init)\b', line, re.IGNORECASE):
            findings.append({
                'rule_id': 'SEC_WEAK_HASH',
                'severity': 'MEDIUM',
                'line': idx,
                'message': "Weak MD5 hashing algorithm detected. Use SHA-256 or secure hashing algorithms.",
                'tool': 'universal-ast'
            })

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
