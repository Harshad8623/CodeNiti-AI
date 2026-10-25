"""Deterministic Python AST Analysis: Complexity metrics and security/code smell detection."""
import ast
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

        # Check for dangerous builtins: eval(), exec()
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

    return {
        'valid_syntax': True,
        'syntax_error': None,
        'loc': loc,
        'cyclomatic_complexity': complexity,
        'function_count': function_count,
        'class_count': class_count,
        'findings': findings
    }
