"""Unit tests for Deterministic Python AST Analyzer and Audit Engine."""
import pytest
from unittest.mock import AsyncMock
from services.ast_analyzer import analyze_ast
from services.audit_engine import audit_code, execute_repair_verification


def test_syntax_error_handling():
    res = analyze_ast("def broken_syntax(:\n    pass")
    assert res['valid_syntax'] is False
    assert len(res['findings']) == 1
    assert res['findings'][0]['rule_id'] == 'SYNTAX_ERR'
    assert res['findings'][0]['severity'] == 'HIGH'


def test_cyclomatic_complexity():
    # Base code: complexity 1
    base = "def simple():\n    return 42\n"
    assert analyze_ast(base)['cyclomatic_complexity'] == 1

    # Branching code: if + for + while + and + or = 1 + 5 = 6
    branched = """
def branchy(a, b, items):
    if a > 0 and b > 0:
        for item in items:
            while item > 0 or a < 100:
                item -= 1
    return item
"""
    res = analyze_ast(branched)
    assert res['cyclomatic_complexity'] >= 6
    assert 'branchy' in res['defined_functions']


def test_dangerous_eval_exec():
    code = """
def run_dynamic(user_payload):
    eval(user_payload)
    exec("import os")
"""
    res = analyze_ast(code)
    rule_ids = [f['rule_id'] for f in res['findings']]
    assert 'AST_DANGEROUS_EVAL' in rule_ids
    assert 'AST_DANGEROUS_EXEC' in rule_ids


def test_subprocess_shell_true():
    code = """
import subprocess
def execute(cmd):
    subprocess.run(cmd, shell=True)
    subprocess.Popen(cmd, shell=False)
"""
    res = analyze_ast(code)
    rule_ids = [f['rule_id'] for f in res['findings']]
    assert 'AST_SUBPROCESS_SHELL_TRUE' in rule_ids
    assert rule_ids.count('AST_SUBPROCESS_SHELL_TRUE') == 1


def test_bare_except():
    code = """
def safe_call():
    try:
        do_something()
    except:
        pass
"""
    res = analyze_ast(code)
    rule_ids = [f['rule_id'] for f in res['findings']]
    assert 'AST_BARE_EXCEPT' in rule_ids


def test_wildcard_import():
    code = "from math import *\n"
    res = analyze_ast(code)
    rule_ids = [f['rule_id'] for f in res['findings']]
    assert 'AST_WILDCARD_IMPORT' in rule_ids


def test_assert_used():
    code = """
def validate_age(age):
    assert age >= 18, "Age must be at least 18"
"""
    res = analyze_ast(code)
    rule_ids = [f['rule_id'] for f in res['findings']]
    assert 'AST_ASSERT_USED' in rule_ids


def test_hardcoded_secrets():
    code = """
api_key = "production_super_secret_token_abcdef"
AUTH_TOKEN = "jwt_signing_key_secret_xyz_9988"
safe_var = "regular value"
"""
    res = analyze_ast(code)
    rule_ids = [f['rule_id'] for f in res['findings']]
    assert 'AST_HARDCODED_SECRET' in rule_ids
    assert rule_ids.count('AST_HARDCODED_SECRET') == 2


def test_structural_symbols_and_loc():
    code = """
class Calculator:
    def add(self, a, b):
        return a + b
    def subtract(self, a, b):
        return a - b
"""
    res = analyze_ast(code)
    assert 'Calculator' in res['defined_classes']
    assert 'add' in res['defined_functions']
    assert 'subtract' in res['defined_functions']
    assert res['loc'] == 5


def test_audit_code_engine_integration():
    vulnerable_code = """
import subprocess
api_key = "secret_prod_token_9999"

def run_task(cmd):
    try:
        assert len(cmd) > 0
        subprocess.run("ls " + cmd, shell=True)
    except:
        print("error")
"""
    audit = audit_code(vulnerable_code)
    assert audit['metrics']['loc'] > 0
    assert audit['metrics']['risk_score'] > 0
    assert len(audit['findings']) >= 4
    rule_ids = [f['rule_id'] for f in audit['findings']]
    assert 'AST_HARDCODED_SECRET' in rule_ids
    assert 'AST_ASSERT_USED' in rule_ids
    assert 'AST_BARE_EXCEPT' in rule_ids
    assert 'AST_SUBPROCESS_SHELL_TRUE' in rule_ids


def test_empty_patch_functionality_risk(monkeypatch):
    """Verify that replacing vulnerable code with 'pass' triggers FUNCTIONALITY_RISK_DETECTED."""
    import asyncio
    import services.gemini as gemini_mod

    original_code = """
def fetch_data(user_id):
    eval(user_id)
    return True
"""
    # Simulate an AI hallucination returning 'pass' which erases the function
    destroyed_code = "```python\npass\n```"
    mock_gemini = AsyncMock(return_value=destroyed_code)
    monkeypatch.setattr(gemini_mod, 'call_gemini', mock_gemini)

    res = asyncio.run(execute_repair_verification(original_code))
    assert res['status'] == 'FUNCTIONALITY_RISK_DETECTED'
    assert res['structural_warning'] is not None
    assert 'deleted' in res['structural_warning'].lower() or 'removed' in res['structural_warning'].lower()


def test_sql_injection_detection():
    code = """
def get_user(cursor, user_id):
    cursor.execute(f"SELECT * FROM users WHERE id = '{user_id}'")
    cursor.execute("SELECT * FROM items WHERE name = '" + user_id + "'")
"""
    res = analyze_ast(code)
    rule_ids = [f['rule_id'] for f in res['findings']]
    assert 'AST_SQL_INJECTION' in rule_ids
    assert rule_ids.count('AST_SQL_INJECTION') == 2


def test_pickle_deserialization():
    code = """
import pickle
def load_data(raw):
    return pickle.loads(raw)
"""
    res = analyze_ast(code)
    rule_ids = [f['rule_id'] for f in res['findings']]
    assert 'AST_INSECURE_DESERIALIZATION' in rule_ids


def test_weak_hash_md5_sha1():
    code = """
import hashlib
def hash_token(data):
    return hashlib.md5(data.encode()).hexdigest()
"""
    res = analyze_ast(code)
    rule_ids = [f['rule_id'] for f in res['findings']]
    assert 'AST_WEAK_HASH' in rule_ids


def test_insecure_tempfile_mktemp():
    code = """
import tempfile
def create_scratch():
    path = tempfile.mktemp()
    return path
"""
    res = analyze_ast(code)
    rule_ids = [f['rule_id'] for f in res['findings']]
    assert 'AST_INSECURE_TEMPFILE' in rule_ids


def test_parameter_signature_preservation_and_mismatch(monkeypatch):
    """Verify that altering a function's parameter signature triggers FUNCTIONALITY_RISK_DETECTED."""
    import asyncio
    import services.gemini as gemini_mod

    original_code = """
def login(username, password, remember_me):
    eval(username)
    return True
"""
    # Simulate repair altering parameter signature from 3 args to 1 arg
    altered_code = "```python\ndef login(username):\n    return True\n```"
    mock_gemini = AsyncMock(return_value=altered_code)
    monkeypatch.setattr(gemini_mod, 'call_gemini', mock_gemini)

    res = asyncio.run(execute_repair_verification(original_code))
    assert res['status'] == 'FUNCTIONALITY_RISK_DETECTED'
    assert 'signature' in res['structural_warning'].lower()

