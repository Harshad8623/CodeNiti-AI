import shutil
import pytest
from services.static_analysis import compare, beautify, security, LocalToolError
from services.cache import MemoryCache
from database import fingerprint


def test_diff_identical_and_changed():
    assert 'identical' in compare('a', 'a', 'python')
    output=compare('a','b','python')
    assert '-a' in output and '+b' in output
    assert 'textual' in output


def test_cache_evicts_lru_and_expired():
    cache=MemoryCache(max_items=2)
    cache.set('a',{'result':'one'})
    cache.set('b',{'result':'two'})
    assert cache.get('a')['result']=='one'
    cache.set('c',{'result':'three'})
    assert cache.get('b') is None
    assert cache.get('a') is not None


def test_fingerprint_is_request_specific():
    assert fingerprint(1, {'tool':'compare','code':'hello'}) != fingerprint(2, {'tool':'compare','code':'hello'})
    assert fingerprint(1, {'tool':'compare','code':'hello'}) != fingerprint(1, {'tool':'compare','code':'Hello'})


def test_local_invalid_language():
    with pytest.raises(LocalToolError):
        beautify('let x=1', 'javascript')
    with pytest.raises(LocalToolError):
        security('let x=1', 'javascript')

@pytest.mark.skipif(not shutil.which('ruff'), reason='ruff executable not installed')
def test_formatter():
    result=beautify('x= 1\nprint( x )', 'python')
    assert 'x = 1' in result
    assert 'print(x)' in result

@pytest.mark.skipif(not shutil.which('bandit'), reason='bandit executable not installed')
def test_static_scan():
    result=security('import subprocess\nsubprocess.run("ls", shell=True)', 'python')
    assert 'Bandit' in result or 'Static security scan' in result
    assert 'potential issue' in result


def test_formatter_adapter_mock(monkeypatch):
    from subprocess import CompletedProcess
    import services.static_analysis as local
    monkeypatch.setattr(local.shutil, 'which', lambda executable: '/usr/bin/ruff')
    monkeypatch.setattr(local.subprocess, 'run', lambda *args, **kwargs: CompletedProcess(args[0], 0, 'x = 1\n', ''))
    output = local.beautify('x=1', 'python')
    assert 'x = 1' in output and 'never executed' in output


def test_bandit_adapter_mock_and_parser_error(monkeypatch):
    import json
    import services.static_analysis as local
    from subprocess import CompletedProcess
    monkeypatch.setattr(local.shutil, 'which', lambda executable: '/usr/bin/bandit')
    mock_json = {'results': [{'issue_severity':'HIGH','test_name':'subprocess_popen_with_shell_equals_true',
                              'line_number':4,'issue_text':'subprocess shell=True'}], 'errors': []}
    monkeypatch.setattr(local.subprocess, 'run', lambda *args, **kwargs: CompletedProcess(args[0], 1, json.dumps(mock_json), ''))
    assert 'HIGH' in local.security('import subprocess', 'python')
    mock_json['errors']=[{'filename':'snippet.py','reason':'Could not parse'}]
    monkeypatch.setattr(local.subprocess, 'run', lambda *args, **kwargs: CompletedProcess(args[0], 1, json.dumps(mock_json), ''))
    with pytest.raises(LocalToolError) as err:
        local.security('not valid python?', 'python')
    assert err.value.status == 422
