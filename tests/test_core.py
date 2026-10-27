import pytest
from app.core import authorize,safe_url
from app.reports import create_pdf

def test_auth_denies_unconfigured(monkeypatch):
    monkeypatch.delenv('CYBERGUARD_API_TOKEN',raising=False)
    assert not authorize('anything')
def test_auth_accepts_valid(monkeypatch):
    monkeypatch.setenv('CYBERGUARD_API_TOKEN','test-secret')
    assert authorize('test-secret')
    assert not authorize('bad')
def test_blocks_local_targets():
    for url in ['http://127.0.0.1','http://192.168.1.2','file:///etc/passwd','http://localhost']:
        with pytest.raises(ValueError):safe_url(url)
def test_report():
    data=create_pdf([{'url':'https://example.org','risk_score':.3,'risk_band':'moderate'}])
    assert data.startswith(b'%PDF')
