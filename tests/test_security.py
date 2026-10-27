from app.security import SlidingWindowLimiter
from app.core import authorize

def test_rate_limiter():
    limiter=SlidingWindowLimiter(limit=2,window=60)
    assert limiter.allow('alice')
    assert limiter.allow('alice')
    assert not limiter.allow('alice')
    assert limiter.allow('bob')

def test_missing_token_is_denied(monkeypatch):
    monkeypatch.delenv('CYBERGUARD_API_TOKEN',raising=False)
    assert not authorize('anything')
