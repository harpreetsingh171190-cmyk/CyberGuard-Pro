"""Basic single-process API defenses; deploy a shared gateway for multi-worker production."""
import os, time, threading, secrets
from collections import defaultdict, deque
from fastapi import Request, HTTPException
from starlette.middleware.base import BaseHTTPMiddleware

class SlidingWindowLimiter:
    def __init__(self, limit=60, window=60):
        self.limit, self.window = limit, window
        self._hits = defaultdict(deque)
        self._lock = threading.Lock()
    def allow(self, identity):
        now = time.monotonic()
        with self._lock:
            hits = self._hits[identity]
            while hits and hits[0] <= now-self.window: hits.popleft()
            if len(hits) >= self.limit: return False
            hits.append(now)
            return True

limiter = SlidingWindowLimiter(int(os.getenv('CYBERGUARD_RATE_LIMIT','60')))

class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        response = await call_next(request)
        response.headers['X-Content-Type-Options'] = 'nosniff'
        response.headers['X-Frame-Options'] = 'DENY'
        response.headers['Referrer-Policy'] = 'no-referrer'
        response.headers['Cache-Control'] = 'no-store'
        response.headers['Content-Security-Policy'] = "default-src 'none'; frame-ancestors 'none'"
        response.headers['X-Request-ID'] = secrets.token_hex(12)
        return response

def rate_limit(request: Request):
    # Token identity is intentionally hashed, not logged. Do not trust X-Forwarded-For.
    import hashlib
    token = request.headers.get('authorization','')
    key = hashlib.sha256(token.encode()).hexdigest() if token else 'anonymous'
    if not limiter.allow(key):
        raise HTTPException(status_code=429, detail='Rate limit exceeded', headers={'Retry-After':'60'})
