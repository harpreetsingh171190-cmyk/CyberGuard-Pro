# CyberGuard security notes

- API tokens are shared secrets, not multi-user identities. Use an identity provider and per-role authorization before public deployment.
- Rate limiting is **per process**, not distributed. Put a shared rate limiter and TLS reverse proxy in front of all replicas.
- Do not expose the Streamlit dashboard directly to the public Internet; it uses a local token prompt.
- URL inputs are lexical-only during model scoring. Optional DNS/TLS and threat-intelligence calls are disabled by default.
- Never accept untrusted joblib artifacts: Python pickle deserialization can execute code.
- Set a long random `CYBERGUARD_API_TOKEN`, restrict file permissions, and rotate it regularly.
- Configure HTTPS, network isolation, secret management, and backups before production use.
- Logs avoid raw URL strings but API responses and CSV exports contain submitted URLs; handle them as sensitive data.
- The model is not a replacement for browser or endpoint protection.
