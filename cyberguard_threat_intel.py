"""CyberGuard Phase 2: opt-in threat intelligence and safe passive network checks.

No URL content is downloaded. Provider responses are observations, not proof of safety.
"""
import base64
import ipaddress
import os
import socket
import ssl
from datetime import datetime, timezone
from urllib.parse import urlsplit

import requests

TIMEOUT = 6
MAX_RESPONSE = 1_000_000

def inspect_target(url):
    if not isinstance(url, str) or not 0 < len(url) <= 2048 or url.strip() != url:
        raise ValueError("Invalid URL")
    if any(ord(c) < 32 or ord(c) == 127 for c in url):
        raise ValueError("Control character in URL")
    parsed = urlsplit(url)
    if parsed.scheme not in ("http", "https") or not parsed.hostname:
        raise ValueError("Only absolute HTTP(S) URLs are supported")
    if parsed.username is not None or parsed.password is not None:
        raise ValueError("Credential-bearing URLs are not supported")
    try:
        port = parsed.port
    except ValueError as exc:
        raise ValueError("Invalid port") from exc
    if port not in (None, 80, 443):
        raise ValueError("Only standard HTTP(S) ports are supported")
    host = parsed.hostname.rstrip(".")
    try:
        ip = ipaddress.ip_address(host)
        if not ip.is_global:
            raise ValueError("Non-public IP address blocked")
        return host
    except ValueError as exc:
        if "blocked" in str(exc):
            raise
    try:
        host = host.encode("idna").decode("ascii")
    except UnicodeError as exc:
        raise ValueError("Invalid hostname") from exc
    if len(host) > 253 or "." not in host or any(
        not label or len(label) > 63 or label.startswith("-") or label.endswith("-")
        or not all(ch.isascii() and (ch.isalnum() or ch == "-") for ch in label)
        for label in host.split(".")
    ):
        raise ValueError("Invalid DNS hostname")
    if host.endswith((".local", ".internal", ".localhost", ".test", ".invalid", ".example")):
        raise ValueError("Reserved hostname blocked")
    return host

def public_addresses(host):
    addresses = sorted({item[4][0] for item in socket.getaddrinfo(host, None, type=socket.SOCK_STREAM)})
    if not addresses:
        raise ValueError("No DNS addresses")
    if any(not ipaddress.ip_address(ip).is_global for ip in addresses):
        raise ValueError("DNS resolution includes non-public address; network check blocked")
    return addresses

def dns_check(url, *, enabled=False):
    if not enabled:
        return {"status": "disabled"}
    try:
        host = inspect_target(url)
        ips = public_addresses(host)
        return {"status": "ok", "host": host, "public_ips": ips}
    except Exception as exc:
        return {"status": "error", "error": str(exc)}

def tls_check(url, *, enabled=False):
    if not enabled:
        return {"status": "disabled"}
    try:
        host = inspect_target(url)
        if urlsplit(url).scheme != "https":
            return {"status": "not_applicable", "reason": "HTTP URL"}
        ips = public_addresses(host)
        # Connect to a previously checked public IP, rather than re-resolving the hostname.
        ctx = ssl.create_default_context()
        with socket.create_connection((ips[0], 443), timeout=TIMEOUT) as raw:
            raw.settimeout(TIMEOUT)
            with ctx.wrap_socket(raw, server_hostname=host) as conn:
                cert = conn.getpeercert()
                return {"status": "ok", "tls_version": conn.version(),
                        "cipher": conn.cipher()[0],
                        "not_after": cert.get("notAfter"),
                        "issuer": str(cert.get("issuer", ""))[:500]}
    except Exception as exc:
        return {"status": "error", "error": str(exc)}

def _request_json(method, endpoint, *, headers=None, params=None, json_body=None, form=None):
    # Only call hardcoded trusted provider endpoints; never fetch the scanned URL.
    allowed = (
        "https://safebrowsing.googleapis.com/v4/threatMatches:find",
        "https://www.virustotal.com/api/v3/urls/",
        "https://urlhaus-api.abuse.ch/v1/url/",
    )
    if not any(endpoint.startswith(prefix) for prefix in allowed):
        raise ValueError("Unapproved API endpoint")
    with requests.Session() as session:
        session.trust_env = False
        response = session.request(method, endpoint, headers=headers, params=params,
                                   json=json_body, data=form, timeout=TIMEOUT,
                                   allow_redirects=False)
        if response.status_code == 404:
            return {"_not_found": True}
        response.raise_for_status()
        if len(response.content) > MAX_RESPONSE:
            raise ValueError("API response exceeds limit")
        return response.json()

def google_safe_browsing(url):
    key = os.getenv("GOOGLE_SAFE_BROWSING_API_KEY")
    if not key:
        return {"status": "not_configured"}
    body = {"client": {"clientId": "cyberguard-research", "clientVersion": "3.0"},
            "threatInfo": {"threatTypes": ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE"],
                           "platformTypes": ["ANY_PLATFORM"],
                           "threatEntryTypes": ["URL"], "threatEntries": [{"url": url}]}}
    try:
        result = _request_json("POST", "https://safebrowsing.googleapis.com/v4/threatMatches:find",
                               params={"key": key}, json_body=body)
        matches = result.get("matches", [])
        return {"status": "ok", "listed": bool(matches),
                "threat_types": sorted({x.get("threatType", "UNKNOWN") for x in matches})}
    except Exception as exc:
        return {"status": "error", "error": str(exc)}

def virustotal(url):
    key = os.getenv("VIRUSTOTAL_API_KEY")
    if not key:
        return {"status": "not_configured"}
    url_id = base64.urlsafe_b64encode(url.encode()).decode().strip("=")
    try:
        result = _request_json("GET", f"https://www.virustotal.com/api/v3/urls/{url_id}",
                               headers={"x-apikey": key})
        if result.get("_not_found"):
            return {"status": "not_found"}
        stats = result.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
        return {"status": "ok", "malicious": stats.get("malicious"),
                "suspicious": stats.get("suspicious"),
                "harmless": stats.get("harmless"), "undetected": stats.get("undetected")}
    except Exception as exc:
        return {"status": "error", "error": str(exc)}

def urlhaus(url):
    # URLhaus API access policies may change; key is optional if provider allows it.
    key = os.getenv("URLHAUS_API_KEY")
    if not key:
        return {"status": "not_configured"}
    try:
        result = _request_json("POST", "https://urlhaus-api.abuse.ch/v1/url/",
                               headers={"Auth-Key": key}, form={"url": url})
        return {"status": "ok", "query_status": result.get("query_status"),
                "url_status": result.get("url_status"),
                "threat": result.get("threat")}
    except Exception as exc:
        return {"status": "error", "error": str(exc)}

def investigate(url, *, network=False, providers=False):
    inspect_target(url)
    output = {"url": url, "checked_at_utc": datetime.now(timezone.utc).isoformat(),
              "dns": dns_check(url, enabled=network),
              "tls": tls_check(url, enabled=network)}
    output["google_safe_browsing"] = google_safe_browsing(url) if providers else {"status": "disabled"}
    output["virustotal"] = virustotal(url) if providers else {"status": "disabled"}
    output["urlhaus"] = urlhaus(url) if providers else {"status": "disabled"}
    output["note"] = "Not listed does not mean safe; API results and TLS status are separate signals."
    return output
