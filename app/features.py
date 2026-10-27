from urllib.parse import urlparse
from collections import Counter
import math,re,ipaddress

SUSPICIOUS = ["login", "verify", "secure", "update", "account", "bank", "free", "bonus",
              "signin", "confirm", "password", "paypal", "wallet", "invoice", "gift"]
BRANDS = ["paypal", "google", "amazon", "microsoft", "apple", "facebook", "netflix",
          "sbi", "hdfc", "icici", "whatsapp", "instagram"]
SHORTENERS = {"bit.ly", "tinyurl.com", "goo.gl", "t.co", "ow.ly", "is.gd", "cutt.ly", "rb.gy"}
RISKY_TLDS = {"xyz", "top", "info", "ru", "tk", "ml", "ga", "cf", "gq", "click", "work", "zip", "buzz"}
IP_RE = re.compile(r"^\d{1,3}(\.\d{1,3}){3}$")

def entropy(s):
    if not s: return 0.0
    counts = Counter(s)
    return -sum((c / len(s)) * math.log2(c / len(s)) for c in counts.values())

def extract_features(url):
    p = urlparse(url if "://" in url else "http://" + url)
    host = (p.hostname or "").lower()
    path, query = p.path.lower(), p.query.lower()
    low = url.lower()
    parts = host.split(".")
    tld = parts[-1] if len(parts) > 1 else ""
    main_domain = parts[-2] if len(parts) > 1 else host
    subdomain = ".".join(parts[:-2])
    try:
        port = p.port
    except ValueError:
        port = None
    tokens = [t for t in re.split(r"[\W_]+", low) if t]
    vowels = sum(ch in "aeiou" for ch in main_domain)
    return {
        # --- length features ---
        "url_length": len(url),
        "host_length": len(host),
        "path_length": len(path),
        "query_length": len(query),
        # --- character counts ---
        "num_dots": url.count("."),
        "num_hyphens": url.count("-"),
        "num_at": url.count("@"),
        "num_digits": sum(ch.isdigit() for ch in url),
        "num_uppercase": sum(ch.isupper() for ch in url),
        "num_special": len(re.findall(r"[^A-Za-z0-9]", url)),
        "num_slashes": url.count("/"),
        "num_equals": url.count("="),
        "digit_ratio": sum(ch.isdigit() for ch in url) / max(len(url), 1),
        # --- structure ---
        "num_params": query.count("&") + (1 if query else 0),
        "num_subdomains": max(len(parts) - 2, 0),
        "path_depth": path.count("/"),
        "double_slash_in_path": int("//" in path),
        "has_hex_encoding": int(bool(re.search(r"%[0-9a-f]{2}", low))),
        "longest_token": max((len(t) for t in tokens), default=0),
        "num_tokens": len(tokens),
        # --- host / domain ---
        "has_https": int(p.scheme == "https"),
        "has_ip": int(bool(IP_RE.match(host))),
        "non_standard_port": int(port not in (None, 80, 443)),
        "is_shortener": int(host.replace("www.", "") in SHORTENERS),
        "risky_tld": int(tld in RISKY_TLDS),
        "tld_length": len(tld),
        "host_hyphens": host.count("-"),
        "host_digit_ratio": sum(ch.isdigit() for ch in host) / max(len(host), 1),
        "domain_vowel_ratio": vowels / max(len(main_domain), 1),
        # --- content / brand tricks ---
        "suspicious_words": sum(w in low for w in SUSPICIOUS),
        "brand_in_subdomain": int(any(b in subdomain for b in BRANDS)),
        "brand_in_path": int(any(b in path for b in BRANDS)),
        "url_entropy": entropy(url),
        "host_entropy": entropy(host),
    }

X = pd.DataFrame([extract_features(u) for u in df["url"]])
y = df["label"].values
print(f"{X.shape[1]} features for {X.shape[0]} URLs")
X.head()