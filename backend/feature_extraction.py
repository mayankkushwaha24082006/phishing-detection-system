"""
feature_extraction.py
---------------------
Converts a URL string into a fixed list of numeric features.

IMPORTANT: This file is used by BOTH training (ml/preprocess.py, ml/train_model.py)
and the live app (backend/prediction.py). That guarantees the model always sees
the same features at training time and at prediction time.

SAFETY: Everything here is pure text analysis. We NEVER open, visit, or
download the URL.
"""

import ipaddress
import math
import re
from urllib.parse import urlparse

# ----------------------------------------------------------------------------
# Constants
# ----------------------------------------------------------------------------
MAX_URL_LENGTH = 2048  # reject absurdly long input

# Words often seen in phishing URLs (fake "login", "verify your account", ...)
SUSPICIOUS_KEYWORDS = [
    "login", "signin", "verify", "update", "secure", "account", "banking",
    "confirm", "password", "paypal", "webscr", "wallet", "support",
    "suspend", "billing", "validate", "authenticate", "unlock", "recover",
    "credential", "free", "bonus", "gift", "prize",
]

# Popular URL shortening services (they hide the real destination)
URL_SHORTENERS = {
    "bit.ly", "tinyurl.com", "goo.gl", "t.co", "ow.ly", "is.gd", "buff.ly",
    "adf.ly", "cutt.ly", "rebrand.ly", "shorturl.at", "tiny.cc", "rb.gy",
    "bl.ink", "lnkd.in", "t.ly",
}

# Two-part endings like ".co.in" so we count subdomains correctly
TWO_LEVEL_SUFFIXES = {
    "co.uk", "org.uk", "ac.uk", "gov.uk", "co.in", "net.in", "org.in",
    "ac.in", "gov.in", "co.jp", "com.au", "com.br", "com.cn", "co.za",
}

# The exact list (and ORDER) of features extract_features() produces.
FEATURE_NAMES = [
    "url_length",
    "hostname_length",
    "path_length",
    "query_length",
    "num_dots",
    "num_hyphens",
    "hostname_hyphens",
    "num_underscores",
    "num_digits",
    "digit_ratio",
    "num_special_chars",
    "num_query_params",
    "path_depth",
    "num_subdomains",
    "has_ip_address",
    "is_https",
    "has_at_symbol",
    "has_port",
    "is_shortener",
    "num_suspicious_keywords",
    "has_double_slash_redirect",
    "has_embedded_url",
    "url_entropy",
]


# ----------------------------------------------------------------------------
# Helper functions
# ----------------------------------------------------------------------------
def is_ip_address(host):
    """True if the host is an IP address like 192.168.1.1 (or hex/decimal form)."""
    if not host:
        return False
    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        pass
    # Tricks like http://0x7f000001 or http://3232235777 also hide an IP
    return bool(re.fullmatch(r"0x[0-9a-fA-F]+", host) or re.fullmatch(r"\d{8,10}", host))


def count_subdomains(host):
    """
    Count subdomains. 'login.secure.paypal.com' -> 2.
    A leading 'www' is ignored because it is extremely common on real sites.
    """
    if not host or is_ip_address(host):
        return 0
    if host.startswith("www."):
        host = host[4:]
    parts = host.split(".")
    base_parts = 3 if len(parts) >= 3 and ".".join(parts[-2:]) in TWO_LEVEL_SUFFIXES else 2
    return max(0, len(parts) - base_parts)


def shannon_entropy(text):
    """How 'random' a string looks. Random-looking URLs have higher entropy."""
    if not text:
        return 0.0
    counts = {}
    for ch in text:
        counts[ch] = counts.get(ch, 0) + 1
    length = len(text)
    return -sum((c / length) * math.log2(c / length) for c in counts.values())


# ----------------------------------------------------------------------------
# URL validation (used by the live app, not by training)
# ----------------------------------------------------------------------------
def normalize_url(raw_url):
    """
    Check and clean a URL typed by a user.
    Returns (clean_url, scheme_was_assumed).
    Raises ValueError with a friendly message if the URL is unusable.
    """
    if not isinstance(raw_url, str):
        raise ValueError("URL must be text.")
    url = raw_url.strip()
    if not url:
        raise ValueError("Please enter a URL.")
    if len(url) > MAX_URL_LENGTH:
        raise ValueError("URL is too long (max 2048 characters).")
    if re.search(r"\s", url):
        raise ValueError("URL must not contain spaces.")

    # Malformed like 'http:facebook.com' (missing the //)
    if re.match(r"^https?:(?!//)", url, re.IGNORECASE):
        raise ValueError("Malformed URL. Use the form http://example.com or https://example.com")

    scheme_assumed = False
    if re.match(r"^[a-zA-Z][a-zA-Z0-9+.\-]*://", url):
        if not re.match(r"^https?://", url, re.IGNORECASE):
            raise ValueError("Only http:// and https:// URLs are supported.")
    else:
        url = "https://" + url   # user typed just 'example.com'
        scheme_assumed = True

    try:
        parsed = urlparse(url)
        host = parsed.hostname
        _ = parsed.port  # raises ValueError if the port is invalid
    except ValueError:
        raise ValueError("This does not look like a valid URL.")

    if not host:
        raise ValueError("This does not look like a valid URL.")
    if not is_ip_address(host) and ("." not in host or ".." in host or host.endswith(".")):
        raise ValueError("The domain name looks invalid (example: example.com).")

    return url, scheme_assumed


# ----------------------------------------------------------------------------
# Main feature extraction
# ----------------------------------------------------------------------------
def extract_features(url):
    """
    Turn one URL string into a dictionary {feature_name: number}.
    Works on the URL text only; never contacts the website.
    """
    url = str(url).strip()
    try:
        parsed = urlparse(url)
        host = (parsed.hostname or "").lower()
        path = parsed.path or ""
        query = parsed.query or ""
        scheme = (parsed.scheme or "").lower()
        has_port = parsed.port is not None
    except ValueError:  # badly broken URLs (e.g. invalid IPv6 brackets)
        host, path, query, scheme, has_port = "", "", "", "", False

    lower_url = url.lower()
    num_digits = sum(ch.isdigit() for ch in url)

    # Everything after "scheme://" (used to spot a second "http" or "//")
    after_scheme = url.split("://", 1)[1] if "://" in url else url

    features = {
        "url_length": len(url),
        "hostname_length": len(host),
        "path_length": len(path),
        "query_length": len(query),
        "num_dots": url.count("."),
        "num_hyphens": url.count("-"),
        "hostname_hyphens": host.count("-"),
        "num_underscores": url.count("_"),
        "num_digits": num_digits,
        "digit_ratio": num_digits / len(url) if url else 0.0,
        # any character that is not a letter or a digit
        "num_special_chars": sum(not ch.isalnum() for ch in url),
        "num_query_params": len(query.split("&")) if query else 0,
        "path_depth": path.count("/"),
        "num_subdomains": count_subdomains(host),
        "has_ip_address": int(is_ip_address(host)),
        "is_https": int(scheme == "https"),
        "has_at_symbol": int("@" in url),
        "has_port": int(has_port),
        "is_shortener": int(host in URL_SHORTENERS),
        "num_suspicious_keywords": sum(kw in lower_url for kw in SUSPICIOUS_KEYWORDS),
        # '//' appearing again after the scheme often means a redirect trick
        "has_double_slash_redirect": int("//" in after_scheme),
        # another 'http' hidden in the path/query, e.g. site.com/?next=http://evil.com
        "has_embedded_url": int("http" in (path + "?" + query).lower()),
        "url_entropy": shannon_entropy(url),
    }
    return features


def features_to_vector(features):
    """Put a features dictionary into the exact order the model expects."""
    return [features[name] for name in FEATURE_NAMES]


# ----------------------------------------------------------------------------
# Domain-only model support
# ----------------------------------------------------------------------------
# The dataset's legitimate URLs are all bare homepages, so path/query/https
# features would be a "shortcut". The ML model therefore only looks at the
# HOSTNAME. Path-based warning signs are handled by rules in prediction.py.
DOMAIN_FEATURES = [
    "url_length", "hostname_length", "num_dots", "num_hyphens",
    "hostname_hyphens", "num_underscores", "num_digits", "digit_ratio",
    "num_special_chars", "num_subdomains", "has_ip_address", "is_shortener",
    "num_suspicious_keywords", "url_entropy",
]


def host_only_url(url):
    """
    'https://www.a.com/x/y?z=1' -> 'http://a.com'
    Keeps only the hostname and REMOVES a leading 'www.'.
    Why: in the dataset almost every legitimate URL starts with 'www.', so the
    model would learn "no www = phishing" and wrongly flag github.com.
    """
    try:
        host = (urlparse(str(url).strip()).hostname or "").lower()
    except ValueError:
        host = ""
    if host.startswith("www."):
        host = host[4:]
    return "http://" + host


def extract_domain_features(url):
    """Feature dict for the domain-only model (same code for training and live use)."""
    feats = extract_features(host_only_url(url))
    return {name: feats[name] for name in DOMAIN_FEATURES}


# ----------------------------------------------------------------------------
# Quick self-test: run `python backend/feature_extraction.py`
# ----------------------------------------------------------------------------
if __name__ == "__main__":
    samples = [
        "https://www.google.com/",
        "http://192.168.10.5/login/verify.php",
        "http://paypal.com@evil-site.xyz/secure",
        "https://bit.ly/3abcXYZ",
        "http://secure-login.update.account-verify.example.co.in/signin?next=http://x.com",
    ]
    for s in samples:
        print("\nURL:", s)
        feats = extract_features(s)
        for name in FEATURE_NAMES:
            print(f"   {name:28s} {feats[name]}")

    print("\n--- Domain-only features for the last sample ---")
    print(extract_domain_features(samples[-1]))

    print("\n--- Validation tests ---")
    for bad in ["", "http:facebook.com", "ftp://example.com", "not a url", "example.com"]:
        try:
            print(repr(bad), "->", normalize_url(bad))
        except ValueError as err:
            print(repr(bad), "-> ERROR:", err)