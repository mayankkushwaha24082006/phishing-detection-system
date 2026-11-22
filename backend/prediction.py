"""
prediction.py
-------------
Turns a (validated) URL into a full analysis:
  1. ML model  -> probability that the HOSTNAME looks like a phishing domain
  2. Rules     -> transparent warning signs found anywhere in the URL
  3. Risk score (0-100) = 75 * model probability + rule points
  4. Label + human-readable explanations

SAFETY: only text analysis. The URL is never opened or downloaded.
"""

from pathlib import Path
from urllib.parse import urlparse

import joblib
import pandas as pd

from feature_extraction import (
    DOMAIN_FEATURES,
    SUSPICIOUS_KEYWORDS,
    extract_domain_features,
    extract_features,
)

ROOT = Path(__file__).resolve().parent.parent
MODEL_PATH = ROOT / "ml" / "saved_model" / "model.joblib"

ML_WEIGHT = 75        # how many risk points a model probability of 1.0 is worth
SUSPICIOUS_AT = 30    # risk score at or above this  -> "Suspicious"
PHISHING_AT = 70      # risk score at or above this  -> "Phishing"

_bundle = None        # the model is loaded once and then reused


class ModelNotAvailableError(Exception):
    """Raised when the trained model cannot be loaded."""


# ----------------------------------------------------------------------------
# Model loading
# ----------------------------------------------------------------------------
def load_model():
    """Load model.joblib (once). Checks that its features match our code."""
    global _bundle
    if _bundle is not None:
        return _bundle

    if not MODEL_PATH.exists():
        raise ModelNotAvailableError(
            "Model file not found. Run `python ml/train_model.py` first.")
    try:
        bundle = joblib.load(MODEL_PATH)
        model, features = bundle["model"], bundle["features"]
    except Exception:
        raise ModelNotAvailableError("The model file could not be loaded. Retrain the model.")

    # Guarantees training features == prediction features
    if list(features) != list(DOMAIN_FEATURES):
        raise ModelNotAvailableError(
            "Model features do not match feature_extraction.py. Retrain the model.")

    _bundle = {"model": model, "features": list(features),
               "model_name": bundle.get("model_name", "Unknown")}
    return _bundle


def _model_probability(bundle, url):
    """P(phishing) from the ML model, using hostname-only features."""
    feats = extract_domain_features(url)
    # Column names must match the names used during training ("dom_...")
    row = pd.DataFrame([[feats[n] for n in bundle["features"]]],
                       columns=[f"dom_{n}" for n in bundle["features"]])
    model = bundle["model"]
    phishing_col = list(model.classes_).index(1)   # class 1 = phishing
    return float(model.predict_proba(row)[0][phishing_col])


# ----------------------------------------------------------------------------
# Rule layer (transparent, explainable warning signs)
# ----------------------------------------------------------------------------
def _rule_indicators(url, f):
    """Return a list of {points, severity, text} for every warning sign found."""
    try:
        parsed = urlparse(url)
        host = (parsed.hostname or "").lower()
        port = parsed.port
    except ValueError:
        host, port = "", None

    found = []

    def add(points, severity, text):
        found.append({"points": points, "severity": severity, "text": text})

    if f["has_ip_address"]:
        add(35, "high", "The address is a raw IP number instead of a domain name. "
                        "Legitimate services rarely do this.")
    if f["has_at_symbol"]:
        add(30, "high", "Contains an '@' symbol. Browsers ignore everything before it, "
                        "so the real destination can be hidden.")
    if f["is_shortener"]:
        add(20, "medium", "Uses a URL shortener, which hides the real destination.")
    if f["has_embedded_url"]:
        add(20, "medium", "Another web address is hidden inside the path or query, "
                          "a common redirect trick.")
    elif f["has_double_slash_redirect"]:
        add(15, "medium", "Contains an extra '//' after the domain, which can be used to redirect.")
    if host.startswith("xn--") or ".xn--" in host:
        add(15, "medium", "The domain uses punycode (xn--), which can disguise look-alike characters.")

    keywords = [k for k in SUSPICIOUS_KEYWORDS if k in url.lower()]
    if len(keywords) >= 3:
        add(20, "high", f"Contains several sensitive words: {', '.join(keywords[:5])}.")
    elif len(keywords) == 2:
        add(15, "medium", f"Contains sensitive words: {', '.join(keywords)}.")
    elif len(keywords) == 1:
        add(5, "low", f"Contains the word '{keywords[0]}', often used in fake login pages.")

    if f["num_subdomains"] >= 3:
        add(10, "medium", f"Has {f['num_subdomains']} subdomains. Attackers stack subdomains "
                          "to imitate a trusted brand.")
    if f["hostname_hyphens"] >= 3:
        add(10, "medium", f"The domain contains {f['hostname_hyphens']} hyphens, "
                          "typical of made-up look-alike names.")
    if port not in (None, 80, 443):
        add(10, "medium", f"Uses an unusual port number ({port}).")
    if f["url_length"] > 100:
        add(5, "low", f"The URL is very long ({f['url_length']} characters).")
    if not f["is_https"]:
        add(10, "low", "Does not use HTTPS, so the connection is not encrypted.")

    return found


def _label_for(score, has_indicators=True):
    """Convert a 0-100 risk score into (label, colour level, status message)."""
    if score >= PHISHING_AT:
        return ("Phishing", "danger",
                "Multiple strong warning signs. Do not open this link or enter any information.")
    if score >= SUSPICIOUS_AT:
        if has_indicators:
            msg = ("Some warning signs found. Avoid entering passwords or personal data "
                   "unless you can verify the site another way.")
        else:
            msg = ("No specific warning signs were found in the URL, but the ML model rated "
                   "the domain name as somewhat unusual. Verify the site before entering "
                   "any personal data.")
        return ("Suspicious", "warning", msg)
    return ("Low Risk", "success",
            "No strong warning signs were found in the URL text. This is NOT a guarantee "
            "that the website is safe.")


# ----------------------------------------------------------------------------
# Main entry point used by app.py
# ----------------------------------------------------------------------------
def analyze(url):
    """Analyze one validated URL. Returns a JSON-friendly dictionary."""
    bundle = load_model()

    probability = _model_probability(bundle, url)
    feats = extract_features(url)
    indicators = _rule_indicators(url, feats)
    rule_points = sum(i["points"] for i in indicators)

    risk_score = int(round(min(100, ML_WEIGHT * probability + rule_points)))

    # The ML model only sees the domain name and is not perfect, so on its own
    # it may not push a URL into "Phishing". If no rule found any warning sign,
    # the score is capped just below the Phishing threshold.
    if not indicators:
        risk_score = min(risk_score, PHISHING_AT - 1)

    # NOTE: this line must NOT be indented under the `if` above.
    label, level, status = _label_for(risk_score, bool(indicators))

    if indicators:
        explanation = (f"{len(indicators)} warning sign(s) found in the URL text. "
                       f"The ML model also rated the domain name at "
                       f"{probability * 100:.0f}% phishing-like.")
    else:
        explanation = ("No rule-based warning signs were found. The ML model rated the "
                       f"domain name at {probability * 100:.0f}% phishing-like.")

    return {
        "url": url,
        "label": label,
        "level": level,                       # success / warning / danger (for UI colours)
        "risk_score": risk_score,             # 0-100 blended score
        "model_probability": round(probability, 4),   # raw, uncalibrated model output
        "rule_points": rule_points,
        "status": status,
        "explanation": explanation,
        "indicators": indicators,
        "features": {
            "url_length": feats["url_length"],
            "num_dots": feats["num_dots"],
            "num_hyphens": feats["num_hyphens"],
            "num_subdomains": feats["num_subdomains"],
            "num_special_chars": feats["num_special_chars"],
            "url_entropy": round(feats["url_entropy"], 2),
            "uses_https": bool(feats["is_https"]),
            "suspicious_keywords": feats["num_suspicious_keywords"],
        },
        "model_name": bundle["model_name"],
        "disclaimer": ("The model probability is an uncalibrated output based on the domain "
                       "name only. The risk score combines it with rule-based checks. This is "
                       "a decision-support tool, not a guarantee of safety."),
    }