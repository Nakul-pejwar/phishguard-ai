import os
import joblib
from urllib.parse import urlparse, urlunparse
from django.conf import settings


MODEL_PATH = os.path.join(
    settings.BASE_DIR,
    "scanner",
    "ml",
    "phishing_url_text_model_v2.joblib",
)

saved_data = joblib.load(MODEL_PATH)
model = saved_data["model"]


TRUSTED_DOMAINS = {
    "google.com",
    "github.com",
    "amazon.com",
    "wikipedia.org",
    "stackoverflow.com",
    "netflix.com",
    "microsoft.com",
    "apple.com",
    "openai.com",
    "youtube.com",
    "linkedin.com",
    "facebook.com",
    "instagram.com",
    "x.com",
    "twitter.com",
    "reddit.com",
}


SENSITIVE_KEYWORDS = {
    "login",
    "verify",
    "verification",
    "account",
    "password",
    "secure",
    "update",
    "payment",
    "bank",
    "wallet",
    "otp",
    "kyc",
}


def normalize_url(url: str) -> str:
    url = str(url).strip().lower()

    if not url.startswith(("http://", "https://")):
        url = "https://" + url

    parsed = urlparse(url)
    domain = parsed.netloc.lower()

    if "@" in domain:
        domain = domain.split("@")[-1]

    if ":" in domain:
        domain = domain.split(":")[0]

    if domain.startswith("www."):
        domain = domain[4:]

    return urlunparse(
        (
            parsed.scheme,
            domain,
            parsed.path,
            "",
            parsed.query,
            "",
        )
    )


def get_domain(clean_url: str) -> str:
    return urlparse(clean_url).netloc.lower()


def is_trusted_domain(domain: str) -> bool:
    return domain in TRUSTED_DOMAINS or any(domain.endswith("." + d) for d in TRUSTED_DOMAINS)


def contains_sensitive_keyword(clean_url: str) -> bool:
    return any(keyword in clean_url for keyword in SENSITIVE_KEYWORDS)


def predict_phishing_url(url: str) -> dict:
    clean_url = normalize_url(url)
    domain = get_domain(clean_url)

    prob_legitimate = model.predict_proba([clean_url])[0][1]
    prob_phishing = 1 - prob_legitimate

    raw_phishing_probability = prob_phishing * 100
    adjusted_phishing_probability = raw_phishing_probability
    reasons = []

    if is_trusted_domain(domain):
        adjusted_phishing_probability = min(adjusted_phishing_probability, 20)
        reasons.append("Trusted domain detected, risk reduced.")

    if clean_url.startswith("http://") and not is_trusted_domain(domain):
        adjusted_phishing_probability += 10
        reasons.append("URL does not use HTTPS.")

    if contains_sensitive_keyword(clean_url) and not is_trusted_domain(domain):
        adjusted_phishing_probability += 10
        reasons.append("Sensitive keyword found in URL.")

    adjusted_phishing_probability = max(0, min(100, adjusted_phishing_probability))
    adjusted_legitimate_probability = 100 - adjusted_phishing_probability

    if adjusted_phishing_probability >= 85:
        verdict = "phishing"
        risk_level = "high"
    elif adjusted_phishing_probability >= 60:
        verdict = "suspicious"
        risk_level = "medium"
    else:
        verdict = "safe"
        risk_level = "low"

    return {
        "input_url": url,
        "clean_url": clean_url,
        "domain": domain,
        "verdict": verdict,
        "risk_level": risk_level,
        "raw_phishing_probability": round(raw_phishing_probability, 2),
        "phishing_probability": round(adjusted_phishing_probability, 2),
        "legitimate_probability": round(adjusted_legitimate_probability, 2),
        "reasons": reasons,
    }