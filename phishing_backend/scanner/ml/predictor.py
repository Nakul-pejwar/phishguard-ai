import logging
import os
from urllib.parse import urlparse, urlunparse

import joblib
from django.conf import settings

logger = logging.getLogger(__name__)

TRUSTED_DOMAINS = {
    "google.com",
    "google.co.in",
    "github.com",
    "amazon.com",
    "amazon.in",
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
    # Indian Banking & Financial Institutions
    "hdfcbank.com",
    "hdfc.com",
    "onlinesbi.sbi",
    "sbi.co.in",
    "icicibank.com",
    "axisbank.com",
    "kotak.com",
    "pnbindia.in",
    "bankofbaroda.in",
    # Indian Fintech & Payments
    "paytm.com",
    "phonepe.com",
    "cred.club",
    "razorpay.com",
    "zerodha.com",
    "groww.in",
    "bharatpe.com",
    # Indian Govt & Utilities
    "npci.org.in",
    "bhimupi.org.in",
    "incometax.gov.in",
    "uidai.gov.in",
    "irctc.co.in",
    "indiapost.gov.in",
    "epfindia.gov.in",
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


class ModelManager:
    _instance = None

    def __init__(self):
        self.model = None
        self.is_loaded = False
        self.load_error = None
        self._load_attempted = False
        self.model_path = getattr(
            settings,
            "PHISHING_MODEL_PATH",
            os.path.join(settings.BASE_DIR, "scanner", "ml", "phishing_url_text_model_v2.joblib"),
        )

    @classmethod
    def get_instance(cls):
        if cls._instance is None:
            cls._instance = cls()
        return cls._instance

    def load_model(self, custom_path=None):
        path_to_load = custom_path or self.model_path
        self._load_attempted = True
        if not os.path.exists(path_to_load):
            self.is_loaded = False
            self.model = None
            self.load_error = f"Model file not found at {path_to_load}"
            logger.warning(
                "PhishGuard Warning: %s. Application will run in heuristic fallback mode.",
                self.load_error,
            )
            return False

        try:
            saved_data = joblib.load(path_to_load)
            self.model = saved_data.get("model", saved_data)
            self.is_loaded = True
            self.load_error = None
            logger.info("Successfully loaded PhishGuard ML model from %s", path_to_load)
            return True
        except Exception as exc:
            self.is_loaded = False
            self.model = None
            self.load_error = f"Failed to load model from {path_to_load}: {exc}"
            logger.error("PhishGuard Error: %s", self.load_error)
            return False


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

    manager = ModelManager.get_instance()
    if not manager.is_loaded and not manager._load_attempted:
        manager.load_model()

    reasons = []

    if manager.is_loaded and manager.model is not None:
        prob_legitimate = manager.model.predict_proba([clean_url])[0][1]
        prob_phishing = 1 - prob_legitimate
        raw_phishing_probability = prob_phishing * 100
    else:
        # Graceful fallback baseline when model is not present
        raw_phishing_probability = 40.0
        reasons.append("ML model unavailable; operating in heuristic fallback mode.")

    adjusted_phishing_probability = raw_phishing_probability

    if is_trusted_domain(domain):
        adjusted_phishing_probability = min(adjusted_phishing_probability, 20)
        reasons.append("Trusted domain detected, risk reduced.")

    if clean_url.startswith("http://") and not is_trusted_domain(domain):
        adjusted_phishing_probability += 10
        reasons.append("URL does not use HTTPS.")

    if contains_sensitive_keyword(clean_url) and not is_trusted_domain(domain):
        adjusted_phishing_probability += 10
        reasons.append("Sensitive keyword found in URL.")

    adjusted_phishing_probability = max(0.0, min(100.0, adjusted_phishing_probability))
    adjusted_legitimate_probability = 100.0 - adjusted_phishing_probability

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
