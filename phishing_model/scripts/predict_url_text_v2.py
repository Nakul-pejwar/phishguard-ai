import joblib
from urllib.parse import urlparse, urlunparse

MODEL_PATH = "models/phishing_url_text_model_v2.joblib"

saved_data = joblib.load(MODEL_PATH)
model = saved_data["model"]


def normalize_url(url: str) -> str:
    url = str(url).strip().lower()

    if not url.startswith(("http://", "https://")):
        url = "https://" + url

    parsed = urlparse(url)

    domain = parsed.netloc.lower()

    if domain.startswith("www."):
        domain = domain[4:]

    normalized = urlunparse(
        (
            parsed.scheme,
            domain,
            parsed.path,
            "",
            parsed.query,
            "",
        )
    )

    return normalized


def predict_url(url: str) -> dict:
    clean_url = normalize_url(url)

    prob_legitimate = model.predict_proba([clean_url])[0][1]
    prob_phishing = 1 - prob_legitimate

    if prob_phishing >= 0.85:
        verdict = "phishing"
    elif prob_phishing >= 0.60:
        verdict = "suspicious"
    else:
        verdict = "safe"

    return {
        "input_url": url,
        "clean_url": clean_url,
        "phishing_probability": round(prob_phishing * 100, 2),
        "legitimate_probability": round(prob_legitimate * 100, 2),
        "verdict": verdict,
    }


if __name__ == "__main__":
    test_urls = [
        "https://google.com",
        "https://www.google.com",
        "https://github.com/login",
        "https://www.github.com/login",
        "https://amazon.com",
        "https://www.amazon.com",
        "https://www.wikipedia.org",
        "https://stackoverflow.com/questions",
        "https://www.stackoverflow.com/questions",
        "https://netflix.com",
        "https://www.netflix.com",
        "http://192.168.1.10/paypal/login",
        "http://free-gift-login-security-check.com/verify?user=123",
        "http://paypa1-login-security-update.com/session?id=928391",
        "https://secure-paypal-login-verification.example.com/login",
    ]

    for url in test_urls:
        result = predict_url(url)
        print("\nInput URL:", result["input_url"])
        print("Clean URL:", result["clean_url"])
        print("Phishing probability:", result["phishing_probability"], "%")
        print("Legitimate probability:", result["legitimate_probability"], "%")
        print("Verdict:", result["verdict"])