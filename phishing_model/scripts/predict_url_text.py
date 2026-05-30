import joblib

MODEL_PATH = "models/phishing_url_text_model.joblib"

saved_data = joblib.load(MODEL_PATH)
model = saved_data["model"]


def normalize_url(url: str) -> str:
    url = url.strip()

    if not url.startswith(("http://", "https://")):
        url = "https://" + url

    return url


def predict_url(url: str) -> dict:
    url = normalize_url(url)

    prob_legitimate = model.predict_proba([url])[0][1]
    prob_phishing = 1 - prob_legitimate

    if prob_phishing >= 0.85:
        verdict = "phishing"
    elif prob_phishing >= 0.60:
        verdict = "suspicious"
    else:
        verdict = "safe"

    return {
        "url": url,
        "phishing_probability": round(prob_phishing * 100, 2),
        "legitimate_probability": round(prob_legitimate * 100, 2),
        "verdict": verdict,
    }


if __name__ == "__main__":
    test_urls = [
        "https://google.com",
        "https://github.com/login",
        "https://amazon.com",
        "https://www.wikipedia.org",
        "https://stackoverflow.com/questions",
        "http://192.168.1.10/paypal/login",
        "http://free-gift-login-security-check.com/verify?user=123",
        "http://paypa1-login-security-update.com/session?id=928391",
        "https://secure-paypal-login-verification.example.com/login",
        "https://netflix.com",
    ]

    for url in test_urls:
        result = predict_url(url)
        print("\nURL:", result["url"])
        print("Phishing probability:", result["phishing_probability"], "%")
        print("Legitimate probability:", result["legitimate_probability"], "%")
        print("Verdict:", result["verdict"])