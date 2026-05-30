import joblib
import pandas as pd
from scripts.url_feature_extractor import extract_url_features

MODEL_PATH = "models/phishing_simple_url_model.joblib"

saved_data = joblib.load(MODEL_PATH)

model = saved_data["model"]
features = saved_data["features"]


def predict_url(url: str) -> dict:
    extracted = extract_url_features(url)

    X = pd.DataFrame([extracted], columns=features)

    prob_legitimate = model.predict_proba(X)[0][1]
    prob_phishing = 1 - prob_legitimate

    if prob_phishing >= 0.80:
        verdict = "phishing"
    elif prob_phishing >= 0.50:
        verdict = "suspicious"
    else:
        verdict = "safe"

    return {
        "url": url,
        "phishing_probability": round(prob_phishing * 100, 2),
        "legitimate_probability": round(prob_legitimate * 100, 2),
        "verdict": verdict,
        "features": extracted,
    }


if __name__ == "__main__":
    test_urls = [
        "https://google.com",
        "https://github.com/login",
        "http://192.168.1.10/paypal/login",
        "http://free-gift-login-security-check.com/verify?user=123",
        "https://amazon.com",
    ]

    for url in test_urls:
        result = predict_url(url)
        print("\nURL:", result["url"])
        print("Phishing probability:", result["phishing_probability"], "%")
        print("Legitimate probability:", result["legitimate_probability"], "%")
        print("Verdict:", result["verdict"])