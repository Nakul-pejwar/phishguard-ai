import joblib
import pandas as pd

MODEL_PATH = "models/phishing_random_forest_model.joblib"

saved_data = joblib.load(MODEL_PATH)

model = saved_data["model"]
features = saved_data["features"]

sample_url_features = {
    "URLLength": 75,
    "DomainLength": 18,
    "IsDomainIP": 0,
    "TLDLegitimateProb": 0.5229,
    "URLCharProb": 0.061,
    "TLDLength": 3,
    "NoOfSubDomain": 1,
    "HasObfuscation": 0,
    "NoOfObfuscatedChar": 0,
    "ObfuscationRatio": 0,
    "NoOfLettersInURL": 55,
    "LetterRatioInURL": 0.73,
    "NoOfDegitsInURL": 4,
    "DegitRatioInURL": 0.05,
    "NoOfEqualsInURL": 0,
    "NoOfQMarkInURL": 0,
    "NoOfAmpersandInURL": 0,
    "NoOfOtherSpecialCharsInURL": 6,
    "SpacialCharRatioInURL": 0.08,
    "IsHTTPS": 1,
}

X = pd.DataFrame([sample_url_features], columns=features)

prob_legitimate = model.predict_proba(X)[0][1]
prob_phishing = 1 - prob_legitimate

if prob_phishing >= 0.80:
    verdict = "phishing"
elif prob_phishing >= 0.50:
    verdict = "suspicious"
else:
    verdict = "safe"

print("Phishing probability:", round(prob_phishing * 100, 2), "%")
print("Legitimate probability:", round(prob_legitimate * 100, 2), "%")
print("Verdict:", verdict)