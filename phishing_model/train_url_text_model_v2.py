import pandas as pd
import joblib
from urllib.parse import urlparse, urlunparse

from sklearn.model_selection import train_test_split
from sklearn.pipeline import Pipeline
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import (
    accuracy_score,
    confusion_matrix,
    classification_report,
    roc_auc_score,
)

DATASET_PATH = "dataset/PhiUSIIL_Phishing_URL_Dataset.csv"
MODEL_PATH = "models/phishing_url_text_model_v2.joblib"


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


df = pd.read_csv(DATASET_PATH)

df["clean_url"] = df["URL"].apply(normalize_url)

print("Dataset shape:", df.shape)
print("Missing URLs:", df["clean_url"].isnull().sum())
print("Label counts:")
print(df["label"].value_counts())

X = df["clean_url"]
y = df["label"]

X_train, X_test, y_train, y_test = train_test_split(
    X,
    y,
    test_size=0.2,
    random_state=42,
    stratify=y,
)

model = Pipeline(
    steps=[
        (
            "tfidf",
            TfidfVectorizer(
                analyzer="char",
                ngram_range=(3, 5),
                lowercase=True,
                max_features=80000,
            ),
        ),
        (
            "classifier",
            LogisticRegression(
                max_iter=1000,
                class_weight="balanced",
            ),
        ),
    ]
)

model.fit(X_train, y_train)

y_pred = model.predict(X_test)
y_proba = model.predict_proba(X_test)[:, 1]

print("\nAccuracy:", accuracy_score(y_test, y_pred))
print("ROC AUC:", roc_auc_score(y_test, y_proba))

print("\nConfusion Matrix:")
print(confusion_matrix(y_test, y_pred, labels=[0, 1]))

print("\nClassification Report:")
print(classification_report(y_test, y_pred, target_names=["phishing", "legitimate"]))

joblib.dump(
    {
        "model": model,
        "label_meaning": {
            0: "phishing",
            1: "legitimate",
        },
        "normalization": "lowercase, remove www, remove fragment",
    },
    MODEL_PATH,
)

print(f"\nModel saved to {MODEL_PATH}")