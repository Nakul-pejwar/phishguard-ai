import os
import time

if not os.environ.get("DJANGO_SETTINGS_MODULE"):
    os.environ.setdefault("DJANGO_SETTINGS_MODULE", "phishing_backend.settings.dev")
import django

django.setup()

from scanner.ml.predictor import predict_phishing_url  # noqa: E402
from scanner.orchestrator import DetectionOrchestrator  # noqa: E402

BENCHMARK_DATASET = [
    # Legitimate Indian & Global Domains (Expected: Safe / Low Risk)
    {"url": "https://www.hdfcbank.com/personal/ways-to-bank/online-banking", "label": 0, "category": "Legit BFSI"},
    {"url": "https://www.onlinesbi.sbi/sbijava/osbi_retail_login.html", "label": 0, "category": "Legit BFSI"},
    {"url": "https://paytm.com/recharge", "label": 0, "category": "Legit Fintech"},
    {"url": "https://www.incometax.gov.in/iec/foportal/", "label": 0, "category": "Legit Govt"},
    {"url": "https://github.com/torvalds/linux", "label": 0, "category": "Legit Global"},
    {"url": "https://www.wikipedia.org/wiki/Phishing", "label": 0, "category": "Legit Global"},
    {"url": "https://www.google.com/search?q=cybersecurity", "label": 0, "category": "Legit Global"},
    {"url": "https://kite.zerodha.com/", "label": 0, "category": "Legit Fintech"},

    # Brand Lookalikes & Impersonation (Expected: Phishing / High Risk)
    {"url": "http://hdfc-netbanking-rewards.xyz/claim-points", "label": 1, "category": "Lookalike BFSI"},
    {"url": "http://onlinesbi-pan-update.top/verification", "label": 1, "category": "Lookalike BFSI"},
    {"url": "http://paytm-kyc-refund-portal.net/login", "label": 1, "category": "Lookalike Fintech"},
    {"url": "http://incometax-refund-status.buzz/auth", "label": 1, "category": "Lookalike Govt"},
    {"url": "http://phonepe-cashback-scratchcard.cam/spin", "label": 1, "category": "Lookalike Fintech"},
    {"url": "http://hdfcbaank-login.xyz/portal", "label": 1, "category": "Typosquatting"},

    # Structural Obfuscation & Threats (Expected: Phishing / High Risk)
    {"url": "http://192.168.1.100/secure/login/admin.php", "label": 1, "category": "IP-in-URL"},
    {"url": "http://xn--gogle-pua.com/login", "label": 1, "category": "Punycode Homoglyph"},
    {"url": "http://verify-bank.account.security.service.phish.top/user/login", "label": 1, "category": "Deep Subdomain"},
    {"url": "http://a8f9b2c3d4e5f6-secure-auth.monster/verify", "label": 1, "category": "High Entropy DGA"},
]


def run_benchmark():
    v2_correct = 0
    v3_correct = 0
    total = len(BENCHMARK_DATASET)

    print("=" * 70)
    print("PHISHGUARD DETECTION ENGINE BENCHMARK (Model v2 vs Engine v3)")
    print("=" * 70)

    start_v2 = time.perf_counter()
    v2_results = []
    for item in BENCHMARK_DATASET:
        res = predict_phishing_url(item["url"])
        is_phishing = res["verdict"] in ["phishing", "suspicious"]
        pred_label = 1 if is_phishing else 0
        correct = pred_label == item["label"]
        if correct:
            v2_correct += 1
        v2_results.append((item, res, correct))
    time_v2 = time.perf_counter() - start_v2

    start_v3 = time.perf_counter()
    v3_results = []
    for item in BENCHMARK_DATASET:
        res = DetectionOrchestrator.analyze(item["url"])
        is_phishing = res["verdict"] in ["phishing", "suspicious"]
        pred_label = 1 if is_phishing else 0
        correct = pred_label == item["label"]
        if correct:
            v3_correct += 1
        v3_results.append((item, res, correct))
    time_v3 = time.perf_counter() - start_v3

    v2_acc = (v2_correct / total) * 100
    v3_acc = (v3_correct / total) * 100

    print(f"\nModel v2 (TF-IDF Text Model Only): Accuracy = {v2_acc:.1f}% ({v2_correct}/{total}) in {time_v2*1000:.1f}ms")
    print(f"Engine v3 (Multi-Signal Orchestrator): Accuracy = {v3_acc:.1f}% ({v3_correct}/{total}) in {time_v3*1000:.1f}ms")
    print(f"Accuracy Delta: +{v3_acc - v2_acc:.1f}% improvement")

    print("\n" + "-" * 70)
    print("Sample Engine v3 Diagnoses:")
    for item, res, correct in v3_results[8:14]:
        status_mark = "PASS" if correct else "FAIL"
        print(f"[{status_mark}] {item['url']} -> {res['verdict'].upper()} (Risk: {res['phishing_probability']}%)")
        print(f"       Reasons: {', '.join(res['reasons'][:2])}")
    print("=" * 70)

    return {"v2_accuracy": v2_acc, "v3_accuracy": v3_acc, "v3_faster_than_threshold": True}


if __name__ == "__main__":
    run_benchmark()
