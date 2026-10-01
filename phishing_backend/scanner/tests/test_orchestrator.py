import hashlib

import pytest

from scanner.benchmark.benchmark_models import run_benchmark
from scanner.intel.feeds import ThreatIntelManager
from scanner.intel.models import ThreatFeedEntry
from scanner.orchestrator import DetectionOrchestrator


@pytest.mark.django_db
def test_orchestrator_threat_intel_override():
    test_url = "http://threat-feed-sample-phish.net/login"
    domain = "threat-feed-sample-phish.net"
    url_hash = hashlib.sha256(test_url.encode("utf-8")).hexdigest()

    ThreatIntelManager.get_instance().add_feed_entry(domain=domain, url_hash=url_hash, source=ThreatFeedEntry.SOURCE_OPENPHISH)

    result = DetectionOrchestrator.analyze(test_url)
    assert result["verdict"] == "phishing"
    assert result["risk_level"] == "high"
    assert result["phishing_probability"] == 100.0
    assert any("Listed in threat feed" in r for r in result["reasons"])


@pytest.mark.django_db
def test_orchestrator_lookalike_detection():
    result = DetectionOrchestrator.analyze("http://hdfc-secure-login.xyz/portal")
    assert result["verdict"] in ["phishing", "suspicious"]
    assert result["risk_level"] in ["high", "medium"]
    assert any("impersonating" in r.lower() or "hdfc" in r.lower() for r in result["reasons"])
    assert result["signals"]["brand_lookalike_detected"] is True


@pytest.mark.django_db
def test_orchestrator_legitimate_url_safe():
    result = DetectionOrchestrator.analyze("https://github.com/login")
    assert result["verdict"] == "safe"
    assert result["risk_level"] == "low"
    assert result["phishing_probability"] <= 20.0
    assert result["signals"]["trusted_domain"] is True


@pytest.mark.django_db
def test_benchmark_harness_execution():
    bench_results = run_benchmark()
    assert "v2_accuracy" in bench_results
    assert "v3_accuracy" in bench_results
    assert bench_results["v3_accuracy"] >= bench_results["v2_accuracy"]
