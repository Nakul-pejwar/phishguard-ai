import hashlib
import logging

from .features.domain_features import extract_domain_features
from .intel.feeds import ThreatIntelManager
from .lookalike.detector import check_brand_impersonation
from .ml.predictor import (
    ModelManager,
    contains_sensitive_keyword,
    get_domain,
    is_trusted_domain,
    normalize_url,
)

logger = logging.getLogger(__name__)


class DetectionOrchestrator:
    """
    Multi-Signal Phishing Detection Engine (v3 Orchestrator).
    Synthesizes Threat Intel, Brand Lookalikes, Structural Features,
    and the ML Text Model into an explainable risk verdict.
    """

    @classmethod
    def analyze(cls, url: str, organization=None, sender_domain: str | None = None) -> dict:
        clean_url = normalize_url(url)
        domain = get_domain(clean_url)
        url_hash = hashlib.sha256(clean_url.encode("utf-8")).hexdigest()

        # Signal 0: Org-Level Security Policy Allowlist & Blocklist
        org_resp = cls._evaluate_org_policy(organization, domain, url, clean_url)
        if org_resp:
            return org_resp

        # Signal 1: Threat Intel Check
        threat_resp = cls._evaluate_threat_intel(url, clean_url, domain, url_hash)
        if threat_resp:
            return threat_resp

        reasons = []
        signals = {
            "threat_intel_match": False,
            "brand_lookalike_detected": False,
            "sender_domain_mismatch": False,
            "structural_risk_score": 0,
            "ml_model_score": 0.0,
            "trusted_domain": False,
        }

        # Signal 2: Indian Brand Lookalike Impersonation
        lookalike_info = check_brand_impersonation(domain)
        lookalike_penalty = 0
        if lookalike_info["is_impersonation"]:
            signals["brand_lookalike_detected"] = True
            lookalike_penalty = 60
            reasons.append(lookalike_info["reason"])

        # Signal 2b: Sender vs Link Domain Mismatch Analysis (Email Phishing Protection)
        mismatch_penalty, mismatch_reasons, is_mismatch = cls._evaluate_sender_mismatch(
            sender_domain, domain, lookalike_info["is_impersonation"]
        )
        if is_mismatch:
            signals["sender_domain_mismatch"] = True
            reasons.extend(mismatch_reasons)

        # Signal 3: Structural Domain Features
        features = extract_domain_features(clean_url, domain)
        signals["structural_risk_score"] = features["risk_points"]
        reasons.extend(features["reasons"])

        # Signal 4: ML Text Model Score
        raw_ml_prob, ml_reason = cls._get_ml_prediction(clean_url)
        if ml_reason:
            reasons.append(ml_reason)
        signals["ml_model_score"] = round(raw_ml_prob, 2)

        # Signal 5: Score Synthesis
        total_penalty = lookalike_penalty + mismatch_penalty
        final_score, synth_reasons = cls._synthesize_risk_score(
            clean_url, domain, raw_ml_prob, total_penalty, features["risk_points"], lookalike_info["is_impersonation"]
        )
        reasons.extend(synth_reasons)
        signals["trusted_domain"] = is_trusted_domain(domain)

        verdict, risk_level = cls._determine_verdict(final_score)

        # Deduplicate reasons preserving order
        unique_reasons = list(dict.fromkeys(reasons))

        return {
            "input_url": url,
            "clean_url": clean_url,
            "domain": domain,
            "verdict": verdict,
            "risk_level": risk_level,
            "raw_phishing_probability": round(raw_ml_prob, 2),
            "phishing_probability": round(final_score, 2),
            "legitimate_probability": round(100.0 - final_score, 2),
            "reasons": unique_reasons,
            "engine_version": "v3-orchestrated",
            "signals": signals,
        }

    @staticmethod
    def _evaluate_org_policy(organization, domain: str, url: str, clean_url: str) -> dict | None:
        if not organization:
            return None
        policy = getattr(organization, "policy", None)
        if not policy:
            return None

        if domain in (policy.custom_allowlist or []):
            return {
                "input_url": url,
                "clean_url": clean_url,
                "domain": domain,
                "verdict": "safe",
                "risk_level": "Safe",
                "raw_phishing_probability": 0.01,
                "phishing_probability": 0.01,
                "legitimate_probability": 0.99,
                "reasons": ["Domain allowlisted by organization security policy."],
                "signals": {"org_policy_allowlist": True},
            }
        if domain in (policy.custom_blocklist or []):
            return {
                "input_url": url,
                "clean_url": clean_url,
                "domain": domain,
                "verdict": "phishing",
                "risk_level": "Critical Risk",
                "raw_phishing_probability": 1.0,
                "phishing_probability": 1.0,
                "legitimate_probability": 0.0,
                "reasons": ["Domain blocked by organization security policy."],
                "signals": {"org_policy_blocklist": True},
            }
        return None

    @staticmethod
    def _evaluate_sender_mismatch(sender_domain: str | None, domain: str, is_lookalike: bool) -> tuple[int, list[str], bool]:
        if not sender_domain:
            return 0, [], False

        clean_sender = sender_domain.split("@")[-1].strip().lower()
        if not clean_sender or clean_sender == domain:
            return 0, [], False

        from .lookalike.indian_brands import INDIAN_BRANDS_CATALOG

        # Check if sender and target domain belong to the same verified brand
        for b_info in INDIAN_BRANDS_CATALOG.values():
            sender_in_brand = any(clean_sender == vd or clean_sender.endswith("." + vd) for vd in b_info["domains"])
            dest_in_brand = any(domain == vd or domain.endswith("." + vd) for vd in b_info["domains"])
            if sender_in_brand and dest_in_brand:
                return 0, [], False

        sender_is_known_brand = False
        for b_info in INDIAN_BRANDS_CATALOG.values():
            if any(clean_sender == vd or clean_sender.endswith("." + vd) for vd in b_info["domains"]):
                sender_is_known_brand = True
                break

        if sender_is_known_brand or is_trusted_domain(clean_sender):
            return (
                40,
                [
                    f"Sender domain ({clean_sender}) claims to be an established brand/institution, "
                    f"but email link targets an external destination ({domain}). Potential spoofing attack."
                ],
                True,
            )
        if is_lookalike:
            return (
                30,
                [f"Sender domain ({clean_sender}) mismatch with lookalike target domain ({domain})."],
                True,
            )

        return 0, [], False



    @staticmethod
    def _evaluate_threat_intel(url: str, clean_url: str, domain: str, url_hash: str):
        is_threat, source = ThreatIntelManager.get_instance().check_threat_intel(url_hash, domain)
        if is_threat:
            return {
                "input_url": url,
                "clean_url": clean_url,
                "domain": domain,
                "verdict": "phishing",
                "risk_level": "high",
                "raw_phishing_probability": 100.0,
                "phishing_probability": 100.0,
                "legitimate_probability": 0.0,
                "reasons": [f"Listed in threat feed ({source})."],
                "engine_version": "v3-orchestrated",
                "signals": {
                    "threat_intel_match": True,
                    "brand_lookalike_detected": False,
                    "structural_risk_score": 100,
                    "ml_model_score": 100.0,
                    "trusted_domain": False,
                },
            }
        return None

    @staticmethod
    def _get_ml_prediction(clean_url: str) -> tuple[float, str | None]:
        manager = ModelManager.get_instance()
        if not manager.is_loaded and not manager._load_attempted:
            manager.load_model()

        if manager.is_loaded and manager.model is not None:
            prob_legitimate = manager.model.predict_proba([clean_url])[0][1]
            return (1.0 - prob_legitimate) * 100.0, None
        return 35.0, "ML text model running in baseline fallback mode."

    @staticmethod
    def _synthesize_risk_score(clean_url: str, domain: str, raw_ml: float, lookalike_penalty: int, feat_points: int, is_impersonating: bool) -> tuple[float, list[str]]:
        reasons = []
        calculated = (raw_ml * 0.5) + lookalike_penalty + (feat_points * 0.5)
        trusted = is_trusted_domain(domain)

        if trusted and not is_impersonating:
            calculated = min(calculated, 20.0)
            reasons.append("Trusted domain detected, risk reduced.")

        if clean_url.startswith("http://") and not trusted:
            calculated += 10.0
            reasons.append("URL does not use HTTPS.")

        if contains_sensitive_keyword(clean_url) and not trusted:
            calculated += 10.0
            reasons.append("Sensitive keyword found in URL.")

        return max(0.0, min(100.0, calculated)), reasons

    @staticmethod
    def _determine_verdict(score: float) -> tuple[str, str]:
        if score >= 80.0:
            return "phishing", "high"
        if score >= 50.0:
            return "suspicious", "medium"
        return "safe", "low"
