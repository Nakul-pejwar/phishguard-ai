import json
import sys
import zipfile
from pathlib import Path

# Add root project directory to sys.path
TEST_FILE = Path(__file__).resolve()
ROOT_DIR = TEST_FILE.parent.parent.parent.parent
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))

from scanner.orchestrator import DetectionOrchestrator  # noqa: E402
from scripts.package_extension import EXTENSION_DIR, package_extension, validate_manifest  # noqa: E402



def test_sender_domain_mismatch_detection():
    # 1. Spoofed Indian Bank Sender vs Malicious Lookalike Link
    result = DetectionOrchestrator.analyze(
        "http://hdfc-verify-login.xyz/auth",
        sender_domain="alerts@hdfcbank.com",
    )
    assert result["signals"]["sender_domain_mismatch"] is True
    assert result["verdict"] == "phishing"
    assert result["risk_level"] in ["high", "Critical Risk"]
    assert any("Sender domain" in r for r in result["reasons"])

    # 2. Legitimate Bank Email & Matching Legitimate Domain Link
    legit_result = DetectionOrchestrator.analyze(
        "https://www.hdfcbank.com/personal/ways-to-bank/online-banking",
        sender_domain="alerts@hdfcbank.com",
    )
    assert legit_result["signals"]["sender_domain_mismatch"] is False
    assert legit_result["verdict"] == "safe"

    # 3. Legitimate SBI Email with official domain
    sbi_result = DetectionOrchestrator.analyze(
        "https://onlinesbi.sbi/portal",
        sender_domain="support@sbi.co.in",
    )
    assert sbi_result["signals"]["sender_domain_mismatch"] is False


def test_manifest_includes_webmail_content_scripts():
    manifest_path = EXTENSION_DIR / "manifest.json"
    manifest = validate_manifest(manifest_path)

    # Check content scripts include Gmail & Outlook matches
    content_scripts = manifest.get("content_scripts", [])
    webmail_script = None
    for cs in content_scripts:
        matches = cs.get("matches", [])
        if any("mail.google.com" in m for m in matches):
            webmail_script = cs
            break

    assert webmail_script is not None
    assert "email_scanner.js" in webmail_script["js"]
    assert "email_scanner.css" in webmail_script["css"]


def test_extension_packager_bundles_email_scanner():
    package_extension()
    manifest_path = EXTENSION_DIR / "manifest.json"
    with open(manifest_path, "r", encoding="utf-8") as f:
        version = json.load(f)["version"]

    zip_path = Path(__file__).resolve().parent.parent.parent.parent / "dist" / f"phishguard-extension-v{version}.zip"
    assert zip_path.exists()

    with zipfile.ZipFile(zip_path, "r") as z:
        namelist = z.namelist()
        assert "email_scanner.js" in namelist
        assert "email_scanner.css" in namelist
        assert "background.js" in namelist
        assert "manifest.json" in namelist

