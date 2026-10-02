import sys
from pathlib import Path

# Add root project directory to sys.path
TEST_FILE = Path(__file__).resolve()
ROOT_DIR = TEST_FILE.parent.parent.parent.parent
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))

EXTENSION_DIR = ROOT_DIR / "browser_extension"
from scripts.package_extension import REQUIRED_FILES, validate_manifest  # noqa: E402


def test_manifest_structure():
    manifest_path = EXTENSION_DIR / "manifest.json"
    manifest = validate_manifest(manifest_path)

    assert manifest["manifest_version"] == 3
    assert "name" in manifest
    assert "version" in manifest
    assert manifest["background"]["service_worker"] == "background.js"
    assert "action" in manifest
    assert manifest["action"]["default_popup"] == "popup.html"


def test_required_extension_files_exist():
    for rel_path in REQUIRED_FILES:
        target = EXTENSION_DIR / rel_path
        assert target.exists(), f"Missing required extension asset: {rel_path}"


def test_interstitial_page_structure():
    interstitial_html = EXTENSION_DIR / "interstitial.html"
    content = interstitial_html.read_text(encoding="utf-8")

    assert "targetDomain" in content
    assert "goBackBtn" in content
    assert "proceedAnywayBtn" in content
    assert "reasonsList" in content
    assert "interstitial.js" in content


def test_background_service_worker_structure():
    bg_js = EXTENSION_DIR / "background.js"
    content = bg_js.read_text(encoding="utf-8")

    assert "onBeforeNavigate" in content
    assert "STATIC_ALLOWLIST" in content
    assert "redirectToInterstitial" in content
    assert "CHECK_URL" in content


def test_content_script_credential_protection():
    content_js = EXTENSION_DIR / "content.js"
    content = content_js.read_text(encoding="utf-8")

    assert "phishguard-credential-banner" in content
    assert "input[type=\"password\"]" in content
    assert "showCredentialWarning" in content
