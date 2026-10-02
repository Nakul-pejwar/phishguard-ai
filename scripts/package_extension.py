#!/usr/bin/env python3
"""
PhishGuard AI — Extension Packaging & Validation Tool
Validates manifest schemas and builds clean distribution ZIP archives
ready for upload to:
  1. Chrome Web Store & Microsoft Edge Add-ons (Manifest V3)
  2. Mozilla Firefox Add-ons / AMO (Manifest V3 Firefox format)
"""

import json
import os
import sys
import zipfile
from pathlib import Path

ROOT_DIR = Path(__file__).resolve().parent.parent
EXTENSION_DIR = ROOT_DIR / "browser_extension"
DIST_DIR = ROOT_DIR / "dist"

REQUIRED_FILES = [
    "background.js",
    "content.js",
    "content.css",
    "email_scanner.js",
    "email_scanner.css",
    "interstitial.html",
    "interstitial.js",
    "interstitial.css",
    "popup.html",
    "popup.js",
    "style.css",
    "icons/icon16.png",
    "icons/icon32.png",
    "icons/icon48.png",
    "icons/icon128.png",
]


def validate_manifest(manifest_path: Path, is_firefox: bool = False) -> dict:
    if not manifest_path.exists():
        print(f"[-] ERROR: Manifest not found at {manifest_path}", file=sys.stderr)
        sys.exit(1)

    with open(manifest_path, "r", encoding="utf-8") as f:
        try:
            data = json.load(f)
        except json.JSONDecodeError as err:
            print(f"[-] ERROR: Invalid JSON in {manifest_path.name}: {err}", file=sys.stderr)
            sys.exit(1)

    # Validate MV3 requirements
    assert data.get("manifest_version") == 3, "manifest_version must be 3"
    assert "name" in data and "version" in data, "name and version are required"
    assert "action" in data and "default_popup" in data["action"], "action.default_popup required"

    if is_firefox:
        assert "background" in data and "scripts" in data["background"], "Firefox background.scripts required"
        assert "browser_specific_settings" in data, "browser_specific_settings required for Firefox"
        print(f"[+] Firefox Manifest Valid: {data['name']} (v{data['version']})")
    else:
        assert "background" in data and "service_worker" in data["background"], "background service_worker required"
        print(f"[+] Chrome/Edge Manifest V3 Valid: {data['name']} (v{data['version']})")

    return data


def build_package(target_name: str, manifest_filename: str, is_firefox: bool = False, api_url: str = None):
    manifest_path = EXTENSION_DIR / manifest_filename
    manifest_data = validate_manifest(manifest_path, is_firefox=is_firefox)
    version = manifest_data.get("version", "2.0.0")

    zip_filename = DIST_DIR / f"phishguard-{target_name}-v{version}.zip"

    # Verify required common files
    for rel_path in REQUIRED_FILES:
        target = EXTENSION_DIR / rel_path
        if not target.exists():
            print(f"[-] WARNING: Missing expected file: {target}")

    with zipfile.ZipFile(zip_filename, "w", zipfile.ZIP_DEFLATED) as zipf:
        for root, dirs, files in os.walk(EXTENSION_DIR):
            files = [f for f in files if not f.startswith(".") and not f.endswith(".tmp")]
            dirs[:] = [d for d in dirs if not d.startswith(".") and d != "__pycache__"]

            for file in files:
                full_path = Path(root) / file
                rel_path = full_path.relative_to(EXTENSION_DIR)

                # Skip the other manifest when building
                if file in ["manifest.json", "manifest_firefox.json"]:
                    continue

                # If a custom API URL is configured (e.g. on VPS deployment), inject it
                if api_url and file == "background.js":
                    content = full_path.read_text(encoding="utf-8")
                    modified = content.replace(
                        'const DEFAULT_API_BASE = "http://127.0.0.1:8000";',
                        f'const DEFAULT_API_BASE = "{api_url.rstrip("/")}";'
                    )
                    zipf.writestr(str(rel_path), modified)
                elif api_url and file == "popup.html":
                    content = full_path.read_text(encoding="utf-8")
                    modified = content.replace(
                        'value="http://127.0.0.1:8000"',
                        f'value="{api_url.rstrip("/")}"'
                    )
                    zipf.writestr(str(rel_path), modified)
                else:
                    zipf.write(full_path, arcname=rel_path)

        # Write the specific manifest as 'manifest.json' inside the archive root
        if api_url:
            m_content = manifest_path.read_text(encoding="utf-8")
            m_data = json.loads(m_content)
            host_perms = m_data.get("host_permissions", [])
            backend_perm = f"{api_url.rstrip('/')}/*"
            if backend_perm not in host_perms and "<all_urls>" not in host_perms:
                host_perms.append(backend_perm)
                m_data["host_permissions"] = host_perms
            zipf.writestr("manifest.json", json.dumps(m_data, indent=2))
        else:
            zipf.write(manifest_path, arcname="manifest.json")

    print(f"[+] Built {target_name.upper()} package: {zip_filename.name} ({zip_filename.stat().st_size / 1024:.2f} KB)")
    return zip_filename


def package_all(api_url: str = None):
    DIST_DIR.mkdir(parents=True, exist_ok=True)

    # Read API URL from env or argument if provided
    if not api_url:
        api_url = os.environ.get("PHISHGUARD_API_URL") or os.environ.get("API_URL")

    print("=" * 60)
    print("PhishGuard AI -- Multi-Browser Extension Packaging")
    if api_url:
        print(f"[*] Pre-configuring extension API backend -> {api_url}")
    print("=" * 60)

    # 1. Chrome / Edge Package
    chrome_zip = build_package("chrome", "manifest.json", is_firefox=False, api_url=api_url)

    # 2. Firefox Package
    firefox_zip = build_package("firefox", "manifest_firefox.json", is_firefox=True, api_url=api_url)

    # 3. Default distribution alias
    manifest_data = validate_manifest(EXTENSION_DIR / "manifest.json")
    version = manifest_data.get("version", "2.0.0")
    default_zip = DIST_DIR / f"phishguard-extension-v{version}.zip"
    import shutil
    shutil.copyfile(chrome_zip, default_zip)

    print("\n" + "=" * 60)
    print(f"[+] Distribution packages created successfully in {DIST_DIR.relative_to(ROOT_DIR)}:")
    print(f"  * Chrome / Edge Store : {chrome_zip.name}")
    print(f"  * Mozilla Firefox AMO : {firefox_zip.name}")
    print(f"  * Default Package     : {default_zip.name}")
    print("=" * 60)


# Alias for backward compatibility
package_extension = package_all


if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description="Package PhishGuard AI Browser Extensions")
    parser.add_argument("--api-url", default=None, help="Custom backend API base URL (e.g. https://phishguard.ai)")
    args = parser.parse_args()
    package_all(api_url=args.api_url)

