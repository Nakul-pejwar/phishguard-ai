#!/usr/bin/env python3
"""
PhishGuard AI — Extension Packaging & Validation Tool
Validates manifest schema and builds a clean distribution ZIP archive
ready for upload to Chrome Web Store and Microsoft Edge Add-ons.
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
    "manifest.json",
    "background.js",
    "content.js",
    "content.css",
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


def validate_manifest(manifest_path: Path) -> dict:
    if not manifest_path.exists():
        print(f"[-] ERROR: manifest.json not found at {manifest_path}", file=sys.stderr)
        sys.exit(1)

    with open(manifest_path, "r", encoding="utf-8") as f:
        try:
            data = json.load(f)
        except json.JSONDecodeError as err:
            print(f"[-] ERROR: Invalid JSON in manifest.json: {err}", file=sys.stderr)
            sys.exit(1)

    # Validate MV3 requirements
    assert data.get("manifest_version") == 3, "manifest_version must be 3"
    assert "name" in data and "version" in data, "name and version are required"
    assert "background" in data and "service_worker" in data["background"], "background service_worker required"
    assert "action" in data and "default_popup" in data["action"], "action.default_popup required"

    print(f"[+] Manifest V3 Valid: {data['name']} (v{data['version']})")
    return data


def package_extension():
    DIST_DIR.mkdir(parents=True, exist_ok=True)
    manifest_path = EXTENSION_DIR / "manifest.json"
    manifest_data = validate_manifest(manifest_path)
    version = manifest_data.get("version", "2.0.0")

    zip_filename = DIST_DIR / f"phishguard-extension-v{version}.zip"

    # Verify required files
    for rel_path in REQUIRED_FILES:
        target = EXTENSION_DIR / rel_path
        if not target.exists():
            print(f"[-] WARNING: Missing expected file: {target}")

    with zipfile.ZipFile(zip_filename, "w", zipfile.ZIP_DEFLATED) as zipf:
        for root, dirs, files in os.walk(EXTENSION_DIR):
            # Ignore hidden files, test logs, etc.
            files = [f for f in files if not f.startswith(".") and not f.endswith(".tmp")]
            dirs[:] = [d for d in dirs if not d.startswith(".") and d != "__pycache__"]

            for file in files:
                full_path = Path(root) / file
                archive_name = full_path.relative_to(EXTENSION_DIR)
                zipf.write(full_path, arcname=archive_name)
                print(f"  -> Added: {archive_name}")

    print(f"\n[+] Successfully packaged extension to: {zip_filename}")
    print(f"[+] Package Size: {zip_filename.stat().st_size / 1024:.2f} KB")


if __name__ == "__main__":
    package_extension()
