#!/usr/bin/env python3
"""
Bundle Dashboard Script
=======================
Compiles the Next.js static dashboard export and syncs it directly into
the Python package static assets directory (sdk/actshield/static/).

Usage:
    python scripts/bundle_dashboard.py
"""
import os
import pathlib
import shutil
import subprocess
import sys

REPO_ROOT = pathlib.Path(__file__).resolve().parents[1]
DASHBOARD_DIR = REPO_ROOT / "dashboard"
STATIC_DIR = REPO_ROOT / "sdk" / "actshield" / "static"


def bundle():
    print(f"[*] Building Next.js static dashboard in {DASHBOARD_DIR}...")
    npm_cmd = "npm.cmd" if os.name == "nt" else "npm"
    res = subprocess.run([npm_cmd, "run", "build"], cwd=str(DASHBOARD_DIR))
    if res.returncode != 0:
        print("[!] Next.js build failed!", file=sys.stderr)
        sys.exit(res.returncode)

    out_dir = DASHBOARD_DIR / "out"
    if not out_dir.exists():
        print(f"[!] Output directory {out_dir} not found!", file=sys.stderr)
        sys.exit(1)

    print(f"[*] Syncing static assets to {STATIC_DIR}...")
    shutil.rmtree(STATIC_DIR, ignore_errors=True)
    shutil.copytree(out_dir, STATIC_DIR)

    files_count = len(list(STATIC_DIR.rglob("*")))
    print(f"[✓] Successfully bundled {files_count} assets into {STATIC_DIR}")


if __name__ == "__main__":
    bundle()
