"""
AgentGuard Live System Runner
=============================
Starts the FastAPI Backend (Port 8000) and Next.js Dashboard (Port 3000) concurrently.
Usage:
    python run_live.py
"""

import os
import subprocess
import sys
import time
from pathlib import Path

ROOT_DIR = Path(__file__).resolve().parent
SDK_DIR = ROOT_DIR / "sdk"
DASHBOARD_DIR = ROOT_DIR / "dashboard"

def main():
    print("=" * 65)
    print("🛡️   AGENTGUARD — LIVE CONTROL PLANE & OBSERVABILITY SYSTEM")
    print("=" * 65)
    print(f"[*] Root Directory: {ROOT_DIR}")
    print(f"[*] Backend API:    http://localhost:8000  (FastAPI / Uvicorn)")
    print(f"[*] Frontend Web:   http://localhost:3000  (Next.js App Router)")
    print("=" * 65)

    env = os.environ.copy()
    env["PYTHONPATH"] = str(SDK_DIR)

    # 1. Start backend
    print("\n[1/2] Starting AgentGuard Backend API on :8000...")
    backend_proc = subprocess.Popen(
        [sys.executable, "-m", "uvicorn", "agentguard.api.server:app", "--host", "0.0.0.0", "--port", "8000", "--reload"],
        cwd=str(ROOT_DIR),
        env=env,
    )

    # 2. Start frontend
    print("[2/2] Starting AgentGuard Dashboard UI on :3000...")
    npm_cmd = "npm.cmd" if os.name == "nt" else "npm"
    frontend_proc = subprocess.Popen(
        [npm_cmd, "run", "dev"],
        cwd=str(DASHBOARD_DIR),
        env=env,
    )

    print("\n🚀 Both services are running!")
    print("   👉 Open http://localhost:3000 to access the AgentGuard Dashboard.")
    print("   👉 Open http://localhost:8000/docs to explore the FastAPI Swagger API.")
    print("\nPress Ctrl+C to terminate both servers.\n")

    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("\nStopping AgentGuard servers...")
        backend_proc.terminate()
        frontend_proc.terminate()
        backend_proc.wait()
        frontend_proc.wait()
        print("Done.")

if __name__ == "__main__":
    main()
