"""
SentinelMesh — Full Phase 5 test runner.

Usage (from project root in PowerShell):
    python run_phase5_tests.py

What it does:
  1. docker compose down -v   (clean slate, removes volumes)
  2. docker compose up -d      (start all services including new dashboard-writer)
  3. Waits 30s for Kafka/Redis/Postgres to be healthy and all agents to connect
  4. python -m pytest tests/test_e2e.py tests/test_dashboard_writer.py -v -s
  5. Writes full stdout+stderr to phase5_test_output.log and prints to console
"""

import subprocess
import sys
import time

LOG_FILE = "phase5_test_output.log"


def run(cmd, **kwargs):
    print(f"\n>>> {' '.join(cmd)}")
    result = subprocess.run(cmd, **kwargs)
    return result


def main():
    lines = []

    def log(msg=""):
        print(msg)
        lines.append(msg)

    log("=" * 72)
    log("Phase 5 — Full stack test run")
    log("=" * 72)

    # 1. Tear down
    log("\n[1/4] docker compose down -v")
    r = run(["docker", "compose", "down", "-v"], capture_output=True, text=True)
    log(r.stdout)
    if r.stderr:
        log(r.stderr)

    # 2. Build & start
    log("\n[2/4] docker compose up -d --build")
    r = run(["docker", "compose", "up", "-d", "--build"], capture_output=True, text=True)
    log(r.stdout)
    if r.stderr:
        log(r.stderr)
    if r.returncode != 0:
        log("ERROR: docker compose up failed — aborting.")
        _write(LOG_FILE, "\n".join(lines))
        sys.exit(1)

    # 3. Wait for stack to settle
    log("\n[3/4] Waiting 30s for stack to be healthy…")
    time.sleep(30)
    log("Done waiting.")

    # 4. Run tests
    log("\n[4/4] pytest tests/test_e2e.py tests/test_dashboard_writer.py -v -s")
    r = run(
        [sys.executable, "-m", "pytest",
         "tests/test_e2e.py", "tests/test_dashboard_writer.py",
         "-v", "-s", "--tb=short"],
        capture_output=True, text=True,
    )
    log(r.stdout)
    if r.stderr:
        log(r.stderr)

    _write(LOG_FILE, "\n".join(lines))
    log(f"\nFull output saved to {LOG_FILE}")
    sys.exit(r.returncode)


def _write(path, content):
    with open(path, "w", encoding="utf-8") as f:
        f.write(content)


if __name__ == "__main__":
    main()
