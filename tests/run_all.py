"""Run every test: unit tests, the end-to-end protocol test and the UI smoke test.
Usage (from the project folder):  python tests/run_all.py
Needs Python 3.10+ and Node.js 18+ (Node is only used for the browser-code tests)."""
import os
import shutil
import socket
import subprocess
import sys
import time

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def free_port():
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def run(cmd, label):
    print(f"\n=== {label} ===", flush=True)
    code = subprocess.call(cmd, cwd=ROOT)
    if code != 0:
        print(f"FAILED: {label}")
        sys.exit(code)


run([sys.executable, "-m", "unittest", "discover", "-s", "backend/tests", "-t", "."], "Python unit tests")

node = shutil.which("node")
if not node:
    print("\nNode.js not found: skipping the browser-code tests (install Node 18+ to run them).")
    sys.exit(0)

port = free_port()
server = subprocess.Popen([sys.executable, "tests/harness_server.py", str(port)], cwd=ROOT)
try:
    for _ in range(50):
        try:
            socket.create_connection(("127.0.0.1", port), timeout=0.2).close()
            break
        except OSError:
            time.sleep(0.1)
    base = f"http://127.0.0.1:{port}"
    run([node, "tests/e2e.mjs", base], "End-to-end protocol test (real browser crypto code)")
    run([node, "tests/ui_smoke.mjs", base], "UI smoke test (real app.js, fake DOM)")
finally:
    server.terminate()
print("\nAll tests passed.")
