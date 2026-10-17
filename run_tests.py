import subprocess

def run_tests():
    print("Running pytest with stdout capture...")
    res = subprocess.run(["pytest", "-v", "tests/test_e2e.py", "-s"], capture_output=True, text=True)
    with open("pytest_output.log", "w", encoding="utf-8") as f:
        f.write(res.stdout)
        f.write(res.stderr)
    print("Saved to pytest_output.log")

if __name__ == "__main__":
    run_tests()
