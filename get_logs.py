import subprocess

try:
    res = subprocess.run(["docker", "compose", "logs", "detection"], capture_output=True, text=True, check=True)
    with open("detection.log", "w", encoding="utf-8") as f:
        f.write(res.stdout)
        f.write(res.stderr)
    print("Logs saved to detection.log")
except Exception as e:
    print(f"Error: {e}")
