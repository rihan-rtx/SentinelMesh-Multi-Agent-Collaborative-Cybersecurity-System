import sys
try:
    import docker
except ImportError:
    import subprocess
    subprocess.run([sys.executable, "-m", "pip", "install", "docker"])
    import docker

try:
    client = docker.from_env()
    for container in client.containers.list(all=True):
        if "detection" in container.name:
            print(f"Logs for {container.name}:")
            logs = container.logs(tail=200).decode("utf-8", errors="replace")
            with open("detection.log", "w", encoding="utf-8") as f:
                f.write(logs)
            print("Successfully wrote detection.log")
            break
except Exception as e:
    print(f"Error: {e}")
