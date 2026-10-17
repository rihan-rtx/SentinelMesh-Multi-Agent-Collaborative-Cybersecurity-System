import os
import shutil
import subprocess
import time
import pytest

# Ensure we are running from project root
os.chdir(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

def wait_for_containers():
    print("\nWaiting for docker containers to be healthy...")
    time.sleep(15)

@pytest.fixture(scope="session")
def setup_docker():
    # Clear old data and start fresh
    print("\n[conftest.py] Starting Docker Compose services (session-scoped)...")
    subprocess.run(["docker", "compose", "down", "-v"], check=True)
    
    # Make sure .env has SNIFFER_MODE=pcap
    env_content = open(".env").read()
    if "SNIFFER_MODE=live" in env_content:
        env_content = env_content.replace("SNIFFER_MODE=live", "SNIFFER_MODE=pcap")
        open(".env", "w").write(env_content)
        
    # Copy benign_sample.pcap as the default demo_scenario.pcap BEFORE docker compose up
    try:
        shutil.copy("pcaps/benign_sample.pcap", "pcaps/demo_scenario.pcap")
    except Exception as e:
        print(f"Warning: could not prepare initial pcap: {e}")

    subprocess.run(["docker", "compose", "up", "-d"], check=True)
    wait_for_containers()
    
    yield
    
    print("\n[conftest.py] Tearing down Docker Compose services...")
    subprocess.run(["docker", "compose", "down", "-v"])
