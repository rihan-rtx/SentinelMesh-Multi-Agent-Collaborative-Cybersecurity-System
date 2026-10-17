import os
import json
import time
import subprocess
import shutil
import pytest
from datetime import datetime

import redis

from shared.kafka_client import SentinelConsumer

# Ensure we are running from project root
os.chdir(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

def wait_for_containers():
    print("Waiting for docker containers to be healthy...")
    # Just wait a bit for Kafka/Redis to settle
    time.sleep(15)

@pytest.fixture(autouse=True)
def flush_redis():
    # Flush redis before each test to ensure Correlation Agent state is clean
    try:
        r = redis.Redis(host='localhost', port=6379)
        r.flushall()
    except Exception as e:
        print(f"Warning: could not flush redis: {e}")

def run_pcap(pcap_name):
    print(f"Running pcap: {pcap_name}")
    # Copy pcap to the default path expected by sniffer
    shutil.copy(f"pcaps/{pcap_name}", "pcaps/demo_scenario.pcap")
    
    # Restart the sniffer container
    # Assuming SNIFFER_MODE=pcap is set in .env
    # We will use 'docker compose up -d --force-recreate sniffer'
    # Actually, if sniffer exited 0, we can just start it again.
    subprocess.run(["docker", "compose", "up", "-d", "--force-recreate", "sniffer"], check=True)
    
    # Wait for sniffer to exit (it exits 0 when done)
    for _ in range(30):
        res = subprocess.run(["docker", "compose", "ps", "--format", "json"], capture_output=True, text=True)
        # Check if sniffer is running
        if "sentinelmesh-sniffer" in res.stdout and "Exited (0)" in res.stdout:
            break
        time.sleep(1)
    
    # Allow time for downstream agents (DPI -> Detection -> Correlation) to process and produce incidents
    # Correlation window is sliding, but since flow assembly is flushed at the end of pcap, 
    # events are emitted. Correlation should trigger. Wait a few seconds for propagation.
    time.sleep(10)

from confluent_kafka import Consumer

def consume_incidents():
    # Consume all messages in the incidents topic using the EXTERNAL listener
    consumer = Consumer({
        "bootstrap.servers": "localhost:29092",
        "group.id": "e2e-test-group",
        "auto.offset.reset": "earliest"
    })
    
    # Fail loudly if connection fails (so we don't silently return [] and pass tests)
    try:
        metadata = consumer.list_topics(timeout=10.0)
        if "incidents" not in metadata.topics:
            raise RuntimeError("Topic 'incidents' not found in Kafka cluster metadata.")
    except Exception as e:
        consumer.close()
        raise RuntimeError(f"Fatal: Failed to connect to Kafka at localhost:29092 or fetch metadata: {e}")
        
    consumer.subscribe(["incidents"])
    
    raw_incidents = []
    # Poll for messages until topic is empty
    while True:
        msg = consumer.poll(timeout=2.0)
        if not msg:
            break
        if msg.error():
            # If there's an actual kafka error, fail loudly rather than ignoring
            raise RuntimeError(f"Kafka Consumer Error: {msg.error()}")
        raw_incidents.append(json.loads(msg.value().decode('utf-8')))
    
    consumer.close()
    
    # Deduplicate by incident_id, keeping only the latest state for each, preserving order
    unique_incidents = {}
    for inc in raw_incidents:
        unique_incidents[inc["incident_id"]] = inc
    return list(unique_incidents.values())

def test_benign_sample(setup_docker):
    run_pcap("benign_sample.pcap")
    dump_topic_counts()
    incidents = consume_incidents()
    assert len(incidents) == 0, f"Expected 0 incidents, got {len(incidents)}: {incidents}"

def dump_topic_counts():
    print("\n--- DIAGNOSTIC: RAW TOPIC MESSAGE COUNTS ---")
    print("(Note: raw 'incidents' message count includes all update/escalation messages; the test harness deduplicates these by incident_id into unique incidents)")
    topics = ["flow-events", "dpi-findings", "detections", "incidents"]
    for t in topics:
        c = Consumer({
            "bootstrap.servers": "localhost:29092",
            "group.id": f"diagnostic-group-{time.time()}", # Unique group to read from beginning
            "auto.offset.reset": "earliest"
        })
        c.subscribe([t])
        count = 0
        while True:
            msg = c.poll(timeout=1.0)
            if not msg:
                break
            if not msg.error():
                count += 1
        c.close()
        print(f"Topic {t}: {count} messages")
    print("--------------------------------\n")

def test_portscan_sample(setup_docker):
    run_pcap("portscan_sample.pcap")
    dump_topic_counts()
    incidents = consume_incidents()
    assert len(incidents) == 1, f"Expected exactly 1 incident, got {len(incidents)}: {incidents}"
    assert incidents[0]["incident_type"] == "coordinated_scan"

def test_multistage_sample(setup_docker):
    run_pcap("multistage_sample.pcap")
    dump_topic_counts()
    incidents = consume_incidents()
    assert len(incidents) == 1, f"Expected exactly 1 incident, got {len(incidents)}: {incidents}"
    assert incidents[0]["incident_type"] == "multi_stage_attack"
    assert incidents[0]["severity"] == "critical"

def test_distributed_target_sample(setup_docker):
    run_pcap("distributed_target_sample.pcap")
    dump_topic_counts()
    incidents = consume_incidents()
    assert len(incidents) == 1, f"Expected exactly 1 incident, got {len(incidents)}: {incidents}"
    assert incidents[0]["incident_type"] == "distributed_target_attack"
