"""
SentinelMesh — Dashboard Writer Integration Tests

Verifies that the dashboard-writer service correctly upserts Kafka messages
into Postgres. Runs after the e2e pcap tests (same module-scoped Docker
environment) and queries Postgres directly, so a broken upsert (wrong SQL,
connection failure, etc.) fails loud here rather than silently during a demo.

Scope: asserts row COUNTS and key CONTENT in all three tables match what was
produced on the Kafka side during test_portscan_sample and
test_multistage_sample. Does NOT re-run pcaps — relies on rows already written
by the time these tests execute (module ordering: test_e2e runs first).

Design choice: uses psycopg2 directly (same library as the writer itself) so
connection config is identical and any env-mismatch surfaces here too.
"""

import os
import time
import psycopg2
import pytest

# Ensure we are running from project root (matches test_e2e.py)
os.chdir(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from dotenv import load_dotenv

load_dotenv()

# ---------------------------------------------------------------------------
# Postgres connection helper
# ---------------------------------------------------------------------------

PG_HOST = os.getenv("POSTGRES_HOST", "localhost")
if PG_HOST == "postgres":
    PG_HOST = "localhost"       # Map container host to localhost for external test runner
PG_PORT = int(os.getenv("POSTGRES_PORT", "5432"))
PG_DB = os.getenv("POSTGRES_DB", "sentinelmesh")
PG_USER = os.getenv("POSTGRES_USER", "sentinelmesh")
PG_PASSWORD = os.getenv("POSTGRES_PASSWORD", "changeme")

DASHBOARD_WRITER_SETTLE_S = 10  # seconds to wait for writer to commit upserts


def _pg_conn():
    return psycopg2.connect(
        host=PG_HOST,
        port=PG_PORT,
        dbname=PG_DB,
        user=PG_USER,
        password=PG_PASSWORD,
    )


def _query(sql: str, params=None):
    """Run a SELECT and return all rows as a list of dicts."""
    with _pg_conn() as conn:
        with conn.cursor() as cur:
            cur.execute(sql, params or ())
            cols = [desc[0] for desc in cur.description]
            return [dict(zip(cols, row)) for row in cur.fetchall()]


# ---------------------------------------------------------------------------
# Fixture: wait for the dashboard-writer to settle after pcaps have run.
# This fixture is session-scoped so the sleep only happens once regardless
# of how many test functions reference it.
# ---------------------------------------------------------------------------

@pytest.fixture(scope="module", autouse=True)
def wait_for_writer(setup_docker):
    """Give the dashboard-writer time to commit all upserts before asserting."""
    print(f"\nWaiting {DASHBOARD_WRITER_SETTLE_S}s for dashboard-writer to settle…")
    time.sleep(DASHBOARD_WRITER_SETTLE_S)


# ---------------------------------------------------------------------------
# Connection smoke-test
# ---------------------------------------------------------------------------

def test_postgres_reachable():
    """Fail loudly if Postgres isn't up rather than getting confusing failures below."""
    try:
        conn = _pg_conn()
        conn.close()
    except Exception as exc:
        pytest.fail(f"Cannot connect to Postgres at {PG_HOST}:{PG_PORT}: {exc}")


# ---------------------------------------------------------------------------
# detections table
# ---------------------------------------------------------------------------

def test_detections_table_has_rows():
    """
    After replaying portscan + multistage pcaps, at least one detection must
    exist in Postgres. Zero rows means the writer never upserted anything.
    """
    rows = _query("SELECT COUNT(*) AS cnt FROM detections")
    count = rows[0]["cnt"]
    assert count > 0, (
        f"Expected >0 rows in detections table after pcap replay, got {count}. "
        "Dashboard-writer may not be consuming or upserting correctly."
    )


def test_detections_classification_values_are_valid():
    """All classification values must be one of the schema-defined strings."""
    rows = _query("SELECT DISTINCT classification FROM detections")
    valid = {"benign", "suspicious", "malicious"}
    actual = {r["classification"] for r in rows}
    invalid = actual - valid
    assert not invalid, f"Unexpected classification values in detections table: {invalid}"


def test_detections_have_expected_attack_types():
    """
    After portscan + multistage, we expect at least port_scan and
    exploit_attempt attack_types in the table.
    """
    rows = _query(
        "SELECT attack_type FROM detections WHERE attack_type IS NOT NULL"
    )
    attack_types = {r["attack_type"] for r in rows}
    assert "port_scan" in attack_types, (
        f"Expected 'port_scan' in detections.attack_type, got: {attack_types}"
    )
    assert "exploit_attempt" in attack_types, (
        f"Expected 'exploit_attempt' in detections.attack_type, got: {attack_types}"
    )


# ---------------------------------------------------------------------------
# incidents table
# ---------------------------------------------------------------------------

def test_incidents_table_has_rows():
    """At least one incident must exist after pcap replay."""
    rows = _query("SELECT COUNT(*) AS cnt FROM incidents")
    count = rows[0]["cnt"]
    assert count > 0, (
        f"Expected >0 rows in incidents table, got {count}. "
        "Dashboard-writer may not be consuming or upserting correctly."
    )


def test_coordinated_scan_incident_exists():
    """portscan_sample.pcap must produce a coordinated_scan incident in Postgres."""
    rows = _query(
        "SELECT incident_id, severity, status FROM incidents WHERE incident_type = %s",
        ("coordinated_scan",),
    )
    assert len(rows) >= 1, (
        "Expected at least one 'coordinated_scan' incident in Postgres after "
        "portscan_sample replay, got none. "
        "Either dashboard-writer didn't upsert it or correlation didn't produce it."
    )


def test_multistage_incident_exists_with_correct_severity():
    """
    multistage_sample.pcap must produce a multi_stage_attack incident with
    severity=critical in Postgres (same assertion as test_e2e.py, but against
    the Postgres row rather than the Kafka message).
    """
    rows = _query(
        "SELECT incident_id, severity, status FROM incidents WHERE incident_type = %s",
        ("multi_stage_attack",),
    )
    assert len(rows) >= 1, (
        "Expected at least one 'multi_stage_attack' incident in Postgres, got none."
    )
    severities = {r["severity"] for r in rows}
    assert "critical" in severities, (
        f"Expected severity='critical' for multi_stage_attack incident, got: {severities}"
    )


def test_incident_upsert_dedup_no_duplicate_rows():
    """
    incident_id is the PRIMARY KEY — there must never be more unique incident
    rows than unique incident_ids (i.e. no duplicate rows from re-delivery).
    This verifies ON CONFLICT DO UPDATE is working.
    """
    total = _query("SELECT COUNT(*) AS cnt FROM incidents")[0]["cnt"]
    unique_ids = _query("SELECT COUNT(DISTINCT incident_id) AS cnt FROM incidents")[0]["cnt"]
    assert total == unique_ids, (
        f"incidents table has {total} rows but only {unique_ids} unique incident_ids. "
        "ON CONFLICT upsert may not be working — duplicate rows detected."
    )


def test_incident_status_values_are_valid():
    """All status values must be schema-defined strings."""
    rows = _query("SELECT DISTINCT status FROM incidents")
    valid = {"open", "escalated", "resolved", "false_positive"}
    actual = {r["status"] for r in rows}
    invalid = actual - valid
    assert not invalid, f"Unexpected status values in incidents table: {invalid}"


# ---------------------------------------------------------------------------
# actions table
# ---------------------------------------------------------------------------

def test_actions_table_has_rows():
    """At least one action must exist — Response Agent should have acted on incidents."""
    rows = _query("SELECT COUNT(*) AS cnt FROM actions")
    count = rows[0]["cnt"]
    assert count > 0, (
        f"Expected >0 rows in actions table, got {count}. "
        "Either dashboard-writer missed the actions topic or Response Agent didn't produce any."
    )


def test_actions_fk_integrity():
    """
    Every action row must have a matching incident row (FK integrity check).
    A missing parent means either the FK retry failed, or the incident was never
    written to Postgres at all.
    """
    orphaned = _query(
        """
        SELECT a.action_id, a.incident_id
        FROM actions a
        LEFT JOIN incidents i ON a.incident_id = i.incident_id
        WHERE i.incident_id IS NULL
        """
    )
    assert len(orphaned) == 0, (
        f"Found {len(orphaned)} action(s) with no matching incident in Postgres: "
        f"{[r['action_id'] for r in orphaned]}. "
        "FK retry logic may not be working, or incidents were never upserted."
    )


def test_actions_action_type_values_are_valid():
    """All action_type values must be schema-defined strings."""
    rows = _query("SELECT DISTINCT action_type FROM actions")
    valid = {"log_only", "alert"}
    actual = {r["action_type"] for r in rows}
    invalid = actual - valid
    assert not invalid, f"Unexpected action_type values in actions table: {invalid}"
