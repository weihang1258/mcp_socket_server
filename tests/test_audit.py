import time

import pytest

from mcp_socket_server.audit import AuditLogger


def test_audit_write_and_cleanup(tmp_path):
    log = AuditLogger(str(tmp_path / "a.db"), retention_days=0)
    log.write("version_query", {"targets": ["10.0.0.1"]},
              [{"target": "10.0.0.1", "version": "1.3.9"}],
              ok_count=1, failed_count=0, duration_ms=42, source_ip="internal")
    rows = log._conn.execute(
        "SELECT tool, ok_count, failed_count, source_ip FROM audit_log").fetchall()
    assert len(rows) == 1
    assert rows[0][0] == "version_query"
    assert rows[0][1] == 1
    assert rows[0][2] == 0
    assert rows[0][3] == "internal"
    log.close()


def test_audit_params_truncation(tmp_path):
    log = AuditLogger(str(tmp_path / "a.db"), retention_days=0)
    long_val = "x" * 500
    log.write("cmd_exec", {"args": long_val}, [], ok_count=0, failed_count=1,
              duration_ms=0)
    row = log._conn.execute("SELECT params FROM audit_log").fetchone()
    assert len(row[0]) < 500 + 20  # truncated
    log.close()


def test_audit_cleanup_old(tmp_path):
    # retention_days=0 -> 跳过清理(保留全部);插入后应保留 1 条
    log = AuditLogger(str(tmp_path / "a.db"), retention_days=0)
    log.write("t", {}, [], 0, 0, 0)
    rows = log._conn.execute("SELECT COUNT(*) FROM audit_log").fetchone()
    assert rows[0] == 1  # 不清理,保留
    log.close()