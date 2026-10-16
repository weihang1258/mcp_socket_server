"""写工具集成测试:cmd_exec / capture / boce + 锁 + 审计。"""
import base64

import pytest

from mcp_socket_server.config import load_config
from mcp_socket_server.server import (
    add_target, boce_run, capture_start, capture_stop, cmd_exec,
    init_server, remove_target, replay_run, socket_listen,
)
from mcp_socket_server.registry import set_registry
from mcp_socket_server.audit import set_audit
from mcp_socket_server.locks import get_lock_manager


@pytest.fixture
def app(mock_server, tmp_path):
    cfg = load_config(None)
    cfg.db_path = str(tmp_path / "t.db")
    init_server(cfg)
    yield mock_server


def test_cmd_exec_tool(app, mock_server):
    res = cmd_exec([mock_server.host], "echo hi", port=mock_server.port)
    assert res["ok"] == 1
    assert res["results"][0]["stdout"] == "mock_out"


def test_cmd_exec_partial_failure(app, mock_server):
    res = cmd_exec([mock_server.host, "192.0.2.1"], "ls", port=mock_server.port)
    assert res["ok"] == 1
    assert len(res["failed"]) == 1
    assert "192.0.2.1" in res["failed"][0]["target"]


def test_capture_start_stop(app, mock_server, tmp_path):
    pcap = str(tmp_path / "c.pcap")
    r1 = capture_start([mock_server.host], path=pcap, port=mock_server.port)
    assert r1["ok"] == 1
    # CAPTURE 锁应持有
    lm = get_lock_manager()
    assert lm.has_active(mock_server.host)
    # 同 path 再 start 应锁冲突
    r2 = capture_start([mock_server.host], path=pcap, port=mock_server.port)
    assert r2["ok"] == 0
    # stop 释放锁
    r3 = capture_stop([mock_server.host], path=pcap, port=mock_server.port)
    assert r3["ok"] == 1
    assert not lm.has_active(mock_server.host)


def test_capture_different_path_concurrent(app, mock_server, tmp_path):
    p1 = str(tmp_path / "a.pcap")
    p2 = str(tmp_path / "b.pcap")
    r1 = capture_start([mock_server.host], path=p1, port=mock_server.port)
    r2 = capture_start([mock_server.host], path=p2, port=mock_server.port)
    assert r1["ok"] == 1 and r2["ok"] == 1  # 不同 path 可并发
    capture_stop([mock_server.host], path=p1, port=mock_server.port)
    capture_stop([mock_server.host], path=p2, port=mock_server.port)


def test_boce_run_tool(app, mock_server):
    res = boce_run([mock_server.host], "http://example.com", port=mock_server.port)
    assert res["ok"] == 1
    assert res["results"][0]["status"] == "ok"


def test_add_remove_target(app, mock_server, tmp_path):
    r1 = add_target("10.99.99.99", 9000, tags=["test"], note="fake")
    assert r1["ok"] is True
    r2 = add_target("10.99.99.99", 9000)  # 重复 IGNORE
    assert r2["ok"] is True
    # remove 无活跃锁的靶机
    r3 = remove_target("10.99.99.99", 9000)
    assert r3["ok"] is True


def test_remove_target_with_active_lock_rejected(app, mock_server, tmp_path):
    add_target(mock_server.host, mock_server.port, tags=["m"])
    pcap = str(tmp_path / "x.pcap")
    capture_start([mock_server.host], path=pcap, port=mock_server.port)
    # 有活跃锁,remove 应拒绝
    r = remove_target(mock_server.host, mock_server.port)
    assert r["ok"] is False
    assert "活跃锁" in r["error"]
    capture_stop([mock_server.host], path=pcap, port=mock_server.port)


def test_audit_recorded(app, mock_server, tmp_path):
    cmd_exec([mock_server.host], "echo hi", port=mock_server.port)
    from mcp_socket_server.audit import get_audit
    audit = get_audit(str(tmp_path / "t.db"))
    rows = audit._conn.execute(
        "SELECT tool, ok_count FROM audit_log WHERE tool='cmd_exec'").fetchall()
    assert len(rows) >= 1
    assert rows[-1][1] == 1


def test_replay_run_tool(app, mock_server):
    res = replay_run([mock_server.host], ["/tmp/a.pcap"], "eth0", "eth1",
                     port=mock_server.port)
    assert res["ok"] == 1
    stats = res["results"][0]
    assert stats["total_packets"] == 10
    assert stats["duration_seconds"] == 0.5


def test_socket_listen_empty_pid_failed(app, mock_server):
    mock_server.listen_pid_mode = "empty"
    try:
        r = socket_listen([mock_server.host], "start", listen_port=30001,
                          port=mock_server.port)
        assert r["ok"] == 0
        assert "pid empty" in r["failed"][0]["reason"]
    finally:
        mock_server.listen_pid_mode = "ok"


def test_replay_run_error_failed(app, mock_server):
    mock_server.replay_mode = "error"
    try:
        r = replay_run([mock_server.host], ["/tmp/a.pcap"], "eth0", "eth1",
                       port=mock_server.port)
        assert r["ok"] == 0
        assert "missing uplink_iface" in r["failed"][0]["reason"]
    finally:
        mock_server.replay_mode = "ok"


def test_socket_listen_lifecycle(app, mock_server, tmp_path):
    r1 = socket_listen([mock_server.host], "start", listen_port=30001,
                       port=mock_server.port)
    assert r1["ok"] == 1
    assert r1["results"][0]["pid"] == ["12345"]

    r2 = socket_listen([mock_server.host], "fetch", max_bytes=1000,
                       port=mock_server.port)
    assert r2["ok"] == 1
    data = r2["results"][0]
    assert data["truncated"] is True          # 1300B > 1000B
    assert data["size"] == 1300
    assert len(base64.b64decode(data["data_b64"])) == 1000
    assert data["file_path"].startswith("/home/tmp/listen_")

    r3 = socket_listen([mock_server.host], "clean", port=mock_server.port)
    assert r3["ok"] == 1
