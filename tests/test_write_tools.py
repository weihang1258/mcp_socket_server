"""写工具集成测试:cmd_exec / capture / boce / file_upload-download + 锁 + 审计。"""
import base64
import os

import pytest

from mcp_socket_server.config import load_config
from mcp_socket_server.server import (
    add_target, boce_run, capture_start, capture_stop, cmd_exec,
    file_download, file_upload, init_server, remove_target,
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


def test_file_upload_download(app, mock_server, tmp_path):
    remote = str(tmp_path / "up.txt")
    content = b"hello-upload-test"
    r1 = file_upload([mock_server.host], remote,
                      base64.b64encode(content).decode(), port=mock_server.port)
    assert r1["ok"] == 1
    assert r1["results"][0]["size"] == len(content)
    # 文件应真实写入(mock 的 21->22->23->24 会落盘)
    assert os.path.isfile(remote)
    # 下载回来
    r2 = file_download([mock_server.host], remote, port=mock_server.port)
    assert r2["ok"] == 1
    assert r2["results"][0]["size"] == len(content)
    with open(r2["results"][0]["local_path"], "rb") as f:
        assert f.read() == content


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
