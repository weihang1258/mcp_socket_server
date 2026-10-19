"""写工具集成测试:cmd_exec / capture / boce + 锁 + 审计。"""
import base64

import pytest

from mcp_socket_server.config import load_config
from mcp_socket_server.server import (
    add_target, boce_run, capture_start, capture_stop, cmd_exec,
    init_server, isfile, remove_target, replay_run, socket_listen,
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
    r1 = add_target("10.99.99.99", 9000, tags=["test"], note="fake", force=True)  # B19 探活:假 IP 须 force
    assert r1["ok"] is True
    r2 = add_target("10.99.99.99", 9000, force=True)  # 重复 IGNORE
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


def test_capture_start_false_becomes_failed(app, mock_server):
    # B23: mock 5 返回 {"res": true}；临时改 mock 让 datatype 5 返回 false——
    # 用 capture_stop_mode 不行，需 mock 5 分支可控：加 capture_start_mode 开关（Task 内 Step 3 mock 扩展）
    mock_server.capture_start_mode = "fail"
    res = capture_start([mock_server.host], path="/tmp/x.pcap", port=mock_server.port)
    mock_server.capture_start_mode = "ok"
    assert res["ok"] == 0, res
    assert any("False" in f["reason"] or "业务失败" in f["reason"] for f in res["failed"]), res


def test_capture_start_failure_releases_capture_lock(app, mock_server):
    # B04: start 失败后同 path 的 CAPTURE 锁应已释放——再次 start 不应锁冲突而应是正常流程
    mock_server.capture_start_mode = "fail"
    r1 = capture_start([mock_server.host], path="/tmp/lockx.pcap", port=mock_server.port)
    mock_server.capture_start_mode = "ok"
    assert r1["ok"] == 0
    lm = get_lock_manager()
    r2 = cmd_exec([mock_server.host], "echo hi", port=mock_server.port)   # 若锁泄漏会 shell 冲突
    assert r2["ok"] == 1, r2


def test_capture_stop_four_state_tool(app, mock_server):
    mock_server.capture_stop_mode = "new_fail"
    r = capture_stop([mock_server.host], path="/tmp/f1.pcap", port=mock_server.port)
    mock_server.capture_stop_mode = "new_ok"
    assert r["ok"] == 0 and "停止未完成" in r["failed"][0]["reason"], r

    mock_server.capture_stop_mode = "new_never"
    r = capture_stop([mock_server.host], path="/tmp/f2.pcap", port=mock_server.port)
    assert r["ok"] == 1, r    # 未在抓=非失败
    assert r["results"][0]["stopped"] is False, r


def test_capture_stop_timeout_passthrough(app, mock_server, monkeypatch):
    # B2 评审遗留:capture_stop 工具的 timeout 须透传给 pool.acquire(socket_timeout=...)
    seen: dict = {}

    from mcp_socket_server import pool as pool_mod

    real_get_pool = pool_mod.Scheduler.get_pool

    def spy_get_pool(self, host, port=9000):
        p = real_get_pool(self, host, port)
        real_acquire = p.acquire

        def spy_acquire(timeout=pool_mod.BORROW_TIMEOUT, socket_timeout=None):
            seen["socket_timeout"] = socket_timeout
            return real_acquire(socket_timeout=socket_timeout)

        monkeypatch.setattr(p, "acquire", spy_acquire)
        return p

    monkeypatch.setattr(pool_mod.Scheduler, "get_pool", spy_get_pool)
    r = capture_stop([mock_server.host], path="/tmp/tmo.pcap",
                     port=mock_server.port, timeout=77)
    assert r["ok"] >= 0, r  # 不关心四态结果,只断言透传
    assert seen.get("socket_timeout") == 77, seen


def test_results_carry_target(app, mock_server):
    # B13: 走 _run_batch 的工具 results 带 target
    res = cmd_exec([mock_server.host], "echo hi", port=mock_server.port)
    assert res["results"][0].get("target") == mock_server.host, res
    assert res["results"][0].get("stdout") == "mock_out", res


def test_cmd_exec_wait_false_note(app, mock_server):
    # B18: wait=False -> note 而非 null
    res = cmd_exec([mock_server.host], "echo hi", port=mock_server.port, wait=False)
    assert res["ok"] == 1, res
    assert res["results"][0].get("note") == "wait=false 无返回值", res


def test_remove_target_with_listener_rejected(app, mock_server):
    # B16: start 登记 liveness -> remove 拒绝 -> stop 后可删
    add_target(mock_server.host, mock_server.port, tags=["t16"])
    socket_listen([mock_server.host], "start", listen_port=39021, port=mock_server.port)
    r = remove_target(mock_server.host, mock_server.port)
    assert r["ok"] is False and "监听" in r["error"], r
    socket_listen([mock_server.host], "stop", port=mock_server.port)
    r = remove_target(mock_server.host, mock_server.port)
    assert r["ok"] is True, r


def test_capture_start_error_passthrough(app, mock_server):
    # N3: 1.7.2 服务端 dt5 失败带原因 -> 桥透传到 reason(带 target)
    mock_server.capture_start_error = "路径不可写: /nonexist/x.pcap"
    res = capture_start([mock_server.host], path="/tmp/err.pcap", port=mock_server.port)
    mock_server.capture_start_error = None
    assert res["ok"] == 0, res
    assert "路径不可写" in res["failed"][0]["reason"], res


def test_lock_conflict_message_has_real_target(app, mock_server):
    # B07: 锁冲突文案含真实靶机 IP 而非 "?"
    from mcp_socket_server.locks import get_lock_manager, LockClass
    res = cmd_exec([mock_server.host], "echo hi", port=mock_server.port)
    assert res["ok"] == 1, res
    lm = get_lock_manager()
    host_port = mock_server.host  # _run_batch 的 target 串=resolved 后的 host(未注册 IP 原样,无端口)
    lm.acquire(host_port, LockClass.CAPTURE, ("/tmp/occupied.pcap",))
    try:
        r2 = capture_start([mock_server.host], path="/tmp/occupied.pcap",
                           port=mock_server.port)
        assert r2["ok"] == 0, r2
        assert "靶机 ?" not in r2["failed"][0]["reason"], r2["failed"]
        assert mock_server.host in r2["failed"][0]["reason"], r2["failed"]
    finally:
        lm.release(host_port, LockClass.CAPTURE, ("/tmp/occupied.pcap",))


def test_boce_error_failed(app, mock_server):
    # N1: 服务端 131 失败 {"error":...} -> failed 而非 ok:1
    mock_server.boce_error = True
    res = boce_run([mock_server.host], "http://example.com", port=mock_server.port)
    mock_server.boce_error = False
    assert res["ok"] == 0, res
    assert "boce failed" in res["failed"][0]["reason"], res
    assert "chromium" in res["failed"][0]["reason"], res
