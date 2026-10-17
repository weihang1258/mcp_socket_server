import json
import struct

from mcp_socket_server.socket_client import SocketServerClient


def test_recv_text_response_version(mock_server):
    c = SocketServerClient(mock_server.host, mock_server.port)
    c.connect()
    c._send(14)
    assert c.recv_text_response() == b'"1.7.1"'
    c.close()


def test_recv_gzip_response_cmd(mock_server):
    c = SocketServerClient(mock_server.host, mock_server.port)
    c.connect()
    c._send(1, json.dumps({"args": "echo hi"}).encode())
    assert c.recv_gzip_response() == {"code": 0, "stdout": "mock_out", "stderr": ""}
    c.close()


def test_recv_file_response_and_upload(mock_server, tmp_path):
    remote = str(tmp_path / "r.txt")
    c = SocketServerClient(mock_server.host, mock_server.port)
    c.connect()
    content = b"hello-file"
    # upload: 21 -> 22 -> 23 -> 24
    c._send(21, json.dumps({"filepath": remote, "gzip": False}).encode())
    assert c.recv_inline_text() == b"21 ok"
    c._send(22, struct.pack("<Q", len(content)))
    assert c.recv_inline_text() == b"22 ok"
    c._send_raw(content)  # 23: 无 datatype 字段,_send_raw 自加 [4B len] 前缀
    assert c.recv_inline_text() == b"23 ok"
    c._send(24, b"")
    assert c.recv_inline_text() == b"24 ok"
    # download: 21(set filepath) -> 3
    c._send(21, json.dumps({"filepath": remote, "gzip": False}).encode())
    assert c.recv_inline_text() == b"21 ok"
    c._send(3, json.dumps({"gzip": False}).encode())
    n, body = c.recv_file_response()
    assert n == len(content) and body == content
    c.close()


def test_read_methods(mock_server, tmp_path):
    f = tmp_path / "x.txt"
    f.write_text("abc")
    c = SocketServerClient(mock_server.host, mock_server.port)
    c.connect()
    assert c.isfile(str(f)) is True
    assert c.isdir(str(tmp_path)) is True
    flows = c.pcap_flow_extract("/some/dir")
    assert flows[0]["protoType"] == 1
    c.close()


def test_replay_run_method(mock_server):
    from mcp_socket_server.socket_client import SocketServerClient
    c = SocketServerClient(mock_server.host, mock_server.port)
    c.connect()
    try:
        stats = c.replay_run(["/tmp/a.pcap"], "eth0", "eth1", mbps=10)
        assert stats["total_packets"] == 10
        assert stats["duration_seconds"] == 0.5
    finally:
        c.close()


def test_replay_run_error_raises(mock_server):
    from mcp_socket_server.socket_client import SocketServerClient
    mock_server.replay_mode = "error"
    c = SocketServerClient(mock_server.host, mock_server.port)
    c.connect()
    try:
        try:
            c.replay_run(["/tmp/a.pcap"], "eth0", "eth1")
            assert False, "should raise"
        except ConnectionError as e:
            assert "missing uplink_iface" in str(e)
    finally:
        c.close()
        mock_server.replay_mode = "ok"


def test_socket_listen_empty_pid_raises(mock_server):
    from mcp_socket_server.socket_client import SocketServerClient
    mock_server.listen_pid_mode = "empty"
    c = SocketServerClient(mock_server.host, mock_server.port)
    c.connect()
    try:
        try:
            c.socket_listen("start")
            assert False, "should raise"
        except ConnectionError as e:
            assert "pid empty" in str(e)
    finally:
        c.close()
        mock_server.listen_pid_mode = "ok"


def test_socket_listen_start_clean_save(mock_server):
    from mcp_socket_server.socket_client import SocketServerClient
    c = SocketServerClient(mock_server.host, mock_server.port)
    c.connect()
    try:
        r = c.socket_listen("start", listen_port=30001)
        assert r["pid"] == ["12345"]
        assert c.socket_listen("clean") == b"ok"
        assert c.socket_listen("save", file="/tmp/l.log") == b"ok"
    finally:
        c.close()


def test_socket_listen_fetch_ok_and_error(mock_server):
    from mcp_socket_server.socket_client import SocketServerClient
    c = SocketServerClient(mock_server.host, mock_server.port)
    c.connect()
    try:
        data = c.socket_listen("fetch", max_bytes=1000)
        assert data == b"listener-data" * 100  # 1300B 全量取回(截断是 server.py 层职责)
    finally:
        c.close()

    # error 形态
    mock_server.listen_mode = "error"
    c2 = SocketServerClient(mock_server.host, mock_server.port)
    c2.connect()
    try:
        try:
            c2.socket_listen("fetch")
            assert False, "should raise"
        except ConnectionError as e:
            assert "未启动监听" in str(e)
    finally:
        c2.close()
        mock_server.listen_mode = "ok"


def test_version_method_restored(mock_server):
    from mcp_socket_server.socket_client import SocketServerClient
    c = SocketServerClient(mock_server.host, mock_server.port)
    c.connect()
    try:
        v = c.version()
        assert isinstance(v, str) and v, v   # mock 返回 "1.7.1"（json 字符串）
    finally:
        c.close()


def test_capture_stop_four_states(mock_server):
    from mcp_socket_server.socket_client import SocketServerClient
    # mock 需要 capture_stop_mode 开关: "new_ok"/"new_never"/"new_fail"/"legacy_ok"/"legacy_fail"
    # (实现见 mock 扩展)默认 "new_ok"
    c = SocketServerClient(mock_server.host, mock_server.port)
    c.connect()
    try:
        d = c.capture_stop("/tmp/a.pcap")
        assert d["stopped"] is True and d["pcap_complete"] is True, d
        mock_server.capture_stop_mode = "legacy_ok"
        d = c.capture_stop("/tmp/a2.pcap")
        assert d["stopped"] is True and d.get("legacy") is True, d
        mock_server.capture_stop_mode = "new_never"
        d = c.capture_stop("/tmp/b.pcap")
        assert d["stopped"] is False and "note" in d, d
        mock_server.capture_stop_mode = "new_fail"
        d = c.capture_stop("/tmp/c.pcap")
        assert d["stopped"] is False and "error" in d, d
        mock_server.capture_stop_mode = "legacy_fail"
        d = c.capture_stop("/tmp/d.pcap")
        assert d["stopped"] is False and "legacy" in d, d
    finally:
        c.close()
        mock_server.capture_stop_mode = "new_ok"


def test_socket_listen_stop_action(mock_server):
    from mcp_socket_server.socket_client import SocketServerClient
    c = SocketServerClient(mock_server.host, mock_server.port)
    c.connect()
    try:
        assert c.socket_listen("stop") == b"ok"
        mock_server.listen_mode = "error"   # 175 error 形态复用
        try:
            c.socket_listen("stop")
            assert False, "should raise"
        except ConnectionError:
            pass
    finally:
        c.close()
        mock_server.listen_mode = "ok"


def test_replay_force_port_zero_omitted(mock_server):
    from mcp_socket_server.socket_client import SocketServerClient
    c = SocketServerClient(mock_server.host, mock_server.port)
    c.connect()
    try:
        # mock 的 datatype 0 handler 记录最近 payload(captured_payload)
        c.replay_run(["/tmp/a.pcap"], "eth0", "eth1", force_sport=0, force_dport=0)
        payload = json.loads(mock_server.captured_payload)
        assert "force_sport" not in payload and "force_dport" not in payload, payload
        c.replay_run(["/tmp/a.pcap"], "eth0", "eth1", force_sport=12345)
        payload = json.loads(mock_server.captured_payload)
        assert payload.get("force_sport") == 12345, payload
    finally:
        c.close()
