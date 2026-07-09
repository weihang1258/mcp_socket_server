import json
import struct

from mcp_socket_server.socket_client import SocketServerClient


def test_recv_text_response_version(mock_server):
    c = SocketServerClient(mock_server.host, mock_server.port)
    c.connect()
    c._send(14)
    assert c.recv_text_response() == b'"1.3.9-mock"'
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
    assert c.version() == "1.3.9-mock"
    assert c.isfile(str(f)) is True
    assert c.isdir(str(tmp_path)) is True
    assert isinstance(c.routeinfo(), dict)
    assert c.command_exists("ls") is True
    assert c.filesize(str(f)) == 1024  # mock 固定值
    assert c.version_detail()["version"] == "1.3.9-mock"
    flows = c.pcap_flow_extract("/some/dir")
    assert flows[0]["protoType"] == 1
    c.close()
