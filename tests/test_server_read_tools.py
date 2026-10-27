"""收敛后读支撑工具测试(0.2.0: 删 version_query/detail/filesize/command_exists/routeinfo)。"""
from mcp_socket_server.server import (
    file_transfer,
    isdir,
    isfile,
    pcap_flow_extract,
    version,
)

def test_version_tool(mock_server, tmp_path):
    mock_server.mock_version = "1.8.0"
    r = version([mock_server.host], port=mock_server.port)
    assert r["ok"] == 1 and r["results"][0]["version"] == "1.8.0", r


def test_file_transfer_guidance_tool(mock_server):
    # 纯指引:零网络调用,返回点对点 curl 命令(IP 用注册的 host)
    r = file_transfer([mock_server.host], http_port=9001)
    assert r["ok"] == 1, r
    c = r["commands"][0]
    assert c["target"] == mock_server.host
    # 裸 host 不得丢失(回归: rpartition 对无冒号 target 会清空 host)
    assert f"http://{mock_server.host}:9001/" in c["download"], c["download"]
    assert f"http://{mock_server.host}:9001/files" in c["upload"], c["upload"]
    assert "curl -o " in c["download"] and ":9001/files?path=" in c["download"]
    assert "curl -F" in c["upload"] and ":9001/files" in c["upload"]
    assert "ssh" not in c["download"].lower()


def test_file_transfer_host_port_form():
    # "host:port" 形态:剥端口取 host,IPv6 裸地址加方括号
    r = file_transfer(["10.0.0.1:9100", "fd00::5"], http_port=9001)
    by = {c["target"]: c for c in r["commands"]}
    assert "http://10.0.0.1:9001/" in by["10.0.0.1:9100"]["download"]
    assert "http://[fd00::5]:9001/" in by["fd00::5"]["upload"]


def test_isfile_and_isdir_tools(mock_server, tmp_path):
    f = tmp_path / "a.txt"
    f.write_text("x")
    r1 = isfile([mock_server.host], str(f), port=mock_server.port)
    assert r1["ok"] == 1 and r1["results"][0]["exists"] is True
    r2 = isdir([mock_server.host], str(tmp_path), port=mock_server.port)
    assert r2["ok"] == 1 and r2["results"][0]["exists"] is True


def test_pcap_flow_extract_tool(mock_server):
    r = pcap_flow_extract([mock_server.host], "/d", port=mock_server.port)
    assert r["ok"] == 1 and r["results"][0]["flows"][0]["protoType"] == 1


def test_partial_failure_isfile(mock_server):
    res = isfile([mock_server.host, "127.0.0.1:1"], "/x", port=mock_server.port)
    assert res["ok"] == 1
    assert len(res["failed"]) == 1


def test_isfile_accepts_timeout(mock_server):
    res = isfile([mock_server.host], "/etc/hostname", port=mock_server.port, timeout=10)
    assert res["ok"] == 1, res
