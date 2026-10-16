"""收敛后读支撑工具测试(0.2.0: 删 version_query/detail/filesize/command_exists/routeinfo)。"""
from mcp_socket_server.server import (
    isdir,
    isfile,
    pcap_flow_extract,
)


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
