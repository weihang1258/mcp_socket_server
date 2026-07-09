from mcp_socket_server.server import (
    command_exists,
    filesize,
    isdir,
    isfile,
    pcap_flow_extract,
    routeinfo,
    version_detail,
    version_query,
)


def test_version_query_tool(mock_server):
    res = version_query([mock_server.host], port=mock_server.port)
    assert res["ok"] == 1
    assert res["results"][0]["version"] == "1.3.9-mock"


def test_isfile_and_isdir_tools(mock_server, tmp_path):
    f = tmp_path / "a.txt"
    f.write_text("x")
    r1 = isfile([mock_server.host], str(f), port=mock_server.port)
    assert r1["ok"] == 1 and r1["results"][0]["exists"] is True
    r2 = isdir([mock_server.host], str(tmp_path), port=mock_server.port)
    assert r2["ok"] == 1 and r2["results"][0]["exists"] is True


def test_other_read_tools(mock_server):
    assert routeinfo([mock_server.host], port=mock_server.port)["ok"] == 1
    assert command_exists([mock_server.host], "ls", port=mock_server.port)["results"][0]["exists"] is True
    assert filesize([mock_server.host], "/x", port=mock_server.port)["results"][0]["size"] == 1024
    assert version_detail([mock_server.host], port=mock_server.port)["results"][0]["detail"]["version"] == "1.3.9-mock"
    r = pcap_flow_extract([mock_server.host], "/d", port=mock_server.port)
    assert r["ok"] == 1 and r["results"][0]["flows"][0]["protoType"] == 1


def test_partial_failure(mock_server):
    res = version_query([mock_server.host, "127.0.0.1:1"], port=mock_server.port)
    assert res["ok"] == 1
    assert len(res["failed"]) == 1
    assert res["failed"][0]["target"] == "127.0.0.1:1"
