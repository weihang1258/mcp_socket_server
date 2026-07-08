import os

from mcp.server.fastmcp import FastMCP

from mcp_socket_server.config import load_config
from mcp_socket_server.transport import streamable_http_app


def test_load_config_defaults(tmp_path):
    cfg_path = tmp_path / "c.yaml"
    cfg_path.write_text("bind: {host: 127.0.0.1, port: 9090}\ndb_path: ./t.db\n")
    cfg = load_config(str(cfg_path))
    assert cfg.host == "127.0.0.1" and cfg.port == 9090
    assert cfg.behind_proxy is False
    assert cfg.pool["max_conn_per_target"] == 5


def test_load_config_deepcopy_no_singleton_pollution(tmp_path):
    # 不传 yaml 时 data["bind"] 不应与 DEFAULTS 共享:env 覆盖不应污染后续调用
    os_environ_host = os.environ.get("MCP_BIND_HOST")
    try:
        os.environ["MCP_BIND_HOST"] = "1.2.3.4"
        cfg = load_config(None)
        assert cfg.host == "1.2.3.4"
    finally:
        if os_environ_host is None:
            os.environ.pop("MCP_BIND_HOST", None)
        else:
            os.environ["MCP_BIND_HOST"] = os_environ_host
    cfg2 = load_config(None)  # 应恢复默认 0.0.0.0,未被上一次 env 覆盖污染
    assert cfg2.host == "0.0.0.0"


def test_streamable_http_app_returns_asgi():
    mcp = FastMCP("t")
    app = streamable_http_app(mcp)
    assert callable(getattr(app, "__call__", None))  # ASGI app
