"""upgrade_run 升级编排集成测试（0.3.0）+ socket_client.upgrade_apply 单测。

中央 GitHub 交互（fetch_latest_version/ensure_release_binary）与 :9001 推送（push_binary）
全部打桩——本套件只验桥侧编排逻辑：预检版本 / dt20 受理 / 轮询确认 / 终态汇总。
"""
import pytest

from mcp_socket_server import server as srv
from mcp_socket_server.config import load_config
from mcp_socket_server.server import init_server, upgrade_run
from mcp_socket_server.socket_client import SocketServerClient

FAKE_SHA = "a" * 64


@pytest.fixture
def app(mock_server, tmp_path, monkeypatch):
    cfg = load_config(None)
    cfg.db_path = str(tmp_path / "t.db")
    init_server(cfg)
    monkeypatch.setattr(srv, "ensure_release_binary",
                        lambda ver, d, p=None: (f"/tmp/fake-{ver}", FAKE_SHA))
    monkeypatch.setattr(srv, "push_binary",
                        lambda host, binary, ver: (True,
                                                   f"/opt/socket/versions/{ver}/.staging/socket_server"))
    yield mock_server


def test_upgrade_apply_ok(mock_server):
    c = SocketServerClient(mock_server.host, mock_server.port)
    c.connect()
    r = c.upgrade_apply("1.8.0", FAKE_SHA)
    assert r == {"ok": True, "version": "1.8.0"}
    c.close()


def test_upgrade_apply_error(mock_server):
    mock_server.upgrade_mode = "error"
    c = SocketServerClient(mock_server.host, mock_server.port)
    c.connect()
    r = c.upgrade_apply("1.8.0", FAKE_SHA)
    assert "error" in r and "未找到" in r["error"]
    c.close()


def test_upgrade_run_happy(app, mock_server):
    mock_server.mock_version = "1.8.0"  # 预检 + 轮询确认都走 dt14
    res = upgrade_run([mock_server.host], version="1.8.0", port=mock_server.port)
    assert res["ok"] == 1
    assert res["results"][0]["upgraded"] is True
    assert res["results"][0]["version"] == "1.8.0"
    assert res["results"][0]["from_version"] == "1.8.0"


def test_upgrade_run_rejects_old_target(app, mock_server):
    mock_server.mock_version = "1.7.1"
    res = upgrade_run([mock_server.host], version="1.8.0", port=mock_server.port)
    assert res["ok"] == 0
    assert "1.8.0+" in res["failed"][0]["reason"]


def test_upgrade_run_dt20_error(app, mock_server):
    mock_server.mock_version = "1.8.0"
    mock_server.upgrade_mode = "error"
    res = upgrade_run([mock_server.host], version="1.8.0", port=mock_server.port)
    assert res["ok"] == 0
    assert "未找到" in res["failed"][0]["reason"]


def test_upgrade_run_invalid_version(app, mock_server):
    res = upgrade_run([mock_server.host], version="../evil", port=mock_server.port)
    assert res["ok"] == 0
    assert "非法" in res["failed"][0]["reason"]


def test_upgrade_run_unreachable_download(app, mock_server, monkeypatch):
    mock_server.mock_version = "1.8.0"
    monkeypatch.setattr(srv, "ensure_release_binary", lambda ver, d, p=None: (None, "下载失败: mock"))
    res = upgrade_run([mock_server.host], version="1.8.0", port=mock_server.port)
    assert res["ok"] == 0
    assert "下载失败" in res["failed"][0]["reason"]
