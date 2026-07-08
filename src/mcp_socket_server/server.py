"""MCP server 入口(一期:只读工具 + Streamable HTTP)。

工具保持 sync def,FastMCP 自动放 threadpool 跑。Plan 2 加 registry/audit/locks + 写工具。
"""
from __future__ import annotations

import logging

from mcp.server.fastmcp import FastMCP

from .pool import get_scheduler

logger = logging.getLogger(__name__)
logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")

mcp = FastMCP("mcp-socket-server")


@mcp.tool()
def list_targets() -> dict:
    """列出已注册的靶机(占位,Plan 2 接 registry/SQLite)。"""
    return {"targets": [], "note": "靶机注册表待接入(Plan 2)"}


def init_server(cfg) -> None:
    """Plan 2 接 registry/audit/locks。本期占位。"""
    logger.info(f"init_server: db={cfg.db_path} bind={cfg.host}:{cfg.port} "
                f"(registry/audit/locks 待 Plan 2)")


def _failed(results) -> list:
    return [{"target": r.target, "reason": r.error} for r in results if not r.ok]


@mcp.tool()
def version_query(targets: list[str], port: int = 9000) -> dict:
    """查询多台靶机 socket_server 版本号(datatype 14,只读)。"""
    results = get_scheduler().batch(targets, lambda c: c.version(), port=port, timeout=15)
    return {"ok": sum(1 for r in results if r.ok),
            "failed": _failed(results),
            "results": [{"target": r.target, "version": r.data} for r in results if r.ok]}


@mcp.tool()
def isfile(targets: list[str], path: str, port: int = 9000) -> dict:
    """检查文件是否存在(datatype 7,只读)。"""
    results = get_scheduler().batch(targets, lambda c: c.isfile(path), port=port, timeout=15)
    return {"ok": sum(1 for r in results if r.ok),
            "failed": _failed(results),
            "results": [{"target": r.target, "exists": r.data} for r in results if r.ok]}


@mcp.tool()
def isdir(targets: list[str], path: str, port: int = 9000) -> dict:
    """检查目录是否存在(datatype 8,只读)。"""
    results = get_scheduler().batch(targets, lambda c: c.isdir(path), port=port, timeout=15)
    return {"ok": sum(1 for r in results if r.ok),
            "failed": _failed(results),
            "results": [{"target": r.target, "exists": r.data} for r in results if r.ok]}


@mcp.tool()
def routeinfo(targets: list[str], port: int = 9000) -> dict:
    """查询路由信息(datatype 4,只读)。"""
    results = get_scheduler().batch(targets, lambda c: c.routeinfo(), port=port, timeout=15)
    return {"ok": sum(1 for r in results if r.ok),
            "failed": _failed(results),
            "results": [{"target": r.target, "routeinfo": r.data} for r in results if r.ok]}


@mcp.tool()
def command_exists(targets: list[str], cmd: str, port: int = 9000) -> dict:
    """检查命令是否存在(datatype 18,只读,不自动安装)。"""
    results = get_scheduler().batch(targets, lambda c: c.command_exists(cmd), port=port, timeout=15)
    return {"ok": sum(1 for r in results if r.ok),
            "failed": _failed(results),
            "results": [{"target": r.target, "exists": r.data} for r in results if r.ok]}


@mcp.tool()
def filesize(targets: list[str], path: str, port: int = 9000) -> dict:
    """查询文件字节数(datatype 11,只读)。"""
    results = get_scheduler().batch(targets, lambda c: c.filesize(path), port=port, timeout=15)
    return {"ok": sum(1 for r in results if r.ok),
            "failed": _failed(results),
            "results": [{"target": r.target, "size": r.data} for r in results if r.ok]}


@mcp.tool()
def version_detail(targets: list[str], port: int = 9000) -> dict:
    """查询服务端版本详情(datatype 19,只读;线上 v1.3.9 可能 REPO bug,失败见 failed)。"""
    results = get_scheduler().batch(targets, lambda c: c.version_detail(), port=port, timeout=15)
    return {"ok": sum(1 for r in results if r.ok),
            "failed": _failed(results),
            "results": [{"target": r.target, "detail": r.data} for r in results if r.ok]}


@mcp.tool()
def pcap_flow_extract(targets: list[str], pcap_dir: str, port: int = 9000) -> dict:
    """提取 pcap 五元组流(datatype 200,只读)。"""
    results = get_scheduler().batch(targets, lambda c: c.pcap_flow_extract(pcap_dir),
                                    port=port, timeout=30)
    return {"ok": sum(1 for r in results if r.ok),
            "failed": _failed(results),
            "results": [{"target": r.target, "flows": r.data} for r in results if r.ok]}


def main() -> None:
    """stdio 模式(本地)。远程用 __main__.main -> transport.run(Streamable HTTP)。"""
    mcp.run()


if __name__ == "__main__":
    main()
