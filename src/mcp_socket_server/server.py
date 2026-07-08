"""MCP server 入口。

启动: mcp-socket-server （stdio 传输，本地）
远程多用户场景改用 SSE/streamable HTTP（待加）。

首批只暴露只读工具跑通链路，写类工具后续按 commands.py 注册表逐步开放。
"""
from __future__ import annotations

import logging
from typing import Any

from mcp.server.fastmcp import FastMCP

from .pool import get_scheduler

logger = logging.getLogger(__name__)
logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")

mcp = FastMCP("mcp-socket-server")


@mcp.tool()
def list_targets() -> dict:
    """列出已注册的靶机（占位实现，后续接靶机注册表）。"""
    # TODO: 接靶机注册表（config 文件或 DB），返回 [{host, tags, healthy}]
    return {"targets": [], "note": "靶机注册表待接入"}


@mcp.tool()
def version_query(targets: list[str], port: int = 9000) -> dict:
    """查询多台靶机的 socket_server 版本号（datatype 14，只读）。

    Args:
        targets: 靶机 IP 列表
        port: socket_server 端口，默认 9000
    Returns:
        {ok: N, failed: [{target, reason}], results: [{target, version}]}
    """
    sched = get_scheduler()
    results = sched.batch(targets, lambda c: c.version(), port=port, timeout=15)
    return {
        "ok": sum(1 for r in results if r.ok),
        "failed": [{"target": r.target, "reason": r.error} for r in results if not r.ok],
        "results": [{"target": r.target, "version": r.data} for r in results if r.ok],
    }


@mcp.tool()
def isfile(targets: list[str], path: str, port: int = 9000) -> dict:
    """检查多台靶机上文件是否存在（datatype 7，只读）。"""
    sched = get_scheduler()
    results = sched.batch(targets, lambda c: c.isfile(path), port=port, timeout=15)
    return {
        "ok": sum(1 for r in results if r.ok),
        "failed": [{"target": r.target, "reason": r.error} for r in results if not r.ok],
        "results": [{"target": r.target, "exists": r.data} for r in results if r.ok],
    }


@mcp.tool()
def routeinfo(targets: list[str], port: int = 9000) -> dict:
    """查询多台靶机的路由信息（datatype 4，只读）。"""
    sched = get_scheduler()
    results = sched.batch(targets, lambda c: c.routeinfo(), port=port, timeout=15)
    return {
        "ok": sum(1 for r in results if r.ok),
        "failed": [{"target": r.target, "reason": r.error} for r in results if not r.ok],
        "results": [{"target": r.target, "routeinfo": r.data} for r in results if r.ok],
    }


def main() -> None:
    mcp.run()


if __name__ == "__main__":
    main()
