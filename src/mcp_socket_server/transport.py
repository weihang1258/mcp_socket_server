"""Streamable HTTP 传输。

mcp 1.28.1:FastMCP.run(transport, mount_path) 不收 host/port(经验证 workflow 确认,
旧 plan 的 mcp.run(transport=,host=,port=) 会 TypeError)。改用 streamable_http_app()
返回 Starlette ASGI,由 uvicorn 绑定 host/port。端点默认 /mcp(streamable_http_path)。
"""
from __future__ import annotations

import logging

import uvicorn

from .config import Config

logger = logging.getLogger(__name__)


def streamable_http_app(mcp):
    """返回 ASGI app(供测试或外部 uvicorn/组合到更大 ASGI)。"""
    return mcp.streamable_http_app()


def run(mcp, cfg: Config) -> None:
    """用 uvicorn 跑 Streamable HTTP。端点 /mcp。log_level 跟随 config(DEBUG 时开 access 日志)。"""
    app = mcp.streamable_http_app()
    logger.info(f"MCP Streamable HTTP 监听 {cfg.host}:{cfg.port}/mcp (log_level={cfg.log_level})")
    uvicorn.run(app, host=cfg.host, port=cfg.port,
                log_level=cfg.log_level.lower(),
                access_log=True)
