"""配置加载:config.yaml + env 覆盖。"""
from __future__ import annotations

import copy
import os
from dataclasses import dataclass
from typing import Any

import yaml

DEFAULTS: dict[str, Any] = {
    "bind": {"host": "0.0.0.0", "port": 8080},
    "db_path": "./mcp_socket_server.db",
    "behind_proxy": False,
    "audit_retention_days": 90,
    "download_dir": "./downloads",
    "pool": {"max_conn_per_target": 5, "idle_timeout": 600,
             "borrow_timeout": 10, "max_global_concurrency": 50},
    "cmd_exec_whitelist": [],
}


@dataclass
class Config:
    host: str
    port: int
    db_path: str
    behind_proxy: bool
    audit_retention_days: int
    download_dir: str
    pool: dict
    cmd_exec_whitelist: list


def _deep_merge(base: dict, over: dict) -> dict:
    out = dict(base)
    for k, v in over.items():
        if isinstance(v, dict) and isinstance(out.get(k), dict):
            out[k] = _deep_merge(out[k], v)
        else:
            out[k] = v
    return out


def load_config(path: str | None = None) -> Config:
    # 深拷贝:避免嵌套 dict(bind/pool)与 DEFAULTS 共享,被 env 覆盖污染模块单例
    data = copy.deepcopy(DEFAULTS)
    if path and os.path.isfile(path):
        with open(path) as f:
            data = _deep_merge(data, yaml.safe_load(f) or {})
    if os.getenv("MCP_BIND_HOST"):
        data["bind"]["host"] = os.environ["MCP_BIND_HOST"]
    if os.getenv("MCP_BIND_PORT"):
        data["bind"]["port"] = int(os.environ["MCP_BIND_PORT"])
    b = data["bind"]
    return Config(host=b["host"], port=b["port"], db_path=data["db_path"],
                  behind_proxy=data["behind_proxy"],
                  audit_retention_days=data["audit_retention_days"],
                  download_dir=data["download_dir"], pool=data["pool"],
                  cmd_exec_whitelist=data["cmd_exec_whitelist"])
