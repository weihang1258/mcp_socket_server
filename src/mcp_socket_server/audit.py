"""审计日志 SQLite(WAL)。

每次工具调用完成后写一条。crash-mid-call 不预记(已知限制)。
source_ip 默认 'internal'();Streamable HTTP 下可传 X-Forwarded-For。
"""
from __future__ import annotations

import json
import sqlite3
import threading
from typing import Any


class AuditLogger:
    def __init__(self, db_path: str, retention_days: int = 90):
        self._lock = threading.Lock()
        self._conn = sqlite3.connect(db_path, check_same_thread=False)
        self._conn.execute("PRAGMA journal_mode=WAL")
        self._conn.execute("""CREATE TABLE IF NOT EXISTS audit_log (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ts TEXT NOT NULL,
            source_ip TEXT NOT NULL DEFAULT 'internal',
            tool TEXT NOT NULL,
            params TEXT NOT NULL DEFAULT '{}',
            ok_count INTEGER NOT NULL DEFAULT 0,
            failed_count INTEGER NOT NULL DEFAULT 0,
            outcomes TEXT NOT NULL DEFAULT '[]',
            duration_ms INTEGER NOT NULL DEFAULT 0
        )""")
        self._conn.commit()
        self._retention_days = retention_days
        if retention_days > 0:
            self._cleanup(retention_days)

    def _cleanup(self, days: int) -> None:
        with self._lock:
            self._conn.execute(
                "DELETE FROM audit_log WHERE ts < datetime('now', ?)",
                (f"-{days} days",))
            self._conn.commit()

    def write(self, tool: str, params: dict, outcomes: list[dict],
              ok_count: int, failed_count: int, duration_ms: int,
              source_ip: str = "internal") -> None:
        with self._lock:
            self._conn.execute(
                "INSERT INTO audit_log "
                "(ts, source_ip, tool, params, ok_count, failed_count, outcomes, duration_ms) "
                "VALUES (datetime('now'), ?, ?, ?, ?, ?, ?, ?)",
                (source_ip, tool,
                 json.dumps(self._truncate_params(params), ensure_ascii=False),
                 ok_count, failed_count,
                 json.dumps(outcomes, ensure_ascii=False), duration_ms))
            self._conn.commit()

    @staticmethod
    def _truncate_params(params: dict, max_len: int = 200) -> dict:
        result = {}
        for k, v in params.items():
            s = str(v)
            if len(s) > max_len:
                result[k] = s[:max_len] + "..."
            else:
                result[k] = v
        return result

    def close(self) -> None:
        self._conn.close()


_audit: Any = None


def get_audit(db_path: str = "./mcp_socket_server.db",
              retention_days: int = 90) -> AuditLogger:
    global _audit
    if _audit is None:
        _audit = AuditLogger(db_path, retention_days)
    return _audit


def set_audit(logger: Any) -> None:
    global _audit
    _audit = logger