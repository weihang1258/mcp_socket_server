"""靶机注册表 SQLite(WAL) + @tag 解析。"""

from __future__ import annotations

import json
import sqlite3
import threading
from typing import Optional


class Registry:
    def __init__(self, db_path: str):
        self._lock = threading.Lock()
        self._conn = sqlite3.connect(db_path, check_same_thread=False)
        self._conn.execute("PRAGMA journal_mode=WAL")
        self._conn.execute("""CREATE TABLE IF NOT EXISTS targets (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            host TEXT NOT NULL,
            port INTEGER NOT NULL DEFAULT 9000,
            tags TEXT NOT NULL DEFAULT '[]',
            note TEXT NOT NULL DEFAULT '',
            created_at TEXT NOT NULL DEFAULT (datetime('now')),
            UNIQUE(host, port)
        )""")
        self._conn.commit()

    def add_target(self, host: str, port: int = 9000,
                   tags: Optional[list[str]] = None,
                   note: str = "") -> dict:
        with self._lock:
            try:
                self._conn.execute(
                    "INSERT OR IGNORE INTO targets (host, port, tags, note) VALUES (?, ?, ?, ?)",
                    (host, port, json.dumps(tags or []), note))
                self._conn.commit()
                return {"ok": True, "host": host, "port": port}
            except Exception as e:
                return {"ok": False, "error": str(e)}

    def remove_target(self, host: str, port: int = 9000) -> dict:
        with self._lock:
            cur = self._conn.execute(
                "DELETE FROM targets WHERE host=? AND port=?", (host, port))
            self._conn.commit()
            if cur.rowcount == 0:
                return {"ok": False, "error": "靶机不存在"}
            return {"ok": True}

    def list_targets(self, tags: Optional[list[str]] = None) -> list[dict]:
        with self._lock:
            if tags:
                rows = self._conn.execute(
                    "SELECT host, port, tags, note, created_at FROM targets").fetchall()
                result = []
                for row in rows:
                    row_tags = json.loads(row[2])
                    if all(t in row_tags for t in tags):
                        result.append({
                            "host": row[0], "port": row[1],
                            "tags": row_tags, "note": row[3],
                            "created_at": row[4],
                        })
                return result
            rows = self._conn.execute(
                "SELECT host, port, tags, note, created_at FROM targets ORDER BY created_at"
            ).fetchall()
            return [
                {"host": r[0], "port": r[1], "tags": json.loads(r[2]),
                 "note": r[3], "created_at": r[4]}
                for r in rows
            ]

    def resolve(self, targets: list[str]) -> list[tuple[str, int]]:
        """展开 @tag 和 host:port -> list[(host,port)]。
        裸 IP -> (ip, 9000)。unknown @tag 静默跳过。
        """
        resolved: list[tuple[str, int]] = []
        with self._lock:
            all_rows = self._conn.execute(
                "SELECT host, port, tags FROM targets").fetchall()
            tag_map: dict[str, list[tuple[str, int]]] = {}
            for row in all_rows:
                for t in json.loads(row[2]):
                    tag_map.setdefault(t, []).append((row[0], row[1]))
        for item in targets:
            if item.startswith("@"):
                entries = tag_map.get(item[1:], [])
                resolved.extend(entries)
            elif ":" in item:
                h, p_str = item.split(":", 1)
                resolved.append((h, int(p_str)))
            else:
                resolved.append((item, 9000))
        return resolved

    def close(self):
        self._conn.close()


_registry: Optional[Registry] = None


def get_registry(db_path: str = "./mcp_socket_server.db") -> Registry:
    global _registry
    if _registry is None:
        _registry = Registry(db_path)
    return _registry


def set_registry(reg: Optional[Registry]) -> None:
    global _registry
    _registry = reg