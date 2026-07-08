"""每靶机连接池 + 批量调度。

连接池参数: min_idle=0, max_conn=5, idle_timeout=10min, borrow_timeout=10s
（突发型命令，不留常连；socket_server 单线程，单靶机并发受限）
"""
from __future__ import annotations

import logging
import threading
import time
from collections import defaultdict
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from typing import Callable, Optional

from .socket_client import SocketServerClient

logger = logging.getLogger(__name__)

MIN_IDLE = 0
MAX_CONN_PER_TARGET = 5
IDLE_TIMEOUT = 600          # 10 分钟
BORROW_TIMEOUT = 10         # 秒
MAX_GLOBAL_CONCURRENCY = 50  # 全局并行靶机数上限


@dataclass
class _PooledConn:
    client: SocketServerClient
    last_used: float = field(default_factory=time.time)


class TargetPool:
    """单靶机连接池。一连接一请求（socket_server 协议现状），池主要用于限流 + 预热校验。"""

    def __init__(self, host: str, port: int = 9000):
        self.host = host
        self.port = port
        self._idle: list[_PooledConn] = []
        self._inuse = 0
        self._lock = threading.Lock()
        self._cond = threading.Condition(self._lock)

    def _try_get_idle(self) -> Optional[SocketServerClient]:
        """取一条空闲连接，丢弃超时的。socket_server 一连接一请求，idle 连接已被服务端关闭，故实际总是新建。"""
        now = time.time()
        while self._idle:
            pc = self._idle.pop()
            if now - pc.last_used > IDLE_TIMEOUT:
                pc.client.close()
                continue
            return pc.client
        return None

    def acquire(self, timeout: float = BORROW_TIMEOUT) -> SocketServerClient:
        """获取一条连接。超时抛 TimeoutError。"""
        deadline = time.time() + timeout
        with self._cond:
            while self._inuse >= MAX_CONN_PER_TARGET:
                remaining = deadline - time.time()
                if remaining <= 0:
                    raise TimeoutError(f"靶机 {self.host} 连接池满，等待超时")
                self._cond.wait(remaining)
            self._inuse += 1
        # socket_server 协议为请求-响应后关连接，idle 复用无意义，直接新建
        client = SocketServerClient(self.host, self.port)
        client.connect()
        return client

    def release(self, client: SocketServerClient, healthy: bool = True) -> None:
        """归还连接。不健康或已被服务端关闭则直接销毁。"""
        client.close()
        with self._cond:
            self._inuse = max(0, self._inuse - 1)
            self._cond.notify_all()


@dataclass
class TargetResult:
    target: str
    ok: bool
    data: object = None
    error: Optional[str] = None


class Scheduler:
    """批量调度：一次调用 fan-out 到多靶机并行，收集逐台结果。"""

    def __init__(self):
        self._pools: dict[str, TargetPool] = {}
        self._pools_lock = threading.Lock()
        self._executor = ThreadPoolExecutor(max_workers=MAX_GLOBAL_CONCURRENCY,
                                            thread_name_prefix="mcp-target")

    def get_pool(self, host: str, port: int = 9000) -> TargetPool:
        key = f"{host}:{port}"
        with self._pools_lock:
            pool = self._pools.get(key)
            if pool is None:
                pool = TargetPool(host, port)
                self._pools[key] = pool
            return pool

    def batch(self, targets: list[str], fn: Callable[[SocketServerClient], object],
              port: int = 9000, timeout: float = 60) -> list[TargetResult]:
        """对多靶机并行执行 fn(client)，返回逐台结果。部分失败不影响其他。"""
        futures = {}
        for host in targets:
            pool = self.get_pool(host, port)
            futures[self._executor.submit(self._run_one, pool, host, fn, timeout)] = host

        results: list[TargetResult] = []
        for fut in as_completed(futures):
            host = futures[fut]
            try:
                data = fut.result()
                results.append(TargetResult(target=host, ok=True, data=data))
            except Exception as e:
                logger.warning(f"靶机 {host} 执行失败: {e}")
                results.append(TargetResult(target=host, ok=False, error=str(e)))
        return results

    def _run_one(self, pool: TargetPool, host: str,
                 fn: Callable[[SocketServerClient], object], timeout: float) -> object:
        client = pool.acquire()
        healthy = True
        try:
            client.timeout = int(timeout)
            return fn(client)
        except Exception:
            healthy = False
            raise
        finally:
            pool.release(client, healthy)


# 全局单例
_scheduler: Optional[Scheduler] = None


def get_scheduler() -> Scheduler:
    global _scheduler
    if _scheduler is None:
        _scheduler = Scheduler()
    return _scheduler
