"""每靶机连接池 + 批量调度(重建版:持久会话 + 连接复用)。

服务端 protocol.py handle() 是持久连接循环,故连接可复用;文件传输需在同一连接多轮往返。
池参数: max_conn_per_target=5, idle_timeout=10min, borrow_timeout=10s, 全局并发 50。

经验证 workflow 核验(2026-07-08)并修复两处 bug:
  - acquire() connect 失败必须递减 _inuse + notify,否则 5 次失败后该 target 池永久耗尽
  - release() 不在持锁期间 close(),避免持锁 I/O 且消除双关闭
"""
from __future__ import annotations

import logging
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from contextlib import contextmanager
from dataclasses import dataclass, field
from typing import Callable, Iterator, Optional

from .socket_client import DEFAULT_TIMEOUT, SocketServerClient

logger = logging.getLogger(__name__)
MAX_CONN_PER_TARGET = 5
IDLE_TIMEOUT = 600
BORROW_TIMEOUT = 10
MAX_GLOBAL_CONCURRENCY = 50


@dataclass
class _PooledConn:
    client: SocketServerClient
    last_used: float = field(default_factory=time.time)


class TargetPool:
    def __init__(self, host: str, port: int = 9000):
        self.host = host
        self.port = port
        self._idle: list[_PooledConn] = []
        self._inuse = 0
        self._cond = threading.Condition(threading.Lock())

    def acquire(self, timeout: float = BORROW_TIMEOUT,
                socket_timeout: int = DEFAULT_TIMEOUT) -> SocketServerClient:
        deadline = time.time() + timeout
        expired: list[SocketServerClient] = []
        reuse: Optional[SocketServerClient] = None
        with self._cond:
            while self._inuse >= MAX_CONN_PER_TARGET:
                remaining = deadline - time.time()
                if remaining <= 0:
                    raise TimeoutError(f"靶机 {self.host} 连接池满,等待超时")
                self._cond.wait(remaining)
            # 复用空闲连接(未超时);超时的收集到锁外关闭(避免持锁 I/O)
            now = time.time()
            while self._idle:
                pc = self._idle.pop()
                if now - pc.last_used > IDLE_TIMEOUT:
                    expired.append(pc.client)
                    continue
                reuse = pc.client
                break
            self._inuse += 1
        for c in expired:
            try:
                c.close()
            except OSError:
                pass
        if reuse is not None:
            return reuse
        # 新建连接(锁外):socket_timeout 同时约束 connect 与后续 recv/send;
        # 失败必须递减 _inuse,否则池计数泄漏致永久耗尽
        client = SocketServerClient(self.host, self.port, timeout=socket_timeout)
        try:
            client.connect()
        except Exception:
            with self._cond:
                self._inuse = max(0, self._inuse - 1)
                self._cond.notify_all()
            raise
        return client

    def release(self, client: SocketServerClient, healthy: bool = True) -> None:
        with self._cond:
            self._inuse = max(0, self._inuse - 1)
            if healthy:
                self._idle.append(_PooledConn(client, time.time()))
            self._cond.notify_all()
        # 不健康连接在锁外关闭(避免持锁 I/O;healthy 连接归还池复用,不关闭)
        if not healthy:
            try:
                client.close()
            except OSError:
                pass

    def close_all(self) -> None:
        with self._cond:
            idle = self._idle
            self._idle = []
        for pc in idle:
            try:
                pc.client.close()
            except OSError:
                pass


@dataclass
class TargetResult:
    target: str
    ok: bool
    data: object = None
    error: Optional[str] = None


class Scheduler:
    def __init__(self):
        self._pools: dict[str, TargetPool] = {}
        self._pools_lock = threading.Lock()
        self._executor = ThreadPoolExecutor(max_workers=MAX_GLOBAL_CONCURRENCY,
                                            thread_name_prefix="mcp-target")

    def get_pool(self, host: str, port: int = 9000) -> TargetPool:
        key = f"{host}:{port}"
        with self._pools_lock:
            p = self._pools.get(key)
            if p is None:
                p = TargetPool(host, port)
                self._pools[key] = p
            return p

    def batch(self, targets: list[str], fn: Callable[[SocketServerClient], object],
              port: int = 9000, timeout: float = 60) -> list[TargetResult]:
        futures = {}
        for host in targets:
            pool = self.get_pool(host, port)
            futures[self._executor.submit(self._run_one, pool, host, fn, timeout)] = host
        results: list[TargetResult] = []
        for fut in as_completed(futures):
            host = futures[fut]
            try:
                results.append(TargetResult(target=host, ok=True, data=fut.result()))
            except Exception as e:
                logger.warning(f"靶机 {host} 执行失败: {e}")
                results.append(TargetResult(target=host, ok=False, error=str(e)))
        return results

    @contextmanager
    def session(self, host: str, port: int = 9000, timeout: float = 30) -> Iterator[SocketServerClient]:
        """借出独占连接用于多步操作(文件上传/下载)。context manager。

        用法:
            with sched.session(host, port) as client:
                client.file_upload(remote, content)
        """
        pool = self.get_pool(host, port)
        client = pool.acquire(socket_timeout=int(timeout))
        healthy = True
        try:
            yield client
        except Exception:
            healthy = False
            raise
        finally:
            pool.release(client, healthy)

    def _run_one(self, pool: TargetPool, host: str,
                 fn: Callable[[SocketServerClient], object], timeout: float) -> object:
        client = pool.acquire(socket_timeout=int(timeout))
        healthy = True
        try:
            return fn(client)
        except Exception:
            healthy = False
            raise
        finally:
            pool.release(client, healthy)


_scheduler: Optional[Scheduler] = None


def get_scheduler() -> Scheduler:
    global _scheduler
    if _scheduler is None:
        _scheduler = Scheduler()
    return _scheduler
