"""MCP server 入口(一期:只读 + 写工具 + Streamable HTTP)。

工具保持 sync def,FastMCP 自动放 threadpool 跑。
架构:每个工具 targets:list[str] -> 并发发往多台靶机 -> 汇总返回 {ok, failed, results}。
"""
from __future__ import annotations

import logging
import os
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
from contextlib import ExitStack
from datetime import datetime, timezone
from typing import Any, Callable, Optional

from mcp.server.fastmcp import FastMCP
from mcp.server.transport_security import TransportSecuritySettings

from .audit import get_audit
from .commands import COMMANDS, Danger, LockClass
from .locks import LockConflict, LockManager, get_lock_manager
from .pool import TargetPool, TargetResult, get_scheduler
from .registry import get_registry

logger = logging.getLogger(__name__)
logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")

# 内网中央节点:关闭 DNS rebinding 保护(默认只放行 127.0.0.1/localhost,
# 内网其它 IP 连过来会 421)。Plan 2 接 auth 后再收紧。
mcp = FastMCP("mcp-socket-server",
               transport_security=TransportSecuritySettings(
                   enable_dns_rebinding_protection=False))

_lock_manager: Optional[LockManager] = None
_registry: Any = None
_audit_logger: Any = None


def init_server(cfg) -> None:
    """初始化 registry/locks/audit。config.yaml 的 db_path 用于所有 SQLite。"""
    global _lock_manager, _registry, _audit_logger
    _lock_manager = get_lock_manager()
    _registry = get_registry(cfg.db_path)
    _audit_logger = get_audit(cfg.db_path, cfg.audit_retention_days)
    logger.info(f"init_server: db={cfg.db_path} bind={cfg.host}:{cfg.port}")


def _resolve_targets(raw_targets: list[str]) -> list[str]:
    """展开 @tag -> IPs;经过 @tag 的项会被替换为具体 IP。"""
    if _registry is None:
        return raw_targets
    return _registry.resolve(raw_targets)


def _failed(results: list[TargetResult]) -> list[dict]:
    return [{"target": r.target, "reason": r.error} for r in results if not r.ok]


def _ok(results: list[TargetResult]) -> list[dict]:
    return [{"target": r.target} for r in results if r.ok]


def _run_batch(
    targets: list[str],
    port: int,
    fn: Callable,
    lock_class: LockClass = LockClass.NONE,
    lock_key_fn: Optional[Callable] = None,
    audit_tool: Optional[str] = None,
    audit_params: Optional[dict] = None,
    timeout: float = 30,
) -> dict:
    """带锁 + 审计的批量执行。fail-fast 锁冲突 -> 该 target failed。"""
    resolved = _resolve_targets(targets)
    sched = get_scheduler()
    results: list[TargetResult] = []

    def run_one(host_port: str) -> TargetResult:
        lock_mgr = _lock_manager
        key = ()
        if lock_key_fn:
            key = lock_key_fn(host_port)
        if lock_mgr is not None and lock_class != LockClass.NONE:
            lock_mgr.acquire(host_port, lock_class, key)
        pool = sched.get_pool(host_port, port)
        client = pool.acquire(socket_timeout=int(timeout))
        healthy = True
        try:
            data = fn(client)
            return TargetResult(target=host_port, ok=True, data=data)
        except Exception as e:
            healthy = False
            return TargetResult(target=host_port, ok=False, error=str(e))
        finally:
            pool.release(client, healthy)
            if lock_mgr is not None and lock_class != LockClass.CAPTURE:
                try:
                    lock_mgr.release(host_port, lock_class, key)
                except Exception:
                    pass

    with ThreadPoolExecutor(max_workers=min(50, len(resolved) or 1),
                           thread_name_prefix="mcp-write") as ex:
        futs = {ex.submit(run_one, h): h for h in resolved}
        for fut in as_completed(futs):
            try:
                results.append(fut.result())
            except Exception as e:
                results.append(TargetResult(target=futs[fut], ok=False, error=str(e)))

    # audit
    if audit_tool and _audit_logger is not None:
        try:
            params = audit_params or {}
            outcomes = [{"target": r.target, "ok": r.ok,
                         "error": getattr(r, "error", None)} for r in results]
            _audit_logger.write(
                audit_tool, params, outcomes,
                ok_count=sum(1 for r in results if r.ok),
                failed_count=sum(1 for r in results if not r.ok),
                duration_ms=0, source_ip="internal",
            )
        except Exception:
            pass

    return {"ok": sum(1 for r in results if r.ok),
            "failed": _failed(results),
            "results": [r.data for r in results if r.ok]}


# ==================== 只读工具 ====================

@mcp.tool()
def list_targets() -> dict:
    """列出已注册的靶机。"""
    if _registry is None:
        return {"targets": [], "note": "注册表未初始化(需调 init_server)"}
    return {"targets": _registry.list_targets()}


@mcp.tool()
def add_target(host: str, port: int = 9000, tags: list[str] | None = None,
               note: str = "") -> dict:
    """注册新靶机。tags 用于 @tag 选机。"""
    if _registry is None:
        return {"ok": False, "error": "注册表未初始化"}
    return _registry.add_target(host, port, tags, note)


@mcp.tool()
def remove_target(host: str, port: int = 9000) -> dict:
    """移除靶机(有活跃锁时拒绝)。"""
    if _registry is None:
        return {"ok": False, "error": "注册表未初始化"}
    if _lock_manager is not None and _lock_manager.has_active(host):
        return {"ok": False, "error": f"靶机 {host} 有活跃锁,无法移除"}
    return _registry.remove_target(host, port)


@mcp.tool()
def version_query(targets: list[str], port: int = 9000) -> dict:
    """查询多台靶机 socket_server 版本号(datatype 14,只读)。"""
    resolved = _resolve_targets(targets)
    results = get_scheduler().batch(resolved, lambda c: c.version(), port=port, timeout=15)
    return {"ok": sum(1 for r in results if r.ok),
            "failed": _failed(results),
            "results": [{"target": r.target, "version": r.data} for r in results if r.ok]}


@mcp.tool()
def isfile(targets: list[str], path: str, port: int = 9000) -> dict:
    """检查文件是否存在(datatype 7,只读)。"""
    resolved = _resolve_targets(targets)
    results = get_scheduler().batch(resolved, lambda c: c.isfile(path), port=port, timeout=15)
    return {"ok": sum(1 for r in results if r.ok),
            "failed": _failed(results),
            "results": [{"target": r.target, "exists": r.data} for r in results if r.ok]}


@mcp.tool()
def isdir(targets: list[str], path: str, port: int = 9000) -> dict:
    """检查目录是否存在(datatype 8,只读)。"""
    resolved = _resolve_targets(targets)
    results = get_scheduler().batch(resolved, lambda c: c.isdir(path), port=port, timeout=15)
    return {"ok": sum(1 for r in results if r.ok),
            "failed": _failed(results),
            "results": [{"target": r.target, "exists": r.data} for r in results if r.ok]}


@mcp.tool()
def routeinfo(targets: list[str], port: int = 9000) -> dict:
    """查询路由信息(datatype 4,只读)。"""
    resolved = _resolve_targets(targets)
    results = get_scheduler().batch(resolved, lambda c: c.routeinfo(), port=port, timeout=15)
    return {"ok": sum(1 for r in results if r.ok),
            "failed": _failed(results),
            "results": [{"target": r.target, "routeinfo": r.data} for r in results if r.ok]}


@mcp.tool()
def command_exists(targets: list[str], cmd: str, port: int = 9000) -> dict:
    """检查命令是否存在(datatype 18,只读,不自动安装)。"""
    resolved = _resolve_targets(targets)
    results = get_scheduler().batch(resolved, lambda c: c.command_exists(cmd), port=port, timeout=15)
    return {"ok": sum(1 for r in results if r.ok),
            "failed": _failed(results),
            "results": [{"target": r.target, "exists": r.data} for r in results if r.ok]}


@mcp.tool()
def filesize(targets: list[str], path: str, port: int = 9000) -> dict:
    """查询文件字节数(datatype 11,只读)。"""
    resolved = _resolve_targets(targets)
    results = get_scheduler().batch(resolved, lambda c: c.filesize(path), port=port, timeout=15)
    return {"ok": sum(1 for r in results if r.ok),
            "failed": _failed(results),
            "results": [{"target": r.target, "size": r.data} for r in results if r.ok]}


@mcp.tool()
def version_detail(targets: list[str], port: int = 9000) -> dict:
    """查询服务端版本详情(datatype 19,只读;v1.3.9 可能 REPO bug,失败见 failed)。"""
    resolved = _resolve_targets(targets)
    results = get_scheduler().batch(resolved, lambda c: c.version_detail(), port=port, timeout=15)
    return {"ok": sum(1 for r in results if r.ok),
            "failed": _failed(results),
            "results": [{"target": r.target, "detail": r.data} for r in results if r.ok]}


@mcp.tool()
def pcap_flow_extract(targets: list[str], pcap_dir: str, port: int = 9000) -> dict:
    """提取 pcap 五元组流(datatype 200,只读)。"""
    resolved = _resolve_targets(targets)
    results = get_scheduler().batch(resolved, lambda c: c.pcap_flow_extract(pcap_dir),
                                    port=port, timeout=30)
    return {"ok": sum(1 for r in results if r.ok),
            "failed": _failed(results),
            "results": [{"target": r.target, "flows": r.data} for r in results if r.ok]}


# ==================== 写工具 ====================

@mcp.tool()
def cmd_exec(targets: list[str], args: str, cwd: str = "", env: dict | None = None,
             wait: bool = True, port: int = 9000) -> dict:
    """执行命令(datatype 1,SHELL/DANGER,白名单校验后转发)。"""
    # 白名单校验
    whitelist = []
    if _audit_logger is not None:
        try:
            whitelist = getattr(_audit_logger, "_cmd_whitelist", [])
        except Exception:
            pass
    if whitelist:
        if not any(args.strip().startswith(w) for w in whitelist):
            return {"ok": 0, "failed": [{"target": t, "reason": f"命令不在白名单: {args}"}
                                         for t in targets],
                    "results": []}
    resolved = _resolve_targets(targets)

    def run_one(client):
        return client.cmd_exec(args, cwd=cwd or None, env=env, wait=wait)

    return _run_batch(resolved, port, run_one,
                      lock_class=LockClass.SHELL,
                      audit_tool="cmd_exec",
                      audit_params={"args": args, "cwd": cwd, "wait": wait},
                      timeout=60 if wait else 15)


@mcp.tool()
def capture_start(targets: list[str], iface: str = "", path: str = "/home/tmp/tmp.pcap",
                  extended: str = "", single_queue: bool = True, port: int = 9000) -> dict:
    """开始 tcpdump 抓包(datatype 5,CAPTURE 持锁)。iface 空则取 routeinfo 默认网卡。"""
    resolved = _resolve_targets(targets)

    def run_one(client):
        return client.capture_start(eth=iface or None, path=path,
                                    extended=extended, single_queue=single_queue)

    return _run_batch(resolved, port, run_one,
                      lock_class=LockClass.CAPTURE,
                      lock_key_fn=lambda h: (path,),
                      audit_tool="capture_start",
                      audit_params={"iface": iface, "path": path,
                                    "extended": extended, "single_queue": single_queue},
                      timeout=30)


@mcp.tool()
def capture_stop(targets: list[str], path: str = "/home/tmp/tmp.pcap",
                 port: int = 9000) -> dict:
    """停止 tcpdump 抓包(datatype 6)。释放 capture_start 持有的 CAPTURE(path) 锁。"""
    resolved = _resolve_targets(targets)
    sched = get_scheduler()
    results: list[TargetResult] = []

    def run_one(host_port: str) -> TargetResult:
        pool = sched.get_pool(host_port, port)
        client = pool.acquire(socket_timeout=30)
        healthy = True
        try:
            ok = client.capture_stop(path=path)
            return TargetResult(target=host_port, ok=ok, data=ok)
        except Exception as e:
            healthy = False
            return TargetResult(target=host_port, ok=False, error=str(e))
        finally:
            pool.release(client, healthy)
            # 释放 start 持有的 CAPTURE 锁(无论 stop 成败)
            if _lock_manager is not None:
                try:
                    _lock_manager.release(host_port, LockClass.CAPTURE, (path,))
                except Exception:
                    pass

    with ThreadPoolExecutor(max_workers=min(50, len(resolved) or 1),
                           thread_name_prefix="mcp-cap-stop") as ex:
        futs = {ex.submit(run_one, h): h for h in resolved}
        for fut in as_completed(futs):
            try:
                results.append(fut.result())
            except Exception as e:
                results.append(TargetResult(target=futs[fut], ok=False, error=str(e)))

    if _audit_logger is not None:
        try:
            _audit_logger.write("capture_stop", {"path": path},
                                [{"target": r.target, "ok": r.ok} for r in results],
                                ok_count=sum(1 for r in results if r.ok),
                                failed_count=sum(1 for r in results if not r.ok),
                                duration_ms=0, source_ip="internal")
        except Exception:
            pass

    return {"ok": sum(1 for r in results if r.ok),
            "failed": _failed(results),
            "results": [{"target": r.target, "res": r.data} for r in results if r.ok]}


@mcp.tool()
def boce_run(targets: list[str], url: str, count: int = 1, interval: int = 0,
             thread_count: int = 1, timeout: int = 3, mode: str = "封堵",
             chromium_path: str = "", port: int = 9000) -> dict:
    """拨测(datatype 131,BROWSER)。"""
    resolved = _resolve_targets(targets)

    def run_one(client):
        return client.boce_run(url, count=count, interval=interval,
                               thread_count=thread_count, timeout=timeout,
                               mode=mode,
                               chromium_path=chromium_path or None)

    return _run_batch(resolved, port, run_one,
                      lock_class=LockClass.BROWSER,
                      audit_tool="boce_run",
                      audit_params={"url": url, "count": count, "mode": mode},
                      timeout=60)


@mcp.tool()
def file_upload(targets: list[str], remote_path: str, content_b64: str,
                use_gzip: bool = False, port: int = 9000) -> dict:
    """上传文件(21->22->23->24 多步握手,FILE_IO 锁,独占连接)。"""
    import base64
    content = base64.b64decode(content_b64)
    resolved = _resolve_targets(targets)
    sched = get_scheduler()
    results: list[TargetResult] = []

    def run_session(host_port: str) -> TargetResult:
        lock_mgr = _lock_manager
        if lock_mgr is not None:
            lock_mgr.acquire(host_port, LockClass.FILE_IO)
        try:
            with sched.session(host_port, port) as client:
                ok = client.file_upload(remote_path, content, use_gzip=use_gzip)
            return TargetResult(target=host_port, ok=ok,
                                data={"remote_path": remote_path, "size": len(content)})
        except Exception as e:
            return TargetResult(target=host_port, ok=False, error=str(e))
        finally:
            if lock_mgr is not None:
                try:
                    lock_mgr.release(host_port, LockClass.FILE_IO)
                except Exception:
                    pass

    with ThreadPoolExecutor(max_workers=min(10, len(resolved) or 1),
                           thread_name_prefix="mcp-file-up") as ex:
        futs = {ex.submit(run_session, h): h for h in resolved}
        for fut in as_completed(futs):
            try:
                results.append(fut.result())
            except Exception as e:
                results.append(TargetResult(target=futs[fut], ok=False, error=str(e)))

    if _audit_logger is not None:
        try:
            _audit_logger.write("file_upload",
                                {"remote_path": remote_path, "size": len(content),
                                 "use_gzip": use_gzip},
                                [{"target": r.target, "ok": r.ok} for r in results],
                                ok_count=sum(1 for r in results if r.ok),
                                failed_count=sum(1 for r in results if not r.ok),
                                duration_ms=0, source_ip="internal")
        except Exception:
            pass

    return {"ok": sum(1 for r in results if r.ok),
            "failed": _failed(results),
            "results": [r.data for r in results if r.ok]}


@mcp.tool()
def file_download(targets: list[str], path: str, use_gzip: bool = False,
                  port: int = 9000) -> dict:
    """下载文件(21->3 多步握手,FILE_IO 锁)。返回 {local_path,size,sha256}。"""
    import base64, hashlib, os, tempfile
    resolved = _resolve_targets(targets)
    sched = get_scheduler()
    results: list[TargetResult] = []
    dl_dir = os.environ.get("MCP_DOWNLOAD_DIR", "./downloads")
    os.makedirs(dl_dir, exist_ok=True)

    def run_session(host_port: str) -> TargetResult:
        lock_mgr = _lock_manager
        if lock_mgr is not None:
            lock_mgr.acquire(host_port, LockClass.FILE_IO)
        try:
            with sched.session(host_port, port) as client:
                body = client.file_download(path, use_gzip=use_gzip)
            basename = os.path.basename(path) or "downloaded"
            local = os.path.join(dl_dir, host_port, basename)
            os.makedirs(os.path.dirname(local), exist_ok=True)
            with open(local, "wb") as f:
                f.write(body)
            sha256 = hashlib.sha256(body).hexdigest()
            return TargetResult(target=host_port, ok=True,
                                data={"local_path": local, "size": len(body),
                                      "sha256": sha256})
        except Exception as e:
            return TargetResult(target=host_port, ok=False, error=str(e))
        finally:
            if lock_mgr is not None:
                try:
                    lock_mgr.release(host_port, LockClass.FILE_IO)
                except Exception:
                    pass

    with ThreadPoolExecutor(max_workers=min(10, len(resolved) or 1),
                           thread_name_prefix="mcp-file-dl") as ex:
        futs = {ex.submit(run_session, h): h for h in resolved}
        for fut in as_completed(futs):
            try:
                results.append(fut.result())
            except Exception as e:
                results.append(TargetResult(target=futs[fut], ok=False, error=str(e)))

    if _audit_logger is not None:
        try:
            _audit_logger.write("file_download", {"path": path, "use_gzip": use_gzip},
                                [{"target": r.target, "ok": r.ok} for r in results],
                                ok_count=sum(1 for r in results if r.ok),
                                failed_count=sum(1 for r in results if not r.ok),
                                duration_ms=0, source_ip="internal")
        except Exception:
            pass

    return {"ok": sum(1 for r in results if r.ok),
            "failed": _failed(results),
            "results": [r.data for r in results if r.ok]}


def main() -> None:
    """stdio 模式(本地)。远程用 __main__.main -> transport.run(Streamable HTTP)。"""
    mcp.run()


if __name__ == "__main__":
    main()