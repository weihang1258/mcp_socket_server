"""MCP server 入口(一期:只读 + 写工具 + Streamable HTTP)。

工具保持 sync def,FastMCP 自动放 threadpool 跑。
架构:每个工具 targets:list[str] -> 并发发往多台靶机 -> 汇总返回 {ok, failed, results}。
"""
from __future__ import annotations

import logging
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Annotated, Any, Callable, Optional

from pydantic import Field

from mcp.server.fastmcp import FastMCP
from mcp.server.transport_security import TransportSecuritySettings

from .audit import get_audit
from .commands import LockClass
from .locks import LockConflict, LockManager, get_lock_manager
from .pool import TargetResult, get_scheduler
from .registry import get_registry

logger = logging.getLogger(__name__)

# 各工具通用的可选 description 参数:调用方(LLM)填"本次调用的目的",
# 随调用回传展示给最终用户(参照 Claude Code Task 工具先例)。
# 仅透传,业务逻辑忽略;不入 required,旧调用方不带该参数不受影响。
CallDescription = Annotated[str, Field(
    description="一句话说明本次调用的目的（将展示给用户），不超过 50 字")]

# timeout 参数统一 schema:description 表达语义,各工具默认值不同。
ToolTimeout = Annotated[int, Field(
    description="单靶机操作超时秒数(connect+执行+返回),多靶机并行各自计时")]

# 业务工具 targets 参数统一 schema:裸 IP / host:port / @tag。
Targets = Annotated[list[str], Field(description="靶机列表(裸IP/host:port/@tag 标签)")]


def _setup_logging(level: str) -> None:
    """统一配置根 logger + 关键子 logger。DEBUG 时让 socket_client/pool/uvicorn 也详细输出。"""
    lvl = getattr(logging, level.upper(), logging.INFO)
    fmt = "%(asctime)s.%(msecs)03d %(levelname)-5s [%(name)s] %(message)s"
    logging.basicConfig(level=lvl, format=fmt, datefmt="%H:%M:%S", force=True)
    # uvicorn access 日志在 DEBUG 下也开
    if lvl <= logging.DEBUG:
        logging.getLogger("uvicorn.access").setLevel(logging.INFO)
    else:
        logging.getLogger("uvicorn.access").setLevel(logging.WARNING)


_setup_logging("INFO")  # 默认 INFO;init_server 会按 config 重设

# 内网中央节点:关闭 DNS rebinding 保护(默认只放行 127.0.0.1/localhost,
# 内网其它 IP 连过来会 421)。Plan 2 接 auth 后再收紧。
mcp = FastMCP("mcp-socket-server",
              transport_security=TransportSecuritySettings(
                  enable_dns_rebinding_protection=False))

_lock_manager: Optional[LockManager] = None
_registry: Any = None
_audit_logger: Any = None
_cmd_whitelist: list[str] = []


def init_server(cfg) -> None:
    """初始化 registry/locks/audit + 日志级别。config.yaml 的 db_path 用于所有 SQLite。"""
    global _lock_manager, _registry, _audit_logger, _cmd_whitelist
    _setup_logging(cfg.log_level)
    _lock_manager = get_lock_manager()
    _registry = get_registry(cfg.db_path)
    _audit_logger = get_audit(cfg.db_path, cfg.audit_retention_days)
    _cmd_whitelist = list(cfg.cmd_exec_whitelist or [])
    logger.info(f"init_server: db={cfg.db_path} bind={cfg.host}:{cfg.port} "
                f"log_level={cfg.log_level} whitelist={_cmd_whitelist}")


def _resolve_targets(raw_targets: list[str]) -> list[str]:
    """展开 @tag -> IPs;经过 @tag 的项会被替换为具体 IP。"""
    if _registry is None:
        return raw_targets
    return _registry.resolve(raw_targets)


def _failed(results: list[TargetResult]) -> list[dict]:
    return [{"target": r.target, "reason": r.error} for r in results if not r.ok]


def _wrap(r: TargetResult) -> dict:
    """B13: results 每项带 target 键。data 是 dict 则展开合并,非 dict 则放 result。"""
    if isinstance(r.data, dict):
        return {"target": r.target, **r.data}
    return {"target": r.target, "result": r.data}


def _run_batch(
    targets: list[str],
    port: int,
    fn: Callable,
    lock_class: LockClass = LockClass.NONE,
    lock_key_fn: Optional[Callable] = None,
    audit_tool: Optional[str] = None,
    audit_params: Optional[dict] = None,
    timeout: int = 30,
) -> dict:
    """带锁 + 审计的批量执行。fail-fast 锁冲突 -> 该 target failed。"""
    resolved = _resolve_targets(targets)
    sched = get_scheduler()
    results: list[TargetResult] = []
    t_batch = time.monotonic()
    logger.debug(f"_run_batch start: raw={targets} resolved={resolved} "
                 f"port={port} lock={lock_class.value if lock_class else 'none'} "
                 f"timeout={timeout}")

    def run_one(host_port: str) -> TargetResult:
        t0 = time.monotonic()
        lock_mgr = _lock_manager
        key = ()
        if lock_key_fn:
            key = lock_key_fn(host_port)
        ok = True
        # 1. 锁
        if lock_mgr is not None and lock_class != LockClass.NONE:
            try:
                lock_mgr.acquire(host_port, lock_class, key)
                logger.debug(f"[{host_port}] lock acquired: {lock_class.value} key={key} "
                             f"({(time.monotonic()-t0)*1000:.0f}ms)")
            except LockConflict as e:
                logger.debug(f"[{host_port}] lock CONFLICT: {e}")
                return TargetResult(target=host_port, ok=False, error=str(e))
        # 2. 池借出
        pool = sched.get_pool(host_port, port)
        t_pool = time.monotonic()
        try:
            client = pool.acquire(socket_timeout=int(timeout))
            logger.debug(f"[{host_port}] pool acquire ({(time.monotonic()-t_pool)*1000:.0f}ms) "
                         f"sock_timeout={timeout}s")
        except Exception as e:
            logger.debug(f"[{host_port}] pool acquire FAILED: {e!r}")
            ok = False
            if lock_mgr is not None and lock_class != LockClass.NONE:
                lock_mgr.release(host_port, lock_class, key)
            return TargetResult(target=host_port, ok=False, error=f"pool: {e}")
        # 3. 执行
        healthy = True
        try:
            t_fn = time.monotonic()
            data = fn(client)
            if data is None:
                data = {"note": "wait=false 无返回值"}   # B18
            elif data is False:
                ok = False                                # B23/B04
                return TargetResult(target=host_port, ok=False,
                                    error="agent 返回 False（业务失败）")
            logger.debug(f"[{host_port}] fn done ({(time.monotonic()-t_fn)*1000:.0f}ms) "
                         f"data_type={type(data).__name__}")
            return TargetResult(target=host_port, ok=True, data=data)
        except Exception as e:
            healthy = False
            ok = False
            logger.debug(f"[{host_port}] fn FAILED ({(time.monotonic()-t_fn)*1000:.0f}ms): {e!r}")
            return TargetResult(target=host_port, ok=False, error=str(e))
        finally:
            pool.release(client, healthy)
            # B04: CAPTURE 长锁仅在本次失败时立即释放;成功时保留给 stop 释放
            if lock_mgr is not None and lock_class != LockClass.NONE:
                if lock_class != LockClass.CAPTURE or not ok:
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

    logger.debug(f"_run_batch done: ok={sum(1 for r in results if r.ok)}/"
                 f"{len(results)} total={(time.monotonic()-t_batch)*1000:.0f}ms")

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
                duration_ms=int((time.monotonic() - t_batch) * 1000),
                source_ip="internal",
            )
        except Exception:
            pass

    return {"ok": sum(1 for r in results if r.ok),
            "failed": _failed(results),
            "results": [_wrap(r) for r in results if r.ok]}


# ==================== 只读工具 ====================

@mcp.tool(annotations={"readOnlyHint": True})
def list_targets(description: CallDescription = "") -> dict:
    """列出已注册的靶机。"""
    if _registry is None:
        return {"targets": [], "note": "注册表未初始化(需调 init_server)"}
    return {"targets": _registry.list_targets()}


@mcp.tool()
def add_target(host: str, port: int = 9000, tags: list[str] | None = None,
               note: str = "", description: CallDescription = "",
               force: bool = False) -> dict:
    """注册新靶机。tags 用于 @tag 选机。注册前 TCP 探活（不通拒绝，force=True 跳过）。"""
    import socket as _socket
    host_clean = host.strip("[]")   # IPv6 方括号剥除
    if not force:
        try:
            _socket.create_connection((host_clean, port), timeout=3).close()
        except OSError as e:
            return {"ok": False,
                    "error": f"{host}:{port} 不可达(TCP connect 失败: {e})，未注册；force=True 可强制注册"}
    if _registry is None:
        return {"ok": False, "error": "注册表未初始化"}
    return _registry.add_target(host_clean, port, tags, note)


@mcp.tool(annotations={"destructiveHint": True})
def remove_target(host: str, port: int = 9000,
                  description: CallDescription = "") -> dict:
    """移除靶机(有活跃锁或活跃监听时拒绝)。"""
    if _registry is None:
        return {"ok": False, "error": "注册表未初始化"}
    if _lock_manager is not None and _lock_manager.has_active(host):
        return {"ok": False, "error": f"靶机 {host} 有活跃锁，无法移除"}
    if _registry is not None and _registry.get_listen_liveness(host, port):
        return {"ok": False, "error": f"靶机 {host} 有活跃监听，请先 socket_listen action=stop"}
    return _registry.remove_target(host, port)


@mcp.tool(annotations={"readOnlyHint": True})
def isfile(targets: Targets, path: str, port: int = 9000,
           timeout: ToolTimeout = 15,
           description: CallDescription = "") -> dict:
    """检查靶机文件是否存在(datatype 7,只读)。
    文件传输用靶机 HTTP 服务(:9001,与 TCP 9000 不同端口):
    下载 curl -o out.pcap "http://<host>:9001/files?path=<远端路径>"
    上传 curl -F "path=<远端路径>" -F "file=@本地文件" http://<host>:9001/files
    host 即 targets 里注册的 IP(IPv6 加方括号);若 9001 拒绝连接,说明该靶机未升级到 1.7.0。"""
    resolved = _resolve_targets(targets)
    results = get_scheduler().batch(resolved, lambda c: c.isfile(path), port=port, timeout=timeout)
    return {"ok": sum(1 for r in results if r.ok),
            "failed": _failed(results),
            "results": [{"target": r.target, "exists": r.data} for r in results if r.ok]}


@mcp.tool(annotations={"readOnlyHint": True})
def isdir(targets: Targets, path: str, port: int = 9000,
          timeout: ToolTimeout = 15,
          description: CallDescription = "") -> dict:
    """检查目录是否存在(datatype 8,只读)。"""
    resolved = _resolve_targets(targets)
    results = get_scheduler().batch(resolved, lambda c: c.isdir(path), port=port, timeout=timeout)
    return {"ok": sum(1 for r in results if r.ok),
            "failed": _failed(results),
            "results": [{"target": r.target, "exists": r.data} for r in results if r.ok]}


@mcp.tool(annotations={"readOnlyHint": True})
def pcap_flow_extract(targets: Targets, pcap_dir: str, port: int = 9000,
                      timeout: ToolTimeout = 30,
                      description: CallDescription = "") -> dict:
    """提取 pcap 五元组流(datatype 200,只读)。pcap 可先经 HTTP 下载到本地分析:
    curl -o out.pcap "http://<host>:9001/files?path=<pcap 路径>"。
    路径不存在/非目录返回空数组；protoType: 1=TCP 2=UDP 4=ICMP。"""
    resolved = _resolve_targets(targets)
    results = get_scheduler().batch(resolved, lambda c: c.pcap_flow_extract(pcap_dir),
                                    port=port, timeout=timeout)
    out = []
    for r in results:
        if not r.ok:
            continue
        flows = r.data or []
        # S09: 超 1000 条截断,防 LLM 上下文爆掉
        out.append({"target": r.target, "flows": flows[:1000],
                    "total": len(flows), "truncated": len(flows) > 1000})
    return {"ok": sum(1 for r in results if r.ok),
            "failed": _failed(results),
            "results": out}


# ==================== 写工具 ====================

@mcp.tool(annotations={"destructiveHint": True})
def cmd_exec(targets: Targets, args: str, cwd: str = "", env: dict | None = None,
             wait: bool = True, port: int = 9000,
             timeout: ToolTimeout = 60,
             description: CallDescription = "") -> dict:
    """执行命令(datatype 1,SHELL/DANGER,白名单校验后转发)。
    白名单为空=不限制（默认）；wait=false 无返回值（返回 note）。"""
    logger.info(f"cmd_exec CALLED: targets={targets} port={port} wait={wait} "
                f"args={args[:120]!r}")
    # 白名单校验
    if _cmd_whitelist:
        if not any(args.strip().startswith(w) for w in _cmd_whitelist):
            logger.info(f"cmd_exec REJECTED by whitelist (allowed={_cmd_whitelist})")
            return {"ok": 0, "failed": [{"target": t, "reason": f"命令不在白名单: {args}"}
                                        for t in targets],
                    "results": []}
        logger.debug(f"cmd_exec whitelist OK (matched prefix)")
    resolved = _resolve_targets(targets)

    def run_one(client):
        return client.cmd_exec(args, cwd=cwd or None, env=env, wait=wait)

    return _run_batch(resolved, port, run_one,
                      lock_class=LockClass.SHELL,
                      audit_tool="cmd_exec",
                      audit_params={"args": args, "cwd": cwd, "wait": wait},
                      timeout=timeout if wait else min(timeout, 15))


@mcp.tool()
def capture_start(targets: Targets, iface: str = "", path: str = "/home/tmp/tmp.pcap",
                  extended: str = "", single_queue: bool = True, port: int = 9000,
                  timeout: ToolTimeout = 30,
                  description: CallDescription = "") -> dict:
    """AF_PACKET 嗅探抓包（datatype 5，CAPTURE 持锁；独立子进程，ps 中无 tcpdump 子进程属正常）。
    iface 空则取 routeinfo 默认网卡；默认 path 全局共用，多任务请显式传不同 path。"""
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
                      timeout=timeout)


@mcp.tool(annotations={"destructiveHint": True})
def capture_stop(targets: Targets, path: str = "/home/tmp/tmp.pcap",
                 port: int = 9000,
                 timeout: ToolTimeout = 30,
                 description: CallDescription = "") -> dict:
    """停止抓包(datatype 6)。返回四态：stopped/exitcode/pcap_complete；
    pcap_complete=false 表示 pcap 可能不完整（该 target 记为 failed）；
    未在抓的路径返回 stopped=false + note（幂等，非错误）。释放 capture_start 持有的 CAPTURE(path) 锁。"""
    t0 = time.monotonic()
    resolved = _resolve_targets(targets)
    sched = get_scheduler()
    results: list[TargetResult] = []

    def run_one(host_port: str) -> TargetResult:
        pool = sched.get_pool(host_port, port)
        client = pool.acquire(socket_timeout=int(timeout))
        healthy = True
        try:
            d = client.capture_stop(path)
            # 四态判定（spec §2.1）：
            #   stopped:True + pcap_complete:False -> failed（pcap 可能不完整）
            #   stopped:False + error -> failed（可重试）
            #   stopped:False + note -> 非失败（幂等明示）
            if d.get("stopped") and d.get("pcap_complete") is False:
                return TargetResult(target=host_port, ok=False,
                                    error=f"pcap 可能不完整/未排序(exitcode={d.get('exitcode')})")
            if d.get("stopped") is False and d.get("error"):
                return TargetResult(target=host_port, ok=False, error=d["error"])
            return TargetResult(target=host_port, ok=True, data=d)
        except Exception as e:
            healthy = False
            return TargetResult(target=host_port, ok=False, error=str(e))
        finally:
            pool.release(client, healthy)
            # 释放 start 持有的 CAPTURE 锁(无论 stop 成败)——stop 就是释放者
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
                                [{"target": r.target, "ok": r.ok,
                                  "error": getattr(r, "error", None)} for r in results],
                                ok_count=sum(1 for r in results if r.ok),
                                failed_count=sum(1 for r in results if not r.ok),
                                duration_ms=int((time.monotonic() - t0) * 1000),
                                source_ip="internal")
        except Exception:
            pass

    return {"ok": sum(1 for r in results if r.ok),
            "failed": _failed(results),
            "results": [_wrap(r) for r in results if r.ok]}


@mcp.tool()
def boce_run(targets: Targets, url: str, count: int = 1, interval: int = 0,
             thread_count: int = 1, http_timeout: int = 3, mode: str = "封堵",
             chromium_path: str = "", port: int = 9000,
             timeout: ToolTimeout = 60,
             description: CallDescription = "") -> dict:
    """拨测(datatype 131,BROWSER)。
    mode 仅"封堵/重定向"有判定实现；"弹窗"未实现（恒失败）；其他值按未知模式恒失败。"""
    resolved = _resolve_targets(targets)

    def run_one(client):
        return client.boce_run(url, count=count, interval=interval,
                               thread_count=thread_count, timeout=http_timeout,
                               mode=mode,
                               chromium_path=chromium_path or None)

    return _run_batch(resolved, port, run_one,
                      lock_class=LockClass.BROWSER,
                      audit_tool="boce_run",
                      audit_params={"url": url, "count": count, "mode": mode},
                      timeout=timeout)


@mcp.tool()
def replay_run(targets: Targets, pcaps: list[str], uplink_iface: str,
               downlink_iface: str, uplink_vlan: int | None = None,
               downlink_vlan: int | None = None, mbps: int = 0,
               force_ip_src: str | None = None, force_ip_dst: str | None = None,
               force_sport: int = 0, force_dport: int = 0,
               port: int = 9000,
               timeout: ToolTimeout = 120,
               description: CallDescription = "") -> dict:
    """在靶机回放 pcap 流量文件(scapy 双接口收发,支持限速/改五元组)。需先用 HTTP 上传把 pcap 传到靶机: curl -F "path=/home/tmp/x.pcap" -F "file=@x.pcap" http://<host>:9001/files。回放与抓包/拨测同靶机互斥;回放+抓包请分属两台靶机(跨机拓扑)。
    单臂回放（uplink_iface == downlink_iface 且无 VLAN 差异）时所有包计为 uplink，downlink/flow_count 恒 0 属正常，需方向统计用双接口。
    返回 {total_files,total_packets,total_bytes,uplink_packets,uplink_bytes,downlink_packets,downlink_bytes,flow_count,duration_seconds,target_mbps,actual_mbps}"""
    logger.info(f"replay_run CALLED: targets={targets} pcaps={pcaps} "
                f"uplink={uplink_iface} downlink={downlink_iface} mbps={mbps}")
    resolved = _resolve_targets(targets)

    def run_one(client):
        return client.replay_run(pcaps, uplink_iface, downlink_iface,
                                 uplink_vlan=uplink_vlan,
                                 downlink_vlan=downlink_vlan, mbps=mbps,
                                 force_ip_src=force_ip_src,
                                 force_ip_dst=force_ip_dst,
                                 force_sport=force_sport,
                                 force_dport=force_dport)

    return _run_batch(resolved, port, run_one,
                      lock_class=LockClass.REPLAY,
                      audit_tool="replay_run",
                      audit_params={"pcaps": pcaps, "uplink_iface": uplink_iface,
                                    "downlink_iface": downlink_iface, "mbps": mbps},
                      timeout=timeout)


@mcp.tool()
def socket_listen(targets: Targets, action: str, listen_port: int = 30001,
                  file: str = "", max_bytes: int = 1048576, port: int = 9000,
                  timeout: ToolTimeout = 30,
                  description: CallDescription = "") -> dict:
    """在靶机启动 TCP 端口监听接收流量(TCP 监听不接收无握手的裸回放流,回放对比需回放侧重建会话或用 UDP)。
    action: start=启动返回pid / stop=停止当前监听 / clean=清空已收数据 / save=已收数据保存到靶机文件 / fetch=取回已收数据(超过 max_bytes 落盘靶机并截断返回)。
    注意: 已在监听时再 start 为幂等操作,返回现有 pid;更换 listen_port 先 stop 再 start;fetch/save 须在 stop 之前。同一监听实例须按 start→...→save/fetch 顺序调用"""
    logger.info(f"socket_listen CALLED: targets={targets} action={action} "
                f"listen_port={listen_port} file={file}")
    if action == "save" and not file:
        return {"ok": 0,
                "failed": [{"target": t, "reason": "save 动作需要 file 参数"}
                           for t in targets],
                "results": []}
    if action not in ("start", "stop", "clean", "save", "fetch"):
        return {"ok": 0,
                "failed": [{"target": t, "reason": f"未知 action: {action}"}
                           for t in targets],
                "results": []}
    resolved = _resolve_targets(targets)

    def run_one(client):
        if action == "start":
            result = client.socket_listen("start", listen_port=listen_port)
            # B16: 1.7.1+ 靶机登记 liveness(旧靶机无法 stop,登记会造成永久不可删)
            try:
                v = client.version()
                parts = [int(x) for x in v.split(".")]
                if tuple(parts[:3]) >= (1, 7, 1) and _registry is not None:
                    _registry.set_listen_liveness(client.host, True, port)
            except Exception:
                logger.warning(f"liveness 登记失败(不影响 start): {client.host}")
            return result
        if action == "stop":
            r = client.socket_listen("stop")
            if _registry is not None:
                _registry.set_listen_liveness(client.host, False, port)
            return r
        if action == "clean":
            return client.socket_listen("clean")
        if action == "save":
            return client.socket_listen("save", file=file)
        # fetch: 174 取全量 -> 超 max_bytes 截断 + 复用 173 落盘
        import base64 as _b64
        import time as _time
        data = client.socket_listen("fetch", max_bytes=max_bytes)
        size = len(data)
        result = {"size": size}
        if size <= max_bytes:
            result.update({"data_b64": _b64.b64encode(data).decode(),
                           "truncated": False})
            return result
        ts = _time.strftime("%Y%m%d_%H%M%S")
        file_path = f"/home/tmp/listen_{ts}.log"
        client.socket_listen("save", file=file_path)  # 173 在靶机侧写全量数据
        result.update({"data_b64": _b64.b64encode(data[:max_bytes]).decode(),
                       "truncated": True, "file_path": file_path})
        return result

    return _run_batch(resolved, port, run_one,
                      lock_class=LockClass.SYSTEM,
                      audit_tool="socket_listen",
                      audit_params={"action": action, "listen_port": listen_port,
                                    "file": file, "max_bytes": max_bytes},
                      timeout=timeout)

def main() -> None:
    """stdio 模式(本地)。远程用 __main__.main -> transport.run(Streamable HTTP)。"""
    mcp.run()


if __name__ == "__main__":
    main()
