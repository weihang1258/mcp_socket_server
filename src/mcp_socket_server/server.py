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
from .socket_client import SocketServerClient
from .upgrades import (ensure_release_binary, fetch_latest_version,
                       push_binary, start_daily_check,
                       version_ok as _upgrade_version_ok)

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

# ---- S01: 各业务参数字段级说明(Annotated 复用类型) ----
HostParam = Annotated[str, Field(description="靶机 IP 或主机名(IPv6 裸地址,自动剥方括号)")]
PortParam = Annotated[int, Field(description="靶机 socket_server TCP 端口(默认 9000)")]
PathParam = Annotated[str, Field(description="靶机上的绝对路径")]
IfaceParam = Annotated[str, Field(description="网卡名,如 eth0;留空自动取默认路由网卡")]
PcapDirParam = Annotated[str, Field(description="靶机上的 pcap 目录绝对路径")]
CmdArgs = Annotated[str, Field(description="要执行的命令及参数(白名单非空时须命中前缀)")]
CwdParam = Annotated[str, Field(description="命令工作目录(留空=默认)")]
EnvParam = Annotated[dict | None, Field(description="命令环境变量键值对(可选)")]
WaitParam = Annotated[bool, Field(description="true=等命令结束返回结果;false=立即返回无结果")]
TagsParam = Annotated[list[str] | None, Field(description="标签列表,用于 @tag 选机")]
NoteParam = Annotated[str, Field(description="备注(如机器用途)")]
ForceParam = Annotated[bool, Field(description="true=跳过探活强制注册离线靶机")]
ModeParam = Annotated[str, Field(description="拨测模式: 封堵/重定向 有效;弹窗未实现(恒失败);其他值按未知模式恒失败")]
UrlParam = Annotated[str, Field(description="拨测目标 URL")]
ChromiumParam = Annotated[str, Field(description="chromium 可执行文件路径(留空=默认 /opt/socket/chrome-linux/chrome)")]
PcapsParam = Annotated[list[str], Field(description="靶机上 pcap 文件的绝对路径列表(需先用 HTTP 上传)")]
UplinkIface = Annotated[str, Field(description="上行物理网卡名,如 eth0")]
DownlinkIface = Annotated[str, Field(description="下行物理网卡名,单臂回放可与上行相同")]
VlanParam = Annotated[int | None, Field(description="VLAN ID(可选,不给则不打 VLAN 标)")]
ForceIpParam = Annotated[str | None, Field(description="强制替换 IP(可选,如 172.31.138.158)")]
ListenPortParam = Annotated[int, Field(description="仅 start 用:监听端口(默认 30001)")]
ListenFileParam = Annotated[str, Field(description="仅 save 用:数据保存到靶机的绝对路径")]
MaxBytesParam = Annotated[int, Field(description="仅 fetch 用:返回内容上限(解压后明文字节),超限截断并落盘靶机")]
ActionParam = Annotated[str, Field(description="start=启动返回pid / clean=清空已收数据 / save=已收数据保存到靶机文件 / fetch=取回已收数据 / stop=停止当前监听")]
ExtendedParam = Annotated[str, Field(description="tcpdump 扩展过滤表达式(传给抓包进程,留空=不过滤)")]
SingleQueueParam = Annotated[bool, Field(description="true=单队列收包(收包序=线序,默认)")]
CountParam = Annotated[int, Field(description="拨测次数(默认 1)")]
IntervalParam = Annotated[int, Field(description="拨测间隔秒(默认 0)")]
ThreadCountParam = Annotated[int, Field(description="拨测并发线程数(默认 1)")]
MbpsParam = Annotated[int, Field(description="回放限速 Mbps,0=不限速(默认)")]
ForceSportParam = Annotated[int, Field(description="强制替换源端口(0=不改写,默认)")]
ForceDportParam = Annotated[int, Field(description="强制替换目的端口(0=不改写,默认)")]


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
# N5: FastMCP 1.28 不透传 version 到 initialize 的 serverInfo(回落 mcp SDK 版本),
# 构造后直设底层 Server.version,让客户端可辨识桥版本
mcp._mcp_server.version = "0.3.2"

_lock_manager: Optional[LockManager] = None
_registry: Any = None
_audit_logger: Any = None
_cmd_whitelist: list[str] = []
# 升级编排(upgrade_run)所需配置,init_server 落地
_cfg_download_dir = "./downloads"
_cfg_proxy: Optional[str] = None


def init_server(cfg) -> None:
    """初始化 registry/locks/audit + 日志级别。config.yaml 的 db_path 用于所有 SQLite。"""
    global _lock_manager, _registry, _audit_logger, _cmd_whitelist
    global _cfg_download_dir, _cfg_proxy
    _setup_logging(cfg.log_level)
    _lock_manager = get_lock_manager()
    _registry = get_registry(cfg.db_path)
    _audit_logger = get_audit(cfg.db_path, cfg.audit_retention_days)
    _cmd_whitelist = list(cfg.cmd_exec_whitelist or [])
    _cfg_download_dir = cfg.download_dir
    _cfg_proxy = (cfg.proxy or "").strip() or None
    start_daily_check(_cfg_proxy, lambda: mcp._mcp_server.version)
    logger.info(f"init_server: db={cfg.db_path} bind={cfg.host}:{cfg.port} "
                f"log_level={cfg.log_level} whitelist={_cmd_whitelist} "
                f"download_dir={_cfg_download_dir} proxy={_cfg_proxy or '(直连)'}")


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
            if isinstance(data, dict) and "_error" in data:
                # 通用失败通道: fn 返回 {"_error": 原因} -> 该 target failed 且 reason 有值
                ok = False
                return TargetResult(target=host_port, ok=False,
                                    error=str(data["_error"]))
            if data is None:
                data = {"note": "wait=false 为异步执行不返回回显;需要 stdout 请 wait=true"}   # B18
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


@mcp.tool(annotations={"destructiveHint": False, "openWorldHint": True})
def add_target(host: HostParam, port: PortParam = 9000, tags: TagsParam = None,
               note: NoteParam = "", description: CallDescription = "",
               force: ForceParam = False) -> dict:
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


@mcp.tool(annotations={"destructiveHint": True, "idempotentHint": True})
def remove_target(host: HostParam, port: PortParam = 9000,
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
def version(targets: Targets, port: PortParam = 9000,
            timeout: ToolTimeout = 15,
            description: CallDescription = "") -> dict:
    """查询靶机 socket_server 版本号(datatype 14,只读)。
    升级前先调本工具确认各靶机现版本，再决定调 upgrade_run 升到哪个版本。"""
    resolved = _resolve_targets(targets)
    results = get_scheduler().batch(resolved, lambda c: c.version(), port=port, timeout=timeout)
    return {"ok": sum(1 for r in results if r.ok),
            "failed": _failed(results),
            "results": [{"target": r.target, "version": r.data} for r in results if r.ok]}


@mcp.tool(annotations={"readOnlyHint": True})
def file_transfer(targets: Targets, http_port: PortParam = 9001,
                  description: CallDescription = "") -> dict:
    """获取客户端与靶机之间点对点传文件的命令(零网络调用,纯指引)。
    客户端本地文件无法经本 MCP 中转到靶机(MCP 运行在远端中央服务器,拿不到客户端
    本地文件),必须客户端直连靶机 :9001 HTTP 文件服务,上传下载均用 curl:
    下载 curl -o 本地文件 "http://<靶机IP>:9001/files?path=<远端绝对路径>"
    上传 curl -F "path=<远端绝对路径>" -F "file=@本地文件" http://<靶机IP>:9001/files
    大小不限(1.8.2 起靶机流式收发,GB 级不 OOM;1.8.1 及更早整载内存,仅建议 MB 级)。
    警示:把脚本/大段内容放到靶机务必走上传,勿经 ssh 命令行内嵌长内容
    (Windows ssh.exe >8K 会被随机截断损坏);上传后需执行权限接 cmd_exec chmod +x。
    9001 拒绝连接=靶机 http_port=0(配置关闭)或版本 <1.7.0,先 upgrade_run 升级。"""
    resolved = _resolve_targets(targets)
    cmds = []
    for t in resolved:
        host, sep, p = t.rpartition(":")
        h6 = f"[{host}]" if ":" in host else host  # IPv6 裸地址加方括号
        cmds.append({
            "target": t,
            "download": f'curl -o 本地文件 "http://{h6}:{http_port}/files?path=<远端绝对路径>"',
            "upload": f'curl -F "path=<远端绝对路径>" -F "file=@本地文件" http://{h6}:{http_port}/files',
        })
    if not cmds:
        return {"ok": 0, "note": "无已注册靶机,先 add_target 注册再用",
                "usage": ["下载: curl -o 本地文件 \"http://<靶机IP>:9001/files?path=<远端绝对路径>\"",
                          "上传: curl -F \"path=<远端绝对路径>\" -F \"file=@本地文件\" http://<靶机IP>:9001/files"]}
    return {"ok": len(cmds), "commands": cmds}


@mcp.tool(annotations={"readOnlyHint": True})
def isfile(targets: Targets, path: PathParam, port: PortParam = 9000,
           timeout: ToolTimeout = 15,
           description: CallDescription = "") -> dict:
    """检查靶机文件是否存在(datatype 7,只读)。
    文件内容的上传下载用 file_transfer 工具(返回点对点直传命令)。"""
    resolved = _resolve_targets(targets)
    results = get_scheduler().batch(resolved, lambda c: c.isfile(path), port=port, timeout=timeout)
    return {"ok": sum(1 for r in results if r.ok),
            "failed": _failed(results),
            "results": [{"target": r.target, "exists": r.data} for r in results if r.ok]}


@mcp.tool(annotations={"readOnlyHint": True})
def isdir(targets: Targets, path: PathParam, port: PortParam = 9000,
          timeout: ToolTimeout = 15,
          description: CallDescription = "") -> dict:
    """检查目录是否存在(datatype 8,只读)。"""
    resolved = _resolve_targets(targets)
    results = get_scheduler().batch(resolved, lambda c: c.isdir(path), port=port, timeout=timeout)
    return {"ok": sum(1 for r in results if r.ok),
            "failed": _failed(results),
            "results": [{"target": r.target, "exists": r.data} for r in results if r.ok]}


@mcp.tool(annotations={"readOnlyHint": True})
def pcap_flow_extract(targets: Targets, pcap_dir: PcapDirParam, port: PortParam = 9000,
                      timeout: ToolTimeout = 30,
                      description: CallDescription = "") -> dict:
    """提取 pcap 五元组流(datatype 200,只读)。pcap 可先经 file_transfer 工具
    给出的命令下载到本地分析(靶机 :9001 点对点直传)。
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
def cmd_exec(targets: Targets, args: CmdArgs, cwd: CwdParam = "", env: EnvParam = None,
             wait: WaitParam = True, port: PortParam = 9000,
             timeout: ToolTimeout = 60,
             description: CallDescription = "") -> dict:
    """执行命令(datatype 1,SHELL/DANGER,白名单校验后转发)。
    返回 {code,stdout,stderr};wait=false 为异步执行不返回回显(需要回显必须 wait=true);
    stdout 超 64KB 截断(带 stdout_truncated 标记)。
    把脚本/大段内容放到靶机勿经命令内嵌(ssh.exe >8K 会截断),调 file_transfer 获取上传命令。
    白名单为空=不限制（默认）。"""
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


@mcp.tool(annotations={"destructiveHint": False, "openWorldHint": True})
def capture_start(targets: Targets, iface: IfaceParam = "", path: PathParam = "/home/tmp/tmp.pcap",
                  extended: ExtendedParam = "", single_queue: SingleQueueParam = True, port: PortParam = 9000,
                  timeout: ToolTimeout = 30,
                  description: CallDescription = "") -> dict:
    """AF_PACKET 嗅探抓包（datatype 5，CAPTURE 持锁；独立子进程，ps 中无 tcpdump 子进程属正常）。
    iface 空则取 routeinfo 默认网卡；默认 path 全局共用，多任务请显式传不同 path。"""
    resolved = _resolve_targets(targets)

    def run_one(client):
        d = client.capture_start(eth=iface or None, path=path,
                                 extended=extended, single_queue=single_queue)
        # 1.7.2+: 失败带原因(dict 含 error)-> {"_error": 原因} 触发 _run_batch failed(带 target);
        # 旧靶机 res:False 无 error -> 返回 False 走 B23 泛化文案
        if not d.get("res"):
            if d.get("error"):
                return {"_error": d["error"]}
            return False
        return d

    return _run_batch(resolved, port, run_one,
                      lock_class=LockClass.CAPTURE,
                      lock_key_fn=lambda h: (path,),
                      audit_tool="capture_start",
                      audit_params={"iface": iface, "path": path,
                                    "extended": extended, "single_queue": single_queue},
                      timeout=timeout)


@mcp.tool(annotations={"destructiveHint": True, "idempotentHint": True})
def capture_stop(targets: Targets, path: PathParam = "/home/tmp/tmp.pcap",
                 port: PortParam = 9000,
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
            # B03 呈现: failed 时 data 仍带结构化字段,results 保留完整视图(不只 reason 文本)
            if d.get("stopped") and d.get("pcap_complete") is False:
                d["warning"] = "pcap 可能不完整/未排序"
                return TargetResult(target=host_port, ok=False,
                                    error=f"pcap 可能不完整/未排序(exitcode={d.get('exitcode')})",
                                    data=d)
            if d.get("stopped") is False and d.get("error"):
                return TargetResult(target=host_port, ok=False, error=d["error"], data=d)
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
            "results": [_wrap(r) for r in results if r.ok],
            # B03 呈现: failed 项也保留结构化数据(如有),调用方可程序化读取
            # stopped/exitcode/pcap_complete,而非仅 reason 文本
            **({"failed_details": [{"target": r.target, **r.data}
                                   for r in results if not r.ok and isinstance(r.data, dict)]}
               if any(not r.ok and isinstance(r.data, dict) for r in results) else {})}


@mcp.tool(annotations={"destructiveHint": False, "openWorldHint": True})
def boce_run(targets: Targets, url: UrlParam, count: CountParam = 1, interval: IntervalParam = 0,
             thread_count: ThreadCountParam = 1, mode: ModeParam = "封堵",
             chromium_path: ChromiumParam = "", port: PortParam = 9000,
             timeout: Annotated[int, Field(ge=10, description="单靶机操作超时秒数(connect+执行+返回),多靶机并行各自计时;至少 10 秒(拨测内部 HTTP/goto 预算自动扣 10s 余量)")] = 60,
             description: CallDescription = "") -> dict:
    """拨测(datatype 131,BROWSER)。
    mode 仅"封堵/重定向"有判定实现；"弹窗"未实现（恒失败，且失败路径实测 20–31s
    波动（含 browser 冷启动抖动）才返回——timeout 建议 ≥ 40（外层=timeout+10 ≥ 50s
    才能稳定覆盖），否则外层先超时返回 timed out 而非结构化原因）；其他值按未知模式
    恒失败。
    timeout 一个参数表示两层超时：既约束单靶机整体操作(connect+执行+返回)，拨测内部
    的 HTTP/goto 预算也取该值扣 10s 余量。下限 10 秒：低于 10 秒的调用会被参数校验拒绝
    （报 Input should be greater than or equal to 10），而非放行后必然超时。"""
    resolved = _resolve_targets(targets)
    # N2: socket 层超时= timeout+10(给 browser 冷启动 5-8s/判定收尾留余量,
    # 防内层失败被外层 timed out 掩盖——0.2.4 曾出现 timeout=10 弹窗 10.1s 超时)。
    # 内层预算(拨测 HTTP/goto)= timeout-10(至少 3s)在 run_one 内计算。
    socket_timeout = timeout + 10

    def run_one(client):
        # 评审链9: 内层预算(拨测 HTTP/goto)只约束 goto 一段;
        # 详见上方 socket_timeout 注释。
        inner = max(3, timeout - 10)
        return client.boce_run(url, count=count, interval=interval,
                               thread_count=thread_count, timeout=inner,
                               mode=mode,
                               chromium_path=chromium_path or None)

    return _run_batch(resolved, port, run_one,
                      lock_class=LockClass.BROWSER,
                      audit_tool="boce_run",
                      audit_params={"url": url, "count": count, "mode": mode},
                      timeout=socket_timeout)


@mcp.tool(annotations={"destructiveHint": True, "openWorldHint": True})
def replay_run(targets: Targets, pcaps: PcapsParam, uplink_iface: UplinkIface,
               downlink_iface: DownlinkIface, uplink_vlan: VlanParam = None,
               downlink_vlan: VlanParam = None, mbps: MbpsParam = 0,
               force_ip_src: ForceIpParam = None, force_ip_dst: ForceIpParam = None,
               force_sport: ForceSportParam = 0, force_dport: ForceDportParam = 0,
               port: PortParam = 9000,
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


@mcp.tool(annotations={"destructiveHint": False, "openWorldHint": True})
def socket_listen(targets: Targets, action: ActionParam, listen_port: ListenPortParam = 30001,
                  file: ListenFileParam = "", max_bytes: MaxBytesParam = 1048576, port: PortParam = 9000,
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

UpgradeVersionParam = Annotated[str, Field(
    description="目标版本号如 1.8.0;留空=自动查 GitHub 最新版(失败可显式指定重试)")]
UpgradeForceParam = Annotated[bool, Field(
    description="true=靶机有其它客户端连接时强制升级(会带着连接重启);默认 false=拒绝")]


@mcp.tool(annotations={"destructiveHint": True})
def upgrade_run(targets: Targets, version: UpgradeVersionParam = "",
                force: UpgradeForceParam = False, port: PortParam = 9000,
                timeout: ToolTimeout = 60,
                description: CallDescription = "") -> dict:
    """升级靶机 socket_server（需靶机 1.8.0+，旧靶机请先用 install.sh 安装）。
    流程:确定版本(指定则零查询/留空查最新)→中央下载→经 :9001 推包→dt20 校验落盘→后台重启→轮询 dt14 确认。
    升级期间靶机服务重启约 5-15 秒不可用;非 force 且靶机有其它客户端连接时靶机拒绝。"""
    t0 = time.monotonic()
    resolved = _resolve_targets(targets)
    if not resolved:
        return {"ok": 0, "version": version,
                "failed": [{"target": t, "reason": "无有效靶机"} for t in targets],
                "results": []}
    # 1) 确定目标版本：指定则零查询（不阻塞），留空才查一次最新
    ver = version.strip().lstrip("v")
    if ver:
        if not _upgrade_version_ok(ver):
            return {"ok": 0, "version": ver,
                    "failed": [{"target": "*", "reason": f"版本号非法: {ver!r}"}],
                    "results": []}
    else:
        ver = fetch_latest_version(_cfg_proxy)
        if not ver:
            return {"ok": 0, "version": "",
                    "failed": [{"target": "*",
                                "reason": "查询最新版失败（GitHub 不可达），可显式指定 version 重试"}],
                    "results": []}
    # 2) 中央下载一次，多靶机共用（已存在则复用，幂等）
    binary, sha = ensure_release_binary(ver, _cfg_download_dir, _cfg_proxy)
    if not binary:
        return {"ok": 0, "version": ver,
                "failed": [{"target": "*", "reason": sha}], "results": []}
    logger.info(f"upgrade_run: v{ver} sha={sha[:16]}... binary={binary} targets={resolved}")

    def run_one(client):
        # 预检：dt20 仅 1.8.0+ 靶机支持
        cur = client.version()
        try:
            parts = tuple(int(x) for x in str(cur).split(".")[:3])
        except ValueError:
            return {"_error": f"靶机版本号异常: {cur!r}"}
        if parts < (1, 8, 0):
            return {"_error": f"靶机 v{cur} 过旧，请先用 install.sh 安装 1.8.0+"}
        ok, err = push_binary(client.host, binary, ver)
        if not ok:
            return {"_error": err}
        resp = client.upgrade_apply(ver, sha, force)
        if resp.get("error"):
            return {"_error": resp["error"]}
        if not resp.get("ok"):
            return {"_error": f"无法解析的 dt20 响应: {resp!r}"}
        # 服务即将重启：close 后归还，池下次 acquire 自动重连，不复用垂死连接
        client.close()
        return {"pushed": True, "from_version": str(cur)}

    batch = _run_batch(resolved, port, run_one, lock_class=LockClass.SYSTEM,
                       audit_params={"version": ver, "force": force},
                       timeout=timeout)
    # 3) 轮询 dt14 确认新版本已生效。窗口 180s：靶机未设 SO_REUSEADDR，停服后
    #    :9000 要等旧连接 TIME_WAIT 自然释放（实测可超 90s），systemd 每 5s 重试绑定
    pushed = [r for r in batch.get("results", []) if r.get("pushed")]
    confirmed: set[str] = set()
    if pushed:
        deadline = time.time() + 180
        pending = []
        for r in pushed:
            # resolve 约定:target 是纯 host(端口由工具 port 参数控制);
            # "host:9100" 形态仅当冒号后全数字才按端口拆(同 registry.resolve)
            host, sep, p = r["target"].rpartition(":")
            pending.append((r["target"], host if sep and p.isdigit() else r["target"],
                            int(p) if sep and p.isdigit() else port))
        while pending and time.time() < deadline:
            time.sleep(3)
            for item in list(pending):
                t, host, p = item
                try:
                    c = SocketServerClient(host, p, timeout=5)
                    c.connect()
                    v = c.version()
                    c.close()
                except Exception:
                    continue  # 重启中，下轮再试
                if v == ver:
                    confirmed.add(t)
                    pending.remove(item)
    # 4) 汇总（终态审计：含轮询确认结果，而非仅推送受理结果）
    results, failed = [], list(batch["failed"])
    for r in pushed:
        if r["target"] in confirmed:
            results.append({"target": r["target"], "upgraded": True,
                            "version": ver, "from_version": r.get("from_version")})
        else:
            failed.append({"target": r["target"],
                           "reason": "推送已受理但 180 秒内未确认到新版本"
                                     "（端口未释放/重启异常），请查靶机日志 /var/log/socket_server.log"})
    if _audit_logger is not None:
        try:
            outcomes = [{"target": r["target"], "ok": True} for r in results] + \
                       [{"target": f["target"], "ok": False} for f in failed if f["target"] != "*"]
            _audit_logger.write("upgrade_run", {"version": ver, "force": force},
                                outcomes, ok_count=len(results),
                                failed_count=len(outcomes) - len(results),
                                duration_ms=int((time.monotonic() - t0) * 1000),
                                source_ip="internal")
        except Exception:
            pass
    return {"ok": len(results), "version": ver, "failed": failed, "results": results,
            "duration_ms": int((time.monotonic() - t0) * 1000)}


def main() -> None:
    """stdio 模式(本地)。远程用 __main__.main -> transport.run(Streamable HTTP)。"""
    mcp.run()


if __name__ == "__main__":
    main()
