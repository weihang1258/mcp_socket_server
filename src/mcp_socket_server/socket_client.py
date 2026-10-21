"""socket_server TCP 客户端(重建版)。

⚠️ 权威协议来源(socket_server 仓库):
  - 帧格式 + send_request/recv_*:socket_server/test_e2e.py
  - datatype 处理 + 参数:socket_server/socket_server/handlers.py do()
  - 连接循环 + 文件传输:socket_server/socket_server/protocol.py handle()

本模块 recv 按 test_e2e.py recv_* 逐 datatype 解析;持久连接(服务端 handle() 循环)。
socket_server 协议变更时同步更新本模块。经验证 workflow 对照权威源核验(2026-07-08)。
"""
from __future__ import annotations

import gzip
import json
import logging
import os
import socket
import struct
from typing import Optional

logger = logging.getLogger(__name__)
# 单靶机 socket 操作默认超时秒数。优先级:环境变量 MCP_DEFAULT_TIMEOUT > 30。
# config.yaml 的 default_timeout 供部署参考(两处需一致),本批以 env 落地。
DEFAULT_TIMEOUT = int(os.environ.get("MCP_DEFAULT_TIMEOUT", "30"))


def compress_gzip(b: bytes) -> bytes:
    return gzip.compress(b)


def decompress_gzip(b: bytes) -> bytes:
    return gzip.decompress(b)


class SocketServerClient:
    """单靶机 socket_server 客户端。一连接多轮往返(持久);由 pool 管理生命周期。"""

    def __init__(self, host: str, port: int = 9000, timeout: int = DEFAULT_TIMEOUT):
        self.host = host
        self.port = port
        self.timeout = timeout
        self._sock: Optional[socket.socket] = None

    def connect(self) -> None:
        if self._sock is not None:
            return
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(self.timeout)
        logger.debug(f"connect start: {self.host}:{self.port} timeout={self.timeout}s")
        try:
            s.connect((self.host, self.port))
        except Exception as e:
            logger.debug(f"connect FAILED: {self.host}:{self.port} -> {e!r}")
            raise
        self._sock = s
        logger.debug(f"connect OK: {self.host}:{self.port} (fileno={s.fileno()})")

    def close(self) -> None:
        if self._sock is not None:
            try:
                self._sock.close()
            except OSError:
                pass
            self._sock = None

    # ===== 发送 =====
    def _send(self, datatype: int, payload: bytes = b"") -> None:
        """发送 [4B len i][4B datatype i][payload]"""
        assert self._sock is not None
        # 重置 timeout:防止上一次 _recv_until_timeout 留下的 0.5s 短 timeout 泄漏到 send
        self._sock.settimeout(self.timeout)
        body = struct.pack("i", datatype) + payload
        msg = struct.pack("i", len(body)) + body
        logger.debug(f"_send dt={datatype} payload={len(payload)}B total={len(msg)}B -> {self.host}:{self.port}")
        self._sock.sendall(msg)

    def _send_raw(self, msg: bytes) -> None:
        """发送裸帧 [4B len][content](用于文件上传 step 23,无 datatype 字段)"""
        assert self._sock is not None
        self._sock.settimeout(self.timeout)
        self._sock.sendall(struct.pack("i", len(msg)) + msg)

    # ===== 接收基础 =====
    def _recv_n(self, n: int) -> bytes:
        """精确读 n 字节"""
        assert self._sock is not None
        # 重置 timeout:防止上一次 _recv_until_timeout 留下的 0.5s 短 timeout 泄漏到长度前缀读取
        self._sock.settimeout(self.timeout)
        buf = b""
        while len(buf) < n:
            chunk = self._sock.recv(min(65536, n - len(buf)))
            if not chunk:
                raise ConnectionError("连接在读取完成前关闭")
            buf += chunk
        return buf

    def _recv_until_timeout(self, timeout: float = 0.5) -> bytes:
        """timeout 读可用字节(用于原始 JSON / inline ack,无长度前缀)。读到首个 chunk 后
        再短 timeout 探一次,无更多即返回。"""
        assert self._sock is not None
        self._sock.settimeout(self.timeout)
        data = b""
        try:
            chunk = self._sock.recv(65536)
            if not chunk:
                return data
            data += chunk
        except socket.timeout:
            return data
        self._sock.settimeout(timeout)
        try:
            while True:
                extra = self._sock.recv(65536)
                if not extra:
                    break
                data += extra
        except socket.timeout:
            pass
        return data

    def recv_text_response(self) -> bytes:
        """原始 JSON 响应(无长度前缀):0/5/6/7/8/171。调用方 json.loads。"""
        return self._recv_until_timeout()

    def recv_gzip_response(self):
        """[4B len i][gzip json] 响应:1/16。返回解压后的对象。"""
        logger.debug(f"recv_gzip start: {self.host}:{self.port}")
        n = struct.unpack("i", self._recv_n(4))[0]
        logger.debug(f"recv_gzip: len prefix={n}")
        gz = self._recv_n(n)
        logger.debug(f"recv_gzip: got {len(gz)}B gzip")
        return json.loads(decompress_gzip(gz))

    def recv_file_response(self, gzip_decompress: bool = False):
        """[8B <Q len][content] 响应:3(可选 gzip)/174(必 gzip)。返回 (len, content)。"""
        n = struct.unpack("<Q", self._recv_n(8))[0]
        body = self._recv_n(n)
        if gzip_decompress:
            body = decompress_gzip(body)
        return n, body

    def recv_inline_text(self, timeout: float = 0.3) -> bytes:
        """inline 短文本 ack(21/22/23/24 -> 'NN ok')。"""
        return self._recv_until_timeout(timeout)

    def recv_lenprefixed_json(self):
        """[4B len i][json](无 gzip):131/200。"""
        n = struct.unpack("i", self._recv_n(4))[0]
        return json.loads(self._recv_n(n).decode("utf-8", "replace"))

    def recv_ok(self) -> bytes:
        """b'ok'/b'error':15/172/173。"""
        return self._recv_until_timeout()

    @staticmethod
    def _decode_listen_error(resp: bytes) -> str:
        """B09/N4: 1.7.1 起 172/173/175 错误为 {"error": "..."} JSON(1.6.x 为裸 b'error')。
        解码出中文文案;解不出就原文返回。"""
        try:
            msg = json.loads(resp.decode("utf-8", "replace"))
            if isinstance(msg, dict) and "error" in msg:
                return msg["error"]
        except ValueError:
            pass
        try:
            return resp.decode("utf-8", "replace")
        except Exception:
            return repr(resp)

    # ===== 只读便捷方法 =====
    def version(self) -> str:
        """datatype 14。v0.2.1 恢复（仅 socket_listen start 内部探测靶机版本用，
        不暴露 MCP 工具）。服务端返回 json.dumps(VERSION) 带引号 JSON 字符串。"""
        self._send(14)
        return json.loads(self.recv_text_response().decode("utf-8", "replace"))

    def isfile(self, path: str) -> bool:
        """datatype 7:payload {"file": path}(字段名对齐 netutils.isfile(file))"""
        self._send(7, json.dumps({"file": path}).encode())
        return json.loads(self.recv_text_response().decode("utf-8", "replace")).get("res", False)

    def isdir(self, path: str) -> bool:
        """datatype 8:payload {"dir": path}(字段名对齐 netutils.isdir(dir))"""
        self._send(8, json.dumps({"dir": path}).encode())
        return json.loads(self.recv_text_response().decode("utf-8", "replace")).get("res", False)

    def pcap_flow_extract(self, pcap_dir: str) -> list:
        """datatype 200:payload {"pcap_dir": pcap_dir} -> 方向化五元组流(长度前缀 JSON)"""
        self._send(200, json.dumps({"pcap_dir": pcap_dir}).encode())
        return self.recv_lenprefixed_json()

    # ===== 写方法 =====
    def cmd_exec(self, args: str, cwd: str = None, env: dict = None,
                 wait: bool = True) -> dict:
        """datatype 1:payload {"args","cwd?","env?","wait?"} -> gzip JSON {code,stdout,stderr}。
        wait=False 为 fire-and-forget,返回 None。stdout 超 64KB 截断(带 stdout_truncated 标记)。"""
        payload = {"args": args, "wait": wait}
        if cwd is not None:
            payload["cwd"] = cwd
        if env is not None:
            payload["env"] = env
        logger.debug(f"cmd_exec send: dt=1 args={args[:80]!r} wait={wait}")
        self._send(1, json.dumps(payload).encode())
        result = self.recv_gzip_response()
        if isinstance(result, dict) and isinstance(result.get("stdout"), str) \
                and len(result["stdout"]) > 65536:
            result["stdout"] = result["stdout"][:65536]
            result["stdout_truncated"] = True
            logger.debug(f"cmd_exec stdout truncated to 64KB: {args[:80]!r}")
        logger.debug(f"cmd_exec recv done: code={result.get('code') if isinstance(result, dict) else '?'}")
        return result

    def capture_start(self, eth: str = None, path: str = None,
                      extended: str = "", single_queue: bool = True) -> dict:
        """datatype 5:payload {"eth?","path?","extended?","single_queue?"}。
        eth 为空时服务端用默认网卡(同 routeinfo 默认路由)。
        1.7.2+: 失败返回 {"res": False, "error": 原因};旧靶机 {"res": False} 无 error。
        统一返回 dict {res, error?} 供工具层判定与透传。"""
        payload = {"extended": extended, "single_queue": single_queue}
        if eth is not None:
            payload["eth"] = eth
        if path is not None:
            payload["path"] = path
        self._send(5, json.dumps(payload).encode())
        data = json.loads(self.recv_text_response().decode("utf-8", "replace"))
        if isinstance(data, dict) and "error" in data:
            return data
        return {"res": bool(data.get("res", False))}

    def capture_stop(self, path: str) -> dict:
        """datatype 6。1.7.1 四态 JSON：stopped/exitcode/pcap_complete/note/error；
        旧靶机 {"res": bool} 转 legacy 形态（res:false=真失败，映射 error）。"""
        self._send(6, json.dumps({"path": path}).encode())
        data = json.loads(self.recv_text_response().decode("utf-8", "replace"))
        if isinstance(data, dict) and "stopped" in data:
            return data                      # 新形态（1.7.1）
        if isinstance(data, dict) and "res" in data:
            if data["res"]:
                return {"stopped": True, "legacy": True}
            return {"stopped": False, "legacy": True,
                    "error": "停止未完成（旧版语义），可重试"}
        return {"stopped": False, "error": f"无法解析的服务端响应: {data!r}"}

    def boce_run(self, url: str, count: int = 1, interval: int = 0,
                 thread_count: int = 1, timeout: int = 3,
                 mode: str = "封堵", chromium_path: str = None) -> dict:
        """datatype 131:payload {"url","count?","interval?","thread_count?","timeout?",
        "mode?","chromium_path?"}。响应 [4B len][json],返回 {total,success,fail,...}。
        N1: 服务端前置失败(chromium 下载/依赖安装失败)返回 {"error": "..."},判失败抛错
        而非原样透传(否则 _run_batch 会把含 error 的 dict 计为 ok)。"""
        payload = {"url": url, "count": count, "interval": interval,
                   "thread_count": thread_count, "timeout": timeout, "mode": mode}
        if chromium_path is not None:
            payload["chromium_path"] = chromium_path
        self._send(131, json.dumps(payload).encode())
        data = self.recv_lenprefixed_json()
        if isinstance(data, dict) and "error" in data:
            raise ConnectionError(f"boce failed: {data['error']}")
        return data

    def replay_run(self, pcaps: list, uplink_iface: str, downlink_iface: str,
                   uplink_vlan=None, downlink_vlan=None, mbps: int = 0,
                   force_ip_src=None, force_ip_dst=None,
                   force_sport=None, force_dport=None) -> dict:
        """datatype 0:pcap 回放。payload 对齐 handlers.py do() 的 0 分支
        (必填 pcaps/uplink_iface/downlink_iface;PcapReplayer(**data) 其余透传)。
        响应无长度前缀 JSON(同 5/6 型),返回 stats dict。"""
        payload = {"pcaps": pcaps, "uplink_iface": uplink_iface,
                   "downlink_iface": downlink_iface, "mbps": mbps}
        if uplink_vlan is not None:
            payload["uplink_vlan"] = uplink_vlan
        if downlink_vlan is not None:
            payload["downlink_vlan"] = downlink_vlan
        if force_ip_src is not None:
            payload["force_ip_src"] = force_ip_src
        if force_ip_dst is not None:
            payload["force_ip_dst"] = force_ip_dst
        if force_sport:
            payload["force_sport"] = force_sport
        if force_dport:
            payload["force_dport"] = force_dport
        self._send(0, json.dumps(payload).encode())
        result = json.loads(self.recv_text_response().decode("utf-8", "replace"))
        if isinstance(result, dict) and result.get("status") == "error":
            raise ConnectionError(f"replay failed: {result.get('message', result)}")
        return result

    def socket_listen(self, action: str, listen_port: int = 30001,
                      file: str = None, max_bytes: int = 1048576) -> object:
        """socket 监听编排(datatype 171-174)。

        start->171 {"host":null,"port":listen_port} -> {"pid":[...]}(json)
        clean->172 / save->173 {"file":file} -> b"ok"(error 判失败)
        fetch->174 -> 全量明文 bytes(gzip 解包)。
        174 失败形态:未启动监听时服务端发 {"error":...} JSON(无 8B 前缀),
        先按首字节探测:非 8B 长度前缀可解析或解析出明文 JSON 时按错误处理。
        """
        if action == "start":
            self._send(171, json.dumps({"host": None, "port": listen_port}).encode())
            result = json.loads(self.recv_text_response().decode("utf-8", "replace"))
            if not result.get("pid"):
                raise ConnectionError(f"listen start failed: pid empty, resp={result}")
            return result
        if action == "clean":
            self._send(172)
            resp = self.recv_ok()
            if resp != b"ok":
                raise ConnectionError(f"listen clean failed: {self._decode_listen_error(resp)}")
            return resp
        if action == "stop":
            self._send(175)
            resp = self.recv_ok()
            if resp != b"ok":
                raise ConnectionError(f"listen stop failed: {self._decode_listen_error(resp)}")
            return resp
        if action == "save":
            if not file:
                raise ValueError("save requires file")
            self._send(173, json.dumps({"file": file}).encode())
            resp = self.recv_ok()
            if resp != b"ok":
                raise ConnectionError(f"listen save failed: {self._decode_listen_error(resp)}")
            return resp
        if action == "fetch":
            self._send(174)
            # 探测:先窥探首 8 字节,合法 <Q 长度前缀则走文件流;否则按 error JSON
            head = self._recv_n(8)
            candidate_len = struct.unpack("<Q", head)[0]
            # 合法性判据:gzip 明文长度不会超过 4GB,且 JSON error 首字节是 '{'(0x7b)
            if head[0:1] == b"{":
                # error JSON:把 head 连同后续一起读完按 JSON 解析
                rest = self._recv_until_timeout()
                raw = (head + rest).decode("utf-8", "replace")
                try:
                    msg = json.loads(raw).get("error", raw)
                except ValueError:
                    msg = raw
                raise ConnectionError(f"listen fetch failed: {msg}")
            content = self._recv_n(candidate_len)
            return decompress_gzip(content)
        raise ValueError(f"unknown action: {action}")

    def upgrade_apply(self, version: str, sha256: str, force: bool = False) -> dict:
        """datatype 20 (1.8.0+):中央推包后的升级落地指令。

        前置:二进制已经 :9001 推到靶机 versions/<version>/.staging/。
        同步返回终态:{"ok": True, "version": ...} 或 {"error": "原因"}
        (版本非法/sha 不符/autoupgrade=off/升级进行中/有其它客户端且非 force)。
        受理后靶机在后台重启生效——调用方随后应轮询 dt14 确认,并避免复用本连接
        (服务重启,连接即死;建议 close 后归还)。
        """
        payload = {"version": version, "sha256": sha256, "force": force}
        self._send(20, json.dumps(payload).encode())
        data = json.loads(self.recv_text_response().decode("utf-8", "replace"))
        if not isinstance(data, dict):
            return {"error": f"无法解析的 dt20 响应: {data!r}"}
        return data
