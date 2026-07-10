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
import socket
import struct
from typing import Optional

logger = logging.getLogger(__name__)
DEFAULT_TIMEOUT = 30


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
        """原始 JSON 响应(无长度前缀):4/7/8/9/10/11/14/18/19/5/6/171。调用方 json.loads。"""
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

    # ===== 只读便捷方法 =====
    def version(self) -> str:
        """datatype 14"""
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

    def routeinfo(self) -> dict:
        """datatype 4:无 payload"""
        self._send(4)
        return json.loads(self.recv_text_response().decode("utf-8", "replace"))

    def command_exists(self, cmd: str) -> bool:
        """datatype 18:payload {"cmd": cmd}(只读路径,不暴露 install_cmd)"""
        self._send(18, json.dumps({"cmd": cmd}).encode())
        return json.loads(self.recv_text_response().decode("utf-8", "replace")).get("res", False)

    def filesize(self, path: str) -> int:
        """datatype 11:payload {"path": path}"""
        self._send(11, json.dumps({"path": path}).encode())
        return json.loads(self.recv_text_response().decode("utf-8", "replace")).get("res", 0)

    def version_detail(self) -> dict:
        """datatype 19。注:handlers.py v1.3.9 因 REPO 未 import(line 8)而 NameError,
        线上未修则本调用失败(连接被服务端关闭)。"""
        self._send(19)
        return json.loads(self.recv_text_response().decode("utf-8", "replace"))

    def pcap_flow_extract(self, pcap_dir: str) -> list:
        """datatype 200:payload {"pcap_dir": pcap_dir} -> 方向化五元组流(长度前缀 JSON)"""
        self._send(200, json.dumps({"pcap_dir": pcap_dir}).encode())
        return self.recv_lenprefixed_json()

    # ===== 写方法 =====
    def cmd_exec(self, args: str, cwd: str = None, env: dict = None,
                 wait: bool = True) -> dict:
        """datatype 1:payload {"args","cwd?","env?","wait?"} -> gzip JSON {code,stdout,stderr}。
        wait=False 为 fire-and-forget,返回 None。"""
        payload = {"args": args, "wait": wait}
        if cwd is not None:
            payload["cwd"] = cwd
        if env is not None:
            payload["env"] = env
        logger.debug(f"cmd_exec send: dt=1 args={args[:80]!r} wait={wait}")
        self._send(1, json.dumps(payload).encode())
        result = self.recv_gzip_response()
        logger.debug(f"cmd_exec recv done: code={result.get('code') if isinstance(result, dict) else '?'}")
        return result

    def capture_start(self, eth: str = None, path: str = None,
                      extended: str = "", single_queue: bool = True) -> bool:
        """datatype 5:payload {"eth?","path?","extended?","single_queue?"}。
        eth 为空时服务端用默认网卡(同 routeinfo 默认路由)。"""
        payload = {"extended": extended, "single_queue": single_queue}
        if eth is not None:
            payload["eth"] = eth
        if path is not None:
            payload["path"] = path
        self._send(5, json.dumps(payload).encode())
        return json.loads(self.recv_text_response().decode("utf-8", "replace")).get("res", False)

    def capture_stop(self, path: str) -> bool:
        """datatype 6:payload {"path"}。"""
        self._send(6, json.dumps({"path": path}).encode())
        return json.loads(self.recv_text_response().decode("utf-8", "replace")).get("res", False)

    def boce_run(self, url: str, count: int = 1, interval: int = 0,
                 thread_count: int = 1, timeout: int = 3,
                 mode: str = "封堵", chromium_path: str = None) -> dict:
        """datatype 131:payload {"url","count?","interval?","thread_count?","timeout?",
        "mode?","chromium_path?"}。响应 [4B len][json],返回 {total,success,fail,...}。"""
        payload = {"url": url, "count": count, "interval": interval,
                   "thread_count": thread_count, "timeout": timeout, "mode": mode}
        if chromium_path is not None:
            payload["chromium_path"] = chromium_path
        self._send(131, json.dumps(payload).encode())
        return self.recv_lenprefixed_json()

    def file_upload(self, remote_path: str, content: bytes,
                    use_gzip: bool = False) -> bool:
        """文件上传 21->22->23->24 多步握手,单持久连接。
        21{"filepath","gzip"}->"21 ok";22[8B <Q len]->"22 ok";
        23[4B len][content] 无 datatype->"23 ok";24->"24 ok"。
        任一步失败抛 ConnectionError,含步骤号 + 服务端实际响应(便于排障);
        抛异常后 session 上下文标记连接不健康并丢弃,避免毒连接复用。"""
        raw = compress_gzip(content) if use_gzip else content
        self._send(21, json.dumps({"filepath": remote_path, "gzip": use_gzip}).encode())
        resp = self.recv_inline_text()
        if resp != b"21 ok":
            raise ConnectionError(
                f"upload step1(21 filepath) failed: resp={resp!r}")
        self._send(22, struct.pack("<Q", len(raw)))
        resp = self.recv_inline_text()
        if resp != b"22 ok":
            raise ConnectionError(
                f"upload step2(22 length={len(raw)}) failed: resp={resp!r}")
        self._send_raw(raw)  # 23: 无 datatype 字段,_send_raw 自加 [4B len] 前缀
        resp = self.recv_inline_text()
        if resp != b"23 ok":
            raise ConnectionError(
                f"upload step3(23 content {len(raw)}B) failed: resp={resp!r}")
        self._send(24, b"")
        resp = self.recv_inline_text()
        if resp != b"24 ok":
            raise ConnectionError(
                f"upload step4(24 commit) failed: resp={resp!r}")
        return True

    def file_download(self, remote_path: str, use_gzip: bool = False) -> bytes:
        """文件下载 21->3,单持久连接。21 先设 filepath(连接状态),3 读 {"gzip":bool}。
        返回文件内容字节。21 步失败抛 ConnectionError(含服务端实际响应)。"""
        self._send(21, json.dumps({"filepath": remote_path, "gzip": use_gzip}).encode())
        resp = self.recv_inline_text()
        if resp != b"21 ok":
            raise ConnectionError(
                f"download step1(21 filepath) failed: resp={resp!r}")
        self._send(3, json.dumps({"gzip": use_gzip}).encode())
        n, body = self.recv_file_response()
        if use_gzip:
            body = decompress_gzip(body)
        return body
