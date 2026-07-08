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
        s.connect((self.host, self.port))
        self._sock = s

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
        self._sock.sendall(struct.pack("i", len(body)) + body)

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
        n = struct.unpack("i", self._recv_n(4))[0]
        gz = self._recv_n(n)
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
