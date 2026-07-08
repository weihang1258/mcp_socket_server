"""socket_server TCP 客户端。

协议帧: [4字节长度 i][4字节 datatype i][payload]
  - 长度 = datatype(4) + payload 字节数
  - payload 多为 JSON，文件类为二进制

⚠️ 权威协议来源（socket_server 仓库）：
  - 帧格式 + send_request/recv_* 逻辑：socket_server/test_e2e.py
  - datatype 处理 + 参数：socket_server/socket_server/handlers.py 的 do()
  - 每个 datatype 的参数/响应/示例：socket_server/docs/api-guide.md

本模块源自 test_e2e.py 客户端部分，必须与之字节级一致。
socket_server 协议变更时同步更新本模块。
"""
from __future__ import annotations

import json
import socket
import struct
import logging
from dataclasses import dataclass
from typing import Optional

logger = logging.getLogger(__name__)

DEFAULT_TIMEOUT = 30


@dataclass
class Response:
    """socket_server 响应。raw 为原始字节，text/json 按需解析。"""
    raw: bytes

    def as_text(self) -> str:
        return self.raw.decode("utf-8", errors="replace")

    def as_json(self):
        return json.loads(self.as_text())


class SocketServerClient:
    """单靶机的 socket_server TCP 客户端。

    一次实例 = 一条连接 = 一个请求（socket_server 协议为请求-响应模型，
    连接复用需服务端支持 handle() 循环，当前按一连接一请求使用，
    由上层连接池管理复用与重建）。
    """

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

    def _send(self, datatype: int, payload: bytes = b"") -> None:
        """发送: [4字节总长度 i][4字节类型 i][载荷]"""
        body = struct.pack("i", datatype) + payload
        msg = struct.pack("i", len(body)) + body
        assert self._sock is not None
        self._sock.sendall(msg)

    def _recv_exactly(self, n: int) -> bytes:
        """精确读取 n 字节"""
        assert self._sock is not None
        buf = b""
        while len(buf) < n:
            chunk = self._sock.recv(min(65536, n - len(buf)))
            if not chunk:
                raise ConnectionError("连接在读取完成前关闭")
            buf += chunk
        return buf

    def _recv_response(self) -> Response:
        """读取响应到连接关闭。socket_server 处理完即关连接。"""
        assert self._sock is not None
        data = b""
        self._sock.settimeout(self.timeout)
        try:
            while True:
                chunk = self._sock.recv(65536)
                if not chunk:
                    break
                data += chunk
        except socket.timeout:
            pass
        return Response(raw=data)

    def call(self, datatype: int, payload: bytes = b"") -> Response:
        """发送请求并返回响应。调用后连接由服务端关闭，本实例应丢弃。"""
        self.connect()
        try:
            self._send(datatype, payload)
            return self._recv_response()
        finally:
            self.close()

    # ===== 便捷方法，按 datatype 封装 =====

    def version(self) -> str:
        """datatype 14: 获取版本号"""
        resp = self.call(14)
        return resp.as_text().strip()

    def isfile(self, path: str) -> bool:
        """datatype 7: 文件是否存在"""
        payload = json.dumps({"path": path}).encode("utf-8")
        resp = self.call(7, payload)
        return resp.as_json().get("res", False)

    def isdir(self, path: str) -> bool:
        """datatype 8: 目录是否存在"""
        payload = json.dumps({"path": path}).encode("utf-8")
        resp = self.call(8, payload)
        return resp.as_json().get("res", False)

    def routeinfo(self) -> dict:
        """datatype 4: 路由信息"""
        resp = self.call(4)
        return resp.as_json()

    def command_exists(self, cmd: str) -> bool:
        """datatype 18: 命令是否存在"""
        payload = json.dumps({"cmd": cmd}).encode("utf-8")
        resp = self.call(18, payload)
        return resp.as_json().get("res", False)

    def capture_start(self, eth: str, path: str, extended: str = "") -> bool:
        """datatype 5: 开始 tcpdump 抓包。不同 (eth, path) 可并发。"""
        payload = json.dumps({"eth": eth, "path": path, "extended": extended}).encode("utf-8")
        resp = self.call(5, payload)
        return resp.as_json().get("res", False)

    def capture_stop(self, path: str) -> bool:
        """datatype 6: 停止 tcpdump 抓包（按 path 定位）"""
        payload = json.dumps({"path": path}).encode("utf-8")
        resp = self.call(6, payload)
        return resp.as_json().get("res", False)
