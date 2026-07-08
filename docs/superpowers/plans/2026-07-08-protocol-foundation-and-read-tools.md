# 协议地基 + 传输 + 只读工具 Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** 重建 `socket_client.py`(per-datatype recv + gzip + 持久会话)与 `pool.py`,修正 `commands.py`,加 config/transport(Streamable HTTP),暴露只读工具,产出可用的远程只读 MCP server。

**Architecture:** `socket_client` 按 `test_e2e.py` recv_* 逐 datatype 解析响应(长度前缀精确读 / 原始 JSON timeout 读),持久连接(服务端 `protocol.py handle()` 循环);`pool` 借出/归还连接;mock socket_server 复刻 `protocol.py` 用于测试。

**Tech Stack:** Python ≥3.10,socket/struct/gzip/json,threading,pytest,pytest-asyncio,mcp SDK(>=1.8),uvicorn,PyYAML。

## Global Constraints

(每个 task 隐含遵守,值逐字来自 spec `docs/superpowers/specs/2026-07-08-mcp-socket-server-phase1-design.md`)

- 发送帧 `[4B len i][4B datatype i][payload]`,len = 4 + payload 字节,与 `test_e2e.py` `send_request` 字节级一致
- recv 用 timeout 读可用字节(**非「读到关闭」**);服务端持久连接(`protocol.py handle()` 循环)
- gzip:`compress_gzip`/`decompress_gzip`;`cmd`(1) 响应 `[4B len i][gzip json]`
- 文件传输多步握手:下载 `21->3`、上传 `21->22->23->24`(23 无 datatype 字段,空文件哨兵 `b"^$"`)
- **161/162/163 死代码,不注册**
- `pyproject`:`mcp>=1.0` -> `mcp>=1.8`;新增 `pyyaml>=6.0`、`uvicorn>=0.30`
- 协议权威:`/opt/socket_server` 的 `handlers.py do()`、`protocol.py handle()`、`test_e2e.py`

## File Structure

- Modify: `src/mcp_socket_server/socket_client.py` — 协议客户端(per-datatype recv + gzip + 持久会话 + 只读方法)
- Modify: `src/mcp_socket_server/pool.py` — 持久会话 + 连接复用
- Modify: `src/mcp_socket_server/commands.py` — 修正注册表
- Create: `src/mcp_socket_server/config.py` — 加载 config.yaml + env
- Create: `src/mcp_socket_server/transport.py` — Streamable HTTP ASGI + uvicorn
- Modify: `src/mcp_socket_server/__main__.py` — CLI 启动 uvicorn
- Modify: `src/mcp_socket_server/server.py` — 只读工具(用新 client/pool)
- Create: `tests/conftest.py` — mock server fixture
- Create: `tests/mock_socket_server.py` — 复刻 protocol.py 的测试服务端
- Create: `tests/test_socket_client.py`
- Create: `tests/test_pool.py`
- Create: `tests/test_commands.py`
- Create: `tests/test_transport.py`
- Create: `tests/test_server_read_tools.py`

---

### Task 1: mock socket_server + conftest

**Files:**
- Create: `tests/mock_socket_server.py`
- Create: `tests/conftest.py`

**Interfaces:**
- Consumes: `socket`, `struct`, `json`, `gzip`, `socketserver`,`threading`(标准库)
- Produces: `MockSocketServer`(测试用 TCP 服务端,复刻 `protocol.py handle()` + 各 datatype 响应);pytest fixture `mock_server`(返回 `(host, port)`,自动清理)

- [ ] **Step 1: Write the failing test**

`tests/test_mock_server.py`:
```python
import json, struct, socket
from tests.mock_socket_server import MockSocketServer

def test_mock_serves_version():
    srv = MockSocketServer()
    srv.start()
    try:
        s = socket.create_connection((srv.host, srv.port), timeout=2)
        body = struct.pack("i", 14)
        s.sendall(struct.pack("i", len(body)) + body)
        data = b""
        s.settimeout(2)
        while True:
            chunk = s.recv(4096)
            if not chunk: break
            data += chunk
            s.settimeout(0.3)
            try:
                extra = s.recv(4096)
                if not extra: break
                data += extra
            except socket.timeout:
                break
        s.close()
        assert json.loads(data) == "1.3.9-mock"
    finally:
        srv.stop()
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd /opt/mcp_socket_server && python -m pytest tests/test_mock_server.py -v`
Expected: FAIL — `ModuleNotFoundError: tests.mock_socket_server`

- [ ] **Step 3: Write minimal implementation**

`tests/mock_socket_server.py`:
```python
"""测试用 mock socket_server,复刻 socket_server/protocol.py handle() 循环 +
各 datatype 响应格式(对齐 handlers.py do() 返回)。用于 socket_client/pool 测试。"""
import json, struct, gzip, socketserver, threading

VERSION = "1.3.9-mock"

def _compress(b: bytes) -> bytes:
    return gzip.compress(b)

class _Handler(socketserver.BaseRequestHandler):
    def setup(self):
        self.filepath = "tmp"
        self.content = b""
        self.length = 0
        self.bin_recv_flag = False
        self.bufsize = 10240

    def handle(self):
        datatotal = b""
        data_len = 0
        while True:
            try:
                data = self.request.recv(self.bufsize)
            except (ConnectionResetError, OSError):
                break
            if not data:
                break
            if data_len == 0:
                if len(data) < 4:
                    break
                data_len = struct.unpack("i", data[:4])[0]
                datatotal += data[4:]
            else:
                datatotal += data
            if len(datatotal) < data_len:
                continue
            if len(datatotal) > data_len:
                datatotal = b""; data_len = 0; continue
            data = datatotal; datatotal = b""; data_len = 0

            if not self.bin_recv_flag:
                datatype = struct.unpack("i", data[:4])[0]
                data = data[4:]
            else:
                datatype = 23

            if datatype in (21,):
                info = json.loads(data)
                self.filepath = info.get("filepath", "tmp")
                self.gzip = info.get("gzip", False)
                self.request.sendall(b"21 ok"); continue
            elif datatype in (22,):
                self.length = struct.unpack("<Q", data)[0]
                self.content = b""
                self.bin_recv_flag = True
                self.bufsize = 102400000
                self.request.sendall(b"22 ok"); continue
            elif datatype in (23,):
                self.content += data
                if len(self.content) == self.length:
                    self.bufsize = 1024
                    self.bin_recv_flag = False
                    self.request.sendall(b"23 ok"); continue
                elif len(self.content) > self.length:
                    self.bin_recv_flag = False; break
                else:
                    continue
            elif datatype in (24,):
                content = _decompress(self.content) if self.gzip else self.content
                if content == b"^$":
                    content = b""
                with open(self.filepath, "wb") as f:
                    f.write(content)
                self.content = b""
                self.request.sendall(b"24 ok"); continue

            resp = self._on_data(datatype, data)
            if resp is not None:
                self.request.sendall(resp)

    def _on_data(self, datatype, data):
        # 只读类:原始 JSON(无长度前缀)
        if datatype == 14:
            return json.dumps(VERSION).encode()
        if datatype == 7:
            import os
            return json.dumps({"res": os.path.isfile(json.loads(data)["file"])}).encode()
        if datatype == 8:
            import os
            return json.dumps({"res": os.path.isdir(json.loads(data)["dir"])}).encode()
        if datatype == 4:
            return json.dumps({"default": {"Iface": "mock_eth0"}, "routes": []}).encode()
        if datatype == 18:
            return json.dumps({"res": True}).encode()
        if datatype == 11:
            return json.dumps({"res": 1024}).encode()
        if datatype == 19:
            return json.dumps({"version": VERSION, "repo": "mock",
                               "latest_version": VERSION, "has_upgrade": False}).encode()
        if datatype == 5:
            return json.dumps({"res": True}).encode()
        if datatype == 6:
            return json.dumps({"res": True}).encode()
        # 长度前缀类
        if datatype == 200:
            res = json.dumps([{"pcap": "a.pcap", "srcIp": "1.1.1.1", "srcPort": 1,
                               "destIp": "2.2.2.2", "destPort": 2, "protoType": 1}]).encode()
            return struct.pack("i", len(res)) + res
        if datatype == 1:
            res = json.dumps({"code": 0, "stdout": "mock_out", "stderr": ""}).encode()
            gz = _compress(res)
            return struct.pack("i", len(gz)) + gz
        if datatype == 131:
            res = json.dumps({"status": "ok", "url": json.loads(data).get("url")}).encode()
            return struct.pack("i", len(res)) + res
        if datatype == 3:
            import os
            if not os.path.isfile(self.filepath):
                return b""
            content = open(self.filepath, "rb").read()
            if json.loads(data).get("gzip"):
                content = _compress(content)
            return struct.pack("<Q", len(content)) + content
        if datatype == 174:
            content = _compress(b"listener-data")
            return struct.pack("<Q", len(content)) + content
        if datatype in (15, 172, 173):
            return b"ok"
        return None

def _decompress(b: bytes) -> bytes:
    return gzip.decompress(b)

class MockSocketServer:
    def __init__(self):
        self._srv = None
        self._thread = None
        self.host = "127.0.0.1"
        self.port = 0

    def start(self):
        self._srv = socketserver.ThreadingTCPServer((self.host, 0), _Handler)
        self._srv.daemon_threads = True
        self.port = self._srv.server_address[1]
        self._thread = threading.Thread(target=self._srv.serve_forever, daemon=True)
        self._thread.start()

    def stop(self):
        if self._srv:
            self._srv.shutdown()
            self._srv.server_close()
            self._srv = None
```

`tests/conftest.py`:
```python
import pytest
from tests.mock_socket_server import MockSocketServer

@pytest.fixture
def mock_server():
    srv = MockSocketServer()
    srv.start()
    yield srv
    srv.stop()
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cd /opt/mcp_socket_server && python -m pytest tests/test_mock_server.py -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
cd /opt/mcp_socket_server
git add tests/mock_socket_server.py tests/conftest.py tests/test_mock_server.py
git commit -m "test: add mock socket_server replicating protocol.py"
```

---

### Task 2: socket_client recv 基础(gzip + send_request + recv_*)

**Files:**
- Modify: `src/mcp_socket_server/socket_client.py`(整文件重建)
- Test: `tests/test_socket_client.py`

**Interfaces:**
- Consumes: `tests.mock_socket_server`(fixture `mock_server`)
- Produces: `SocketServerClient(host, port)`,方法 `connect()`/`close()`/`_send(datatype, payload)`/`_recv_n(n)`/`_recv_until_timeout(timeout)`/`recv_text_response()`/`recv_gzip_response()`/`recv_file_response()`/`recv_inline_text()`

- [ ] **Step 1: Write the failing test**

`tests/test_socket_client.py`:
```python
import json, struct
from mcp_socket_server.socket_client import SocketServerClient

def test_recv_text_response_version(mock_server):
    c = SocketServerClient(mock_server.host, mock_server.port)
    c.connect()
    c._send(14)
    assert c.recv_text_response() == b'"1.3.9-mock"'
    c.close()

def test_recv_gzip_response_cmd(mock_server):
    c = SocketServerClient(mock_server.host, mock_server.port)
    c.connect()
    c._send(1, json.dumps({"args": "echo hi"}).encode())
    assert c.recv_gzip_response() == {"code": 0, "stdout": "mock_out", "stderr": ""}
    c.close()

def test_recv_file_response_and_upload(mock_server, tmp_path):
    remote = str(tmp_path / "r.txt")
    c = SocketServerClient(mock_server.host, mock_server.port)
    c.connect()
    content = b"hello-file"
    # upload: 21 -> 22 -> 23 -> 24
    c._send(21, json.dumps({"filepath": remote, "gzip": False}).encode())
    assert c.recv_inline_text() == b"21 ok"
    c._send(22, struct.pack("<Q", len(content)))
    assert c.recv_inline_text() == b"22 ok"
    c._send_raw(struct.pack("i", len(content)) + content)  # 23: 无 datatype
    assert c.recv_inline_text() == b"23 ok"
    c._send(24, b"")
    assert c.recv_inline_text() == b"24 ok"
    # download: 21(set filepath) -> 3
    c._send(21, json.dumps({"filepath": remote, "gzip": False}).encode())
    assert c.recv_inline_text() == b"21 ok"
    c._send(3, json.dumps({"gzip": False}).encode())
    n, body = c.recv_file_response()
    assert n == len(content) and body == content
    c.close()
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd /opt/mcp_socket_server && python -m pytest tests/test_socket_client.py -v`
Expected: FAIL — `AttributeError`/`ImportError`(SocketServerClient 缺方法)

- [ ] **Step 3: Write minimal implementation**

`src/mcp_socket_server/socket_client.py`(整文件覆盖):
```python
"""socket_server TCP 客户端(重建版)。

⚠️ 权威协议来源(socket_server 仓库):
  - 帧格式 + send_request/recv_*:socket_server/test_e2e.py
  - datatype 处理 + 参数:socket_server/socket_server/handlers.py do()
  - 连接循环 + 文件传输:socket_server/socket_server/protocol.py handle()

本模块 recv 按 test_e2e.py recv_* 逐 datatype 解析;持久连接(服务端 handle() 循环)。
socket_server 协议变更时同步更新本模块。
"""
from __future__ import annotations
import json, socket, struct, gzip, logging
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
            try: self._sock.close()
            except OSError: pass
            self._sock = None

    # ===== 发送 =====
    def _send(self, datatype: int, payload: bytes = b"") -> None:
        """发送 [4B len i][4B datatype i][payload]"""
        body = struct.pack("i", datatype) + payload
        self._sock.sendall(struct.pack("i", len(body)) + body)

    def _send_raw(self, msg: bytes) -> None:
        """发送裸帧 [4B len][content](用于文件上传 step 23,无 datatype 字段)"""
        self._sock.sendall(struct.pack("i", len(msg)) + msg)

    # ===== 接收基础 =====
    def _recv_n(self, n: int) -> bytes:
        """精确读 n 字节"""
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
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cd /opt/mcp_socket_server && python -m pytest tests/test_socket_client.py -v`
Expected: PASS(4 tests)

- [ ] **Step 5: Commit**

```bash
cd /opt/mcp_socket_server
git add src/mcp_socket_server/socket_client.py tests/test_socket_client.py
git commit -m "feat: rebuild socket_client recv foundation (per-datatype, gzip, persistent)"
```

---

### Task 3: socket_client 只读方法

**Files:**
- Modify: `src/mcp_socket_server/socket_client.py`(追加只读便捷方法)
- Test: `tests/test_socket_client.py`(追加)

**Interfaces:**
- Produces: `version()`->str、`isfile(path)`->bool、`isdir(path)`->bool、`routeinfo()`->dict、`command_exists(cmd)`->bool、`filesize(path)`->int、`version_detail()`->dict、`pcap_flow_extract(pcap_dir)`->list

- [ ] **Step 1: Write the failing test**

追加到 `tests/test_socket_client.py`:
```python
def test_read_methods(mock_server, tmp_path):
    f = tmp_path / "x.txt"; f.write_text("abc")
    c = SocketServerClient(mock_server.host, mock_server.port); c.connect()
    assert c.version() == "1.3.9-mock"
    assert c.isfile(str(f)) is True
    assert c.isdir(str(tmp_path)) is True
    assert isinstance(c.routeinfo(), dict)
    assert c.command_exists("ls") is True
    assert c.filesize(str(f)) == 1024  # mock 固定值
    assert c.version_detail()["version"] == "1.3.9-mock"
    flows = c.pcap_flow_extract("/some/dir")
    assert flows[0]["protoType"] == 1
    c.close()
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd /opt/mcp_socket_server && python -m pytest tests/test_socket_client.py::test_read_methods -v`
Expected: FAIL — `AttributeError: 'SocketServerClient' object has no attribute 'version'`

- [ ] **Step 3: Write minimal implementation**

追加到 `src/mcp_socket_server/socket_client.py` 的 `SocketServerClient` 类内:
```python
    # ===== 只读便捷方法 =====
    def version(self) -> str:
        """datatype 14"""
        self._send(14)
        return json.loads(self.recv_text_response().decode("utf-8", "replace"))

    def isfile(self, path: str) -> bool:
        self._send(7, json.dumps({"file": path}).encode())
        return json.loads(self.recv_text_response().decode("utf-8", "replace")).get("res", False)

    def isdir(self, path: str) -> bool:
        self._send(8, json.dumps({"dir": path}).encode())
        return json.loads(self.recv_text_response().decode("utf-8", "replace")).get("res", False)

    def routeinfo(self) -> dict:
        self._send(4)
        return json.loads(self.recv_text_response().decode("utf-8", "replace"))

    def command_exists(self, cmd: str) -> bool:
        self._send(18, json.dumps({"cmd": cmd}).encode())
        return json.loads(self.recv_text_response().decode("utf-8", "replace")).get("res", False)

    def filesize(self, path: str) -> int:
        self._send(11, json.dumps({"path": path}).encode())
        return json.loads(self.recv_text_response().decode("utf-8", "replace")).get("res", 0)

    def version_detail(self) -> dict:
        """datatype 19。注:handlers.py v1.3.9 可能因 REPO 未 import 而 NameError,线上未修则失败。"""
        self._send(19)
        return json.loads(self.recv_text_response().decode("utf-8", "replace"))

    def pcap_flow_extract(self, pcap_dir: str) -> list:
        """datatype 200:pcap 目录 -> 方向化五元组流"""
        self._send(200, json.dumps({"pcap_dir": pcap_dir}).encode())
        return self.recv_lenprefixed_json()
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cd /opt/mcp_socket_server && python -m pytest tests/test_socket_client.py -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
cd /opt/mcp_socket_server
git add src/mcp_socket_server/socket_client.py tests/test_socket_client.py
git commit -m "feat: socket_client read methods (14/7/8/4/18/11/19/200)"
```

---

### Task 4: pool.py 重建(持久会话 + 连接复用)

**Files:**
- Modify: `src/mcp_socket_server/pool.py`(整文件重建)
- Test: `tests/test_pool.py`

**Interfaces:**
- Consumes: `SocketServerClient`
- Produces: `TargetPool(host, port)` 的 `acquire(timeout)->SocketServerClient` / `release(client, healthy=True)`;`Scheduler` 的 `get_pool(host,port)` / `batch(targets, fn, port, timeout)->list[TargetResult]`;`get_scheduler()->Scheduler`;`TargetResult(target, ok, data, error)`

- [ ] **Step 1: Write the failing test**

`tests/test_pool.py`:
```python
from mcp_socket_server.pool import Scheduler, TargetResult

def test_batch_read_fanout(mock_server):
    sched = Scheduler()
    results = sched.batch([mock_server.host], lambda c: c.version(), port=mock_server.port, timeout=5)
    assert len(results) == 1
    r = results[0]
    assert isinstance(r, TargetResult)
    assert r.ok and r.data == "1.3.9-mock"

def test_batch_partial_failure(mock_server):
    sched = Scheduler()
    results = sched.batch([mock_server.host, "127.0.0.1:1"], lambda c: c.version(),
                          port=mock_server.port, timeout=2)
    assert sum(1 for r in results if r.ok) == 1
    failed = [r for r in results if not r.ok]
    assert len(failed) == 1 and failed[0].error

def test_connection_reuse(mock_server):
    from mcp_socket_server.pool import TargetPool
    p = TargetPool(mock_server.host, mock_server.port)
    c1 = p.acquire(timeout=5); c1.version(); p.release(c1)
    c2 = p.acquire(timeout=5)  # 应复用同一条连接
    assert c2 is c1
    p.release(c2); p.close_all()
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd /opt/mcp_socket_server && python -m pytest tests/test_pool.py -v`
Expected: FAIL — `test_connection_reuse` 无 `close_all`/复用逻辑;或旧 batch 仍用读到关闭

- [ ] **Step 3: Write minimal implementation**

`src/mcp_socket_server/pool.py`(整文件覆盖):
```python
"""每靶机连接池 + 批量调度(重建版:持久会话 + 连接复用)。

服务端 protocol.py handle() 是持久连接循环,故连接可复用;文件传输需在同一连接多轮往返。
池参数: max_conn_per_target=5, idle_timeout=10min, borrow_timeout=10s, 全局并发 50。
"""
from __future__ import annotations
import logging, threading, time
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from typing import Callable, Optional

from .socket_client import SocketServerClient

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
        self.host = host; self.port = port
        self._idle: list[_PooledConn] = []
        self._inuse = 0
        self._cond = threading.Condition(threading.Lock())

    def acquire(self, timeout: float = BORROW_TIMEOUT) -> SocketServerClient:
        deadline = time.time() + timeout
        with self._cond:
            while self._inuse >= MAX_CONN_PER_TARGET:
                remaining = deadline - time.time()
                if remaining <= 0:
                    raise TimeoutError(f"靶机 {self.host} 连接池满,等待超时")
                self._cond.wait(remaining)
            # 复用空闲连接(未超时且健康)
            now = time.time()
            while self._idle:
                pc = self._idle.pop()
                if now - pc.last_used > IDLE_TIMEOUT:
                    pc.client.close(); continue
                self._inuse += 1
                return pc.client
            self._inuse += 1
        client = SocketServerClient(self.host, self.port)
        client.connect()
        return client

    def release(self, client: SocketServerClient, healthy: bool = True) -> None:
        with self._cond:
            self._inuse = max(0, self._inuse - 1)
            if healthy:
                self._idle.append(_PooledConn(client, time.time()))
            else:
                try: client.close()
                except OSError: pass
            self._cond.notify_all()
        if not healthy:
            try: client.close()
            except OSError: pass

    def close_all(self) -> None:
        with self._cond:
            for pc in self._idle:
                try: pc.client.close()
                except OSError: pass
            self._idle.clear()

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
                p = TargetPool(host, port); self._pools[key] = p
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

_scheduler: Optional[Scheduler] = None
def get_scheduler() -> Scheduler:
    global _scheduler
    if _scheduler is None:
        _scheduler = Scheduler()
    return _scheduler
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cd /opt/mcp_socket_server && python -m pytest tests/test_pool.py -v`
Expected: PASS(3 tests)

- [ ] **Step 5: Commit**

```bash
cd /opt/mcp_socket_server
git add src/mcp_socket_server/pool.py tests/test_pool.py
git commit -m "feat: rebuild pool with persistent session + connection reuse"
```

---

### Task 5: commands.py 修正

**Files:**
- Modify: `src/mcp_socket_server/commands.py`
- Modify: `pyproject.toml`(pin mcp + 加依赖)
- Test: `tests/test_commands.py`

**Interfaces:**
- Produces: `COMMANDS` 注册表含 `version_detail`(19,NONE,SAFE)、`pcap_flow_extract`(200,NONE,SAFE)、`cmd_exec`(1,SHELL,DANGER);`file_upload`/`file_download` 标记为多步会话(无单 datatype);无 161/162/163;无 `version_switch`/`firewall_disable` 本期(下期)

- [ ] **Step 1: Write the failing test**

`tests/test_commands.py`:
```python
from mcp_socket_server.commands import COMMANDS, LockClass, Danger

def test_registry_has_phase1_read_tools():
    for name, dt in [("version_query",14),("isfile",7),("isdir",8),("routeinfo",4),
                     ("command_exists",18),("filesize",11),("version_detail",19),
                     ("pcap_flow_extract",200)]:
        assert name in COMMANDS, name
        assert COMMANDS[name].datatype == dt
        assert COMMANDS[name].lock_class == LockClass.NONE
        assert COMMANDS[name].danger == Danger.SAFE

def test_registry_no_dead_datatypes():
    # 161/162/163 死代码不注册;version_switch/firewall 本期不暴露
    for name in ["version_switch", "firewall_disable"]:
        assert name not in COMMANDS, f"{name} 本期不应暴露"

def test_file_transfer_is_session_not_single_datatype():
    # file_upload/download 是多步会话,commands.py 不应记单 datatype
    assert "file_upload" in COMMANDS
    assert "file_download" in COMMANDS
    assert COMMANDS["file_upload"].datatype is None  # 多步会话标记
    assert COMMANDS["file_download"].datatype is None
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd /opt/mcp_socket_server && python -m pytest tests/test_commands.py -v`
Expected: FAIL(`version_detail`/`pcap_flow_extract` 不存在;file_upload.datatype==22;version_switch 存在)

- [ ] **Step 3: Write minimal implementation**

`src/mcp_socket_server/commands.py`(整文件覆盖):
```python
"""命令注册表:datatype -> (锁类, 危险等级)。

⚠️ 权威协议来源(socket_server 仓库,勿在此手抄臆造):
  - datatype 编号 + 参数 JSON 字段:socket_server/socket_server/handlers.py 的 do() 函数
  - 协议帧 + 收发:socket_server/test_e2e.py
  - 连接循环 + 文件传输(21/22/23/24):socket_server/socket_server/protocol.py handle()
  - datatype 表(含锁类/并发/危险):socket_server/docs/mcp-integration.md

本表从上述来源派生。socket_server 协议变更时按 docs/mcp-integration.md §8 同步本表 + socket_client.py。
注:
  - 161/162/163(socket_linux.py dpi_operation)服务端无处理,死代码,不注册;DPI 生命周期走 cmd(1)。
  - 文件传输是多步会话(21->3 / 21->22->23->24),非单 datatype;此处 datatype=None 标记。
  - 下期再补:10/15/16/0/171-174;version_switch 拆 dpi_mode_switch+dpi_upgrade。
"""
from __future__ import annotations
from dataclasses import dataclass
from enum import Enum
from typing import Optional

class LockClass(str, Enum):
    NONE = "none"; CAPTURE = "capture"; FILE_IO = "file_io"
    SHELL = "shell"; BROWSER = "browser"; SYSTEM = "system"

class Danger(str, Enum):
    SAFE = "safe"; WRITE = "write"; DANGER = "danger"

@dataclass(frozen=True)
class CommandSpec:
    name: str
    datatype: Optional[int]       # None = 多步会话(如文件传输)或编排工具
    lock_class: LockClass
    danger: Danger
    lock_key_fields: tuple[str, ...] = ()

COMMANDS: dict[str, CommandSpec] = {
    # 只读类(NONE/SAFE)
    "version_query":   CommandSpec("version_query", 14, LockClass.NONE, Danger.SAFE),
    "isfile":          CommandSpec("isfile", 7, LockClass.NONE, Danger.SAFE),
    "isdir":           CommandSpec("isdir", 8, LockClass.NONE, Danger.SAFE),
    "routeinfo":       CommandSpec("routeinfo", 4, LockClass.NONE, Danger.SAFE),
    "command_exists":  CommandSpec("command_exists", 18, LockClass.NONE, Danger.SAFE),
    "filesize":        CommandSpec("filesize", 11, LockClass.NONE, Danger.SAFE),
    "version_detail":  CommandSpec("version_detail", 19, LockClass.NONE, Danger.SAFE),
    "pcap_flow_extract": CommandSpec("pcap_flow_extract", 200, LockClass.NONE, Danger.SAFE),

    # 抓包(CAPTURE,按 path 排他;capture_start 持锁到 capture_stop)
    "capture_start":   CommandSpec("capture_start", 5, LockClass.CAPTURE, Danger.WRITE, ("path",)),
    "capture_stop":    CommandSpec("capture_stop", 6, LockClass.CAPTURE, Danger.WRITE, ("path",)),

    # 文件传输(多步会话,datatype=None;FILE_IO per-target 排他)
    "file_upload":     CommandSpec("file_upload", None, LockClass.FILE_IO, Danger.WRITE),
    "file_download":   CommandSpec("file_download", None, LockClass.FILE_IO, Danger.WRITE),

    # 命令执行(危险,白名单;本期实现)
    "cmd_exec":        CommandSpec("cmd_exec", 1, LockClass.SHELL, Danger.DANGER),

    # 拨测
    "boce_run":        CommandSpec("boce_run", 131, LockClass.BROWSER, Danger.WRITE),
}
# 下期:replay(0)/mtu(10)/unzip(15)/python_cmd(16)/socketserver_*(171-174)/
#        dpi_mode_switch+dpi_upgrade(cmd 编排)/tap_mirror(SSH)
```

`pyproject.toml` dependencies 改为:
```toml
dependencies = [
    "mcp>=1.8",
    "anyio>=4.0",
    "pyyaml>=6.0",
    "uvicorn>=0.30",
]
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cd /opt/mcp_socket_server && python -m pytest tests/test_commands.py -v`
Expected: PASS(3 tests)

- [ ] **Step 5: Commit**

```bash
cd /opt/mcp_socket_server
git add src/mcp_socket_server/commands.py pyproject.toml tests/test_commands.py
git commit -m "fix: commands.py registry (file=session, +19/200, -161/162/163, pin mcp>=1.8)"
```

---

### Task 6: config.py + transport.py + __main__.py(Streamable HTTP)

**Files:**
- Create: `src/mcp_socket_server/config.py`
- Create: `src/mcp_socket_server/transport.py`
- Modify: `src/mcp_socket_server/__main__.py`
- Test: `tests/test_transport.py`

**Interfaces:**
- Produces: `config.load_config(path)->Config`(dataclass:`host`,`port`,`db_path`,`behind_proxy`,`audit_retention_days`,`download_dir`,`pool.max_conn_per_target` 等);`transport.run(mcp, cfg)`;`transport.streamable_http_app(mcp)`(返回 ASGI)

- [ ] **Step 1: Write the failing test**

`tests/test_transport.py`:
```python
from mcp_socket_server.config import load_config
from mcp_socket_server.transport import streamable_http_app
from mcp.server.fastmcp import FastMCP

def test_load_config_defaults(tmp_path):
    cfg_path = tmp_path / "c.yaml"
    cfg_path.write_text("bind: {host: 127.0.0.1, port: 9090}\ndb_path: ./t.db\n")
    cfg = load_config(str(cfg_path))
    assert cfg.host == "127.0.0.1" and cfg.port == 9090
    assert cfg.behind_proxy is False
    assert cfg.pool["max_conn_per_target"] == 5

def test_streamable_http_app_returns_asgi():
    mcp = FastMCP("t")
    app = streamable_http_app(mcp)
    assert callable(getattr(app, "__call__", None))  # ASGI app
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd /opt/mcp_socket_server && python -m pytest tests/test_transport.py -v`
Expected: FAIL — `ModuleNotFoundError: mcp_socket_server.config`

- [ ] **Step 3: Write minimal implementation**

`src/mcp_socket_server/config.py`:
```python
"""配置加载:config.yaml + env 覆盖。"""
from __future__ import annotations
import os
from dataclasses import dataclass, field
from typing import Any
import yaml

DEFAULTS: dict[str, Any] = {
    "bind": {"host": "0.0.0.0", "port": 8080},
    "db_path": "./mcp_socket_server.db",
    "behind_proxy": False,
    "audit_retention_days": 90,
    "download_dir": "./downloads",
    "pool": {"max_conn_per_target": 5, "idle_timeout": 600,
             "borrow_timeout": 10, "max_global_concurrency": 50},
    "cmd_exec_whitelist": [],
}

@dataclass
class Config:
    host: str
    port: int
    db_path: str
    behind_proxy: bool
    audit_retention_days: int
    download_dir: str
    pool: dict
    cmd_exec_whitelist: list

def _deep_merge(base: dict, over: dict) -> dict:
    out = dict(base)
    for k, v in over.items():
        if isinstance(v, dict) and isinstance(out.get(k), dict):
            out[k] = _deep_merge(out[k], v)
        else:
            out[k] = v
    return out

def load_config(path: str | None = None) -> Config:
    data = dict(DEFAULTS)
    if path and os.path.isfile(path):
        with open(path) as f:
            data = _deep_merge(data, yaml.safe_load(f) or {})
    # env 覆盖(简单字段)
    if os.getenv("MCP_BIND_HOST"): data["bind"]["host"] = os.environ["MCP_BIND_HOST"]
    if os.getenv("MCP_BIND_PORT"): data["bind"]["port"] = int(os.environ["MCP_BIND_PORT"])
    if os.getenv("MCP_CONFIG_PATH"): pass
    b = data["bind"]
    return Config(host=b["host"], port=b["port"], db_path=data["db_path"],
                  behind_proxy=data["behind_proxy"],
                  audit_retention_days=data["audit_retention_days"],
                  download_dir=data["download_dir"], pool=data["pool"],
                  cmd_exec_whitelist=data["cmd_exec_whitelist"])
```

`src/mcp_socket_server/transport.py`:
```python
"""Streamable HTTP 传输。mcp SDK: mcp.run(transport='streamable-http') 或 streamable_http_app()。"""
from __future__ import annotations
import logging
from .config import Config

logger = logging.getLogger(__name__)

def streamable_http_app(mcp):
    """返回 ASGI app(供测试或外部 uvicorn)。"""
    return mcp.streamable_http_app()

def run(mcp, cfg: Config) -> None:
    """用 uvicorn 跑 Streamable HTTP。端点默认 /mcp。"""
    logger.info(f"MCP Streamable HTTP 监听 {cfg.host}:{cfg.port}/mcp")
    mcp.run(transport="streamable-http", host=cfg.host, port=cfg.port)
```

`src/mcp_socket_server/__main__.py`(覆盖):
```python
from .config import load_config
from .server import mcp, init_server
from .transport import run

def main() -> None:
    import sys
    cfg_path = sys.argv[1] if len(sys.argv) > 1 else None
    cfg = load_config(cfg_path)
    init_server(cfg)
    run(mcp, cfg)

if __name__ == "__main__":
    main()
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cd /opt/mcp_socket_server && python -m pytest tests/test_transport.py -v`
Expected: PASS(2 tests)

- [ ] **Step 5: Commit**

```bash
cd /opt/mcp_socket_server
git add src/mcp_socket_server/config.py src/mcp_socket_server/transport.py src/mcp_socket_server/__main__.py tests/test_transport.py
git commit -m "feat: config loader + Streamable HTTP transport + CLI"
```

---

### Task 7: server.py 只读工具 + 集成

**Files:**
- Modify: `src/mcp_socket_server/server.py`
- Test: `tests/test_server_read_tools.py`

**Interfaces:**
- Produces: `mcp`(FastMCP 实例)、`init_server(cfg)`(占位,Plan 2 接 registry/audit/locks)、只读 MCP 工具 `version_query`/`isfile`/`isdir`/`routeinfo`/`command_exists`/`filesize`/`version_detail`/`pcap_flow_extract`(均 `targets: list[str]`,返回 `{ok, failed, results}`)

- [ ] **Step 1: Write the failing test**

`tests/test_server_read_tools.py`:
```python
import pytest
from mcp_socket_server.server import mcp, init_server
from mcp_socket_server.config import load_config

@pytest.fixture
def app(mock_server, tmp_path, monkeypatch):
    cfg = load_config(None)
    cfg.db_path = str(tmp_path / "t.db")
    init_server(cfg)
    return mcp.streamable_http_app()

@pytest.mark.asyncio
async def test_version_query_tool(app, mock_server):
    from httpx import AsyncClient, ASGITransport
    # 用 mcp client 调工具太重;直接调 tool 函数验证
    from mcp_socket_server.server import version_query
    res = version_query([mock_server.host], port=mock_server.port)
    assert res["ok"] == 1
    assert res["results"][0]["version"] == "1.3.9-mock"

def test_isfile_and_isdir_tools(mock_server, tmp_path):
    from mcp_socket_server.server import isfile, isdir
    f = tmp_path / "a.txt"; f.write_text("x")
    r1 = isfile([mock_server.host], str(f), port=mock_server.port)
    assert r1["ok"] == 1 and r1["results"][0]["exists"] is True
    r2 = isdir([mock_server.host], str(tmp_path), port=mock_server.port)
    assert r2["ok"] == 1 and r2["results"][0]["exists"] is True

def test_pcap_flow_extract_tool(mock_server):
    from mcp_socket_server.server import pcap_flow_extract
    r = pcap_flow_extract([mock_server.host], "/d", port=mock_server.port)
    assert r["ok"] == 1 and r["results"][0]["flows"][0]["protoType"] == 1
```

注:`version_query` 等工具是 sync def,FastMCP 注册;测试直接调用函数(不经 HTTP),验证 batch + 新 client。

- [ ] **Step 2: Run test to verify it fails**

Run: `cd /opt/mcp_socket_server && python -m pytest tests/test_server_read_tools.py -v`
Expected: FAIL — `init_server`/`pcap_flow_extract`/`isdir` 等不存在

- [ ] **Step 3: Write minimal implementation**

`src/mcp_socket_server/server.py`(整文件覆盖):
```python
"""MCP server 入口(一期:只读工具 + Streamable HTTP)。

工具保持 sync def,FastMCP 自动放 threadpool 跑。Plan 2 加 registry/audit/locks + 写工具。
"""
from __future__ import annotations
import logging
from typing import Any

from mcp.server.fastmcp import FastMCP

from .pool import get_scheduler

logger = logging.getLogger(__name__)
logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")

mcp = FastMCP("mcp-socket-server")

def init_server(cfg) -> None:
    """Plan 2 接 registry/audit/locks。本期占位。"""
    logger.info(f"init_server: db={cfg.db_path} bind={cfg.host}:{cfg.port} (registry/audit/locks 待 Plan 2)")

def _batch(targets, fn, port=9000, timeout=15):
    sched = get_scheduler()
    results = sched.batch(targets, fn, port=port, timeout=timeout)
    return {
        "ok": sum(1 for r in results if r.ok),
        "failed": [{"target": r.target, "reason": r.error} for r in results if not r.ok],
        "results": [r.data for r in results if r.ok],
    }

@mcp.tool()
def version_query(targets: list[str], port: int = 9000) -> dict:
    """查询多台靶机 socket_server 版本号(datatype 14)。"""
    sched = get_scheduler()
    results = sched.batch(targets, lambda c: c.version(), port=port, timeout=15)
    return {"ok": sum(1 for r in results if r.ok),
            "failed": [{"target": r.target, "reason": r.error} for r in results if not r.ok],
            "results": [{"target": r.target, "version": r.data} for r in results if r.ok]}

@mcp.tool()
def isfile(targets: list[str], path: str, port: int = 9000) -> dict:
    """检查文件是否存在(datatype 7)。"""
    sched = get_scheduler()
    results = sched.batch(targets, lambda c: c.isfile(path), port=port, timeout=15)
    return {"ok": sum(1 for r in results if r.ok),
            "failed": [{"target": r.target, "reason": r.error} for r in results if not r.ok],
            "results": [{"target": r.target, "exists": r.data} for r in results if r.ok]}

@mcp.tool()
def isdir(targets: list[str], path: str, port: int = 9000) -> dict:
    """检查目录是否存在(datatype 8)。"""
    sched = get_scheduler()
    results = sched.batch(targets, lambda c: c.isdir(path), port=port, timeout=15)
    return {"ok": sum(1 for r in results if r.ok),
            "failed": [{"target": r.target, "reason": r.error} for r in results if not r.ok],
            "results": [{"target": r.target, "exists": r.data} for r in results if r.ok]}

@mcp.tool()
def routeinfo(targets: list[str], port: int = 9000) -> dict:
    """查询路由信息(datatype 4)。"""
    sched = get_scheduler()
    results = sched.batch(targets, lambda c: c.routeinfo(), port=port, timeout=15)
    return {"ok": sum(1 for r in results if r.ok),
            "failed": [{"target": r.target, "reason": r.error} for r in results if not r.ok],
            "results": [{"target": r.target, "routeinfo": r.data} for r in results if r.ok]}

@mcp.tool()
def command_exists(targets: list[str], cmd: str, port: int = 9000) -> dict:
    """检查命令是否存在(datatype 18,只读,不自动安装)。"""
    sched = get_scheduler()
    results = sched.batch(targets, lambda c: c.command_exists(cmd), port=port, timeout=15)
    return {"ok": sum(1 for r in results if r.ok),
            "failed": [{"target": r.target, "reason": r.error} for r in results if not r.ok],
            "results": [{"target": r.target, "exists": r.data} for r in results if r.ok]}

@mcp.tool()
def filesize(targets: list[str], path: str, port: int = 9000) -> dict:
    """查询文件字节数(datatype 11)。"""
    sched = get_scheduler()
    results = sched.batch(targets, lambda c: c.filesize(path), port=port, timeout=15)
    return {"ok": sum(1 for r in results if r.ok),
            "failed": [{"target": r.target, "reason": r.error} for r in results if not r.ok],
            "results": [{"target": r.target, "size": r.data} for r in results if r.ok]}

@mcp.tool()
def version_detail(targets: list[str], port: int = 9000) -> dict:
    """查询服务端版本详情(datatype 19;线上 v1.3.9 可能 REPO bug,失败见 failed)。"""
    sched = get_scheduler()
    results = sched.batch(targets, lambda c: c.version_detail(), port=port, timeout=15)
    return {"ok": sum(1 for r in results if r.ok),
            "failed": [{"target": r.target, "reason": r.error} for r in results if not r.ok],
            "results": [{"target": r.target, "detail": r.data} for r in results if r.ok]}

@mcp.tool()
def pcap_flow_extract(targets: list[str], pcap_dir: str, port: int = 9000) -> dict:
    """提取 pcap 五元组流(datatype 200,只读)。"""
    sched = get_scheduler()
    results = sched.batch(targets, lambda c: c.pcap_flow_extract(pcap_dir), port=port, timeout=30)
    return {"ok": sum(1 for r in results if r.ok),
            "failed": [{"target": r.target, "reason": r.error} for r in results if not r.ok],
            "results": [{"target": r.target, "flows": r.data} for r in results if r.ok]}

def main() -> None:
    mcp.run()

if __name__ == "__main__":
    main()
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cd /opt/mcp_socket_server && python -m pytest tests/ -v`
Expected: PASS(全部测试,含 mock/socket_client/pool/commands/transport/server)

- [ ] **Step 5: Commit**

```bash
cd /opt/mcp_socket_server
git add src/mcp_socket_server/server.py tests/test_server_read_tools.py
git commit -m "feat: server read tools over Streamable HTTP (14/7/8/4/18/11/19/200)"
```

---

## Self-Review(plan 自检,已执行)

**1. Spec 覆盖:** Plan 1 覆盖 spec §5(socket_client/pool 重建)、§6(recv + gzip + 文件传输握手)、§7(pool 持久会话/复用)、§12(commands.py 修正:file 多步、+19/200、删 161/162/163、pin mcp)、§4 只读工具、§2 协议权威(mock 复刻 protocol.py)。未覆盖(Plan 2):registry/audit/locks(§9/§10)、写工具 cmd_exec/file/capture/boce(§11)、@tag 解析、audit 装饰器。

**2. 占位符扫描:** 无 TBD/TODO;每个 step 有完整代码或确切命令。

**3. 类型一致:** `SocketServerClient` 方法名(version/isfile/...)在 Task 2/3 定义、Task 4 pool fn 回调用、Task 7 server 工具调用——一致。`TargetPool.acquire/release/close_all`、`Scheduler.batch`、`TargetResult(target,ok,data,error)` 一致。`Config` 字段(host/port/db_path/...)在 Task 6 定义、`__main__` 用——一致。

**4. 已知风险(实现时注意):**
- Task 6 `mcp.run(transport="streamable-http", host=, port=)` 与 `streamable_http_app()` 的确切签名以安装的 mcp SDK 版本为准(v1.12.4 已确认支持);若版本差异,查 `/modelcontextprotocol/python-sdk` docs。
- `_recv_until_timeout` 的 0.5s timeout 是原始 JSON 响应的延迟下限;批量并行下可接受。若响应分片,调大 timeout 或改 length-prefixed(协议层无法,因原始 JSON 无前缀)。
- mock server 的 `routeinfo` 返回格式为占位(`{"default":{"Iface":"mock_eth0"}}`);真实格式以 `socket_server/netutils.py routeinfo()` 为准(Plan 2 capture auto-eth 用到时核对)。
