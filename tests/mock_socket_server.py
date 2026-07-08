"""测试用 mock socket_server,复刻 socket_server/protocol.py handle() 循环 +
各 datatype 响应格式(对齐 handlers.py do() 返回)。用于 socket_client/pool 测试。

协议权威:/opt/socket_server 的 protocol.py handle() + handlers.py do() + test_e2e.py。
本 mock 经验证 workflow 对照权威源核验(2026-07-08):
  - 持久连接 while True 循环(复刻 protocol.py:33)
  - 21/22/23/24 文件握手状态机(复刻 protocol.py:77-119);23 无 datatype 字段
  - datatype 响应格式:原始 JSON(4/7/8/11/14/18/19/5/6)、[4B len][gzip](1)、
    [4B len][json](131/200)、[8B <Q len][content](3/174)、b"ok"(15/172/173)
  - 字段名对齐 handlers.py:isfile 读 "file"、isdir 读 "dir"、filesize 读 "path"、
    command_exists 读 "cmd"、pcap_flow_extract 读 "pcap_dir"
"""
import json
import struct
import gzip
import os
import socketserver
import threading

VERSION = "1.3.9-mock"


def _compress(b: bytes) -> bytes:
    return gzip.compress(b)


def _decompress(b: bytes) -> bytes:
    return gzip.decompress(b)


class _Handler(socketserver.BaseRequestHandler):
    def setup(self):
        self.filepath = "tmp"
        self.content = b""
        self.length = 0
        self.bin_recv_flag = False
        self.bufsize = 10240
        self.gzip = False

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
                datatotal = b""
                data_len = 0
                continue
            data = datatotal
            datatotal = b""
            data_len = 0

            if not self.bin_recv_flag:
                datatype = struct.unpack("i", data[:4])[0]
                data = data[4:]
            else:
                datatype = 23

            if datatype in (21,):
                info = json.loads(data)
                self.filepath = info.get("filepath", "tmp")
                self.gzip = info.get("gzip", False)
                self.request.sendall(b"21 ok")
                continue
            elif datatype in (22,):
                self.length = struct.unpack("<Q", data)[0]
                self.content = b""
                self.bin_recv_flag = True
                self.bufsize = 102400000
                self.request.sendall(b"22 ok")
                continue
            elif datatype in (23,):
                self.content += data
                if len(self.content) == self.length:
                    self.bufsize = 1024
                    self.bin_recv_flag = False
                    self.request.sendall(b"23 ok")
                    continue
                elif len(self.content) > self.length:
                    self.bin_recv_flag = False
                    break
                else:
                    continue
            elif datatype in (24,):
                content = _decompress(self.content) if self.gzip else self.content
                if content == b"^$":
                    content = b""
                with open(self.filepath, "wb") as f:
                    f.write(content)
                self.content = b""
                self.request.sendall(b"24 ok")
                continue

            resp = self._on_data(datatype, data)
            if resp is not None:
                self.request.sendall(resp)

    def _on_data(self, datatype, data):
        # 只读类:原始 JSON(无长度前缀)
        if datatype == 14:
            return json.dumps(VERSION).encode()
        if datatype == 7:
            return json.dumps({"res": os.path.isfile(json.loads(data)["file"])}).encode()
        if datatype == 8:
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
            # 文件下载:filepath 由 21 设置(同 test_e2e.py:360-361);payload 仅 {"gzip":bool}
            if not os.path.isfile(self.filepath):
                # 真实服务端 FileNotFoundError->关连接;mock 返回零长度帧避免客户端 _recv_n 阻塞
                return struct.pack("<Q", 0) + b""
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
