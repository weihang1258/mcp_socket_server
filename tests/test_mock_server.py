import json
import struct
import socket

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
            if not chunk:
                break
            data += chunk
            s.settimeout(0.3)
            try:
                extra = s.recv(4096)
                if not extra:
                    break
                data += extra
            except socket.timeout:
                break
        s.close()
        assert json.loads(data) == "1.3.9-mock"
    finally:
        srv.stop()
