import pytest

from tests.mock_socket_server import MockSocketServer


@pytest.fixture
def mock_server():
    srv = MockSocketServer()
    srv.start()
    yield srv
    srv.stop()
