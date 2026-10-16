from __future__ import annotations

import threading
import os

import pytest

from mcp_socket_server.locks import LockManager, LockConflict
from mcp_socket_server.commands import LockClass


class TestTargetLock:
    def test_capture_lock_exclusive_by_path(self):
        lm = LockManager()
        lm.acquire("10.0.0.1", LockClass.CAPTURE, ("/tmp/a.pcap",))
        # 同 path 冲突
        with pytest.raises(LockConflict):
            lm.acquire("10.0.0.1", LockClass.CAPTURE, ("/tmp/a.pcap",))
        # 不同 path 可并发
        lm.acquire("10.0.0.1", LockClass.CAPTURE, ("/tmp/b.pcap",))
        lm.release("10.0.0.1", LockClass.CAPTURE, ("/tmp/a.pcap",))
        lm.release("10.0.0.1", LockClass.CAPTURE, ("/tmp/b.pcap",))

    def test_exclusive_lock_blocks_others(self):
        lm = LockManager()
        lm.acquire("10.0.0.1", LockClass.SHELL)
        # CAPTURE 与 SHELL 不兼容
        with pytest.raises(LockConflict):
            lm.acquire("10.0.0.1", LockClass.CAPTURE, ("/p.pcap",))
        with pytest.raises(LockConflict):
            lm.acquire("10.0.0.1", LockClass.BROWSER)
        lm.release("10.0.0.1", LockClass.SHELL)

    def test_none_is_free(self):
        lm = LockManager()
        lm.acquire("10.0.0.1", LockClass.NONE)
        lm.acquire("10.0.0.1", LockClass.NONE)  # NONE 从不冲突
        # NONE 不影响排他
        lm.acquire("10.0.0.1", LockClass.SHELL)
        lm.release("10.0.0.1", LockClass.SHELL)

    def test_capture_blocks_exclusive(self):
        lm = LockManager()
        lm.acquire("10.0.0.1", LockClass.CAPTURE, ("/p.pcap",))
        with pytest.raises(LockConflict):
            lm.acquire("10.0.0.1", LockClass.FILE_IO)
        lm.release("10.0.0.1", LockClass.CAPTURE, ("/p.pcap",))

    def test_has_active(self):
        lm = LockManager()
        assert not lm.has_active("10.0.0.1")
        lm.acquire("10.0.0.1", LockClass.CAPTURE, ("/p.pcap",))
        assert lm.has_active("10.0.0.1")
        lm.release("10.0.0.1", LockClass.CAPTURE, ("/p.pcap",))
        assert not lm.has_active("10.0.0.1")

    def test_multitarget_independence(self):
        lm = LockManager()
        lm.acquire("10.0.0.1", LockClass.SHELL)
        lm.acquire("10.0.0.2", LockClass.CAPTURE, ("/p.pcap",))
        lm.release("10.0.0.1", LockClass.SHELL)
        lm.release("10.0.0.2", LockClass.CAPTURE, ("/p.pcap",))


def test_system_lock_per_target_exclusive():
    from mcp_socket_server.locks import LockManager, LockConflict
    from mcp_socket_server.commands import LockClass
    mgr = LockManager()
    mgr.acquire("t1", LockClass.SYSTEM)      # 不再 raise(stub 移除)
    try:
        mgr.acquire("t1", LockClass.SHELL)
        assert False, "SYSTEM 持有期间 SHELL 应冲突"
    except LockConflict:
        pass
    mgr.acquire("t2", LockClass.SHELL)        # 不同靶机不受影响(per-target)
    mgr.release("t1", LockClass.SYSTEM)
    mgr.acquire("t1", LockClass.SHELL)        # 释放后可获取
    mgr.release("t1", LockClass.SHELL)
    mgr.release("t2", LockClass.SHELL)


def test_replay_lock_exclusive_with_capture():
    from mcp_socket_server.locks import LockManager, LockConflict
    from mcp_socket_server.commands import LockClass
    mgr = LockManager()
    mgr.acquire("t1", LockClass.REPLAY)
    try:
        mgr.acquire("t1", LockClass.CAPTURE, ("/tmp/a.pcap",))
        assert False, "REPLAY 持有期间 CAPTURE 应冲突"
    except LockConflict:
        pass
    mgr.release("t1", LockClass.REPLAY)
    mgr.acquire("t1", LockClass.CAPTURE, ("/tmp/a.pcap",))
    mgr.release("t1", LockClass.CAPTURE, ("/tmp/a.pcap",))