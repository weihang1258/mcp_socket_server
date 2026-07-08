from mcp_socket_server.pool import (
    MAX_CONN_PER_TARGET,
    Scheduler,
    TargetPool,
    TargetResult,
)


def test_batch_read_fanout(mock_server):
    sched = Scheduler()
    results = sched.batch([mock_server.host], lambda c: c.version(),
                          port=mock_server.port, timeout=5)
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
    p = TargetPool(mock_server.host, mock_server.port)
    c1 = p.acquire(timeout=5)
    c1.version()
    p.release(c1)
    c2 = p.acquire(timeout=5)  # 应复用同一条连接(服务端持久连接)
    assert c2 is c1
    p.release(c2)
    p.close_all()


def test_acquire_connect_failure_no_leak(mock_server):
    # blocker 4 回归:connect 失败必须递减 _inuse,否则 MAX_CONN_PER_TARGET 次失败后池永久耗尽
    p = TargetPool("127.0.0.1:1", mock_server.port)  # 无效 host,connect 必失败
    for _ in range(MAX_CONN_PER_TARGET + 2):
        try:
            p.acquire(timeout=1)
        except Exception:
            pass
    # 无修复:_inuse 会累积到 5(池满,后续 acquire 永久阻塞);有修复:_inuse 归 0
    assert p._inuse == 0
    p.close_all()


def test_acquire_socket_timeout_propagated(mock_server):
    # warning 回归:用户 batch timeout 应传到 SocketServerClient,约束 connect+recv,而非只设 read
    p = TargetPool(mock_server.host, mock_server.port)
    c = p.acquire(timeout=5, socket_timeout=7)
    assert c.timeout == 7
    p.release(c)
    # 经 batch 路径:batch(timeout=9) -> _run_one -> acquire(socket_timeout=9)
    sched = Scheduler()
    sched.batch([mock_server.host], lambda c: None,
                port=mock_server.port, timeout=9)
    pool = sched.get_pool(mock_server.host, mock_server.port)
    pc = pool._idle[-1]
    assert pc.client.timeout == 9
    pool.close_all()
