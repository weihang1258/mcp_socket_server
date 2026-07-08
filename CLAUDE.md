# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

`mcp_socket_server` - MCP server bridging LLM platforms to multiple socket_server targets. Batch-parallel execution of capture/boce/command/file ops with auth, audit, and state-locking. Runs as a central node, connects to N socket_server targets over TCP.

## Critical: Protocol Contract Source

This project does **NOT** own the socket_server protocol. It is a consumer. The protocol contract lives in the **socket_server** repository (sibling directory `/opt/socket_server`). Always cross-reference before changing protocol-touching code.

| What you're doing | Must read first in socket_server repo |
|---|---|
| Change `commands.py` (datatype numbers, params, lock classes) | `socket_server/handlers.py` `do()` function - authoritative datatype→handler+param mapping |
| Change `socket_client.py` (frame format, send/recv) | `socket_server/test_e2e.py` - authoritative frame + `send_request`/`recv_*` logic. Must stay byte-level identical |
| Look up any datatype's params/response/example | `socket_server/docs/api-guide.md` - per-datatype param + response + example table. **查 "type X 是什么/参数/示例" 先看这里** |
| Design tools / concurrency rules | `socket_server/docs/mcp-integration.md` - datatype table with lock-class/concurrency/danger markings |

**Never invent datatype numbers or param field names from memory.** Always derive from `handlers.py` / `api-guide.md`. The `commands.py` and `socket_client.py` headers pin these sources.

### 特殊协议（易踩坑）
- **文件上传是 21->22->23->24 四步握手**（非单个 datatype），在 `socket_server/protocol.py` 协议层处理（不在 `handlers.py` 的 `do()`），**必须同一 TCP 连接完成**。`file_upload` 工具需独占连接，连接池"一连接一请求"假设在此不成立。详见 `api-guide.md` "文件上传流程"。
- **文件下载 type 3** 路径走 `kwargs["filepath"]`（非 payload 的 `path`），响应是 `[8B 长度 Q][文件内容]`。
- **scapy 抓包 121/122/123 已弃用**，MCP 层勿暴露。业务用 type 5/6（tcpdump 命令行）。

## Sync Rule (prevent drift)

When socket_server protocol changes, sync in this order (see socket_server `docs/mcp-integration.md` §8):
1. socket_server changes `handlers.py` `do()`
2. socket_server updates `test_e2e.py` client + `docs/mcp-integration.md` datatype table
3. socket_server releases new version
4. **This project**: update `socket_client.py` (frame/recv) + `commands.py` (datatype/params)

## Architecture

```
LLM client ──MCP──► mcp_socket_server (this project, central node, 1 instance)
                          │ TCP client (socket_client.py)
                          ▼
                  socket_server (per-target :9000, N instances)
```

- **Deployment**: central node, 1 instance. socket_server is per-target, N instances. They are independent projects/repos/releases.
- **Batch-first**: every tool takes `targets: list[str]`, fans out to parallel targets, returns per-target results. Never one-tool-per-target.
- **State locks**: per-target multi-mode lock by `lock_class` (see `commands.py`). Read=shared, capture=by(iface,path), SYSTEM=global exclusive.
- **Connection pool**: per-target, `min_idle=0`, `max_conn=5`, `idle_timeout=10min`. socket_server is request-response (closes conn after), so pool is mainly for concurrency limiting.

## Module Map

- `src/mcp_socket_server/socket_client.py` - TCP client (derived from socket_server/test_e2e.py)
- `src/mcp_socket_server/commands.py` - command registry: datatype → (lock_class, danger, lock_key_fields)
- `src/mcp_socket_server/pool.py` - per-target connection pool + batch scheduler (`Scheduler.batch()`)
- `src/mcp_socket_server/server.py` - FastMCP entry + tool definitions
- `src/mcp_socket_server/__main__.py` - `mcp-socket-server` CLI entrypoint

## Build & Run

```bash
cd /opt/mcp_socket_server
python3.10 -m venv venv
source venv/bin/activate
pip install -e .          # installs mcp, anyio; creates mcp-socket-server command
mcp-socket-server         # stdio transport, for local MCP clients
```

For remote/multi-user: switch `server.py` to SSE/streamable HTTP (TODO).

## Current State (0.1.0)

Read-only tools wired (version_query / isfile / routeinfo / list_targets) to prove the pipeline. TODO:
- Target registry (config/DB) + `list_targets` real impl
- State-lock enforcement in `pool.py` (registry defined in `commands.py`, not yet enforced)
- Write tools (capture/cmd_exec/boce/version_switch) with danger confirmation
- Auth + audit logging
- SSE transport for remote

## Key Patterns

- **No shell injection risk here** (this project doesn't run shell commands; it speaks socket_server protocol). But `cmd_exec` tool passes through to socket_server datatype 1 - enforce a command whitelist at MCP layer before forwarding.
- **Partial failure is normal**: `Scheduler.batch()` returns per-target `TargetResult`; one target failing never fails the batch. LLM sees `{ok: N, failed: [...]}`.
- **Danger tools need confirmation**: `version_switch` / `firewall_disable` / `cmd_exec` are `Danger.DANGER` in `commands.py` - MCP layer must elicit confirmation before executing.
