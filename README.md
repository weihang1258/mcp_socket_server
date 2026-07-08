# mcp_socket_server

MCP server，桥接 LLM 平台与多台 socket_server 靶机。批量并行执行抓包/拨测/命令/文件操作，带鉴权、审计、状态锁。

## 架构

```
LLM 客户端 ──MCP──► mcp_socket_server（本项目，中央节点）
                          │ TCP 客户端
                          ▼
                  socket_server（每台靶机 :9000）
```

详细对接契约见 socket_server 仓库的 `docs/mcp-integration.md`。

## 安装

```bash
cd /opt/mcp_socket_server
python3.10 -m venv venv
source venv/bin/activate
pip install -e .
```

## 运行（stdio，本地）

```bash
mcp-socket-server
```

接入 Claude Code / Cursor 等 MCP 客户端时，配置 stdio 启动本命令。

## 当前状态（0.1.0）

首批只读工具跑通链路：
- `list_targets` — 列靶机（占位）
- `version_query(targets)` — datatype 14
- `isfile(targets, path)` — datatype 7
- `routeinfo(targets)` — datatype 4

待加：连接池健康检查、靶机注册表、状态锁（commands.py 已定义）、写类工具、鉴权审计、SSE 远程传输。

## 模块

- `socket_client.py` — TCP 客户端（源自 socket_server/test_e2e.py）
- `commands.py` — 命令注册表（datatype → 锁类/危险等级）
- `pool.py` — 每靶机连接池 + 批量调度
- `server.py` — MCP server 入口 + 工具定义

## 与 socket_server 的关系

独立项目、独立 git 仓库、独立部署。唯一耦合是 socket_server 的 TCP 协议（datatype 表），权威定义在 socket_server 仓库，本项目 `commands.py` 派生自它。
