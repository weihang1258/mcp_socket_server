# mcp_socket_server

MCP server 桥接 LLM 平台到 N 个 socket_server 靶机。批量并行执行 capture/boce/command/file ops,支持状态锁与审计。中央节点单实例,靶机每台 :9000 TCP。

## 快速开始

```bash
# 安装
cd /opt/mcp_socket_server
python3.10 -m venv venv && source venv/bin/activate
pip install -e ".[dev]"

# 启动（Streamable HTTP，远程模式）
cp config.example.yaml config.yaml   # 编辑修改
mcp-socket-server config.yaml

# 或标准输入模式（本机 MCP client 用）
mcp-socket-server
```

## 架构

```
LLM client ──MCP──► mcp_socket_server (本服务, 1 实例)
                          │ TCP socket_client
                          ▼
                  socket_server (每靶机 :9000, N 实例)
```

- 每个 **工具** 都接受 `targets: list[str]` → 并发发往多台靶机 → 汇总返回 `{ok, failed, results}`
- 部分失败是正常设计：一台 down 不影响其他
- 靶机 IP 目前手填（Plan 2 接 SQLite 注册表 + `@tag` 选机）

## 配置

参见 [config.example.yaml](config.example.yaml)。配置项：

| 项 | 默认 | 说明 |
|---|---|---|
| `bind.host` | 0.0.0.0 | 监听地址 |
| `bind.port` | 8080 | MCP HTTP 端口 |
| `pool.max_conn_per_target` | 5 | 单靶机最大并发连接数 |
| `pool.max_global_concurrency` | 50 | 全局并行靶机数上限 |

## 已注册工具（Phase 1）

| 工具 | datatype | 说明 |
|---|---|---|
| `version_query(targets, port?)` | 14 | 查询版本号 |
| `isfile(targets, path, port?)` | 7 | 文件是否存在 |
| `isdir(targets, path, port?)` | 8 | 目录是否存在 |
| `routeinfo(targets, port?)` | 4 | 路由信息（含默认网卡） |
| `command_exists(targets, cmd, port?)` | 18 | 命令是否存在 |
| `filesize(targets, path, port?)` | 11 | 文件大小 |
| `version_detail(targets, port?)` | 19 | 版本详情（⚠️ v1.3.9 线上可能崩溃，见下方说明） |
| `pcap_flow_extract(targets, pcap_dir, port?)` | 200 | pcap 五元组流提取 |
| `list_targets()` | - | 列出注册靶机（占位） |

### 已知问题：version_detail（datatype 19）

socket_server v1.3.9 的 handlers.py 中引用了 REPO 但未 import，调用 version_detail 会使服务端崩溃断开连接。如线上未升级，请勿使用此工具。影响范围仅 version_detail，其他 7 个只读工具正常。

## MCP Client 配置

### 在 Claude Code 中使用（stdio 本地）

```json
// ~/.claude/settings.json 或项目 .claude/settings.json
{
  "mcpServers": {
    "mcp-socket-server": {
      "command": "/opt/mcp_socket_server/venv/bin/python",
      "args": ["-m", "mcp_socket_server"]
    }
  }
}
```

### Streamable HTTP（远程 / 多客户端）

```json
{
  "mcpServers": {
    "mcp-socket-server": {
      "url": "http://your-server:8080/mcp"
    }
  }
}
```
先启动服务端：`mcp-socket-server config.yaml`

## 自动方向功能

有，通过 `routeinfo(targets)` 工具。它的 datatype 4 查询靶机路由表，返回当前默认网关和网卡信息。这是 Plan 2 `capture_start` 工具「iface 自动选择」的基础——当 iface 留空时，先调 `routeinfo` 取默认网卡。

目前为只读工具，你可以直接调用看靶机路由：
```json
{"targets": ["10.0.0.1"]}
→ {"ok":1, "results":[{"target":"10.0.0.1", "routeinfo":{"default":{"Iface":"eth0",...}}}]}
```

## 开发

```bash
pytest tests/ -v
# 21 tests, 全部通过
```

### 协议同步

本项目是 [socket_server](https://github.com/weihang1258/socket_server) 协议的 **消费者**。协议变更时按以下顺序同步：

1. socket_server 修改 handlers.py / protocol.py / test_e2e.py
2. 本仓库更新 socket_client.py（帧 + recv）+ commands.py（datatype/params）
3. 运行全量测试

## Phase 2 规划

- target 注册表（SQLite + @tag 选机）
- 状态锁强制执行
- 审计日志
- 写工具：cmd_exec / file_upload / file_download / capture_start/stop / boce_run