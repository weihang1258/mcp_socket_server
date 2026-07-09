# mcp_socket_server

MCP server 桥接 LLM 平台到 N 个 socket_server 靶机。批量并行执行 capture/boce/command/file ops,支持状态锁、靶机注册表与审计。中央节点单实例,靶机每台 :9000 TCP。

## 架构

```
LLM client (Cherry Studio / Claude Code / ...)
    └── MCP (Streamable HTTP 或 stdio)
        └── mcp_socket_server (本服务, 中央节点, 1 实例)
                └── TCP socket_client (每靶机独立连接池)
                    └── socket_server (每靶机 :9000, N 实例)
```

- 每个**工具**都接受 `targets: list[str]` -> 并发发往多台靶机 -> 汇总返回 `{ok, failed, results}`
- 部分失败是正常设计:一台 down 不影响其他
- `targets` 可填裸 IP(`10.0.0.1`)、`host:port`(`10.0.0.1:9000`)、或 `@tag`(`@web`,需先 add_target 注册)

---

## 1. 下载

```bash
# 方式一: git clone(若有远程仓库)
git clone <repo-url> /opt/mcp_socket_server
cd /opt/mcp_socket_server

# 方式二: 直接使用已部署的代码
cd /opt/mcp_socket_server
git pull   # 更新到最新
```

依赖的 Python 版本:**>=3.10**(mcp SDK 要求)。系统若只有 3.8,用 uv 装 3.10(见下文「常见问题」)。

---

## 2. 安装

```bash
cd /opt/mcp_socket_server

# 创建虚拟环境(需 python3.10+)
python3.10 -m venv venv

# 激活
source venv/bin/activate

# 安装本包 + 依赖(mcp / uvicorn / pyyaml / anyio)+ 开发依赖(pytest / httpx)
pip install -e ".[dev]"
```

验证安装:

```bash
venv/bin/python -c "from mcp_socket_server.server import mcp; print('OK')"
venv/bin/mcp-socket-server --help 2>&1 || echo "命令存在(无 --help 是正常,直接启动)"
```

---

## 3. 配置

```bash
cp config.example.yaml config.yaml
vi config.yaml
```

**每一项的详细说明见 [config.example.yaml](config.example.yaml)**(含枚举值、单位、默认值、示例)。最常改的几项:

| 项 | 说明 | 常用值 |
|---|---|---|
| `bind.host` | 监听 IP | `0.0.0.0`(内网) / `127.0.0.1`(本机) |
| `bind.port` | HTTP 端口 | `8080` |
| `log_level` | 日志级别 | `INFO`(生产) / `DEBUG`(排障) |
| `cmd_exec_whitelist` | 命令白名单 | `[]`(全放行) / `["ls","ping","tcpdump"]` |

环境变量可覆盖:`MCP_BIND_HOST` / `MCP_BIND_PORT` / `MCP_LOG_LEVEL`。

---

## 4. 启动

### 4.1 前台启动(调试用,直接看日志)

```bash
cd /opt/mcp_socket_server
venv/bin/mcp-socket-server config.yaml
```

看到 `Uvicorn running on http://0.0.0.0:8080` 即启动成功。`Ctrl+C` 停止。

### 4.2 后台启动(生产用,日志落盘)

```bash
cd /opt/mcp_socket_server
nohup venv/bin/mcp-socket-server config.yaml \
  > /var/log/mcp-socket-server.log 2>&1 &

# 记下 PID
echo $! > /var/run/mcp-socket-server.pid
echo "started, pid=$(cat /var/run/mcp-socket-server.pid)"
```

### 4.3 systemd 服务(推荐,开机自启 + 自动拉起)

创建 `/etc/systemd/system/mcp-socket-server.service`:

```ini
[Unit]
Description=MCP Socket Server
After=network.target

[Service]
Type=simple
User=root
WorkingDirectory=/opt/mcp_socket_server
ExecStart=/opt/mcp_socket_server/venv/bin/mcp-socket-server /opt/mcp_socket_server/config.yaml
Restart=on-failure
RestartSec=5
StandardOutput=append:/var/log/mcp-socket-server.log
StandardError=append:/var/log/mcp-socket-server.log

[Install]
WantedBy=multi-user.target
```

```bash
# 首次建日志文件
touch /var/log/mcp-socket-server.log

systemctl daemon-reload
systemctl enable mcp-socket-server
systemctl start mcp-socket-server
systemctl status mcp-socket-server
```

### 4.4 stdio 模式(本机 MCP client 直接拉起,无需常驻)

Cherry Studio / Claude Code 配置成 stdio 模式时,client 会自动启停本服务,无需手动启动。见第 6 节。

---

## 5. 停止

| 启动方式 | 停止命令 |
|---|---|
| 前台 | `Ctrl+C` |
| nohup 后台 | `kill $(cat /var/run/mcp-socket-server.pid)` |
| systemd | `systemctl stop mcp-socket-server` |

确认进程已退出:

```bash
ps aux | grep mcp-socket-server | grep -v grep
# 应无输出
```

---

## 6. 日志查询

### 6.1 systemd 启动的日志

```bash
# 实时跟踪
journalctl -u mcp-socket-server -f

# 最近 100 行
journalctl -u mcp-socket-server -n 100

# 今天的日志
journalctl -u mcp-socket-server --since today

# 某次报错前后
journalctl -u mcp-socket-server --since "10 min ago" | grep -i error
```

### 6.2 nohup / 文件日志

```bash
# 实时跟踪
tail -f /var/log/mcp-socket-server.log

# 最近 50 行
tail -50 /var/log/mcp-socket-server.log

# 只看错误
grep -iE "error|exception|failed" /var/log/mcp-socket-server.log | tail -30
```

### 6.3 开 DEBUG 排障

`config.yaml` 改 `log_level: DEBUG`,重启。DEBUG 下会输出全链路:

```
cmd_exec CALLED: targets=["10.12.131.32"] args='echo hi'
[10.12.131.32] lock acquired: shell
[10.12.131.32] pool acquire (12ms)
connect start: 10.12.131.32:9000 timeout=60s
connect OK: 10.12.131.32:9000
cmd_exec send: dt=1 args='echo hi'
recv_gzip: got 45B gzip
[10.12.131.32] fn done (23ms)
```

根据日志停在哪一行即可定位问题(见「常见问题」)。

### 6.4 审计日志(SQLite)

每次写工具调用都会记一条审计:

```bash
venv/bin/python -c "
import sqlite3
c = sqlite3.connect('mcp_socket_server.db')
for r in c.execute('SELECT ts,tool,ok_count,failed_count FROM audit_log ORDER BY id DESC LIMIT 10'):
    print(r)
"
```

---

## 7. MCP 对接(Cherry Studio / Claude Code 等)

### 7.1 Streamable HTTP(远程,推荐)

先按第 4 节启动服务(假设 server 在 `10.12.131.81:8080`)。

**Cherry Studio**:设置 -> MCP 服务器 -> 添加

- 类型:`URL` / `Streamable HTTP`
- URL:`http://10.12.131.81:8080/mcp`
- 名称:`mcp-socket-server`

保存后 Cherry Studio 会自动 `list_tools` 发现 17 个工具。

**Claude Code**(`~/.claude/settings.json` 或项目 `.claude/settings.json`):

```json
{
  "mcpServers": {
    "mcp-socket-server": {
      "url": "http://10.12.131.81:8080/mcp"
    }
  }
}
```

### 7.2 stdio(本机,client 自动启停)

适合 Cherry Studio / Claude Code 与 server 在同一台机器。

**Cherry Studio**:类型选 `stdio`

- 命令:`/opt/mcp_socket_server/venv/bin/python`
- 参数:`-m mcp_socket_server`

**Claude Code**:

```json
{
  "mcpServers": {
    "mcp-socket-server": {
      "command": "/opt/mcp_socket_server/venv/bin/python",
      "args": ["-m", "mcp_socket_server"]
    }
  }
}
```

stdio 模式无需 config.yaml(用默认配置,bind 0.0.0.0:8080)。若要自定义,改参数为 `["-m", "mcp_socket_server", "/path/to/config.yaml"]`。

### 7.3 验证对接

对接成功后,在 client 的工具列表里应看到 17 个工具(见下文工具表)。可直接让 LLM 调用:

> "查一下 10.12.131.32 的 socket_server 版本"

LLM 会调 `version_query(targets=["10.12.131.32"])`,返回版本号。

---

## 8. 工具列表(17 个)

### 只读(NONE/SAFE,无锁)

| 工具 | datatype | 说明 |
|---|---|---|
| `version_query(targets, port?)` | 14 | 查版本号 |
| `isfile(targets, path, port?)` | 7 | 文件是否存在 |
| `isdir(targets, path, port?)` | 8 | 目录是否存在 |
| `routeinfo(targets, port?)` | 4 | 路由信息(含默认网卡) |
| `command_exists(targets, cmd, port?)` | 18 | 命令是否存在 |
| `filesize(targets, path, port?)` | 11 | 文件大小 |
| `version_detail(targets, port?)` | 19 | 版本详情(⚠️ 见下) |
| `pcap_flow_extract(targets, pcap_dir, port?)` | 200 | pcap 五元组流 |

### 写(有锁 + 审计)

| 工具 | datatype | 锁类 | 说明 |
|---|---|---|---|
| `cmd_exec(targets, args, cwd?, env?, wait?, port?)` | 1 | SHELL | 执行命令(白名单校验) |
| `capture_start(targets, iface?, path, port?)` | 5 | CAPTURE | 开始抓包(持锁到 stop) |
| `capture_stop(targets, path, port?)` | 6 | CAPTURE | 停止抓包(释放锁) |
| `boce_run(targets, url, count?, ..., port?)` | 131 | BROWSER | 拨测 |
| `file_upload(targets, remote_path, content_b64, port?)` | 21-24 | FILE_IO | 上传文件 |
| `file_download(targets, path, port?)` | 21-3 | FILE_IO | 下载文件 |

### 注册表

| 工具 | 说明 |
|---|---|
| `add_target(host, port?, tags?, note?)` | 注册靶机 |
| `remove_target(host, port?)` | 移除靶机(有活跃锁时拒绝) |
| `list_targets()` | 列出已注册靶机 |

### 返回格式(统一)

```json
{
  "ok": 2,
  "failed": [{"target": "10.0.0.3", "reason": "Connection refused"}],
  "results": [{"target": "10.0.0.1", "version": "1.3.9"}, ...]
}
```

---

## 9. 常见问题

### Q: 启动报 `mcp-socket-server: command not found`

没激活 venv。用完整路径:`/opt/mcp_socket_server/venv/bin/mcp-socket-server config.yaml`

### Q: Cherry Studio 连接报 502 Bad Gateway

环境有 `http_proxy` 代理,client 走代理连不上本机。设 `no_proxy`:

```bash
export no_proxy="127.0.0.1,localhost,10.12.131.81"
```

或在 Cherry Studio 所在机器的系统代理里排除 server IP。

### Q: Cherry Studio 报 421 Misdirected Request

MCP SDK 默认 DNS rebinding 保护只放行 localhost。本服务已关闭此保护(`server.py` 里 `enable_dns_rebinding_protection=False`)。若仍报 421,确认用的是最新代码。

### Q: cmd_exec 超时(`MCP error -32001: Request timed out`)

按 DEBUG 日志定位(第 6.3 节):

| 日志停在哪 | 原因 | 解决 |
|---|---|---|
| 无 `cmd_exec CALLED` | Cherry Studio HTTP 超时,请求没到 server | 加 Cherry Studio 的 timeout 配置 |
| 停在 `connect start` 后无 `connect OK` | TCP 连不上靶机 | `nc -zv 靶机IP 9000` 检查网络/socket_server 是否在跑 |
| 停在 `recv_gzip start` 后无 `len prefix` | 命令在靶机执行中 | 等待;超 60s 是 socket_client timeout |
| 全跑完但 Cherry Studio 报超时 | server 正常,client 超时太短 | Cherry Studio 加 `timeout: 120000` |

含 `sleep` 的长命令建议:拆短 / 用 `wait=false` / 调大 client 超时。

### Q: 系统 Python 是 3.8,装不了 mcp

用 uv 装 3.10:

```bash
curl -LsSf https://astral.sh/uv/install.sh | sh
export PATH="$HOME/.local/bin:$PATH"
uv python install 3.10
uv venv --python 3.10 venv
uv pip install --python venv/bin/python -e ".[dev]"
```

### Q: version_detail 报错

socket_server v1.3.9 的 `handlers.py` 未 import `REPO`,调用 datatype 19 会使服务端崩溃。需在 socket_server 仓修 `handlers.py:8` 为 `from .version import VERSION, REPO`。其他工具不受影响。

---

## 10. 开发

```bash
# 跑全量测试(47 个)
venv/bin/python -m pytest tests/ -v

# 跑单个模块
venv/bin/python -m pytest tests/test_socket_client.py -v
```

### 协议同步

本项目是 [socket_server](https://github.com/weihang1258/socket_server) 协议的**消费者**。协议变更时:

1. socket_server 改 `handlers.py` / `protocol.py` / `test_e2e.py`
2. 本仓更新 `socket_client.py`(帧+recv) + `commands.py`(datatype/params)
3. 跑全量测试

### 模块结构

```
src/mcp_socket_server/
  __main__.py      CLI 入口
  config.py        配置加载(yaml + env)
  transport.py     Streamable HTTP(uvicorn)
  server.py        FastMCP + 17 个工具
  socket_client.py TCP 客户端(per-datatype recv + gzip + 文件传输)
  pool.py          连接池 + 批量调度 + session
  commands.py      datatype 注册表(锁类/危险等级)
  locks.py         LockManager(per-target 多模式锁)
  registry.py      靶机注册表(SQLite + @tag)
  audit.py         审计日志(SQLite)
```

### 已知限制

- 审计源 IP 当前为 `internal`(behind_proxy 下取 X-Forwarded-For 待实现)
- SYSTEM 锁类(version_switch/firewall/DPI)未实现
- cmd_exec 白名单为前缀匹配,有注入局限(见 config.example.yaml 注释)
- 重启丢内存 CAPTURE 锁,tcpdump 可能残留(需手动清理)
