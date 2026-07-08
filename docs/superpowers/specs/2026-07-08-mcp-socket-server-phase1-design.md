# mcp_socket_server 一期设计

- **日期**:2026-07-08
- **状态**:待审阅(brainstorming 产出)
- **范围**:phase 1 本期交付

## 1. 背景与现状

`mcp_socket_server` 是 MCP server,桥接 LLM 平台到 N 个 socket_server 靶机(每靶机 TCP :9000)。中央节点单实例,批量并行执行 capture/boce/command/file 操作,带状态锁与审计。本项目是 socket_server 协议的**消费者**,不拥有协议;权威在 `/opt/socket_server`(`handlers.py` 的 `do()`、`test_e2e.py`、`docs/mcp-integration.md`)。触碰协议代码前必读上述来源。

**现状 0.1.0**:只读工具 `version_query`/`isfile`/`routeinfo` 跑通;`list_targets` 占位;状态锁注册表已定义但未执行;无 auth/audit;仅 stdio 传输。`commands.py` 注册表较完整,但与 `handlers.py` 有偏差:`file_upload=22` 在派发表中不存在;漏了 `10/15/16/19/171-174/200`。

## 2. 锁定决策

经 brainstorming 两轮选择 + 执行模型确认:

| 项 | 决策 |
|---|---|
| 传输 | Streamable HTTP(pin `mcp>=1.8` + uvicorn),取代 stdio |
| 认证 | 无(内网信任);审计记源 IP(反代取 `X-Forwarded-For`) |
| 靶机注册表 | SQLite + LLM 工具 `add/remove/list`,按标签选机(`@tag`) |
| 危险确认 | 无;`cmd_exec` 白名单(下期);所有写操作必审计 |
| 状态锁 | 单实例 + 进程内 threading 锁,per-target 按 `lock_class` 仲裁 |
| 审计 | SQLite(WAL) |
| 执行模型 | 全同步工具 + threadpool(FastMCP 自动调度);`socket_client`/`pool` 维持 threading |
| version_switch / firewall | 本期暂缓(无 socket datatype) |

**残余安全网** = 内网隔离 + `cmd_exec` 白名单(下期)+ 按 IP 审计 + `remove_target` 活跃锁检查。无 auth + 无确认 + LLM 可增删靶机的风险交内网隔离兜底;若内网存在不可信节点需重新评估。

## 3. 本期范围

**本期交付**:Streamable HTTP 传输、靶机注册表、状态锁、审计、写工具(`capture_start` 5 / `capture_stop` 6 / `file_download` 3 / `mkdir` 9 / `file_upload` 特殊帧)、只读补齐(`isdir` 8 / `command_exists` 18 / `filesize` 11)。

**下期**:`cmd_exec`(1,白名单)、`boce`(131)、`replay`(0)、`version_switch`/`firewall`(暂缓)。

## 4. 架构与模块结构

```
src/mcp_socket_server/
  __main__.py       改:CLI 从 stdio 改为 uvicorn(Streamable HTTP)
  config.py          [新] 加载 config.yaml + env 覆盖
  transport.py       [新] 构造 Streamable HTTP ASGI app + uvicorn 启动参数
  server.py          改:FastMCP 工具(只读补齐 + 写工具),保持 sync def;工具经 audit 装饰器记审计
  registry.py        [新] 靶机注册表 SQLite + add/remove/list 逻辑
  audit.py           [新] 审计 SQLite + 源 IP 提取
  locks.py           [新] LockManager:per-target 多模式锁(threading)
  pool.py            改:batch() 增 lock acquire/release(审计在 server.py 工具层,非 pool)
  socket_client.py   改:补 file_download/mkdir/filesize + do_file_upload 特殊帧
  commands.py        改:修正 file_upload 标注 + 核对遗漏 datatype
```

## 5. 请求数据流

以 `capture_start(targets, iface, path)` 为例:

```
MCP client ──Streamable HTTP──► FastMCP tool capture_start(targets, iface, path)
  │  sync def,FastMCP 放 threadpool 跑(不阻塞事件循环)
  ├─ registry.resolve(targets) -> IP 列表(支持 @tag 展开)
  ├─ scheduler.batch(targets, fn, lock=CAPTURE, lock_key=(path,)):
  │     per target:
  │       lock_mgr.acquire(target, CAPTURE, (path,))   # 冲突->该 target failed
  │       pool.borrow -> socket_client.capture_start(iface, path) -> bool
  │       pool.release   (TCP 归还;tcpdump 在靶机后台跑)
  │       ★ CAPTURE 类:锁不释放,持到 capture_stop;其他写类在此 release
  │     收集 TargetResult
  ├─ audit.write(源IP, "capture_start", params, outcomes, ts, duration)   # 单条
  └─ return {ok, failed:[{target,reason}], results:[...]}
```

## 6. 数据层:注册表 + 审计

SQLite 单文件(config `db_path`,默认 `./mcp_socket_server.db`),WAL 模式,启动时建表。写入用一把 `threading.Lock` 守护单连接(`check_same_thread=False`);WAL 下读不阻塞写。

**`targets` 表**
```sql
CREATE TABLE targets(
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  host TEXT NOT NULL, port INTEGER NOT NULL DEFAULT 9000,
  tags TEXT NOT NULL DEFAULT '[]',   -- JSON array
  note TEXT DEFAULT '', created_at TEXT NOT NULL,
  UNIQUE(host,port));
```
- `add_target(host, port=9000, tags=[], note="")` -> `{id,host,port,tags}`
- `remove_target(host, port=9000)` -> 先查 `lock_mgr.has_active(host,port)`,**有活跃锁则拒绝** `{removed:false, reason:"有活跃锁"}`;无则删。
- `list_targets(tags=[])` -> target 须**包含全部**请求标签(AND 语义)。
- **标签选机**:批量工具 `targets: list[str]` 每项可为 IP 或 `@tag`;`registry.resolve()` 展开 `@tag` 为该标签下全部靶机 IP。

**`audit_log` 表**
```sql
CREATE TABLE audit_log(
  id INTEGER PRIMARY KEY AUTOINCREMENT, ts TEXT NOT NULL,   -- UTC ISO8601
  source_ip TEXT NOT NULL, tool TEXT NOT NULL,
  params TEXT NOT NULL,        -- JSON,按工具截断/脱敏
  ok_count INTEGER, failed_count INTEGER,
  outcomes TEXT NOT NULL,      -- JSON,逐 target 摘要(截断)
  duration_ms INTEGER);
```
- **何时记**:每次工具调用**完成后**写一条(单条),用 ok/failed 计数表达状态;不在调用前预记(crash-mid-call 为已知限制)。
- **源 IP**:ASGI 请求 peer;`config.behind_proxy=true` 时取 `X-Forwarded-For` 首个。
- **参数脱敏**:按工具序列化器截断(值 ≤200 字符);`file_upload` 只记 `{remote_path, size}` 不记内容;`capture` 记 `{iface,path}`。
- **保留**:`config.audit_retention_days`(默认 90),启动时清理超期记录。

## 7. 状态锁(locks.py)

`LockManager`:`dict[(host,port), TargetLock]`,进程内单例(threading)。`TargetLock` 用一把 `threading.Lock` 守护状态 `{active_captures: set[(path,)], exclusive_held: bool}`。

**仲裁(本期)**:
- `NONE`(读):跳过,自由并发。
- `CAPTURE`:按 (target, path) 排他;`capture_start` 获取并**持到 `capture_stop`**,`capture_stop` 释放。不同 path 可并发。
- `FILE_IO` / `SHELL` / `BROWSER` / `REPLAY`:per-target 排他,短(batch 内获取+释放)。注:`commands.py` 这几类 `lock_key_fields=()`,故 per-target 排他(文档 §3 字面 file_io「按 path」但注册表未给 key;本期从简 per-target,文件操作短影响小)。
- `SYSTEM`:本期暂缓,留 stub。

**冲突策略**:**fail-fast**(非阻塞 try;冲突 -> 该 target `failed`,reason 标冲突类+key)。LLM 可重试,避免线程阻塞。

**CAPTURE 锁 key = (path,)** 而非文档字面 (iface,path):`capture_stop`(datatype 6)只收 path,锁须能按 path 释放;同 path 不同 iface 写同一文件本应互斥,不同 path 可并发满足并发需求。`commands.py` 的 `capture_start` `lock_key_fields` 同步改为 `("path",)`。

**API**:`acquire(host,port,lock_class,key=None)->bool` / `release(host,port,lock_class,key=None)` / `has_active(host,port)->bool`(`remove_target` 用)。

**已知限制**:进程重启丢内存 CAPTURE 锁,tcpdump 可能在靶机残留;本期不清理(下期)。

## 8. 工具与协议层

**server.py 工具(本期)**
- 只读补齐:`isdir` / `command_exists` / `filesize`(NONE,无锁)
- 写:`capture_start(targets, iface, path, filter="")`(CAPTURE,持到 stop)/ `capture_stop(targets, path)`(CAPTURE,释放)/ `file_download(targets, path)`(FILE_IO)/ `mkdir(targets, path)`(FILE_IO)/ `file_upload(targets, remote_path, content_b64)`(FILE_IO)
- 注册表:`add_target` / `remove_target` / `list_targets`

**socket_client.py 补**
- `filesize(path)`(datatype 11)
- `file_download(path)`(datatype 3):需实现 `recv_file_response`(8B 长度+内容,按 `test_e2e.py`)
- `mkdir(path)`(datatype 9)
- `file_upload(remote_path, content, use_gzip=False)`:**非 datatype 22**,走 `do_file_upload` 特殊帧(按 `test_e2e.py`)
- `capture_start`/`capture_stop` 已存在;对齐参数名(`iface` 而非 `eth`)

**关键设计点**
- `file_download`:不把大文件塞回 LLM;**存中央节点** `download_dir/{target}/{basename}`,返回 `{target, local_path, size, sha256}`。
- `file_upload`:`content_b64` base64 传入,转字节后走 `do_file_upload`。
- `commands.py` 修正:`file_upload` datatype 22 -> 标记为"特殊帧(do_file_upload)";补注释列出 handlers 已有但本期未暴露的 datatype(10/15/16/19/171-174/200),其中 200=pcap 五元组流(只读,后续可加工具)。
- `pyproject`:`mcp>=1.0` -> `mcp>=1.8`。

## 9. 错误处理

- **部分失败正常**:单 target 失败(连接/超时/锁冲突/协议错误)不影响其他,汇总 `{ok, failed:[{target,reason}]}`。
- **锁冲突**:fail-fast,该 target `failed`,reason 标冲突类+key。
- **超时**:`borrow_timeout`(池满)/ 工具 timeout -> 该 target `failed`。
- **协议错误**:`socket_client` 帧/连接错误 -> 该 target `failed`。
- **审计**:无论成功失败都记一条(用 ok/failed 计数)。

## 10. 测试策略

- **单元**:LockManager 仲裁矩阵(CAPTURE 不同 path 并发/同 path 冲突、FILE_IO 排他、NONE 旁路、`has_active`);registry(add/remove/list、tag AND、`@tag` 展开、UNIQUE);audit(写入/截断/源IP)。
- **集成**:mock socket_server(简单 TCP stub,按 datatype 回响应)跑通 `socket_client` 帧正确性 + batch + 锁 + 审计,无需真靶机。
- **协议同步测试**:断言 `socket_client` 帧与 `test_e2e.py` 的 `send_request`/`recv_*` 字节级一致(import `test_e2e` 对比,或 stub 复刻其服务端行为)。
- **传输**:用 mcp SDK client 走 Streamable HTTP 调工具,验证端到端 + 部分失败(一靶机 down,返回 ok+failed)。

## 11. 协议同步清理

- `commands.py` `file_upload`:datatype 22 -> 特殊帧(do_file_upload),非 do() datatype。
- `commands.py` 补注释:handlers 已有但本期未暴露的 datatype(10/15/16/19/171-174/200)。
- `pyproject` `mcp>=1.0` -> `mcp>=1.8`。
- `socket_client` 新增方法实现前必读 `test_e2e.py` 对应 `recv_*`/`do_file_upload`,保证字节级一致。
- `capture_start` 额外参数名(工具 `filter` vs socket_client 现有 `extended`)以 `handlers.py` datatype 5 的 `do()` 参数为准,实现前核对。

## 12. 已知限制 / 待办

- 进程重启丢 CAPTURE 内存锁,tcpdump 可能在靶机残留;本期不清理(下期,需 socket_server 提供"列在跑抓包"接口或按已知 path 扫)。
- crash-mid-call 不预记审计(单实例少见)。
- SYSTEM 类(version_switch/firewall)未实现,留 stub。
- 无 auth:依赖内网隔离;若内网有不可信节点需重新评估。
- 审计保留默认 90 天,启动清理。

## 13. 配置(config.yaml)

```yaml
bind: {host: 0.0.0.0, port: 8080}
db_path: ./mcp_socket_server.db
behind_proxy: false          # true 则源 IP 取 X-Forwarded-For
audit_retention_days: 90
download_dir: ./downloads
pool: {max_conn_per_target: 5, borrow_timeout: 10, max_global_concurrency: 50}
# cmd_exec_whitelist: [...]   # 下期
```
