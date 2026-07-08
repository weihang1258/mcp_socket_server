# mcp_socket_server 一期设计

- **日期**:2026-07-08(基于 6 个在用业务脚本分析修订)
- **状态**:待审阅(brainstorming 产出,已按业务脚本验证修订)
- **范围**:phase 1 本期交付

## 1. 背景与现状

`mcp_socket_server` 是 MCP server,桥接 LLM 平台到 N 个 socket_server 靶机(每靶机 TCP :9000)。中央节点单实例,批量并行执行,带状态锁与审计。本项目是 socket_server 协议的**消费者**,不拥有协议;权威在 `/opt/socket_server`。

**现状 0.1.0**:只读工具 `version_query`/`isfile`/`routeinfo` 跑通(靠 timeout 侥幸,非正确协议读取);`list_targets` 占位;状态锁未执行;无 auth/audit;仅 stdio。`commands.py` 与协议有偏差;`socket_client.py` 是 `test_e2e.py` 的**不完整镜像**(缺 per-datatype recv/gzip/文件传输/持久会话);`pool.py`「一连接一请求」模型**错误**。

**业务脚本分析(2026-07-08)**:用户提供 6 个在用脚本(`tcpdump.py`/`socket_linux.py`/`webvisit.py`/`dpi.py`/`hengwei.py`/`dpi_constants.py`)。`socket_linux.py` 是**真正的生产协议客户端**(包全 datatype),证明真实业务面远大于原 spec,且推翻了 `socket_client`/`pool` 的地基假设(见 §2)。

## 2. 权威协议来源(已验证)

CLAUDE.md 指定的权威来源,全部核实:

| 来源 | 角色 | 关键事实 |
|---|---|---|
| `socket_server/handlers.py` `do()` | datatype->handler 映射 | 实现:0,1,3,4,5,6,7,8,9,10,11,14,15,16,18,19,131,171,172,173,174,200。**无 21/22/23/24/161/162/163** |
| `socket_server/protocol.py` `handle()` | 连接层帧循环 + 文件传输 | **持久连接循环**(L33 `while True: recv`),简单 datatype 响应后 `continue` 等下一帧、不关闭;21/22/23/24 文件传输握手在此(state machine + "21 ok" 等 ack);`datatype=23` 是服务端对原始内容帧的内部标记 |
| `socket_server/test_e2e.py` | 客户端参考实现 | `send_request`/`recv_raw`/`recv_text_response`/`recv_gzip_response`/`recv_file_response`/`recv_inline_text`/`do_file_upload`。`socket_client.py` 必须按此字节级一致 |

**额外参考**:`socket_linux.py`(生产客户端,method 语义参考;但有死代码 161/162/163,勿抄)。

**关键纠正**:
- **161/162/163**(`socket_linux.py` `dpi_operation`):`protocol.py`+`handlers.py` **均无处理**,死代码。DPI 生命周期走 `cmd(1)` 编排(如 `dpi.py`)。**不注册**。
- **文件传输是多步握手,非单 datatype**:下载 `21->3`、上传 `21->22->23->24`,单持久连接。
- **服务端是持久连接模型**,非「一连接一请求」。
- **响应体格式 per-datatype 不同**(见 §6 表)。

## 3. 锁定决策

| 项 | 决策 |
|---|---|
| 传输 | Streamable HTTP(pin `mcp>=1.8` + uvicorn) |
| 认证 | 无(内网信任);审计记源 IP(反代取 `X-Forwarded-For`) |
| 靶机注册表 | SQLite + LLM 工具 add/remove/list,`@tag` 选机 |
| 危险确认 | 无;`cmd_exec` 白名单;所有写操作必审计 |
| 状态锁 | 单实例 + 进程内 threading 锁,per-target 按 `lock_class` 仲裁 |
| 审计 | SQLite(WAL) |
| 执行模型 | 全同步工具 + threadpool(FastMCP 自动调度) |
| phase-1 范围 | **地基重建 + 核心 ops**(见 §4) |

残余安全网 = 内网隔离 + `cmd_exec` 白名单 + 按 IP 审计 + `remove_target` 活跃锁检查。

## 4. 本期范围(重定)

**本期交付**:
- **地基重建**:`socket_client.py`(按 test_e2e.py per-datatype recv + gzip + 文件传输 + 持久会话)、`pool.py`(持久会话 + 连接复用)、`config.py`/`transport.py`/`registry.py`/`audit.py`/`locks.py`、Streamable HTTP。
- **工具**:
  - 只读(NONE/SAFE):`version_query`(14)、`isfile`(7)、`isdir`(8)、`routeinfo`(4)、`command_exists`(18,只读路径,不暴露 `install_cmd`)、`filesize`(11)、`version_detail`(19)、`pcap_flow_extract`(200)
  - 写:`cmd_exec`(1,SHELL/DANGER,白名单+gzip)、`file_upload`(21->22->23->24 多步,FILE_IO)、`file_download`(21->3 多步,FILE_IO)、`capture_start`(5+`single_queue`,CAPTURE 持锁)、`capture_stop`(6,CAPTURE 释放)、`boce_run`(131+`mode`,BROWSER)
  - 注册表:`add_target`/`remove_target`/`list_targets`
  - pcap 拉取:复用 `file_download`(抓包停止后下载 pcap 路径)

**下期**:DPI 管理族(`mode_switch`/`upgrade`/`config_edit`/`policy_manage`/`state_reset`,cmd 编排)、`socketserver_listener`(171-174)、`mtu`(10)/`unzip`(15)/`python_cmd`(16,第二 RCE)、`replay`(0)、`tap_mirror`(hengwei SSH,独立传输)、`version_switch` 拆分(`dpi_mode_switch`+`dpi_upgrade`)。

## 5. 架构与模块结构

```
src/mcp_socket_server/
  __main__.py       改:CLI 从 stdio 改 uvicorn(Streamable HTTP)
  config.py          [新] 加载 config.yaml + env
  transport.py       [新] Streamable HTTP ASGI app + uvicorn
  server.py          改:FastMCP 工具(只读+写),sync def,audit 装饰器
  registry.py        [新] 靶机注册表 SQLite + add/remove/list + @tag 解析
  audit.py           [新] 审计 SQLite + 源 IP
  locks.py           [新] LockManager:per-target 多模式锁(threading)
  pool.py            重建:持久会话 + 连接复用(取代一连接一请求)
  socket_client.py   重建:按 test_e2e.py per-datatype recv + gzip + 文件传输
  commands.py        改:file 多步会话;补 19/200;删 161/162/163;version_switch 下期拆分
```

## 6. 协议客户端重建(socket_client.py)

**发送帧**:`[4B len i][4B datatype i][payload]`(len = 4 + payload 字节),与 `test_e2e.py` `send_request` 一致。

**持久会话**:一连接多轮往返(服务端 `protocol.py handle()` 循环)。`socket_client` 不在每次调用后关闭;由 `pool` 管理生命周期。**不再用「读到关闭」**。

**per-datatype 响应解析**(核心,按 `test_e2e.py` recv_*):

| datatype | 响应体格式 | recv 方法 |
|---|---|---|
| 4/7/8/9/10/11/14/18/19/5/6/171 | 原始 JSON(无长度前缀) | `recv_text_response`(读到 JSON 可解析) |
| 1/16 | `[4B len i][gzip json]` | `recv_gzip_response` |
| 131/200 | `[4B len i][json]`(无 gzip) | 长度前缀读取 |
| 3 | `[8B <Q len][content]` + 可选 gzip | `recv_file_response` |
| 174 | `[8B <Q len][gzip bytes]` | `recv_file_response`(gzip) |
| 15/172/173 | `b"ok"`/`b"error"` | `recv_raw` |
| 21/22/23/24 | inline `"NN ok"` ack | `recv_inline_text` |

**gzip**:`compress_gzip`/`decompress_gzip`(收 1/16/3/174;发送侧文件可选 gzip)。

**文件传输**(按 `test_e2e.py` `do_file_upload`/`recv_file_response`,与 `socket_linux.py` 一致),**单持久连接**:
- **下载 `get/getfo`**:`isfile(7)` 校验 -> `21({filepath,gzip})` 收 "21 ok" -> `3({filepath,gzip})` 收 `[8B <Q len][content]` -> 解压。
- **上传 `put/putfo`**:`21({filepath,gzip})` 收 "21 ok" -> `22([8B <Q len])` 收 "22 ok" -> `23`(`[4B len][raw content]`,**无 datatype 字段**,空文件哨兵 `b"^$"`)收 "23 ok" -> `24` 收 "24 ok"。

**便捷方法**:version(14)/isfile(7)/isdir(8)/routeinfo(4)/command_exists(18)/filesize(11)/version_detail(19)/pcap_flow_extract(200)/cmd(1)/get/getfo/put/putfo/capture_start(5)/capture_stop(6)/boce(131)。

## 7. 连接池/会话重建(pool.py)

- **持久会话 + 复用**:`TargetPool` 维护可复用连接;`acquire()` 借出已连接的 `SocketServerClient`(复用空闲或新建);`release()` 归还池(不关闭,记空闲时间)。空闲超时(`IDLE_TIMEOUT`)才关闭。
- **多轮往返**:文件传输等在借出的同一连接上完成多步 send/recv,用完归还。
- **并发限流**:`MAX_CONN_PER_TARGET=5`、`MAX_GLOBAL_CONCURRENCY=50`。
- **连接健康**:借出时若连接已断(服务端关闭/超时),丢弃重建。
- 取代旧「acquire 总新建、release 总关闭」。

## 8. 请求数据流

以 `capture_start(targets, iface, path, single_queue=True)` 为例:
```
MCP client ──Streamable HTTP──► FastMCP tool capture_start(targets, iface, path, single_queue)
  │ sync def,FastMCP threadpool
  ├─ registry.resolve(targets) -> IPs(@tag 展开)
  ├─ scheduler.batch(targets, fn, lock=CAPTURE, lock_key=(path,)):
  │     per target:
  │       lock_mgr.acquire(target, CAPTURE, (path,))   # 冲突->failed
  │       pool.borrow -> client
  │         若 iface 空:client.routeinfo(4) 取默认网卡
  │         client.capture_start(iface, path, single_queue)(5)   # tcpdump 后台跑
  │       pool.release(client)   # ★ CAPTURE 锁不释放,持到 capture_stop
  │     收集 TargetResult
  ├─ audit.write(源IP, "capture_start", params, outcomes, ts, duration)
  └─ return {ok, failed:[{target,reason}], results:[...]}
```
`capture_stop(targets, path)`(6)释放对应 (path,) 锁;之后 LLM 调 `file_download(targets, path)` 拉取 pcap。

## 9. 数据层:注册表 + 审计

SQLite 单文件(`db_path`),WAL,启动建表。写入用 `threading.Lock` 守护单连接(`check_same_thread=False`)。

**`targets`**:`id,host,port,tags(JSON array),note,created_at,UNIQUE(host,port)`。
- `add_target(host,port=9000,tags=[],note="")`、`remove_target(host,port=9000)`(先查 `lock_mgr.has_active`,有活跃锁拒绝)、`list_targets(tags=[])`(AND 语义)。
- `@tag` 选机:批量工具 `targets: list[str]` 每项可为 IP 或 `@tag`;`registry.resolve()` 展开。

**`audit_log`**:`id,ts(UTC ISO8601),source_ip,tool,params(截断/脱敏),ok_count,failed_count,outcomes(逐 target 摘要),duration_ms`。
- 每次工具调用**完成后**写一条(单条);crash-mid-call 不预记(已知限制)。
- 源 IP:ASGI peer;`behind_proxy=true` 取 `X-Forwarded-For` 首个。
- 参数脱敏:值 ≤200 字符;`file_upload` 只记 `{remote_path,size}`;`capture` 记 `{iface,path}`。
- 保留 `audit_retention_days`(默认 90),启动清理。

## 10. 状态锁(locks.py)

`LockManager`:`dict[(host,port), TargetLock]`,进程内 threading。`TargetLock` 用一把 `threading.Lock` 守护 `{active_captures:set[(path,)], exclusive_held:bool}`。

- **NONE**(读):跳过,自由并发。
- **CAPTURE**:按 (target,path) 排他;`capture_start` 获取并**持到 `capture_stop`**。不同 path 可并发。key=(path,)(`capture_stop` 只收 path;同 path 不同 iface 写同一文件本应互斥)。
- **FILE_IO / SHELL / BROWSER**:per-target 排他,短(batch 内获取+释放)。注:`commands.py` 这些类 `lock_key_fields=()`,故 per-target(文档 §3 字面 file_io「按 path」但注册表未给 key;从简)。
- **SYSTEM**:本期无(stub)。

冲突:**fail-fast**(非阻塞 try;冲突 -> 该 target failed,reason 标冲突类+key)。API:`acquire(host,port,lock_class,key=None)->bool`/`release(...)`/`has_active(host,port)->bool`。已知限制:重启丢内存 CAPTURE 锁,tcpdump 可能残留(本期不清理)。

## 11. 工具与协议层(server.py)

**只读**(NONE/SAFE):`version_query`(14)、`isfile`(7)、`isdir`(8)、`routeinfo`(4)、`command_exists`(18,不暴露 `install_cmd`)、`filesize`(11)、`version_detail`(19)、`pcap_flow_extract`(200,返回 `[{pcap,srcIp,srcPort,destIp,destPort,protoType 1=TCP/2=UDP/3=SCTP/4=ICMP}]`)。

**写**:
- `cmd_exec(targets, args, cwd?, env?, wait=True, returnall=False)`:datatype 1,SHELL/DANGER,**白名单**校验 `args` 后转发;响应 gzip 解析。`wait=False`=fire-and-forget;`returnall=True` 返回 `{code,stdout,stderr}`。
- `file_upload(targets, remote_path, content_b64)`:21->22->23->24 多步;FILE_IO。
- `file_download(targets, path)`:21->3 多步;存 `download_dir/{target}/{basename}`,返回 `{local_path,size,sha256}`;FILE_IO。
- `capture_start(targets, iface, path, filter?, single_queue=True)`(5,CAPTURE 持锁;`iface` 空则 routeinfo 自动测)/ `capture_stop(targets, path)`(6,CAPTURE 释放)。
- `boce_run(targets, url, count, interval, thread_count, timeout, mode="封堵")`:131,BROWSER;`mode` ∈ {封堵,访问}。132/133 不存在,131 同步返回。

**注册表**:`add_target`/`remove_target`/`list_targets`。

## 12. commands.py 修正

- `file_upload`:删 `datatype=22` 单值;标「多步会话 21->22->23->24」。FILE_IO/WRITE。
- `file_download`:删 `datatype=3` 单值;标「多步会话 21->3」。FILE_IO/WRITE。
- 补:`version_detail`(19,NONE,SAFE)、`pcap_flow_extract`(200,NONE,SAFE)、`cmd_exec`(1,SHELL,DANGER,本期实现)。
- `command_exists`(18):SAFE(只读);`install_cmd` 不在 MCP 暴露。
- `capture_start`(5):`lock_key_fields` 改 `("path",)`;补 `single_queue` 说明;工具参数 `iface`/`filter` 映射协议 `eth`/`extended`(以 `handlers.py` datatype 5 `do()` 参数为准,实现前核对)。
- **删 161/162/163**(死代码)。
- `version_switch`(-1):本期不实现;下期拆 `dpi_mode_switch`+`dpi_upgrade`(cmd 编排)。
- 下期再补:10/15/16/0/171-174。
- `pyproject`:`mcp>=1.0` -> `mcp>=1.8`。

## 13. 错误处理

部分失败正常(单 target 失败不影响其他,汇总 `{ok,failed}`)。锁冲突 fail-fast。超时(`borrow_timeout`/工具 timeout)failed。协议错误(帧/连接/gzip)failed。审计无论成败记一条(用 ok/failed 计数)。

## 14. 测试策略

- **单元**:LockManager 仲裁矩阵;registry(tag AND/`@tag` 展开/UNIQUE);audit(截断/源IP)。
- **协议同步**:**断言 `socket_client` 帧与 `test_e2e.py` `send_request`/`recv_*` 字节级一致**(import test_e2e 对比);文件传输握手与 `do_file_upload` 一致。
- **集成**:mock socket_server(复刻 `protocol.py handle()` 持久循环 + 21/22/23/24 状态机 + 各 datatype 响应)跑通 socket_client + batch + 锁 + 审计。
- **传输**:mcp SDK client 走 Streamable HTTP 调工具 + 部分失败(一靶机 down,返回 ok+failed)。

## 15. 已知限制 / 待办

- 重启丢 CAPTURE 内存锁,tcpdump 可能残留;本期不清理(下期,需 socket_server 提供「列在跑抓包」接口或按已知 path 扫)。
- crash-mid-call 不预记审计(单实例少见)。
- SYSTEM 类(version_switch/firewall/DPI)本期不实现。
- 无 auth:依赖内网隔离;若内网有不可信节点需重新评估。
- `python_cmd`(16 第二 RCE)、`tap_mirror`(SSH)、DPI 管理族、`socketserver_listener` 下期。
- 简单 datatype 响应无长度前缀,持久连接下 recv 须按 `test_e2e.py` `recv_text_response` 实现(读至 JSON 可解析),勿用「读到关闭」。
- 审计保留 90 天,启动清理。

## 16. 配置(config.yaml)

```yaml
bind: {host: 0.0.0.0, port: 8080}
db_path: ./mcp_socket_server.db
behind_proxy: false          # true 则源 IP 取 X-Forwarded-For
audit_retention_days: 90
download_dir: ./downloads
pool: {max_conn_per_target: 5, idle_timeout: 600, borrow_timeout: 10, max_global_concurrency: 50}
cmd_exec_whitelist: []       # 本期必填,从严
```
