"""命令注册表：datatype → (锁类, 是否只读, 危险等级)。

⚠️ 权威协议来源（socket_server 仓库，勿在此手抄臆造）：
  - datatype 编号 + 参数 JSON 字段：socket_server/socket_server/handlers.py 的 do() 函数
  - 每个 datatype 的参数/响应/示例：socket_server/docs/api-guide.md（查"type X 是什么"先看这）
  - 协议帧 + 收发：socket_server/test_e2e.py
  - datatype 表（含锁类/并发/危险标记）：socket_server/docs/mcp-integration.md

特殊：文件上传 21->22->23->24 是四步握手，在 protocol.py 协议层处理
（不在 do()），必须同一连接完成。详见 api-guide.md "文件上传流程"。

本表从上述来源派生。socket_server 协议变更时，按 docs/mcp-integration.md
第 8 节"协议演进流程"同步本表 + socket_client.py。加新命令只改本表。
"""
from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import Optional


class LockClass(str, Enum):
    NONE = "none"          # 只读，自由并发
    CAPTURE = "capture"    # 按 (iface, path) 排他
    REPLAY = "replay"      # 发包重放，同靶机排他
    FILE_IO = "file_io"    # 文件读写，短排他
    SHELL = "shell"        # 命令执行，同靶机排他
    BROWSER = "browser"    # 拨测，同靶机排他
    SYSTEM = "system"      # 版本切换/防火墙，全局排他，执行前停长操作


class Danger(str, Enum):
    SAFE = "safe"          # 只读，无需确认
    WRITE = "write"        # 写操作，记录审计
    DANGER = "danger"      # 危险，需二次确认（switch/firewall/exec）


@dataclass(frozen=True)
class CommandSpec:
    name: str
    datatype: int
    lock_class: LockClass
    danger: Danger
    lock_key_fields: tuple[str, ...] = ()  # CAPTURE 类用 (iface, path) 区分并发槽


# 注册表：MCP 工具名 → 规范
COMMANDS: dict[str, CommandSpec] = {
    # 只读类
    "version_query":   CommandSpec("version_query", 14, LockClass.NONE, Danger.SAFE),
    "isfile":          CommandSpec("isfile", 7, LockClass.NONE, Danger.SAFE),
    "isdir":           CommandSpec("isdir", 8, LockClass.NONE, Danger.SAFE),
    "routeinfo":       CommandSpec("routeinfo", 4, LockClass.NONE, Danger.SAFE),
    "command_exists":  CommandSpec("command_exists", 18, LockClass.NONE, Danger.SAFE),
    "filesize":        CommandSpec("filesize", 11, LockClass.NONE, Danger.SAFE),

    # 抓包（tcpdump 命令行，datatype 5/6，支持不同 网卡+path 并发）
    "capture_start":   CommandSpec("capture_start", 5, LockClass.CAPTURE, Danger.WRITE, ("iface", "path")),
    "capture_stop":    CommandSpec("capture_stop", 6, LockClass.CAPTURE, Danger.WRITE, ("path",)),

    # 文件
    "file_upload":     CommandSpec("file_upload", 22, LockClass.FILE_IO, Danger.WRITE),
    "file_download":   CommandSpec("file_download", 3, LockClass.FILE_IO, Danger.WRITE),
    "mkdir":           CommandSpec("mkdir", 9, LockClass.FILE_IO, Danger.WRITE),

    # 命令执行（危险，白名单 + 确认）
    "cmd_exec":        CommandSpec("cmd_exec", 1, LockClass.SHELL, Danger.DANGER),

    # 拨测
    "boce_run":        CommandSpec("boce_run", 131, LockClass.BROWSER, Danger.WRITE),

    # 发包重放
    "replay":          CommandSpec("replay", 0, LockClass.REPLAY, Danger.WRITE),

    # 系统级（最危险）
    "version_switch":  CommandSpec("version_switch", -1, LockClass.SYSTEM, Danger.DANGER),  # 走 CLI switch
    "firewall_disable": CommandSpec("firewall_disable", -1, LockClass.SYSTEM, Danger.DANGER),
}

# datatype 121/122/123 (scapy 抓包) 已弃用，不暴露
