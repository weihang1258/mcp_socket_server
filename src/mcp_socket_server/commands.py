"""命令注册表:datatype -> (锁类, 危险等级)。

⚠️ 权威协议来源(socket_server 仓库,勿在此手抄臆造):
  - datatype 编号 + 参数 JSON 字段:socket_server/socket_server/handlers.py 的 do() 函数
  - 协议帧 + 收发:socket_server/test_e2e.py
  - 连接循环 + 文件传输(21/22/23/24):socket_server/socket_server/protocol.py handle()
  - datatype 表(含锁类/并发/危险):socket_server/docs/mcp-integration.md

本表从上述来源派生,经验证 workflow 核验(2026-07-08)。socket_server 协议变更时按
docs/mcp-integration.md §8 同步本表 + socket_client.py。加新命令只改本表。
注:
  - 161/162/163(socket_linux.py dpi_operation)handlers.py 无处理,死代码,不注册;DPI 生命周期走 cmd(1)。
  - 文件传输是多步会话(21->3 / 21->22->23->24),非单 datatype;此处 datatype=None 标记。
  - version_detail(19)/pcap_flow_extract(200) 锁类 NONE/SAFE 为推断:mcp-integration.md
    未列 19,200 标 '-'(二者均只读分析,同 14/18 处理)。
  - 下期再补:10/15/16/0/171-174;version_switch 拆 dpi_mode_switch+dpi_upgrade。
"""
from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import Optional


class LockClass(str, Enum):
    NONE = "none"          # 只读,自由并发
    CAPTURE = "capture"    # 按 path 排他;capture_start 持锁到 capture_stop
    FILE_IO = "file_io"    # 文件读写,per-target 短排他
    SHELL = "shell"        # 命令执行,per-target 排他
    BROWSER = "browser"    # 拨测,per-target 排他
    SYSTEM = "system"      # 版本切换/防火墙,全局排他(本期 stub)


class Danger(str, Enum):
    SAFE = "safe"          # 只读,无需确认
    WRITE = "write"        # 写操作,记录审计
    DANGER = "danger"      # 危险,需二次确认(cmd_exec)


@dataclass(frozen=True)
class CommandSpec:
    name: str
    datatype: Optional[int]       # None = 多步会话(如文件传输)或编排工具
    lock_class: LockClass
    danger: Danger
    lock_key_fields: tuple[str, ...] = ()


COMMANDS: dict[str, CommandSpec] = {
    # 只读类(NONE/SAFE)
    "version_query":     CommandSpec("version_query", 14, LockClass.NONE, Danger.SAFE),
    "isfile":            CommandSpec("isfile", 7, LockClass.NONE, Danger.SAFE),
    "isdir":             CommandSpec("isdir", 8, LockClass.NONE, Danger.SAFE),
    "routeinfo":         CommandSpec("routeinfo", 4, LockClass.NONE, Danger.SAFE),
    "command_exists":    CommandSpec("command_exists", 18, LockClass.NONE, Danger.SAFE),
    "filesize":          CommandSpec("filesize", 11, LockClass.NONE, Danger.SAFE),
    "version_detail":    CommandSpec("version_detail", 19, LockClass.NONE, Danger.SAFE),
    "pcap_flow_extract": CommandSpec("pcap_flow_extract", 200, LockClass.NONE, Danger.SAFE),

    # 抓包(CAPTURE,按 path 排他;capture_start 持锁到 capture_stop)
    "capture_start":     CommandSpec("capture_start", 5, LockClass.CAPTURE, Danger.WRITE, ("path",)),
    "capture_stop":      CommandSpec("capture_stop", 6, LockClass.CAPTURE, Danger.WRITE, ("path",)),

    # 文件传输(多步会话,datatype=None;FILE_IO per-target 排他)
    "file_upload":       CommandSpec("file_upload", None, LockClass.FILE_IO, Danger.WRITE),
    "file_download":     CommandSpec("file_download", None, LockClass.FILE_IO, Danger.WRITE),

    # 命令执行(危险,白名单;本期实现)
    "cmd_exec":          CommandSpec("cmd_exec", 1, LockClass.SHELL, Danger.DANGER),

    # 拨测
    "boce_run":          CommandSpec("boce_run", 131, LockClass.BROWSER, Danger.WRITE),
}
# 下期:replay(0)/mtu(10)/unzip(15)/python_cmd(16)/socketserver_*(171-174)/
#        dpi_mode_switch+dpi_upgrade(cmd 编排)/tap_mirror(SSH)
