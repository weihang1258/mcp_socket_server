#!/usr/bin/env python
# -*- coding: utf-8 -*-
# @Time    : 2023/10/7 17:35
# @Author  : weihang
# @File    : webvisit.py
# @Desc    : 网站访问/封堵功能

import time
import json
import struct
from device.socket_linux import SocketLinux
from utils.common import setup_logging

logger = setup_logging(log_file_path="log/webvisit.log", logger_name="webvisit")


class Webvisit(SocketLinux):
    """网站访问/封堵类。

    继承自 SocketLinux，提供模拟网站访问和封堵测试功能。

    Attributes:
        client: Socket 客户端连接
    """

    def __init__(self, client: tuple):
        """初始化 Webvisit 对象。

        Args:
            client: Socket 客户端元组 (host, port)
        """
        super().__init__(client)

    def boce(self, url, count=1, interval=0, thread_count=1, timeout=3, mode="封堵", bufsize=1024):
        """
        模拟网站访问/封堵

        Args:
            url: 目标URL
            count: 访问次数
            interval: 间隔时间
            thread_count: 线程数
            timeout: 超时时间
            mode: 模式（封堵）
            bufsize: 缓冲区大小

        Returns:
            dict: 访问结果
        """
        data = {"url": url, "count": count, "interval": interval, "thread_count": thread_count,
                "timeout": timeout, "mode": mode}
        msg = struct.pack("i", 131) + json.dumps(obj=data).encode("utf-8")
        msg = struct.pack("i", len(msg)) + msg
        self.client.sendall(msg)

        data = self.client.recv(bufsize)

        length = struct.unpack("i", data[:4])[0]
        res = data[4:]
        while len(res) < length:
            tmp = self.client.recv(bufsize)
            if not tmp:
                time.sleep(0.01)
            res += tmp

        if len(res) > length:
            raise RuntimeError(f"接收字节数大于原始文件字节数：接收{len(res)}，原始{length}")
        data = json.loads(res)
        return data
