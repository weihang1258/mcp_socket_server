#!/usr/bin/env python
# -*- coding: utf-8 -*-
# @Time    : 2024/10/7
# @Author  : weihang
# @File    : tcpdump.py
# @Desc    : TCP抓包类

import struct
import json
from device.socket_linux import SocketLinux, logger


class Tcpdump(SocketLinux):
    """TCP 抓包类。

    继承自 SocketLinux，提供远程设备的 TCP 抓包功能。

    Attributes:
        eth (str): 网络接口名称
        path (str): 临时 pcap 文件路径
        extended (str): tcpdump 扩展参数
        single_queue (bool): 是否使用单队列模式
    """

    def __init__(self, client, eth=None, extended="", tmppath="/home/tmp/tmp.pcap", single_queue=True):
        """初始化 Tcpdump 对象。

        Args:
            client: Socket 客户端元组 (host, port)
            eth: 网络接口，None 则自动获取
            extended: 扩展参数
            tmppath: 临时 pcap 文件路径
            single_queue: 是否使用单队列模式
        """
        super().__init__(client)
        self.eth = eth
        self.path = tmppath
        self.extended = extended
        self.single_queue = single_queue

        # 创建临时目录
        dir_path = tmppath.rsplit("/", maxsplit=1)[0]
        if not self.isdir(dir=dir_path):
            self.mkdir(dir=dir_path)

        # 如果未指定网络接口，自动获取
        if not self.eth:
            self.eth = self.routeinfo().get("0.0.0.0", {}).get("Iface", None)

    def tcpdump_start(self, bufsize=1024):
        """启动 tcpdump 抓包。

        Args:
            bufsize: 接收缓冲区大小

        Returns:
            dict: 命令执行结果
        """
        self.tcpdump_stop()
        data = {"eth": self.eth, "path": self.path, "extended": self.extended, "single_queue": self.single_queue}
        logger.info(data)
        msg = struct.pack("i", 5) + json.dumps(obj=data).encode("utf-8")
        msg = struct.pack("i", len(msg)) + msg
        self.client.sendall(msg)
        data = self.client.recv(bufsize)
        data = json.loads(data)
        return data["res"]

    def tcpdump_stop(self, bufsize=1024):
        """停止 tcpdump 抓包。

        Args:
            bufsize: 接收缓冲区大小

        Returns:
            dict: 命令执行结果
        """
        data = {"path": self.path}
        msg = struct.pack("i", 6) + json.dumps(obj=data).encode("utf-8")
        msg = struct.pack("i", len(msg)) + msg
        self.client.sendall(msg)
        data = self.client.recv(bufsize)
        data = json.loads(data)
        return data["res"]

    def pcap_get(self, locatpath):
        """获取 pcap 文件到本地。

        Args:
            locatpath: 本地保存路径
        """
        logger.info([self.path, locatpath])
        self.get(remotepath=self.path, locatpath=locatpath, gzip=True)

    def pcap_getfo(self):
        """获取 pcap 文件对象。

        Returns:
            BytesIO: pcap 文件内容
        """
        return self.getfo(remotepath=self.path, gzip=True)


if __name__ == '__main__':
    tcpdump = Tcpdump(("10.12.131.32", 9000), tmppath="/home/tmp/tmp.pcap", eth="enp6s0f1", extended="port 8000")
    # print(tcpdump.tcpdump_start())
    # time.sleep(22)
    # print(tcpdump.tcpdump_stop())
    print(tcpdump.getsize("/home/tmp/tmp.pcap"))
    # tcpdump.path = "/home/tmp/tmp.pcap"
    # print(tcpdump.pcap_get("aaaa.pcap"))
    # pkt = tcpdump.getfo("/home/tmp/tmp.pcap",gzip=True)
    pkt = tcpdump.pcap_getfo()
    print(type(pkt))
    # sys.exit()
