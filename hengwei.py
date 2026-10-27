#!/usr/bin/env python
# -*- coding: utf-8 -*-
# @Time    : 2023/10/7 17:35
# @Author  : weihang
# @File    : hengwei.py
# @Desc    : 恒为网络设备控制

import time
import re
from utils.common import setup_logging

logger = setup_logging(log_file_path="log/hengwei.log", logger_name="hengwei")


class HengweiDevice:
    """恒为网络设备 SSH 控制类。

    通过 SSH 连接控制恒为网络设备，支持命令执行和模式切换。

    Attributes:
        hostname (str): 目标设备主机名或 IP 地址
        port (int): SSH 端口
        username (str): 登录用户名
        password (str): 登录密码
        pkey: Paramiko RSAKey 私钥对象
        client: Paramiko SSHClient 对象
        shell: SSH Shell 对象
    """

    def __init__(self, hostname, port=22, username=None, password=None, pkey=None, passphrase=None):
        """初始化 Hengwei 设备的 SSH 连接。

        Args:
            hostname: 目标设备的主机名或 IP 地址
            port: SSH 端口，默认为 22
            username: 登录用户名
            password: 登录密码
            pkey: 私钥文件路径
            passphrase: 私钥密码
        """
        import paramiko
        self.hostname = hostname
        self.port = port
        self.username = username
        self.password = password
        self.pkey = paramiko.RSAKey.from_private_key_file(pkey, passphrase) if pkey else None
        self.client = paramiko.SSHClient()
        self.client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        self.shell = None
        self._connect()

    def _connect(self):
        """建立 SSH 连接并启动 shell。"""
        self.client.connect(
            self.hostname,
            port=self.port,
            username=self.username,
            password=self.password,
            pkey=self.pkey
        )
        self.shell = self.client.invoke_shell()
        logger.info(f"ssh连接设备{self.hostname}:{self.port}成功")
        time.sleep(1)  # Give the shell some time to start

    def execute_command(self, command, prompt=None):
        """在设备上执行命令并获取输出。

        Args:
            command: 要执行的命令
            prompt: 命令的响应结尾符，默认为 '>'

        Returns:
            tuple: (stdout, stderr) 命令执行的标准输出和标准错误
        """
        prompt = prompt or '>'
        self.shell.send(command + '\n')
        stdout_data = ""
        stderr_data = ""

        while True:
            if self.shell.recv_ready():
                output = self.shell.recv(1024).decode()
                stdout_data += output
                if prompt in output:
                    break
            time.sleep(0.5)

        return stdout_data, stderr_data

    def switch_mode(self, mode):
        """切换设备模式。

        Args:
            mode: 目标模式，如 'system' 或 'admin'

        Raises:
            ValueError: 当模式不支持时抛出异常
        """
        if mode == 'system':
            self.execute_command('system-view')
        elif mode == 'admin':
            self.execute_command('su admin')
        else:
            raise ValueError("Unsupported mode: {}".format(mode))

    def close(self):
        """关闭 SSH 连接。"""
        if self.shell:
            self.shell.close()
        self.client.close()


def start_mirror(hostname='172.31.140.13', port=22, username='root', password='embed220', inport="1/f/47",
                 outport="1/f/39"):
    """启动镜像"""
    device = HengweiDevice(hostname=hostname, port=port, username=username, password=password)
    device.switch_mode('admin')

    # 执行设备命令
    output, error = device.execute_command('show configuration ', prompt=">")

    # 查询inport_id和outport_id
    inport_id = re.search(r"add inports (\d+) %s" % inport, output).groups()[0]
    outport_id = re.search(r"add outports (\d+) \w+? %s" % outport, output).groups()[0]

    rule = re.search(r"set rule\s+\d*?\s+inports\s+%s.+?\n" % inport_id, output).group().strip()
    if f",{outport_id}" in rule:
        logger.info(f"{outport_id}端口id已经加入")
    else:
        new_rule = re.sub(r"$", f",{outport_id}", rule)
        logger.info(new_rule)
        device.execute_command(new_rule)
    device.close()


def stop_mirror(hostname='172.31.140.13', port=22, username='root', password='embed220', inport="1/f/47",
                outport="1/f/39"):
    """停止镜像"""
    device = HengweiDevice(hostname=hostname, port=port, username=username, password=password)
    device.switch_mode('admin')
    # 执行设备命令
    output, error = device.execute_command('show configuration ', prompt=">")

    # 查询inport_id和outport_id
    inport_id = re.search(r"add inports (\d+) %s" % inport, output).groups()[0]
    outport_id = re.search(r"add outports (\d+) \w+? %s" % outport, output).groups()[0]

    rule = re.search(r"set rule\s+\d*?\s+inports\s+%s.+?\n" % inport_id, output).group().strip()
    if f",{outport_id}" not in rule:
        logger.info(f"{outport_id}端口已经移除")
    else:
        new_rule = re.sub(r",%s(?!\d)" % outport_id, "", rule)
        logger.info(new_rule)
        device.execute_command(new_rule)
    device.close()