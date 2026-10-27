#!/usr/bin/env python
# -*- coding: utf-8 -*-
# @Time    : 2023/12/7 10:45
# @Author  : weihang
# @File    : socket_linux.py
import datetime
import gzip
import io
import json
import os
import re
import socket
import struct
import subprocess
import sys
import time
from io import BytesIO
from scapy.all import rdpcap, wrpcap
from utils.common import md5, setup_logging

# 添加日志打印
logger = setup_logging(log_file_path="log/socket_linux.log", logger_name="socket_linux")

def compress_gzip(content):
    compressed_data = gzip.compress(content)
    return compressed_data

def decompress_gzip(compressed_data):
    content = gzip.decompress(compressed_data)
    return content


class SocketLinux:
    """Linux 设备 Socket 通信客户端。

    基于二进制协议与远程 Linux 设备通信，支持命令执行、文件传输等操作。
    协议格式：<长度(4字节)><gzip压缩的JSON数据>

    Attributes:
        host (str): 远程主机地址
        port (int): 远程主机端口
        client (socket.socket): Socket 连接对象

    Examples:
        >>> client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        >>> client.connect(("192.168.1.100", 9000))
        >>> with SocketLinux(client) as s:
        ...     result = s.cmd("ls -la")
        ...     print(result)
    """
    _initialized_connections = set()

    def __init__(self, client):
        """初始化 SocketLinux 客户端。

        Args:
            client: socket.socket 对象或 (host, port) 元组
        """
        if isinstance(client, tuple):
            self.host, self.port = client
            self.client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.client.connect(client)
        else:
            self.client = client

    def __del__(self):
        try:
            if self.client:
                self.client.close()
        except Exception as e:
            logger.info(e)

    def close(self):
        try:
            if self.client:
                self.client.close()
        except Exception as e:
            logger.info(e)

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.close()

    def cmd(self, args, cwd=None, env=None, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, encoding="utf-8", wait=True, bufsize=4096,returnall=False, use_run=False):
        data = {"args": args, "cwd": cwd, "env": env, "shell": shell, "stdout": stdout, "stderr": stderr, "encoding": encoding, "wait": wait, "use_run": use_run}
        # logger.info(data)
        msg = struct.pack("i", 1) + json.dumps(obj=data).encode("utf-8")
        msg = struct.pack("i", len(msg)) + msg
        self.client.sendall(msg)
        data = self.client.recv(bufsize)
        # logger.info(f"length:{len(data)}")
        # logger.info(f"length:{len(data)}, response:{data}")
        length = struct.unpack("i", data[:4])[0]
        res = data[4:]
        while len(res) < length:
            tmp = self.client.recv(bufsize)
            if not tmp:
                time.sleep(0.01)
            res += tmp
            # logger.info(length, len(res), len(tmp))
        str_decompress_gzip = decompress_gzip(res)
        if len(res) > length:
            raise RuntimeError(f"接收字节数大于原始文件字节数：接收{len(res)}，原始{length}")

        data = json.loads(str_decompress_gzip)
        if not wait:
            return
        if returnall:
            return data
        else:
            return data["stdout"]


    def isdir(self, dir, bufsize=1024):
        data = {"dir": dir}
        msg = struct.pack("i", 8) + json.dumps(obj=data).encode("utf-8")
        msg = struct.pack("i", len(msg)) + msg
        self.client.sendall(msg)
        data = self.client.recv(bufsize)
        data = json.loads(data)
        return data["res"]

    def isfile(self, file, bufsize=1024):
        data = {"file": file}
        msg = struct.pack("i", 7) + json.dumps(obj=data).encode("utf-8")
        msg = struct.pack("i", len(msg)) + msg
        self.client.sendall(msg)
        data = self.client.recv(bufsize)
        data = json.loads(data)
        return data["res"]

    def mkdir(self, dir, bufsize=1024):
        data = {"dir": dir}
        msg = struct.pack("i", 9) + json.dumps(obj=data).encode("utf-8")
        msg = struct.pack("i", len(msg)) + msg
        self.client.sendall(msg)
        data = self.client.recv(bufsize)
        return data

    def mtu(self, eth, value=2000, bufsize=1024):
        data = {"eth": eth, "value": value}
        msg = struct.pack("i", 10) + json.dumps(obj=data).encode("utf-8")
        msg = struct.pack("i", len(msg)) + msg
        self.client.sendall(msg)
        data = self.client.recv(bufsize)
        return data

    def getfo(self, remotepath, gzip=False):
        if not self.isfile(remotepath):
            raise RuntimeError(f"远程文件不存在: {remotepath}")

        # ==== 第一步：获取文件基本信息 ====
        data = {"filepath": remotepath}
        msg = struct.pack("i", 21) + json.dumps(data).encode("utf-8")
        msg = struct.pack("i", len(msg)) + msg
        self.client.sendall(msg)

        # 接收确认信息
        tmp = self.client.recv(1024)
        # 可以加日志打印确认 tmp 的内容

        # ==== 第二步：请求实际文件 ====
        if gzip:
            data["gzip"] = True
        msg = struct.pack("i", 3) + json.dumps(data).encode("utf-8")
        msg = struct.pack("i", len(msg)) + msg
        self.client.sendall(msg)

        # ==== 第三步：接收文件长度 + 第一段数据 ====
        tmp = self.client.recv(1024)
        if len(tmp) < 8:
            raise RuntimeError("接收到的数据太少，无法提取长度")
        length = struct.unpack("<Q", tmp[:8])[0]  # 文件压缩后长度
        left_data = tmp[8:]

        # ==== 第四步：边接收边写入内存缓冲区 ====
        received = len(left_data)
        res_buffer = BytesIO()
        res_buffer.write(left_data)

        while received < length:
            chunk = self.client.recv(min(102400, length - received))
            if not chunk:
                raise RuntimeError("连接中断，数据未接收完整")
            res_buffer.write(chunk)
            received += len(chunk)

        if received > length:
            raise RuntimeError(f"接收字节数大于原始文件字节数：接收{received}，原始{length}")

        # ==== 第五步：解压并返回 BytesIO ====
        res_buffer.seek(0)
        if gzip:
            decompressed_data = decompress_gzip(res_buffer.read())
        else:
            decompressed_data = res_buffer.read()

        logger.info(
            f"get host:{self.host}, port:{self.port}, 文件名：{remotepath}, 文件长度:{len(decompressed_data)}, 传输长度:{length}")

        fl = BytesIO()
        fl.write(decompressed_data)
        fl.seek(0)
        return fl

    def get(self, remotepath, locatpath, gzip=False):
        fl = self.getfo(remotepath=remotepath, gzip=gzip)
        with open(locatpath, "wb") as f:
            f.write(fl.getvalue())

    def put(self, locatpath, remotepath, overwrite=False, gzip=False):
        if not os.path.isfile(locatpath):
            raise RuntimeError(f"本地文件不存在:{locatpath}")
        if not overwrite and self.md5(remotepath) == md5(locatpath):
            return

        with open(locatpath, "rb") as f:
            content = f.read()

        if len(content) == 0:
            content_tmp = b"^$"
        else:
            content_tmp = content
        # gzip压缩文件
        str_compress_gzip = compress_gzip(content_tmp) if gzip else content_tmp

        data = {"filepath": remotepath, "gzip": gzip}
        # 传文件名
        # logger.info([data])
        msg = struct.pack("i", 21) + json.dumps(obj=data).encode("utf-8")
        # logger.info([21, msg])
        msg = struct.pack("i", len(msg)) + msg
        self.client.sendall(msg)
        data = self.client.recv(1024)
        # logger.info(data)
        # 传文件长度
        # logger.info(len(content))
        msg = struct.pack("i", 22) + struct.pack("<Q", len(str_compress_gzip))
        # logger.info([22, msg])
        msg = struct.pack("i", len(msg)) + msg
        self.client.sendall(msg)
        data = self.client.recv(1024)
        # logger.info(data)
        # 传文件内容
        msg = str_compress_gzip
        # logger.info([23, msg[:20]])
        msg = struct.pack("i", len(msg)) + msg
        self.client.sendall(msg)
        data = self.client.recv(1024)
        # logger.info(data)
        # 传文件接收标识
        msg = struct.pack("i", 24)
        # logger.info([24, msg])
        msg = struct.pack("i", len(msg)) + msg
        self.client.sendall(msg)
        data = self.client.recv(1024)
        # logger.info(data)
        logger.info(f"put host:{self.host}, port:{self.port}, 文件名：{locatpath}->{remotepath}, 文件长度:{len(content)}, 传输长度：{len(str_compress_gzip)}")

    def putfo(self, fl: BytesIO, remotepath, overwrite=False, gzip=False):
        content = fl.read()
        if not overwrite and self.md5(remotepath) == md5(content):
            return
        if len(content) == 0:
            content_tmp = b"^$"
        else:
            content_tmp = content
        # gzip压缩文件
        str_compress_gzip = compress_gzip(content_tmp) if gzip else content_tmp

        data = {"filepath": remotepath, "gzip": gzip}
        # 传文件名
        # logger.info([data])
        msg = struct.pack("i", 21) + json.dumps(obj=data).encode("utf-8")
        # logger.info([21, msg])
        msg = struct.pack("i", len(msg)) + msg
        self.client.sendall(msg)
        data = self.client.recv(1024)
        # logger.info(data)
        # 传文件长度
        # logger.info(len(content))
        length = len(str_compress_gzip)
        msg = struct.pack("i", 22) + struct.pack("<Q", length)
        # logger.info([22, msg])
        msg = struct.pack("i", len(msg)) + msg
        self.client.sendall(msg)
        data = self.client.recv(1024)
        # logger.info(data)
        # 传文件内容
        msg = str_compress_gzip
        # logger.info([23, msg[:20]])
        msg = struct.pack("i", len(msg)) + msg
        self.client.sendall(msg)
        data = self.client.recv(1024)
        # logger.info(data)
        # 传文件接收标识
        msg = struct.pack("i", 24)
        # logger.info([24, msg])
        msg = struct.pack("i", len(msg)) + msg
        self.client.sendall(msg)
        data = self.client.recv(1024)
        # logger.info(data)
        logger.info(f"putfo host:{self.host}, port:{self.port}, 文件名：{remotepath}, 文件长度:{len(content)}, 传输长度：{len(str_compress_gzip)}")

    def getsize(self, path, bufsize=1024):
        '''
        path的字节数
        :param path: 文件或者目录路径
        :return:
        '''
        if not self.isfile(path):
            raise RuntimeError(f"文件路径{path}不存在。")
        data = {"path": path}
        msg = struct.pack("i", 11) + json.dumps(obj=data).encode("utf-8")
        msg = struct.pack("i", len(msg)) + msg
        self.client.sendall(msg)
        data = self.client.recv(bufsize)
        data = json.loads(data)
        return data["res"]


    def scapy_send(self, pcaps, uplink_iface,downlink_iface=None, uplink_vlan=None, downlink_vlan=None, mbps=50, verbose=None, force_ip_src=None, force_ip_dst=None, force_sport=None, force_dport=None, force_build_flow=None, enable_pcap_cache=False, pcap_cache_dir="cached_pcaps", bufsize=1024):
        if not downlink_iface:
            downlink_iface = uplink_iface
        data = {"pcaps": pcaps, "uplink_iface": uplink_iface, "downlink_iface": downlink_iface, "uplink_vlan": uplink_vlan, "downlink_vlan": downlink_vlan, "mbps": mbps, "verbose": verbose, "force_ip_src": force_ip_src, "force_ip_dst": force_ip_dst, "force_sport": force_sport, "force_dport": force_dport, "force_build_flow": force_build_flow, "enable_pcap_cache": enable_pcap_cache, "pcap_cache_dir": pcap_cache_dir}
        # logger.info(data)
        msg = struct.pack("i", 0) + json.dumps(obj=data).encode("utf-8")
        msg = struct.pack("i", len(msg)) + msg
        self.client.sendall(msg)
        data = self.client.recv(bufsize)
        data = json.loads(data)
        return data

    def routeinfo(self, bufsize=1024):
        msg = struct.pack("i", 4)
        msg = struct.pack("i", len(msg)) + msg
        self.client.sendall(msg)
        data = self.client.recv(bufsize)
        data = json.loads(data)
        return data

    def getsocketclientverion(self, bufsize=1024):
        msg = struct.pack("i", 14)
        msg = struct.pack("i", len(msg)) + msg
        self.client.sendall(msg)
        data = self.client.recv(bufsize)
        data = json.loads(data)
        return data

    def upgrade_socketclient(self, localpath, version=None):
        socketserver_path = self.cmd(args="pwd").strip()
        res = re.findall(r"socket_sevrer_(\d+\.\d+)$", localpath)
        if res:
            version = res[-1]
        remotepath = socketserver_path + "/socket_sevrer_" + version
        self.put(locatpath=localpath, remotepath=remotepath, overwrite=True)
        content = re.sub(r"version=\d+\.\d+".encode("utf-8"), b"version=" + version.encode("utf-8"), self.getfo(remotepath=socketserver_path + "/config").read())
        logger.info(content)
        fl = io.BytesIO()
        fl.write(content)
        fl.seek(0)
        self.putfo(fl=fl, remotepath=socketserver_path + "/config", overwrite=True)

    def unzip(self, file, outdir=None, passwd=None, overwrite=True, bufsize=1024):
        logger.info(f"解压：{file} --> {outdir}")
        data = {"file": file, "outdir": outdir, "passwd": passwd, "overwrite": overwrite}
        msg = struct.pack("i", 15) + json.dumps(obj=data).encode("utf-8")
        msg = struct.pack("i", len(msg)) + msg
        self.client.sendall(msg)
        data = self.client.recv(bufsize)
        return data

    def update_systime(self, settime=None):
        """更新系统时间，格式 YYYY-MM-DD HH:MM:SS，例如 2023-01-01 12:00:00"""
        if settime is None:
            settime = datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        logger.info(f"更新系统时间：{settime}")
        cmd = f"date -s '{settime}'"
        self.cmd(cmd)
        cmd = "hwclock -w"
        self.cmd(cmd)

    def dpi_operation(self, op, bufsize=1024):
        """dpi重启操作，op可为 stop、start、restart"""
        if op == "stop":
            msg = struct.pack("i", 161)
            msg = struct.pack("i", len(msg)) + msg
            self.client.sendall(msg)
            data = self.client.recv(bufsize)
            data = json.loads(data)
            return data["res"]
        elif op == "start":
            msg = struct.pack("i", 162)
            msg = struct.pack("i", len(msg)) + msg
            self.client.sendall(msg)
            data = self.client.recv(bufsize)
        elif op == "restart":
            msg = struct.pack("i", 163)
            msg = struct.pack("i", len(msg)) + msg
            self.client.sendall(msg)
            data = self.client.recv(bufsize)

    def python_cmd(self, *args, bufsize=1024):
        data = args
        msg = struct.pack("i", 16) + json.dumps(obj=data).encode("utf-8")
        msg = struct.pack("i", len(msg)) + msg
        self.client.sendall(msg)
        data = self.client.recv(bufsize)

        length = struct.unpack("i", data[:4])[0]
        res = data[4:]
        while len(res) < length:
            tmp = self.client.recv(bufsize)
            res += tmp
            # logger.info([length, len(res), len(tmp)])
        str_decompress_gzip = decompress_gzip(res)
        if len(res) > length:
            raise RuntimeError(f"接收字节数大于原始文件字节数：接收{len(res)}，原始{length}")

        data = json.loads(str_decompress_gzip)
        return data

    def get_systemversion(self):
        if self.cmd("ls /etc/system-release").strip():
            return self.cmd("cat /etc/system-release").strip()
        else:
            response = self.cmd("lsb_release -d").strip()
            res = response.strip().split(":", 1)[1].strip()
            return res

    def md5(self, file):
        return self.cmd("md5sum %s|awk {'print $1'}" % file).strip()

    def socketserver_start(self, host=None, port=30001, bufsize=1024):
        data = {"host": host, "port": port}
        msg = struct.pack("i", 171) + json.dumps(obj=data).encode("utf-8")
        msg = struct.pack("i", len(msg)) + msg
        self.client.sendall(msg)
        data = self.client.recv(bufsize)
        return data

    def socketserver_dataclean(self, bufsize=1024):
        msg = struct.pack("i", 172)
        msg = struct.pack("i", len(msg)) + msg
        self.client.sendall(msg)
        data = self.client.recv(bufsize)
        return data

    def socketserver_writefile(self, file="/tmp/socketserver.bin", bufsize=1024):
        data = {"file": file}
        msg = struct.pack("i", 173) + json.dumps(obj=data).encode("utf-8")
        msg = struct.pack("i", len(msg)) + msg
        self.client.sendall(msg)
        data = self.client.recv(bufsize)
        return data

    def socketserver_data(self):
        msg = struct.pack("i", 174)
        msg = struct.pack("i", len(msg)) + msg
        self.client.sendall(msg)

        # 接收二进制文件
        res = b""
        tmp = self.client.recv(1024)
        # logger.info(tmp)
        length = struct.unpack("<Q", tmp[:8])[0]
        res += tmp[8:]
        while len(res) < length:
            tmp = self.client.recv(102400)
            res += tmp
            # logger.info([length, len(res), len(tmp)])
        # logger.info(res)
        str_decompress_gzip = decompress_gzip(res)
        logger.info(
            f"get host:{self.host}, port:{self.port}, 文件长度:{len(str_decompress_gzip)}, 传输长度:{length}")
        if len(res) > length:
            raise RuntimeError(f"接收字节数大于原始文件字节数：接收{len(res)}，原始{length}")
        return str_decompress_gzip

    # def socketserver_cachedata(self, bufsize=1024):
    #     msg = struct.pack("i", 175)
    # msg = struct.pack("i", len(msg)) + msg
    #     self.client.sendall(msg)
    #     data = self.client.recv(bufsize)
    #     return data

    def listdir(self, path, args="", maxdepth=1, sorted=False):
        '''通过find命令查询，
        :param path:
        :param args: 例如：-name "*.txt"
        :param maxdepth: 默认1，0不限制
        :return:
        '''
        res = list()
        param = f"-maxdepth {maxdepth} {args}" if maxdepth else f"{args}"
        if sorted:
            param += "|sort -V"
        if not self.isdir(path):
            logger.error(f"SocketLinux.listdir找不到目录：{path}")
            return res
        else:
            cmd = f"cd {path};find ./ {param}"
            response = self.python_cmd(f"os.popen('{cmd}')", "read()")
            # response = self.cmd(args=cmd, cwd=path, bufsize=bufsize).strip()
            if response:
                res = response.strip().split("\n")
        res = list(map(lambda x: x[2:], res))
        return res

    def cp(self, spath, dpath, cwd=None, args="-r"):
        '''使用cp命令
        :param spath:支持/tmp/*
        :param dpath:
        :param cwd:
        :param args: 例如： -r
        :return:
        '''
        cmd = f"sudo cp {args} {spath} {dpath}"
        response = self.cmd(cmd, cwd=cwd, returnall=True)
        if response["code"] != 0:
            raise RuntimeError(f"SocketLinux.cp处理异常：{response}，对应命令：{cmd}")

    def mv(self, spath, dpath, cwd=None, args=""):
        '''使用mv命令
        :param spath:支持/tmp/*
        :param dpath:
        :param cwd:
        :param args: 例如： -r
        :return:
        '''
        cmd = f"sudo mv {args} {spath} {dpath}"
        response = self.cmd(cmd, cwd=cwd, returnall=True)
        if response["code"] != 0:
            raise RuntimeError(f"SocketLinux.mv处理异常：{response}，对应命令：{cmd}")

    def rm(self, path, cwd=None, args="-rf"):
        '''使用rm命令
        :param path:支持/tmp/*
        :param cwd:
        :param args: 例如： -r
        :return:
        '''
        cmd = f"rm {args} {path}"
        response = self.cmd(cmd, cwd=cwd, returnall=True)
        if response["code"]!= 0:
            raise RuntimeError(f"SocketLinux.rm处理异常：{response}，对应命令：{cmd}")

    def cleardir(self, path, cwd=None, args=""):
        '''使用find命令
        :param path:
        :param cwd:
        :param args: 例如： -name "*.txt"
        :return:
        '''
        if not self.isdir(path):
            logger.info(f"目录不存在：{path}")
            return
        cmd = f"find {path} {args} -exec rm -rf {{}} \\;"
        logger.info(f"清空目录：{path}，命令：{cmd}")
        response = self.cmd(cmd, cwd=cwd, returnall=True)
        # if response["code"]!= 0:
        #     raise RuntimeError(f"SocketLinux.cleandir处理异常：{response}，对应命令：{cmd}")

    def clearsubfile(self, path, cwd=None, args=""):
        '''使用find命令
        :param path:
        :param cwd:
        :param args: 例如： -name "*.txt"
        :return:
        '''
        cmd = f"find {path} {args} -type f -exec rm -rf {{}} \\;"
        response = self.cmd(cmd, cwd=cwd, returnall=True)
        if response["code"]!= 0:
            raise RuntimeError(f"SocketLinux.clearsubfile处理异常：{response}，对应命令：{cmd}")

    def cleardpifile(self, paths=('/tmp/dpi',)):
        '''使用find命令
        :param paths:
        :return:
        '''
        for path in paths:
            cmd = f"find / {path}* -exec rm -rf {{}} \\;"
            response = self.cmd(cmd, returnall=True)
            if response["code"]!= 0:
                raise RuntimeError(f"SocketLinux.cleardpifile处理异常：{response}，对应命令：{cmd}")
    def wget_ftp(self, remotepath, localpath, user="weihang", password="12345678", overwrite=True):
        logger.info(f"下载：{remotepath} --> {localpath}")
        if self.isfile(localpath):
            logger.info(f"已经存在{localpath}")
            if overwrite:
                self.rm(localpath)
            else:
                return
        elif self.isdir(localpath):
            localpath = localpath.rstrip("/") + "/" + os.path.basename(remotepath)
        if remotepath.startswith("ftp://"):
            cmd = f"wget  --ftp-user={user}  --ftp-password={password}  -O {localpath} {remotepath}"
            # logger.info(f"服务器：{self.host}，执行命令：{cmd}")
            logger.info(self.python_cmd(f"os.popen('{cmd}')", "read()"))
        else:
            self.put(locatpath=remotepath, remotepath=localpath, overwrite=overwrite)
        logger.info(f"下载完成：{localpath}")

    def is_virtual_machine(self):
        cmd = "systemd-detect-virt"
        response = self.cmd(cmd).strip()
        if response in ("kvm", "vmware", "oracle", "microsoft", "qemu", "xen"):
            return True
        else:
            return False

    def ensure_command(self, cmd: str, install_cmd: str = None, bufsize=1024):
        """
        确保系统中存在指定命令，如果不存在且提供了安装命令，则尝试自动安装。
        :param cmd:
        :param install_cmd:
        :return:
        """
        logger.info(f"查询系统命令是否存在：{cmd}")
        data = {"cmd": cmd, "install_cmd": install_cmd}
        msg = struct.pack("i", 18) + json.dumps(obj=data).encode("utf-8")
        msg = struct.pack("i", len(msg)) + msg
        self.client.sendall(msg)
        data = self.client.recv(bufsize)
        data = json.loads(data)
        return data["res"]

    def extract_pcap_flow_five_tuples(self, pcap_dir, bufsize=4096):
        """提取远端 pcap 目录下所有 pcap 文件的方向化五元组流。

        调用 socket_server 端的 extract_pcap_flow_five_tuples，全包遍历 pcap，
        按双向流分组并修正方向（TCP 三次握手 / HTTP 标识），每条流至多调整一次。

        :param pcap_dir: 远端 pcap 文件所在目录（递归查找 *.pcap）
        :return: list[dict]，每条流一项：
                 {pcap, srcIp, srcPort, destIp, destPort, protoType}
                 src=方向化后的客户端；ICMP 无端口，srcPort/destPort 为 "0"
                 protoType: 1=TCP, 2=UDP, 3=SCTP, 4=ICMP
        """
        logger.info(f"提取pcap五元组流：{pcap_dir}")
        data = {"pcap_dir": pcap_dir}
        msg = struct.pack("i", 200) + json.dumps(obj=data).encode("utf-8")
        msg = struct.pack("i", len(msg)) + msg
        self.client.sendall(msg)
        # 接收 4字节长度前缀 + JSON
        data = self.client.recv(bufsize)
        length = struct.unpack("i", data[:4])[0]
        res = data[4:]
        while len(res) < length:
            tmp = self.client.recv(bufsize)
            if not tmp:
                time.sleep(0.01)
            res += tmp
        if len(res) > length:
            raise RuntimeError(f"接收字节数大于原始字节数：接收{len(res)}，原始{length}")
        result = json.loads(res.decode("utf-8"))
        logger.info(f"提取pcap五元组流完成，共 {len(result)} 条流")
        return result

    from scapy.all import rdpcap, wrpcap
    import os

    def download_pcap(self, remotepath: str, localpath: str, return_pkts=False):
        # 创建本地目录
        if localpath.endswith(".pcap"):
            localdir = os.path.dirname(localpath)
        else:
            localdir = localpath

        if not os.path.isdir(localdir):
            os.makedirs(localdir)

        pkts = list()
        # 单文件下载
        if self.isfile(file=remotepath):
            if os.path.isdir(localpath):
                remotename = remotepath.rsplit("/", 1)[-1]
                localpath_tmp = os.path.join(localpath, remotename)
            else:
                localpath_tmp = localpath
            with open(localpath_tmp, "wb") as f:
                fl = self.getfo(remotepath=remotepath, gzip=True)
                f.write(fl.getvalue())
                if return_pkts:
                    fl.seek(0)
                    pkts = rdpcap(fl)

        # 多文件合并下载（写入一个 pcap）
        else:
            if not os.path.isdir(localpath):
                first = True  # 标记是否是第一个文件
                for remotepcap in self.listdir(path=remotepath, args='-name "*.pcap"', sorted=True):
                    full_remote = remotepath.rstrip("/") + "/" + remotepcap
                    fl = self.getfo(remotepath=full_remote, gzip=True)
                    pkts_tmp = rdpcap(fl)
                    wrpcap(localpath, pkts_tmp, append=not first)
                    if return_pkts:
                        pkts += list(pkts_tmp)
                    first = False
            else:
                for remotepcap in self.listdir(path=remotepath, args='-name "*.pcap"', sorted=True):
                    full_remote = remotepath.rstrip("/") + "/" + remotepcap
                    localpath_tmp = os.path.join(localpath, remotepcap)
                    with open(localpath_tmp, "wb") as f:
                        fl = self.getfo(remotepath=full_remote, gzip=True)
                        f.write(fl.getvalue())
                        if return_pkts:
                            fl.seek(0)
                            pkts += list(rdpcap(fl))
        if return_pkts:
            return pkts

# type 0 scapy 发包【0,发包参数{pcap=pcap, iface=iface, inter=inter,return_packets=true}转json】
# type 1 操作系统命令【{args=data, cwd=None, env=None,shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, encoding="utf-8"}转json】
# type 21 文件上传/下载：文件名【{"filepath":filepath}转json】
# type 22 文件上传：文件长度【4字节整形b"
# type 23 文件上传：文件内容上传【b"】
# type 24 文件上传：内容写入文件【】
# type 3 文件下载：获取21对应的文件【】，返回二进制字符串
# type 4 路由信息查询routeinfo
# type 5 开启tcpdump抓包，【eth=None, path="/home/tmp/tmp.pcap", extended=""】
# type 6 停止tcpdump抓包
# type 7 是否文件【file=''】
# type 8 是否目录【dir=''】
# type 9 创建目录【dir=''】
# type 10 修改mtu【eth='', value=2000】
# type 11 文件大小【file=''】
# type 121 开启抓包【"iface": self.iface, "filter": self.filter, "path": self.remotepath, "timeout": self.timeout】
# type 122 停止抓包【】
# type 123 下载pcap包【】
# type 131 开始拨测【url, count=1, interval=0, thread_count=1, timeout=None】
# type 132 拨测线程运行状态【】
# type 133 获取拨测结果【】
# type 133 获取拨测结果【】
# type 14 获取版本号【】
# type 15 zip文件解压【file, outdir=None, passwd=None】
# type 16 本地执行os命令，示例：python_cmd(f"os.popen('{cmd}')", "read()")
# type 171 socket监听-启动，【host="0.0.0.0", port=30001】
# type 172 socket监听-清理数据，【】
# type 173 socket监听-保存数据，【file="/tmp/socketserver.bin"】
# type 174 socket监听-取数据
# type 174 socket监听-缓存数据，数据提取前都需先要缓存数据
# tpye 18 确保系统中存在指定命令，如果不存在且提供了安装命令，则尝试自动安装。ensure_command(cmd="ifconfig", install_cmd="yum install -y net-tools")

if __name__ == '__main__':
    # client = socket.socket(family=socket.AF_INET, type=socket.SOCK_STREAM)
    # client.connect(("172.31.140.98", 9000))
    sl = SocketLinux(("10.12.131.82", 9000))
    print(sl.cmd("date +%s"))
    # logger.info([sl.scapy_send(pcaps=["/home/pcap_auto/bc/pcapdump_1.pcap"],uplink_iface="ens192f2" )])
    # print(sl.update_systime())
    # a = sl.getfo(remotepath="/dev/shm/sess/pcap/0xffff/100000000012345/13/2025-11-04/1006/421310_001002_1006202511040902228950670004000.pcap")
    # a = sl.download_pcap("/dev/shm/sess/pcap/0xffff/100000000012345/13/2025-11-04/1006", r"D:\Desktop\v1.1\aaa\11.pcap", return_pkts=True)
    # s1 = time.time()
    # print(s1)
    # sl.getfo(remotepath="/home/ACT-ALL-SSSP-1.2.3.0-2_20250605101010.tar.gz", gzip=True)
    # s2 = time.time()
    # print(s2)
    # print(s2 - s1)
    # a = sl.scapy_send(eth="ens193", pcaps=[r"/tmp/tmp.pcap"], mbps=50)
    # a = sl.scapy_send(**{'pcaps': ['/home/pcap_auto/monitor/IP-TCP-10.1.1.1-20.1.1.1-8604-80-5-2-361-1231.pcap', '/home/pcap_auto/monitor/IP-TCP-10.1.1.2-20.1.1.2-4537-80-5-2-361-1226.pcap', '/home/pcap_auto/monitor/IP-TCP-10.1.1.10-20.1.1.10-29379-80-6-4-428-3381.pcap', '/home/pcap_auto/monitor/IP-TCP-10.1.1.11-20.1.1.11-63725-80-6-4-433-3368.pcap', '/home/pcap_auto/monitor/IP-TCP-10.1.1.12-20.1.1.12-62110-80-19-28-1359-35007.pcap', '/home/pcap_auto/monitor/IP-TCP-10.1.1.13-20.1.1.13-53335-8880-15-22-1096-27224.pcap', '/home/pcap_auto/monitor/IP-TCP-10.1.1.14-20.1.1.14-20175-80-11-16-745-21964.pcap', '/home/pcap_auto/monitor/IP-TCP-10.1.1.22-20.1.1.22-15231-80-7-7-493-8669.pcap', '/home/pcap_auto/monitor/IP-TCP-10.1.1.23-20.1.1.23-59595-80-7-9-1475-4099.pcap', '/home/pcap_auto/monitor/IP-TCP-10.1.1.24-20.1.1.24-52788-80-6-7-577-5424.pcap', '/home/pcap_auto/monitor/IP-TCP-10.1.1.25-20.1.1.25-49774-28597-10-14-803-15001.pcap', '/home/pcap_auto/monitor/IP-TCP-10.1.1.26-20.1.1.26-60898-80-7-8-869-9507.pcap', '/home/pcap_auto/monitor/IP-TCP-10.1.1.27-20.1.1.27-47304-80-4-2-367-1312.pcap', '/home/pcap_auto/monitor/IP-TCP-10.1.1.28-20.1.1.28-51703-80-6-5-549-2533.pcap', '/home/pcap_auto/monitor/IP-TCP-10.1.1.29-20.1.1.29-59568-80-5-4-395-3829.pcap', '/home/pcap_auto/monitor/IP-TCP-10.1.1.30-20.1.1.30-59569-80-5-4-395-3829.pcap', '/home/pcap_auto/monitor/IP-TCP-10.1.1.31-20.1.1.31-59570-80-5-4-395-3829.pcap', '/home/pcap_auto/monitor/IP-TCP-10.1.1.32-20.1.1.32-59571-80-5-4-395-3829.pcap', '/home/pcap_auto/monitor/IP-TCP-10.1.1.33-20.1.1.33-59572-80-5-4-395-3829.pcap', '/home/pcap_auto/monitor/IP-TCP-10.1.1.34-20.1.1.34-59573-80-5-4-395-3829.pcap', '/home/pcap_auto/monitor/IP-TCP-10.1.1.35-20.1.1.35-59575-80-5-4-395-3829.pcap', '/home/pcap_auto/monitor/IP-TCP-10.1.1.36-20.1.1.36-59576-80-5-4-395-3829.pcap', '/home/pcap_auto/monitor/IP-TCP-10.1.1.37-20.1.1.37-59577-80-5-4-396-3829.pcap', '/home/pcap_auto/monitor/IP-TCP-10.1.1.38-20.1.1.38-59578-80-5-4-396-3829.pcap', '/home/pcap_auto/monitor/IP-TCP-10.1.1.39-20.1.1.39-59579-80-5-4-396-3829.pcap', '/home/pcap_auto/monitor/IP-TCP-10.1.1.40-20.1.1.40-59580-80-5-4-396-3829.pcap', '/home/pcap_auto/monitor/IP-TCP-10.1.1.41-20.1.1.41-59581-80-5-4-396-3829.pcap', '/home/pcap_auto/monitor/IP-TCP-10.1.1.42-20.1.1.42-59582-80-5-4-396-3829.pcap', '/home/pcap_auto/monitor/IP-TCP-10.1.1.43-20.1.1.43-59583-80-5-4-396-3829.pcap', '/home/pcap_auto/monitor/IP-TCP-10.1.1.44-20.1.1.44-59584-80-5-4-396-3829.pcap', '/home/pcap_auto/monitor/IP-TCP-10.1.1.45-20.1.1.45-59585-80-5-4-396-3829.pcap', '/home/pcap_auto/monitor/IP-TCP-10.1.1.46-20.1.1.46-59586-80-5-4-396-3829.pcap', '/home/pcap_auto/monitor/IP-TCP-10.1.1.47-20.1.1.47-59587-80-5-4-396-3829.pcap', '/home/pcap_auto/monitor/IP-TCP-10.1.1.48-20.1.1.48-59588-80-5-4-396-3829.pcap', '/home/pcap_auto/monitor/IP-TCP-10.1.1.49-20.1.1.49-59589-80-5-4-396-3829.pcap', '/home/pcap_auto/monitor/IP-TCP-10.1.1.50-20.1.1.50-59590-80-5-4-396-3829.pcap', '/home/pcap_auto/monitor/IP-TCP-10.1.1.51-20.1.1.51-59591-80-5-4-396-3829.pcap', '/home/pcap_auto/monitor/IP-TCP-10.1.1.52-20.1.1.52-59592-80-5-4-396-3829.pcap', '/home/pcap_auto/monitor/IP-TCP-10.1.1.53-20.1.1.53-59593-80-5-4-396-3829.pcap', '/home/pcap_auto/monitor/IP-TCP-10.1.1.54-20.1.1.54-59594-80-5-4-396-3829.pcap', '/home/pcap_auto/monitor/IP-TCP-10.1.1.55-20.1.1.55-59595-80-5-4-396-3829.pcap', '/home/pcap_auto/monitor/IP-TCP-10.1.1.56-20.1.1.56-26914-80-5-2-373-596.pcap', '/home/pcap_auto/monitor/IP-TCP-10.1.1.57-20.1.1.57-1716-80-9-11-613-14982.pcap', '/home/pcap_auto/monitor/IP-TCP-10.1.1.58-20.1.1.58-24104-80-9-13-615-18187.pcap', '/home/pcap_auto/monitor/IP-TCP-10.1.1.59-20.1.1.59-12660-80-9-11-615-14912.pcap', '/home/pcap_auto/monitor/IP-TCP-10.1.1.60-20.1.1.60-47563-80-10-13-673-18218.pcap', '/home/pcap_auto/monitor/IP-TCP-10.1.1.61-20.1.1.61-15313-80-9-13-615-18202.pcap', '/home/pcap_auto/monitor/IP-TCP-20.2.1.174-30.2.1.174-5376-21-9-11-606-948.pcap', '/home/pcap_auto/monitor/IP-TCP-20.2.1.176-30.2.1.176-62741-22-9-9-1170-1538.pcap', '/home/pcap_auto/monitor/IP-TCP-20.2.1.178-30.2.1.178-1254-23-159-113-10761-9208.pcap', '/home/pcap_auto/monitor/IP-TCP-20.2.1.180-30.2.1.180-62125-25-29-25-23700-1851.pcap', '/home/pcap_auto/monitor/IP-TCP-20.2.1.182-30.2.1.182-20480-80-4-2-318-356.pcap', '/home/pcap_auto/monitor/IP-TCP-20.2.1.184-30.2.1.184-61215-110-24-31-1478-27266.pcap', '/home/pcap_auto/monitor/IP-TCP-20.2.1.186-30.2.1.186-55617-443-78-148-5147-219640.pcap', '/home/pcap_auto/monitor/IP-UDP-20.2.1.188-30.2.1.188-48346-53-1-1-83-940.pcap', '/home/pcap_auto/monitor/IP-TCP-20.2.1.190-30.2.1.190-49169-389-11-7-2955-3721.pcap', '/home/pcap_auto/monitor/IP-TCP-20.2.1.192-30.2.1.192-13178-3389-218-211-50100-39196.pcap', '/home/pcap_auto/monitor/IP-UDP-20.2.1.194-30.2.1.194-38414-161-1-1-79-154.pcap', '/home/pcap_auto/monitor/IP-UDP-20.2.1.196-30.2.1.196-63675-1900-1-0-216-0.pcap', '/home/pcap_auto/monitor/IP-TCP-20.2.1.198-30.2.1.198-1160-5901-1149-1631-69054-2262354.pcap', '/home/pcap_auto/monitor/IP-UDP-20.2.1.200-30.2.1.200-5353-5353-50-0-6565-0.pcap', '/home/pcap_auto/monitor/IP-TCP-20.2.1.202-30.2.1.202-49194-1723-12-10-1260-980.pcap', '/home/pcap_auto/monitor/IP-UDP-20.2.1.206-30.2.1.206-53136-4500-1023-1022-227819-1148634.pcap', '/home/pcap_auto/monitor/IP-ICMP-20.2.1.208-30.2.1.208-None-None-21-10-1260-600.pcap', '/home/pcap_auto/monitor/IP-TCP-20.2.1.209-30.2.1.209-50489-143-13-9-1066-850.pcap', '/home/pcap_auto/monitor/IP-UDP-20.2.1.211-30.2.1.211-68-67-1-0-342-0.pcap', '/home/pcap_auto/monitor/IP-TCP-20.2.1.213-30.2.1.213-30000-1720-10-10-2271-1779.pcap', '/home/pcap_auto/monitor/IP-TCP-20.2.1.215-30.2.1.215-53533-1080-8-6-695-2003.pcap', '/home/pcap_auto/monitor/IP-TCP-20.2.1.217-30.2.1.217-36164-1080-7-7-491-478.pcap', '/home/pcap_auto/monitor/IP-UDP-20.2.1.219-30.2.1.219-62570-1813-4-4-2039-248.pcap', '/home/pcap_auto/monitor/IP-TCP-20.2.1.221-30.2.1.221-53336-80-4-6-520-6110.pcap', '/home/pcap_auto/monitor/IP-UDP-20.2.1.223-30.2.1.223-123-123-2-2-240-240.pcap', '/home/pcap_auto/monitor/IP-UDP-20.2.1.227-30.2.1.227-61442-69-1-0-78-0.pcap', '/home/pcap_auto/monitor/IP-TCP-20.2.1.229-30.2.1.229-50216-1935-379-500-29190-729154.pcap', '/home/pcap_auto/monitor/IP-TCP-20.2.1.231-30.2.1.231-54100-5060-7-7-1449-1720.pcap', '/home/pcap_auto/monitor/IP-TCP-20.2.1.233-30.2.1.233-54150-554-9-8-1460-1897.pcap', '/home/pcap_auto/monitor/IP-UDP-20.2.1.235-30.2.1.235-25963-31601-74-18-11396-2412.pcap', '/home/pcap_auto/monitor/IP-TCP-20.2.1.237-30.2.1.237-54150-554-9-8-1460-1897.pcap', '/home/pcap_auto/monitor/IP-TCP-20.2.1.239-30.2.1.239-58340-5222-11-7-1203-1392.pcap', '/home/pcap_auto/monitor/IP-TCP-20.2.1.241-30.2.1.241-41188-80-79-78-5227-104967.pcap', '/home/pcap_auto/monitor/IP-TCP-20.2.1.245-30.2.1.245-59911-995-26-35-2211-18488.pcap', '/home/pcap_auto/monitor/IP-TCP-20.2.1.247-30.2.1.247-61816-465-19-19-3524-4825.pcap', '/home/pcap_auto/monitor/IP-TCP-20.2.1.249-30.2.1.249-20021-62763-2-2-502-167.pcap', '/home/pcap_auto/monitor/IP-TCP-20.2.1.251-30.2.1.251-55794-443-11-9-1234-7915.pcap', '/home/pcap_auto/monitor/IP-TCP-20.2.1.253-30.2.1.253-5454-443-7524-9294-1714901-11110132.pcap', '/home/pcap_auto/monitor/IP-TCP-20.2.1.255-30.2.1.255-4194-443-8-9-1309-6371.pcap', '/home/pcap_auto/monitor/IP-TCP-20.2.2.1-30.2.2.1-4624-80-6-5-2399-1060.pcap', '/home/pcap_auto/monitor/IP-UDP-20.2.2.3-30.2.2.3-4466-17767-2-0-804-0.pcap', '/home/pcap_auto/monitor/IP-TCP-20.2.2.5-30.2.2.5-14265-443-1583-2718-414766-1897141.pcap', '/home/pcap_auto/monitor/IP-TCP-20.2.2.7-30.2.2.7-49287-443-22-21-6448-8107.pcap', '/home/pcap_auto/monitor/IP-TCP-20.2.2.9-30.2.2.9-58140-443-10-11-1383-4847.pcap', '/home/pcap_auto/monitor/IP-TCP-20.2.2.11-30.2.2.11-43130-443-17-16-3703-3958.pcap', '/home/pcap_auto/monitor/IP-TCP-20.2.2.13-30.2.2.13-16343-443-24-38-3639-39949.pcap', '/home/pcap_auto/monitor/IP-TCP-20.2.2.15-30.2.2.15-3659-443-10-8-2440-1343.pcap', '/home/pcap_auto/monitor/IP-TCP-20.2.2.17-30.2.2.17-60373-80-29-25-2443-26097.pcap', '/home/pcap_auto/monitor/IP-TCP-20.2.2.19-30.2.2.19-21146-80-260-268-27555-320666.pcap', '/home/pcap_auto/monitor/IP-TCP-20.2.2.21-30.2.2.21-49828-993-75-70-6162-76458.pcap', '/home/pcap_auto/monitor/IP-TCP-20.2.2.23-30.2.2.23-2914-80-53-53-54034-3317.pcap', '/home/pcap_auto/monitor/IP-TCP-20.2.2.25-30.2.2.25-50649-443-8-10-1101-6060.pcap', '/home/pcap_auto/monitor/IP-TCP-20.2.2.29-30.2.2.29-61956-80-5-3-1711-1605.pcap', '/home/pcap_auto/monitor/IP-TCP-20.2.2.31-30.2.2.31-13743-80-5-4-1234-485.pcap', '/home/pcap_auto/monitor/IP-TCP-20.2.2.33-30.2.2.33-57042-80-18-49-1322-68370.pcap', '/home/pcap_auto/monitor/IP-TCP-20.2.2.35-30.2.2.35-56862-443-15-14-1807-7932.pcap', '/home/pcap_auto/monitor/IP-TCP-20.2.2.37-30.2.2.37-44034-443-14-13-3049-8745.pcap', '/home/pcap_auto/monitor/IP-TCP-20.2.2.39-30.2.2.39-42071-443-351-353-29184-459443.pcap', '/home/pcap_auto/monitor/IP-TCP-20.2.2.43-30.2.2.43-55746-443-40-69-8558-75909.pcap', '/home/pcap_auto/monitor/IP-TCP-20.2.2.45-30.2.2.45-5885-443-171-269-26022-311223.pcap', '/home/pcap_auto/monitor/IP-TCP-20.2.2.47-30.2.2.47-40448-443-12-12-1499-5660.pcap', '/home/pcap_auto/monitor/IP-TCP-20.2.2.49-30.2.2.49-46028-80-8-7-1985-2527.pcap', '/home/pcap_auto/monitor/IPv6-TCP-2e01__1-2e02__1-21592-80-4-3-375-481.pcap', '/home/pcap_auto/monitor/IPv6-TCP-2e01__2-2e02__2-19142-80-4-3-375-481.pcap', '/home/pcap_auto/monitor/IPv6-TCP-2e01__3-2e02__3-10092-80-4-3-375-481.pcap', '/home/pcap_auto/monitor/IPv6-TCP-__1001-2e02__4-14841-80-4-3-375-481.pcap', '/home/pcap_auto/monitor/IPv6-TCP-2e01__5-2e02__5-12906-80-4-3-375-481.pcap', '/home/pcap_auto/monitor/IPv6-TCP-2e01__6-2e02__6-34931-80-4-3-375-481.pcap', '/home/pcap_auto/monitor/IPv6-TCP-2e01__7-2e02__7-4127-80-4-3-375-481.pcap', '/home/pcap_auto/monitor/IPv6-TCP-2e01__8-2e02__8-10650-80-4-3-375-481.pcap', '/home/pcap_auto/monitor/IPv6-TCP-2e01__9-2e02__9-38189-80-4-3-375-481.pcap', '/home/pcap_auto/monitor/IPv6-TCP-2e01__a-2e02__a-19143-80-4-3-375-481.pcap', '/home/pcap_auto/monitor/IPv6-TCP-2e01__b-__2001-21647-80-4-3-375-481.pcap', '/home/pcap_auto/monitor/IPv6-TCP-2e01__c-2e02_1__-53079-80-4-3-375-481.pcap', '/home/pcap_auto/monitor/IPv6-TCP-2e01__d-2e02__d-10093-80-4-3-375-481.pcap', '/home/pcap_auto/monitor/IPv6-TCP-2e01__e-2e02__e-34932-80-4-3-375-481.pcap', '/home/pcap_auto/monitor/IPv6-TCP-2e01__10-2e02__10-34933-80-4-3-376-481.pcap', '/home/pcap_auto/monitor/IPv6-TCP-2e01__11-__2_0_0_1-22967-80-4-2-377-388.pcap', '/home/pcap_auto/monitor/IPv6-TCP-2e01__12-__2_0_0_2-22968-80-4-2-377-388.pcap', '/home/pcap_auto/monitor/IPv6-TCP-2e01__13-2e02__13-48276-80-4-3-374-1355.pcap', '/home/pcap_auto/monitor/IPv6-TCP-2e01__14-2e02__14-46171-80-4-4-389-555.pcap', '/home/pcap_auto/monitor/IPv6-TCP-2e01__15-2e02__15-43995-8001-4-3-379-481.pcap', '/home/pcap_auto/monitor/IPv6-TCP-2e01__16-2e02__16-62086-80-4-3-384-481.pcap', '/home/pcap_auto/monitor/IPv6-TCP-2e01__17-2e02__17-54309-80-7-8-603-9739.pcap', '/home/pcap_auto/monitor/IPv6-TCP-2e01__1a-2e02__1a-18314-80-4-2-378-388.pcap', '/home/pcap_auto/monitor/IPv6-TCP-2e01__1f-2e02__1f-51684-80-4-3-376-481.pcap', '/home/pcap_auto/monitor/IPv6-TCP-2e01__20-2e02__20-63141-8002-4-3-381-481.pcap', '/home/pcap_auto/monitor/IPv6-TCP-2e01__21-2e02__21-13200-80-4-3-376-481.pcap', '/home/pcap_auto/monitor/IPv6-TCP-2e01__22-2e02__22-13607-80-4-3-376-481.pcap', '/home/pcap_auto/monitor/IPv6-TCP-2e01__23-2e02__23-46377-80-7-8-603-9739.pcap', '/home/pcap_auto/monitor/IPv6-TCP-2e01__24-2e02__24-63142-8002-4-3-381-481.pcap', '/home/pcap_auto/monitor/IPv6-TCP-2e01__25-2e02__25-43996-8001-4-3-379-481.pcap', '/home/pcap_auto/monitor/IPv6-TCP-2e01__26-2e02__26-55157-80-4-3-396-481.pcap', '/home/pcap_auto/monitor/IPv6-TCP-2e01__27-2e02__27-55133-80-4-3-435-481.pcap', '/home/pcap_auto/monitor/IPv6-TCP-2e01__28-2e02__28-55156-80-4-3-383-481.pcap', '/home/pcap_auto/monitor/IPv6-TCP-2e01__29-2e02__29-55127-80-4-3-468-481.pcap', '/home/pcap_auto/monitor/IPv6-TCP-2e01__2a-2e02__2a-55128-80-4-3-468-481.pcap', '/home/pcap_auto/monitor/IPv6-TCP-2e01__2b-2e02__2b-55129-80-4-3-468-481.pcap', '/home/pcap_auto/monitor/IPv6-TCP-2e01__2c-2e02__2c-55130-80-4-3-468-481.pcap', '/home/pcap_auto/monitor/IPv6-TCP-2e01__2d-2e02__2d-44931-80-4-3-468-481.pcap', '/home/pcap_auto/monitor/IPv6-TCP-2e01__2e-2e02__2e-55132-80-4-3-468-481.pcap', '/home/pcap_auto/monitor/IPv6-TCP-2e01__2f-2e02__2f-55134-80-4-3-468-481.pcap', '/home/pcap_auto/monitor/IPv6-TCP-2e01__30-2e02__30-55135-80-4-3-468-481.pcap', '/home/pcap_auto/monitor/IPv6-TCP-2e01__31-2e02__31-55136-80-4-3-469-481.pcap', '/home/pcap_auto/monitor/IPv6-TCP-2e01__32-2e02__32-55137-80-4-3-469-481.pcap', '/home/pcap_auto/monitor/IPv6-TCP-2e01__33-2e02__33-55138-80-4-3-469-481.pcap', '/home/pcap_auto/monitor/IPv6-TCP-2e01__34-2e02__34-55139-80-4-3-469-481.pcap', '/home/pcap_auto/monitor/IPv6-TCP-2e01__35-2e02__35-55140-80-4-3-469-481.pcap', '/home/pcap_auto/monitor/IPv6-TCP-2e01__36-2e02__36-55141-80-4-3-469-481.pcap', '/home/pcap_auto/monitor/IPv6-TCP-2e01__37-2e02__37-55142-80-4-3-469-481.pcap', '/home/pcap_auto/monitor/IPv6-TCP-2e01__38-2e02__38-55143-80-4-3-469-481.pcap', '/home/pcap_auto/monitor/IPv6-TCP-2e01__39-2e02__39-55144-80-4-3-469-481.pcap', '/home/pcap_auto/monitor/IPv6-TCP-2e01__3a-2e02__3a-55145-80-4-3-469-481.pcap', '/home/pcap_auto/monitor/IPv6-TCP-2e01__3b-2e02__3b-55146-80-4-3-469-481.pcap', '/home/pcap_auto/monitor/IPv6-TCP-2e01__3c-2e02__3c-55148-80-4-3-469-481.pcap', '/home/pcap_auto/monitor/IPv6-TCP-2e01__3d-2e02__3d-55149-80-4-3-469-481.pcap', '/home/pcap_auto/monitor/IPv6-TCP-2e01__3e-2e02__3e-55150-80-4-3-469-481.pcap', '/home/pcap_auto/monitor/IPv6-TCP-2e01__3f-2e02__3f-55151-80-4-3-469-481.pcap', '/home/pcap_auto/monitor/IPv6-TCP-2e01__40-2e02__40-55152-80-4-3-469-481.pcap', '/home/pcap_auto/monitor/IPv6-TCP-2e01__41-2e02__41-55153-80-4-3-469-481.pcap', '/home/pcap_auto/monitor/IPv6-TCP-2e01__42-2e02__42-55154-80-4-3-469-481.pcap', '/home/pcap_auto/monitor/IPv6-TCP-2e01__43-2e02__43-55147-80-4-3-469-481.pcap', '/home/pcap_auto/monitor/IPv6-TCP-2e02__2ac-2e03__2ac-5376-21-9-11-782-1164.pcap', '/home/pcap_auto/monitor/IPv6-TCP-2e02__2ae-2e03__2ae-62741-22-9-9-1350-1718.pcap', '/home/pcap_auto/monitor/IPv6-TCP-2e02__2b0-2e03__2b0-1254-23-159-113-13941-11468.pcap', '/home/pcap_auto/monitor/IPv6-TCP-2e02__2b2-2e03__2b2-62125-25-29-25-24262-2267.pcap', '/home/pcap_auto/monitor/IPv6-TCP-2e02__2b4-2e03__2b4-20480-80-4-2-394-396.pcap', '/home/pcap_auto/monitor/IPv6-TCP-2e02__2b6-2e03__2b6-61215-110-24-31-1862-27865.pcap', '/home/pcap_auto/monitor/IPv6-TCP-2e02__2b8-2e03__2b8-55617-443-78-148-6261-222598.pcap', '/home/pcap_auto/monitor/IPv6-UDP-2e02__2ba-2e03__2ba-48346-53-1-1-103-547.pcap', '/home/pcap_auto/monitor/IPv6-TCP-2e02__2bc-2e03__2bc-49169-389-11-7-3145-3849.pcap', '/home/pcap_auto/monitor/IPv6-TCP-2e02__2be-2e03__2be-13178-3389-218-211-54178-42840.pcap', '/home/pcap_auto/monitor/IPv6-UDP-2e02__2c0-2e03__2c0-38414-161-1-1-99-174.pcap', '/home/pcap_auto/monitor/IPv6-UDP-2e02__2c2-2e03__2c2-63675-1900-1-0-236-0.pcap', '/home/pcap_auto/monitor/IPv6-TCP-2e02__2c4-2e03__2c4-1160-5901-1149-1631-85704-2294709.pcap', '/home/pcap_auto/monitor/IPv6-UDP-2e02__2c6-2e03__2c6-5353-5353-50-0-6503-0.pcap', '/home/pcap_auto/monitor/IPv6-TCP-2e02__2c8-2e03__2c8-49194-1723-12-10-1476-1168.pcap', '/home/pcap_auto/monitor/IPv6-UDP-2e02__2cc-2e03__2cc-53136-4500-1023-1022-247939-1168734.pcap', '/home/pcap_auto/monitor/IPv6-ICMPv6-2e02__2ce-2e03__2ce-None-None-1-1-86-86.pcap', '/home/pcap_auto/monitor/IPv6-TCP-2e02__2cf-2e03__2cf-50489-143-13-9-1326-1030.pcap', '/home/pcap_auto/monitor/IPv6-UDP-2e02__2d1-2e03__2d1-546-547-1-0-98-0.pcap', '/home/pcap_auto/monitor/IPv6-TCP-2e02__2d3-2e03__2d3-30000-1720-10-10-2471-1979.pcap', '/home/pcap_auto/monitor/IPv6-TCP-2e02__2d5-2e03__2d5-53533-1080-8-6-855-2123.pcap', '/home/pcap_auto/monitor/IPv6-TCP-2e02__2d7-2e03__2d7-36164-1080-7-7-631-618.pcap', '/home/pcap_auto/monitor/IPv6-UDP-2e02__2d9-2e03__2d9-62570-1813-4-4-2119-328.pcap', '/home/pcap_auto/monitor/IPv6-TCP-2e02__2db-2e03__2db-53336-80-4-6-600-6230.pcap', '/home/pcap_auto/monitor/IPv6-UDP-2e02__2dd-2e03__2dd-123-123-2-2-280-280.pcap', '/home/pcap_auto/monitor/IPv6-UDP-2e02__2e1-2e03__2e1-61442-69-1-0-98-0.pcap', '/home/pcap_auto/monitor/IPv6-TCP-2e02__2e3-2e03__2e3-50216-1935-379-500-36770-739154.pcap', '/home/pcap_auto/monitor/IPv6-TCP-2e02__2e5-2e03__2e5-54100-5060-7-7-1569-1846.pcap', '/home/pcap_auto/monitor/IPv6-TCP-2e02__2e7-2e03__2e7-54150-554-9-8-1620-2043.pcap', '/home/pcap_auto/monitor/IPv6-UDP-2e02__2e9-2e03__2e9-25963-31601-74-18-12876-2772.pcap', '/home/pcap_auto/monitor/IPv6-TCP-2e02__2eb-2e03__2eb-54150-554-9-8-1620-2043.pcap', '/home/pcap_auto/monitor/IPv6-TCP-2e02__2ed-2e03__2ed-58340-5222-11-7-1423-1532.pcap', '/home/pcap_auto/monitor/IPv6-TCP-2e02__2ef-2e03__2ef-41188-80-79-78-6339-106527.pcap', '/home/pcap_auto/monitor/IPv6-TCP-2e02__2f3-2e03__2f3-59911-995-26-35-2647-19134.pcap', '/home/pcap_auto/monitor/IPv6-TCP-2e02__2f5-2e03__2f5-61816-465-19-19-3874-5181.pcap', '/home/pcap_auto/monitor/IPv6-TCP-2e02__2f7-2e03__2f7-20021-62763-2-2-542-201.pcap', '/home/pcap_auto/monitor/IPv6-TCP-2e02__2f9-2e03__2f9-55794-443-11-9-1412-8089.pcap', '/home/pcap_auto/monitor/IPv6-TCP-2e02__2fb-2e03__2fb-5454-443-7524-9294-1857677-11291260.pcap', '/home/pcap_auto/monitor/IPv6-TCP-2e02__2fd-2e03__2fd-4194-443-8-9-1439-6539.pcap', '/home/pcap_auto/monitor/IPv6-TCP-2e02__2ff-2e03__2ff-4624-80-6-5-2501-1142.pcap', '/home/pcap_auto/monitor/IPv6-UDP-2e02__301-2e03__301-4466-17767-2-0-844-0.pcap', '/home/pcap_auto/monitor/IPv6-TCP-2e02__303-2e03__303-14265-443-1583-2718-441446-1949791.pcap', '/home/pcap_auto/monitor/IPv6-TCP-2e02__305-2e03__305-49287-443-22-21-6811-8503.pcap', '/home/pcap_auto/monitor/IPv6-TCP-2e02__307-2e03__307-58140-443-10-11-1559-5043.pcap', '/home/pcap_auto/monitor/IPv6-TCP-2e02__309-2e03__309-43130-443-17-16-3995-4260.pcap', '/home/pcap_auto/monitor/IPv6-TCP-2e02__30b-2e03__30b-16343-443-24-38-4019-40679.pcap', '/home/pcap_auto/monitor/IPv6-TCP-2e02__30d-2e03__30d-3659-443-10-8-2610-1479.pcap', '/home/pcap_auto/monitor/IPv6-TCP-2e02__30f-2e03__30f-60373-80-29-25-2939-26572.pcap', '/home/pcap_auto/monitor/IPv6-TCP-2e02__311-2e03__311-21146-80-260-268-31687-325913.pcap', '/home/pcap_auto/monitor/IPv6-TCP-2e02__313-2e03__313-49828-993-75-70-7476-77834.pcap', '/home/pcap_auto/monitor/IPv6-TCP-2e02__315-2e03__315-2914-80-53-53-55076-4071.pcap', '/home/pcap_auto/monitor/IPv6-TCP-2e02__317-2e03__317-50649-443-8-10-1237-6242.pcap', '/home/pcap_auto/monitor/IPv6-TCP-2e02__31b-2e03__31b-61956-80-5-3-1793-1659.pcap', '/home/pcap_auto/monitor/IPv6-TCP-2e02__31d-2e03__31d-13743-80-5-4-1316-553.pcap', '/home/pcap_auto/monitor/IPv6-TCP-2e02__31f-2e03__31f-57042-80-18-49-1598-69344.pcap', '/home/pcap_auto/monitor/IPv6-TCP-2e02__321-2e03__321-56862-443-15-14-2053-8188.pcap', '/home/pcap_auto/monitor/IPv6-TCP-2e02__323-2e03__323-44034-443-14-13-3275-8981.pcap', '/home/pcap_auto/monitor/IPv6-TCP-2e02__325-2e03__325-42071-443-351-353-36078-466491.pcap', '/home/pcap_auto/monitor/IPv6-TCP-2e02__329-2e03__329-55746-443-40-69-9232-77241.pcap', '/home/pcap_auto/monitor/IPv6-TCP-2e02__32b-2e03__32b-5885-443-171-269-29125-316573.pcap', '/home/pcap_auto/monitor/IPv6-TCP-2e02__32d-2e03__32d-40448-443-12-12-1691-5870.pcap', '/home/pcap_auto/monitor/IPv6-TCP-2e02__32f-2e03__32f-46028-80-8-7-2115-2649.pcap', '/home/pcap_auto/monitor/IP-TCP-10.11.1.1-20.11.1.1-46028-80-8-7-1985-2527.pcap', '/home/pcap_auto/monitor/IP-UDP-10.11.1.2-20.11.1.2-48346-53-1-1-83-527.pcap', '/home/pcap_auto/monitor/IP-SCTP-10.11.1.3-20.11.1.3-38413-38412-1-0-146-0.pcap', '/home/pcap_auto/monitor/IP-ICMP-10.11.1.4-20.11.1.4-None-None-21-10-1260-600.pcap', '/home/pcap_auto/monitor/IP-TCP-10.11.1.5-20.11.1.5-9968-7611-29-28-2723-2038.pcap', '/home/pcap_auto/monitor/IP-TCP-10.11.1.6-20.11.1.6-58164-14567-5-4-578-260.pcap', '/home/pcap_auto/monitor/IP-TCP-10.11.1.9-20.11.1.9-28360-443-8-7-1737-1810.pcap', '/home/pcap_auto/fiter/IPv6-TCP-2e01__1133-2e02__1133-28360-443-8-7-1873-1932.pcap', '/home/pcap_auto/monitor/IP-TCP-10.11.1.10-20.11.1.10-8604-80-2-1-120-60.pcap', '/home/pcap_auto/fiter/IPv6-TCP-2e01__1134-2e02__1134-8604-80-2-1-152-78.pcap', '/home/pcap_auto/monitor/IP-TCP-20.12.1.1-30.12.1.1-46028-80-8-7-1985-2527.pcap', '/home/pcap_auto/monitor/IP-UDP-20.12.1.2-30.12.1.2-48346-53-1-1-83-527.pcap', '/home/pcap_auto/monitor/IP-SCTP-20.12.1.3-30.12.1.3-38413-38412-1-0-146-0.pcap', '/home/pcap_auto/monitor/IP-ICMP-20.12.1.4-30.12.1.4-None-None-21-10-1260-600.pcap', '/home/pcap_auto/monitor/IP-TCP-20.12.1.5-30.12.1.5-9968-7611-29-28-2723-2038.pcap', '/home/pcap_auto/monitor/IP-TCP-20.12.1.6-30.12.1.6-58164-14567-5-4-578-260.pcap', '/home/pcap_auto/monitor/IP-TCP-20.12.1.9-30.12.1.9-28360-443-8-7-1737-1810.pcap', '/home/pcap_auto/fiter/IPv6-TCP-2e02__1333-2e03__1333-28360-443-8-7-1873-1932.pcap', '/home/pcap_auto/monitor/IP-TCP-20.12.1.10-30.12.1.10-8604-80-2-1-120-60.pcap', '/home/pcap_auto/fiter/IPv6-TCP-2e02__1334-2e03__1334-8604-80-2-1-152-78.pcap', '/home/pcap_auto/accesslog/IP-TCP-10.17.1.1-20.17.1.1-8604-80-5-2-362-1237.pcap', '/home/pcap_auto/accesslog/IP-TCP-10.17.1.2-20.17.1.2-8604-80-5-2-362-1248.pcap', '/home/pcap_auto/accesslog/IP-TCP-10.17.1.3-20.17.1.3-8604-80-5-2-362-1239.pcap', '/home/pcap_auto/accesslog/IP-TCP-10.17.1.4-20.17.1.4-8604-80-5-2-362-1231.pcap', '/home/pcap_auto/accesslog/IP-TCP-10.17.1.5-20.17.1.5-8604-80-5-2-362-1236.pcap', '/home/pcap_auto/accesslog/IP-TCP-10.17.1.6-20.17.1.6-8604-80-5-2-362-1237.pcap', '/home/pcap_auto/accesslog/IP-TCP-10.17.1.7-20.17.1.7-8604-80-5-2-362-1239.pcap', '/home/pcap_auto/accesslog/IP-TCP-10.17.1.8-20.17.1.8-8604-80-5-2-362-1244.pcap', '/home/pcap_auto/accesslog/IP-TCP-10.17.1.9-20.17.1.9-8604-80-5-2-362-1240.pcap', '/home/pcap_auto/accesslog/IP-TCP-10.17.1.10-20.17.1.10-8604-80-5-2-363-1241.pcap', '/home/pcap_auto/accesslog/IP-TCP-10.17.1.11-20.17.1.11-8604-80-5-2-363-1238.pcap', '/home/pcap_auto/accesslog/IP-TCP-10.17.1.12-20.17.1.12-8604-80-5-2-363-1238.pcap', '/home/pcap_auto/accesslog/IP-TCP-10.17.1.13-20.17.1.13-8604-80-5-2-363-1247.pcap', '/home/pcap_auto/accesslog/IP-TCP-10.17.1.14-20.17.1.14-8604-80-5-2-363-1244.pcap', '/home/pcap_auto/accesslog/IP-TCP-10.17.1.15-20.17.1.15-8604-80-5-2-363-1237.pcap', '/home/pcap_auto/accesslog/IP-TCP-10.17.1.16-20.17.1.16-8604-80-5-2-363-1233.pcap', '/home/pcap_auto/accesslog/IP-TCP-10.17.1.17-20.17.1.17-8604-80-5-2-363-1246.pcap', '/home/pcap_auto/accesslog/IP-TCP-10.17.1.18-20.17.1.18-8604-80-5-2-363-1250.pcap', '/home/pcap_auto/accesslog/IP-TCP-10.17.1.19-20.17.1.19-8604-80-5-2-363-1244.pcap', '/home/pcap_auto/accesslog/IP-TCP-10.17.1.20-20.17.1.20-8604-80-5-2-363-1240.pcap', '/home/pcap_auto/accesslog/IP-TCP-10.17.1.21-20.17.1.21-8604-80-5-2-363-1248.pcap', '/home/pcap_auto/accesslog/IP-TCP-10.17.1.22-20.17.1.22-8604-80-5-2-363-1244.pcap', '/home/pcap_auto/accesslog/IP-TCP-10.17.1.23-20.17.1.23-8604-80-5-2-363-1255.pcap', '/home/pcap_auto/accesslog/IP-TCP-10.17.1.24-20.17.1.24-51562-8000-5-3-556-206.pcap', '/home/pcap_auto/accesslog/IP-TCP-20.18.1.1-30.18.1.1-8604-80-5-2-362-1237.pcap', '/home/pcap_auto/accesslog/IP-TCP-20.18.1.2-30.18.1.2-8604-80-5-2-362-1248.pcap', '/home/pcap_auto/accesslog/IP-TCP-20.18.1.3-30.18.1.3-8604-80-5-2-362-1239.pcap', '/home/pcap_auto/accesslog/IP-TCP-20.18.1.4-30.18.1.4-8604-80-5-2-362-1231.pcap', '/home/pcap_auto/accesslog/IP-TCP-20.18.1.5-30.18.1.5-8604-80-5-2-362-1236.pcap', '/home/pcap_auto/accesslog/IP-TCP-20.18.1.6-30.18.1.6-8604-80-5-2-362-1237.pcap', '/home/pcap_auto/accesslog/IP-TCP-20.18.1.7-30.18.1.7-8604-80-5-2-362-1239.pcap', '/home/pcap_auto/accesslog/IP-TCP-20.18.1.8-30.18.1.8-8604-80-5-2-362-1244.pcap', '/home/pcap_auto/accesslog/IP-TCP-20.18.1.9-30.18.1.9-8604-80-5-2-362-1240.pcap', '/home/pcap_auto/accesslog/IP-TCP-20.18.1.10-30.18.1.10-8604-80-5-2-363-1241.pcap', '/home/pcap_auto/accesslog/IP-TCP-20.18.1.11-30.18.1.11-8604-80-5-2-363-1238.pcap', '/home/pcap_auto/accesslog/IP-TCP-20.18.1.12-30.18.1.12-8604-80-5-2-363-1238.pcap', '/home/pcap_auto/accesslog/IP-TCP-20.18.1.13-30.18.1.13-8604-80-5-2-363-1247.pcap', '/home/pcap_auto/accesslog/IP-TCP-20.18.1.14-30.18.1.14-8604-80-5-2-363-1244.pcap', '/home/pcap_auto/accesslog/IP-TCP-20.18.1.15-30.18.1.15-8604-80-5-2-363-1237.pcap', '/home/pcap_auto/accesslog/IP-TCP-20.18.1.16-30.18.1.16-8604-80-5-2-363-1233.pcap', '/home/pcap_auto/accesslog/IP-TCP-20.18.1.17-30.18.1.17-8604-80-5-2-363-1246.pcap', '/home/pcap_auto/accesslog/IP-TCP-20.18.1.18-30.18.1.18-8604-80-5-2-363-1250.pcap', '/home/pcap_auto/accesslog/IP-TCP-20.18.1.19-30.18.1.19-8604-80-5-2-363-1244.pcap', '/home/pcap_auto/accesslog/IP-TCP-20.18.1.20-30.18.1.20-8604-80-5-2-363-1240.pcap', '/home/pcap_auto/accesslog/IP-TCP-20.18.1.21-30.18.1.21-8604-80-5-2-363-1248.pcap', '/home/pcap_auto/accesslog/IP-TCP-20.18.1.22-30.18.1.22-8604-80-5-2-363-1244.pcap', '/home/pcap_auto/accesslog/IP-TCP-20.18.1.23-30.18.1.23-8604-80-5-2-363-1255.pcap', '/home/pcap_auto/accesslog/IP-TCP-20.18.1.24-30.18.1.24-51562-8000-5-3-556-206.pcap', '/home/pcap_auto/accesslog/IPv6-TCP-2e01__1401-2e02__1401-8604-80-5-2-445-1275.pcap', '/home/pcap_auto/accesslog/IPv6-TCP-2e01__1402-2e02__1402-8604-80-5-2-445-1286.pcap', '/home/pcap_auto/accesslog/IPv6-TCP-2e01__1403-2e02__1403-8604-80-5-2-445-1277.pcap', '/home/pcap_auto/accesslog/IPv6-TCP-2e01__1404-2e02__1404-8604-80-5-2-445-1269.pcap', '/home/pcap_auto/accesslog/IPv6-TCP-2e01__1405-2e02__1405-8604-80-5-2-445-1274.pcap', '/home/pcap_auto/accesslog/IPv6-TCP-2e01__1406-2e02__1406-8604-80-5-2-445-1275.pcap', '/home/pcap_auto/accesslog/IPv6-TCP-2e01__1407-2e02__1407-8604-80-5-2-445-1277.pcap', '/home/pcap_auto/accesslog/IPv6-TCP-2e01__1408-2e02__1408-8604-80-5-2-445-1282.pcap', '/home/pcap_auto/accesslog/IPv6-TCP-2e01__1409-2e02__1409-8604-80-5-2-445-1278.pcap', '/home/pcap_auto/accesslog/IPv6-TCP-2e01__140a-2e02__140a-8604-80-5-2-445-1279.pcap', '/home/pcap_auto/accesslog/IPv6-TCP-2e01__140b-2e02__140b-8604-80-5-2-445-1276.pcap', '/home/pcap_auto/accesslog/IPv6-TCP-2e01__140c-2e02__140c-8604-80-5-2-445-1276.pcap', '/home/pcap_auto/accesslog/IPv6-TCP-2e01__140d-2e02__140d-8604-80-5-2-445-1285.pcap', '/home/pcap_auto/accesslog/IPv6-TCP-2e01__140e-2e02__140e-8604-80-5-2-445-1282.pcap', '/home/pcap_auto/accesslog/IPv6-TCP-2e01__140f-2e02__140f-8604-80-5-2-445-1275.pcap', '/home/pcap_auto/accesslog/IPv6-TCP-2e01__1410-2e02__1410-8604-80-5-2-445-1271.pcap', '/home/pcap_auto/accesslog/IPv6-TCP-2e01__1411-2e02__1411-8604-80-5-2-445-1284.pcap', '/home/pcap_auto/accesslog/IPv6-TCP-2e01__1412-2e02__1412-8604-80-5-2-445-1288.pcap', '/home/pcap_auto/accesslog/IPv6-TCP-2e01__1413-2e02__1413-8604-80-5-2-445-1282.pcap', '/home/pcap_auto/accesslog/IPv6-TCP-2e01__1414-2e02__1414-8604-80-5-2-445-1278.pcap', '/home/pcap_auto/accesslog/IPv6-TCP-2e01__1415-2e02__1415-8604-80-5-2-445-1286.pcap', '/home/pcap_auto/accesslog/IPv6-TCP-2e01__1416-2e02__1416-8604-80-5-2-445-1282.pcap', '/home/pcap_auto/accesslog/IPv6-TCP-2e01__1417-2e02__1417-8604-80-5-2-445-1293.pcap', '/home/pcap_auto/accesslog/IPv6-TCP-2e01__1418-2e02__1418-51562-8000-5-3-656-266.pcap', '/home/pcap_auto/accesslog/IPv6-TCP-2e02__1501-2e03__1501-8604-80-5-2-445-1275.pcap', '/home/pcap_auto/accesslog/IPv6-TCP-2e02__1502-2e03__1502-8604-80-5-2-445-1286.pcap', '/home/pcap_auto/accesslog/IPv6-TCP-2e02__1503-2e03__1503-8604-80-5-2-445-1277.pcap', '/home/pcap_auto/accesslog/IPv6-TCP-2e02__1504-2e03__1504-8604-80-5-2-445-1269.pcap', '/home/pcap_auto/accesslog/IPv6-TCP-2e02__1505-2e03__1505-8604-80-5-2-445-1274.pcap', '/home/pcap_auto/accesslog/IPv6-TCP-2e02__1506-2e03__1506-8604-80-5-2-445-1275.pcap', '/home/pcap_auto/accesslog/IPv6-TCP-2e02__1507-2e03__1507-8604-80-5-2-445-1277.pcap', '/home/pcap_auto/accesslog/IPv6-TCP-2e02__1508-2e03__1508-8604-80-5-2-445-1282.pcap', '/home/pcap_auto/accesslog/IPv6-TCP-2e02__1509-2e03__1509-8604-80-5-2-445-1278.pcap', '/home/pcap_auto/accesslog/IPv6-TCP-2e02__150a-2e03__150a-8604-80-5-2-445-1279.pcap', '/home/pcap_auto/accesslog/IPv6-TCP-2e02__150b-2e03__150b-8604-80-5-2-445-1276.pcap', '/home/pcap_auto/accesslog/IPv6-TCP-2e02__150c-2e03__150c-8604-80-5-2-445-1276.pcap', '/home/pcap_auto/accesslog/IPv6-TCP-2e02__150d-2e03__150d-8604-80-5-2-445-1285.pcap', '/home/pcap_auto/accesslog/IPv6-TCP-2e02__150e-2e03__150e-8604-80-5-2-445-1282.pcap', '/home/pcap_auto/accesslog/IPv6-TCP-2e02__150f-2e03__150f-8604-80-5-2-445-1275.pcap', '/home/pcap_auto/accesslog/IPv6-TCP-2e02__1510-2e03__1510-8604-80-5-2-445-1271.pcap', '/home/pcap_auto/accesslog/IPv6-TCP-2e02__1511-2e03__1511-8604-80-5-2-445-1284.pcap', '/home/pcap_auto/accesslog/IPv6-TCP-2e02__1512-2e03__1512-8604-80-5-2-445-1288.pcap', '/home/pcap_auto/accesslog/IPv6-TCP-2e02__1513-2e03__1513-8604-80-5-2-445-1282.pcap', '/home/pcap_auto/accesslog/IPv6-TCP-2e02__1514-2e03__1514-8604-80-5-2-445-1278.pcap', '/home/pcap_auto/accesslog/IPv6-TCP-2e02__1515-2e03__1515-8604-80-5-2-445-1286.pcap', '/home/pcap_auto/accesslog/IPv6-TCP-2e02__1516-2e03__1516-8604-80-5-2-445-1282.pcap', '/home/pcap_auto/accesslog/IPv6-TCP-2e02__1517-2e03__1517-8604-80-5-2-445-1293.pcap', '/home/pcap_auto/accesslog/IPv6-TCP-2e02__1518-2e03__1518-51562-8000-5-3-656-266.pcap'], 'uplink_iface': 'enp129s0f0', 'downlink_iface': 'enp129s0f0', 'uplink_vlan': None, 'downlink_vlan': None, 'mbps': 50, 'verbose': None, 'force_ip_src': None, 'force_ip_dst': None, 'force_sport': None, 'force_dport': None, 'force_build_flow': None, 'enable_pcap_cache': False, 'pcap_cache_dir': 'cached_pcaps'})
    # a = sl.cmd("kill `ps -ef|grep dpi_monitor|grep -v grep|awk '{print $2}'`",wait=False)
    # print([a])
    # print(sl.put(locatpath=r"D:\Desktop\test3.pcap", remotepath="/home/test2.pcap",gzip=True))

    # dir = "/home/pcap_auto/"
    # names = [
    #     # "mypcap/publicpcap/IPv4/sip/sip_rtp_ipv6.pcap",
    #     # "mypcap/publicpcap/IPv4/sip/sip_rtp_ipv4.pcap",
    #     # "mypcap/publicpcap/IPv4/sip/SIP_UDP6.pcap",
    #     # "mypcap/publicpcap/IPv4/sip/portion_sip.pcap",
    #     "/tmp/BitTorrent2.pcap"
    #          ]
    # files = list(map(lambda x: dir + x, names))
    # files = ["/home/pcap_auto/llcj_pcap/IP-TCP-10.3.1.155-20.3.1.155-53336-80-4-6-520-6110.pcap"]
    # print(files)
    # print(sl.scapy_send(pcaps=files,
    #                     uplink_iface="ens193",
    #                     downlink_iface="ens193",
    #                     uplink_vlan=None,
    #                     downlink_vlan=None,
    #                     mbps=50,
    #                     verbose=True,
    #                     force_ip_src=None,     # 示例：指定发包源 IP
    #                     force_ip_dst=None,
    #                     force_sport=None,
    #                     force_dport=None,
    #                     force_build_flow=False,
    #                     enable_pcap_cache=True,
    #                     pcap_cache_dir="/tmp"
    #
    # ))

    # a = {'pcaps': ['/home/pcap_auto/bc/pcapdump_1.pcap'], 'eth': 'ens256', 'chunk_size': 1, 'buffer_size': 1,'pps_limit': None, 'mbps_limit': None, 'num_producers': None, 'show_stats': True, 'show_progress': True}
    # a = {'args': 'ls -rt|tail -n 1|grep xml$', 'cwd': '/xdr/100000000012345/3/2025-02-17', 'env': None, 'shell': True, 'stdout': -1, 'stderr': -1, 'encoding': 'utf-8', 'wait': True}
    # a = {'args': 'expr $(find /tmp/txt -type f | wc -l) % 2', 'cwd': None, 'env': None, 'shell': True, 'stdout': -1, 'stderr': -1, 'encoding': 'utf-8', 'wait': True}
    # logger.info([sl.cmd("md5sum /dev/shm/xsa/time_main.stat1|awk '{print $1}'")])

    # logger.info(sl.getsocketclientverion())
    # logger.info([sl.cmd("ls", cwd="/home")])
    # logger.info(sl.md5("/home/1.pcap"))
    logger.info(sl.socketserver_start(port=30001))
    # logger.info(sl.socketserver_dataclean())
    # sl.socketserver_cachedata()
    # logger.info(111,sl.socketserver_data())
    # time.sleep(30)
    # sl.socketserver_cachedata()
    # logger.info(2222, sl.socketserver_data())
    #
    #
    # logger.info(sl.socketserver_writefile())
    sys.exit()
    # logger.info(sl.cmd(args='bash cucc_mod_switch.sh isbns', cwd='/opt/dpi/mconf/modelswitch', bufsize=4096))
    # logger.info([sl.python_cmd("os.popen('wget  --ftp-user=weihang  --ftp-password=12345678  -P   /tmp/ ftp://172.31.130.111/ACT-DPI-ISE-1.0.1.5-4_20240410124756.tar.gz')", "read()")])
    # cmd = "java -Dfile._encoding=UTF-8 -jar idc-1.0.0.8.jar"
    # logger.info(sl.cmd(cmd, cwd="/home/idc-1.0.0.8/", shell=True, wait=False,bufsize=4096000))
    # logger.info()
    # logger.info(sl.os_popen(cmd))
    # os.popen()
    # logger.info(sl.upgrade_socketclient(localpath=r"D:\weihang\Desktop\socket_sevrer_1.10"))
    # logger.info(sl.getsocketclientverion())
    # time.sleep(60)
    # sl = SocketLinux(("172.31.140.98", 9000))
    # logger.info(sl.getsocketclientverion())
    sl.cmd("rm -rf /home/ACT-DPI-ISE-1.0.4.4-4_20240926190325")
    sl.unzip(file="/home/ACT-DPI-ISE-1.0.4.4-4_20240926190325.tar.gz", outdir="ACT-DPI-ISE-1.0.4.4-4_20240926190325", passwd="GeUpms@1995")
    # '/home/tmp/tmp.pcap', 'out/f008-过滤-关键字（出向）_B1709093118.pcap'
    logger.info([sl.scapy_send(eth="ens192f2", pcap="/home/pcap_auto/bc/pcapdump_1.pcap")])
    # sl.put(locatpath=r"D:\weihang\Desktop\test.pcap", remotepath="/home/test1.pcap")
    # sl.get(remotepath="/home/pcap_auto/accesslog.pcap", locatpath=r"D:\weihang\Desktop\test.pcap")

    # logger.info([sl.get('/home/tmp/tmp.pcap', r'E:\PycharmProjects\pythonProject_socket\mycode\script\auto_test\idc30\out\f011-过滤-应用层（双向）-目的IP+HTTP_A1706145059.pcap')])