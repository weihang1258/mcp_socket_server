#!/usr/bin/env python
# -*- coding: utf-8 -*-
# @Time    : 2023/3/14 9:32
# @Author  : weihang
# @File    : dpi.py
import collections
import copy
import io
import json
import os
import re
import sys
import time
from collections import OrderedDict
from io import BytesIO, StringIO
from utils.common import reverse_dict, list_split_by_unit, list_pop, wait_until, wait_not_until, md5, \
    setup_logging, gettime
from data.dict_comparer import DictComparer
from device.socket_linux import SocketLinux
from device.dpi_constants import action2policyfile
import ftplib

logger = setup_logging(log_file_path="log/dpi.log", logger_name="dpi")


class Dpi(SocketLinux):
    """DPI (Deep Packet Inspection) 设备控制类。

    继承自 SocketLinux，提供 DPI 设备的生命周期管理、策略配置等功能。

    Attributes:
        adms_idc_debug2dict: ADMS IDC 调试信息字典
        dpi_path (str): DPI 安装路径，默认 "/opt/dpi"
    """

    def __init__(self, client):
        """初始化 DPI 客户端。

        Args:
            client: socket.socket 对象或 (host, port) 元组
        """
        super().__init__(client)
        self.adms_idc_debug2dict = None
        self.dpi_path = "/opt/dpi"

    def modify_modcfg(self, path="/opt/dpi/idc30_is.cfg", **module2value):
        """修改 DPI 配置文件 (idc30_is.cfg)。

        Args:
            path: 配置文件路径，默认 "/opt/dpi/idc30_is.cfg"
            **module2value: 模块配置参数，如 httpproto=1, proto=1

        Returns:
            None
        """
        # 提取创建目录
        dir = path.rsplit("/", 1)[0]
        if dir and not self.isdir(dir):
            self.mkdir(dir)
        modcfg = self.modcfg2dict(path=path, effective=False)
        for key, val in module2value.items():
            modcfg[key] = val
        tmp = [f"{key}:{val}" for key, val in modcfg.items()]
        tmp1 = "# 下面的模块顺序最好不要调整,只配置其它的开关，置成0或1， 0是关； 1是开; 如果是2,则不要修改，表示一定要使用这个模块\n#\n" + "\n".join(
            tmp) + "\n"
        tmp1 = tmp1.encode()
        with BytesIO() as fl:
            fl.write(tmp1)
            fl.seek(0)
            self.putfo(fl=fl, remotepath=path, overwrite=True)

    def wait_alive(self, timeout=60):
        """判断 DPI 是否存活。

        通过检查 stat 文件的 MD5 值变化来判断 DPI 进程是否正常运行。

        Args:
            timeout: 超时时间（秒），默认 60

        Returns:
            bool: True 表示存活，False 表示超时
        """
        path_stat = "/dev/shm/xsa/time_main_io.stat"
        self.rm(path_stat)
        cmd = "md5sum %s|awk '{print $1}'" % path_stat
        md5_old = self.cmd(cmd)
        time_start = time.time()
        while time.time() - time_start < timeout:
            md5_new = self.cmd(cmd)
            if md5_old == md5_new:
                time.sleep(2)
            else:
                return True
        logger.info(f"isalive 等待超时:{timeout}")
        return False

    def stop(self, timeout=300):
        """停止 DPI 进程。

        Args:
            timeout: 超时时间（秒），默认 300

        Returns:
            bool: True 表示成功停止，False 表示失败
        """
        self.cmd(args="sh dpikill.sh", cwd="/opt/dpi")
        logger.info("DPI停止")
        response = wait_until(func=self.cmd, expect_value="0\n", timeout=timeout, args="ps -ef|grep '/opt/dpi/xsa$' -c")
        if response:
            time.sleep(2)
            return True
        else:
            return False

    def start(self, timeout=600):
        """启动 DPI 进程。

        Args:
            timeout: 超时时间（秒），默认 600

        Returns:
            bool: True 表示启动成功，False 表示失败
        """
        if self.cmd("ps -ef|grep '/opt/dpi/xsa$' -c") == "1\n":
            # self.cmd(args="sh dpikill.sh", cwd="/opt/dpi")
            return self.wait_alive(timeout)

        self.cmd(args="sh dpirun.sh", cwd="/opt/dpi")
        logger.info("DPI启动中")
        if self.wait_alive(timeout):
            time.sleep(10)
            return True
        else:
            return False

    def restart(self, timeout=600):
        """重启 DPI 进程。

        Args:
            timeout: 超时时间（秒），默认 600

        Returns:
            bool: True 表示重启成功，False 表示失败
        """
        if self.stop(timeout=timeout):
            return self.start(timeout=timeout)
        else:
            return False

    def dpi_monitor(self, op):
        """DPI Monitor 程序启停操作。

        Args:
            op: 操作类型，"start" 或 "stop"
        """
        if op == "start" and int(self.cmd(args="ps -ef|grep dpi_monitor|grep -v grep|wc -l")) == 0:
            cmd = "/opt/dpi/dpi_monitor -t 5"
        elif op == "stop":
            cmd = "kill `ps -ef|grep dpi_monitor|grep -v grep|awk '{print $2}'`"
        else:
            return
        self.cmd(args=cmd, wait=False)

    def policyserver(self, op):
        """PolicyServer 程序启停操作。

        Args:
            op: 操作类型，"start" 或 "stop"
        """
        if op == "start" and int(self.cmd(args="ps -ef|grep policyserver|grep -v grep|wc -l")) == 0:
            cmd = "/opt/dpi/policyserver &"
        elif op == "stop":
            cmd = "kill `ps -ef|grep policyserver|grep -v grep|awk '{print $2}'`"
        else:
            return
        self.cmd(args=cmd, wait=False)

    def app_proto_pid2other(self, path_app_proto="/opt/dpi/xsaconf/rule/app_proto.txt", row_start=0):
        res = dict()
        cmd = "cat %s" % path_app_proto
        response = self.cmd(cmd).strip().split("\n")
        for i in range(row_start, len(response)):
            line = response[i].strip()
            tmp = line.split("\t")
            key = tmp[0]
            val = tmp[1:]
            res[key] = val
        return res

    def clean_stat(self, timeout=60):
        """清空 DPI 状态。

        执行清空命令并等待流超时，确保 DPI 状态被重置。

        Args:
            timeout: 等待超时时间（秒），默认 60

        Returns:
            bool: True 表示成功，抛出异常表示失败
        """
        logger.info("清空dpi状态:/opt/dpi/cmdmsg xsa 1")
        cmd1 = "/opt/dpi/cmdmsg xsa 1"
        cmd2 = "cat /dev/shm/xsa/xrt.stat |grep total|awk '{print $4}'"
        res = None
        # 等待流量超时
        for i in range(3):
            try:
                self.wait_flow_timeout(timeout=timeout)
                # 判断xrt收包数
                rx_cur = int(self.cmd(cmd2).strip())
                logger.info("\t等待状态文件数据重置")
                if rx_cur == 0:
                    res = True
                    break
                else:
                    res_cmd1 = self.cmd(cmd1, returnall=True)
                    if res_cmd1["code"] != 0:
                        logger.info(f"执行命令：{cmd1},结果：{res_cmd1}")
                        res = False
                        break
                    if wait_until(func=self.cmd, args=cmd2,
                                  expect_value="0\n") and not self.wait_flow_timeout(timeout=timeout):
                        res = True
                        break
            except Exception as e:
                logger.info(e)
                if str(e).startswith("等待流超时失败"):
                    raise RuntimeError("无法判断流超时")
                else:
                    self.cmd(cmd1)
                    time.sleep(5)
                    continue
        if res is None:
            raise RuntimeError("清空dpi状态失败:/opt/dpi/cmdmsg xsa 1")

    def wait_flow_timeout(self, timeout=60):
        """等待所有流超时。

        等待 flow.stat 文件中的并发连接数降为 0。

        Args:
            timeout: 超时时间（秒），默认 60

        Raises:
            RuntimeError: 当等待超时时抛出异常
        """
        logger.info(f"等待流超时({timeout}s)")
        cmd = "cat /dev/shm/xsa/flow.stat |grep concurrent_cnt|awk '{print $2}'"
        if re.match(r"\d{5,15}", self.cmd(cmd)):
            raise RuntimeError("format err")
        # if not wait_until_by_ssh(c=self.c, cmd=cmd, expect_value=b'0\n', timeout=timeout):
        if not wait_until(func=self.cmd, args=cmd, expect_value='0\n', timeout=timeout):
            raise RuntimeError("等待流超时失败，等待时间：%ss" % timeout)

    def marex_policy_get(self, path="/opt/dpi/euconf/rule/eu_policy.rule"):
        """获取 Marex 策略文件内容。

        Args:
            path: 策略文件路径，默认 "/opt/dpi/euconf/rule/eu_policy.rule"

        Returns:
            list: 策略内容行列表，每行为 bytes 类型
        """
        # [b"", b""]
        # cmd = f"cat {path}|grep -v ^#|grep -v ^//|grep -v '^$'"
        # res = c.ssh_exec_cmd(cmd).decode().strip().split("\n")
        content = self.getfo(remotepath=path).getvalue()
        return content.strip().split(b"\n")

    def marex_policy_append(self, policy: list, path="/opt/dpi/euconf/rule/eu_policy.rule"):
        """增加策略，同时去重"""
        policy_cur = self.marex_policy_get(path)
        with BytesIO() as fl:
            fl.write(b"\n".join(list(set((policy_cur + policy)))))
            fl.seek(0)
            self.putfo(fl=fl, remotepath=path, overwrite=True)

    def marex_policy_update(self, policy: list, path="/opt/dpi/euconf/rule/eu_policy.rule", md5check=False):
        """增加策略，直接覆盖全部"""
        content = b"\n".join(policy) + b"\n"
        if md5check and self.md5(path) == md5(content):
            return
        with BytesIO() as fl:
            fl.write(content)
            fl.seek(0)
            self.putfo(fl=fl, remotepath=path, overwrite=True)

    def json_get(self, path):
        if not self.isfile(path):
            return {}
        with self.getfo(remotepath=path) as fl:
            content_dict = json.load(fp=fl, object_pairs_hook=OrderedDict)
        return content_dict

    def json_put(self, dict1, path, indent=2):
        with BytesIO() as fl:
            fl.write(json.dumps(dict1, indent=indent).encode("utf-8"))
            fl.seek(0)
            self.putfo(fl=fl, remotepath=path, overwrite=True)

    def app_proto2dict(self, path="/opt/dpi/xsaconf/rule/app_proto.txt"):
        """将app_proto.txt转换成dict"""
        res = dict()
        head = ["pid", "provider_id", "app_type", "app_name", "sub_type", "ctnt_type", "app", "ctnt_name", "sub_name"]
        content = self.getfo(remotepath=path).read().decode("utf-8")
        for line in content.strip().split("\n"):
            line = line.strip()
            if line:
                fields = line.split("\t")
                if len(fields) != len(head):
                    raise RuntimeError(("err len：%s,%s" % (len(head), fields)))
                tmp_dict = dict(zip(head, fields))
                key = "-".join([tmp_dict["app_type"], tmp_dict["sub_type"], tmp_dict["ctnt_type"]])
                if key in res:
                    raise RuntimeError("大类小类细分类重复：%s" % key)
                else:
                    res[key] = tmp_dict
        return res

    def numa_sh(self):
        """{"numa2cpu": numa2cpu, "pci_info": pci_info}
        {'numa2cpu': {'0': [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 24, 25, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35], '1': [12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 36, 37, 38, 39, 40, 41, 42, 43, 44, 45, 46, 47]}, 'pci_info': {'0000:02:00.1': {'name': 'I350 Gigabit Network Connection 1521', 'drv': 'vfio-pci', 'unused': 'igb', 'numa': '0'}, '0000:81:00.0': {'name': '82599ES 10-Gigabit SFI/SFP+ Network Connection 10fb', 'drv': 'vfio-pci', 'unused': 'ixgbe', 'numa': '1'}, '0000:84:00.1': {'name': '82599ES 10-Gigabit SFI/SFP+ Network Connection 10fb', 'drv': 'vfio-pci', 'unused': 'ixgbe', 'numa': '1'}, '0000:02:00.0': {'name': 'I350 Gigabit Network Connection 1521', 'if': 'enp2s0f0', 'drv': 'igb', 'unused': 'vfio-pci', 'numa': '0'}, '0000:02:00.2': {'name': 'I350 Gigabit Network Connection 1521', 'if': 'enp2s0f2', 'drv': 'igb', 'unused': 'vfio-pci', 'numa': '0'}, '0000:02:00.3': {'name': 'I350 Gigabit Network Connection 1521', 'if': 'enp2s0f3', 'drv': 'igb', 'unused': 'vfio-pci', 'numa': '0'}, '0000:06:00.0': {'name': '82599ES 10-Gigabit SFI/SFP+ Network Connection 10fb', 'if': 'enp6s0f0', 'drv': 'ixgbe', 'unused': 'vfio-pci', 'numa': '0'}, '0000:06:00.1': {'name': '82599ES 10-Gigabit SFI/SFP+ Network Connection 10fb', 'if': 'enp6s0f1', 'drv': 'ixgbe', 'unused': 'vfio-pci', 'numa': '0'}, '0000:09:00.0': {'name': '82599ES 10-Gigabit SFI/SFP+ Network Connection 10fb', 'if': 'enp9s0f0', 'drv': 'ixgbe', 'unused': 'vfio-pci', 'numa': '0'}, '0000:09:00.1': {'name': '82599ES 10-Gigabit SFI/SFP+ Network Connection 10fb', 'if': 'enp9s0f1', 'drv': 'ixgbe', 'unused': 'vfio-pci', 'numa': '0'}, '0000:81:00.1': {'name': '82599ES 10-Gigabit SFI/SFP+ Network Connection 10fb', 'if': 'enp129s0f1', 'drv': 'ixgbe', 'unused': 'vfio-pci', 'numa': '1'}, '0000:84:00.0': {'name': '82599ES 10-Gigabit SFI/SFP+ Network Connection 10fb', 'if': 'enp132s0f0', 'drv': 'ixgbe', 'unused': 'vfio-pci', 'numa': '1'}}}"""
        numa2cpu = dict()
        pci_info = dict()
        cmd = "cd /opt/dpi/kmod;./numa.sh"
        response = self.cmd(cmd).strip()
        id_node = 0
        numa_flag = None
        for line in response.strip().split("\n"):
            # if line.startswith("NUMA ") and "CPU" not in line:
            #     count_node = int(line.split(":")[1])
            if line.startswith("NUMA ") and "CPU" in line:
                tmp_list = list()
                for ran in line.split(":")[1].strip().split(","):
                    if "-" not in ran:
                        tmp_list.append(int(ran))
                    else:
                        s, e = ran.split("-", 1)
                        tmp_list += list(range(int(s), int(e) + 1))
                numa2cpu[str(id_node)] = tmp_list
                id_node += 1
            if line.startswith("0000:"):
                pci, tmp = line.strip().split(maxsplit=1)
                name, tmp1 = tmp.split("'", maxsplit=2)[1:]
                pci_info[pci] = {"name": name}
                for field in tmp1.split():
                    if "=" in field:
                        key, val = field.split("=", maxsplit=1)
                        pci_info[pci][key.strip()] = val.strip()
                numa_flag = pci
            if line.startswith("numa,"):
                pci_info[numa_flag]["numa"] = line.lstrip("numa,").strip()
        return {"numa2cpu": numa2cpu, "pci_info": pci_info}

    def get_meminfo(self):
        res = dict()
        cmd = "cat /proc/meminfo"
        response = self.cmd(cmd).strip()
        for line in response.split("\n"):
            k, v = line.split(":", 1)
            res[k.strip()] = v.strip()
        return res

    def create_syscfg_json(self, path="/opt/dpi/syscfg.json"):
        dir, basename = os.path.split(path)
        if not self.isfile(path):
            self.cmd(args="sh dpirun.sh", cwd=self.dpi_path)
            cmd = "ls %s" % basename
            flag = wait_until(func=self.cmd, expect_value=basename + "\n", timeout=20, args=cmd,
                              cwd=dir)
            self.stop()
            return flag
        else:
            return True

    def get_modfile_from_modcfg(self, path="/opt/dpi/syscfg.json"):
        """
        从idc30_is.cfg中提取module对应的cfg，modfile字段
        :param path:
        :return:
        """
        sys_dict = self.json_get(path)
        return sys_dict["modfile"]

    def modcfg2dict(self, path=None, effective=True):
        """
        从idc30_is.cfg中提取module和对应的值
        :param path:默认cfg路径
        :param effective:True时只提取非0字段
        :return:dict
        """
        res = collections.OrderedDict()
        if not path:
            path = "/opt/dpi/" + self.get_modfile_from_modcfg()
        if not self.isfile(path):
            return res
        content = self.getfo(remotepath=path).read().decode("utf-8")
        for line in content.strip().split("\n"):
            line = line.strip()
            if line and (not line.startswith("#") and not line.startswith("//")):
                # logger.info(line)
                key, value = line.split(":", 1)
                # logger.info([key, value])
                if effective:
                    if value != "0":
                        res[key] = value
                else:
                    res[key] = value
        return res

    def create_xsajson(self, xsajson_template, xsajson="/opt/dpi/xsaconf/xsa.json", *modules):
        with open(xsajson_template, "r") as fl:
            xsa_template = json.load(fl)
        xsa = dict()
        for module in modules:
            xsa[module] = xsa_template[module]
        self.json_put(xsa, path=xsajson)

    def modify_xsajson(self, path="/opt/dpi/xsaconf/xsa.json", xsajson: dict = None, **kargs):
        if xsajson:
            xsa = xsajson
        else:
            xsa = self.json_get(path=path)
        flag = copy.deepcopy(xsa)
        for key, val in kargs.items():
            logger.info(f"修改{key}为{val}")
            tmp = xsa
            key_list = key.strip().split(".")
            key_list = list(map(lambda x: int(x) if x.isdigit() else x, key_list))
            if len(key_list) == 1:
                tmp[key_list[0]] = val
            else:
                for i in key_list[:-1]:
                    tmp = tmp[i]
                tmp[key_list[-1]] = val
        if xsa == flag:
            return False
        else:
            self.json_put(xsa, path=path)
            return True

    def create_cpuxsajson(self, cpuxsajson="/opt/dpi/xsaconf/cpuxsa.json", **kwargs):
        cpuxsa = {"ver": "1.0.0|22545", "buildtime": "2022-12-08 14:59:23"}
        for key, val in kwargs.items():
            cpuxsa[key] = val
        self.json_put(cpuxsa, path=cpuxsajson)

    def config_syscfgjson(self, config: dict, path="/opt/dpi/syscfg.json"):
        # config = {"modfile": "idc30_is.cfg",
        #           "mem_channels": 4,
        #           "master_core": 12,
        #           "ports": {
        #               "0000:03:00.0": {"mbuf_numa": 0,"name": "port0", "io_cores": "1-2", "wk_cores": "3-6"},
        #               "0000:03:00.2": {"mbuf_numa": 0,"name": "port1", "io_cores": "13", "wk_cores": "15-18"},
        #           },
        #           "tasks": [{"send_cores": "3-6", "recv_cores": "7", "name": "wk_fo0"},
        #                     {"send_cores": "15-18", "recv_cores": "19", "name": "wk_fo1"}]
        #           }
        syscfg = self.json_get(path)
        template_port = {
            "id": 1,
            "mtu": 2000,
            "link_id": 0,
            "mbuf_numa": 0,
            "bind_mode": 0,
            "rx_desc": 4096,
            "tx_desc": 4096,
            "rx_mpool_size": 16384,
            "wk_mpool_size": 16384,
            "io_cores": "13",
            "wk_cores": "15-18",
            "name": "port1",
            "pci": "0000:03:00.2",
            "tx_pci": "",
            "spec_param": ""
        }
        template_task = {
            "id": 0,
            "send_type": 0,
            "recv_type": 1,
            "send_cores": "3-6",
            "recv_cores": "7",
            "name": "wk_fo0"
        }
        for key, val in config.items():
            if key == "ports":
                ports = list()
                id = 0
                for pci, val1 in val.items():
                    port_tmp = copy.deepcopy(template_port)
                    for k, v in val1.items():
                        port_tmp[k] = v
                    port_tmp["id"] = id
                    port_tmp["pci"] = pci
                    ports.append(port_tmp)
                    id += 1
                syscfg["ports"] = ports
            elif key == "tasks":
                tasks = list()
                id = 0
                for task in val:
                    task_tmp = copy.deepcopy(template_task)
                    for k, v in task.items():
                        task_tmp[k] = v
                    task_tmp["id"] = id
                    tasks.append(task_tmp)
                    id += 1
                syscfg["tasks"] = tasks
            elif key == "cpuxsa":
                pass
            else:
                syscfg[key] = val
        self.json_put(syscfg, path=path)

    def get_syscfg_cpu(self):
        tmp = list()
        res = list()
        syscfg = self.json_get(path="/opt/dpi/syscfg.json")
        tmp.append(str(syscfg["master_core"]))
        for port in syscfg["ports"]:
            tmp.append(port["io_cores"])
            tmp.append(port["wk_cores"])
        for task in syscfg["tasks"]:
            tmp.append(task["send_cores"])
            tmp.append(task["recv_cores"])
        for field in ",".join(tmp).split(","):
            if "-" in field:
                s, e = field.split("-", 1)
                res += list(range(int(s), int(e) + 1))
            elif field == "":
                pass
            else:
                res.append(int(field))
        return res

    def get_cpuxsa_cpu(self):
        tmp = list()
        res = list()
        cpuxsa = self.json_get(path="/opt/dpi/xsaconf/cpuxsa.json")
        for k, v in cpuxsa.items():
            if k not in ("ver", "buildtime") and v not in (-1, "", "-1"):
                tmp.append(str(v))
        for field in ",".join(tmp).split(","):
            if "-" in field:
                s, e = field.split("-", 1)
                res += list(range(int(s), int(e) + 1))
            elif field == "":
                pass
            else:
                res.append(int(field))
        return res

    def get_dpimode(self, dpipath="/opt/dpi"):
        """
        获取dpi模式。如：com_cmcc_is

        Args:
            dpipath: DPI 程序路径，默认为 /opt/dpi

        Returns:
            str: DPI 模式，如 "com_cmcc_is"、"com_cucc_isbns"、"com_ctcc_isbns"
                 如果无法获取模式，返回 None
        """
        cmd = f'cat {dpipath}/config/rule/dpiconfig.ok'
        try:
            response = self.cmd(cmd).strip()
            mode = re.match(r"(\w+?_\w+?_\w+?)(?=_|$)", response).group()
            return mode
        except Exception as e:
            logger.warning(f"无法从 {dpipath}/config/rule/dpiconfig.ok 获取模式：{e}")
            return None

    def get_dpiversion(self, dpipath="/opt/dpi"):
        """获取dpi版本"""
        cmd = f"cat ver.txt |head -n 1"
        response = self.cmd(cmd, cwd=dpipath).strip()
        if not response:
            logger.warning(f"获取 DPI 版本失败：命令返回为空，dpipath={dpipath}")
            return None
        if ":" in response:
            return response.split(":")[-1].strip().lstrip("V")
        else:
            parts = response.split()
            if not parts:
                logger.warning(f"获取 DPI 版本失败：无法解析版本字符串 '{response}'")
                return None
            return parts[-1].strip().lstrip("V")

    def get_pcicfg(self):
        """获取pcip配置信息"""
        res = dict()
        cmd = "cat /opt/dpi/mconf/modelswitch/xsajson/pci.cfg"
        for line in self.cmd(cmd).strip().split("\n"):
            line = line.strip()
            if line and not line.startswith("#"):
                if line.startswith("pci_list"):
                    pci_list = line.split()[1:]
                    if pci_list:
                        res["pci_list"] = pci_list
                elif line.startswith("raw_port"):
                    raw_port = line.split()[1:]
                    if raw_port:
                        res["raw_port"] = raw_port[0]
                elif line.startswith("src_mac"):
                    src_mac = line.split()[1:]
                    if src_mac:
                        res["src_mac"] = src_mac[0]
                elif line.startswith("dst_mac"):
                    dst_mac = line.split()[1:]
                    if dst_mac:
                        res["dst_mac"] = dst_mac[0]
        return res

    def config_pcicfg(self, pcicfg=None):
        """配置pcip配置信息"""
        if not pcicfg:
            pcicfg = dict()
        if "raw_port" not in pcicfg:
            pcicfg["raw_port"] = ""
        if "src_mac" not in pcicfg:
            pcicfg["src_mac"] = ""
        if "dst_mac" not in pcicfg:
            pcicfg["dst_mac"] = ""
        if "pci_list" not in pcicfg:
            pcicfg["pci_list"] = []

        for k, v in pcicfg.items():
            if k == "pci_list":
                cmd = f"sed -i 's/^{k}.*/{k} {' '.join(v)}/' /opt/dpi/mconf/modelswitch/xsajson/pci.cfg"
            else:
                cmd = f"sed -i 's/^{k}.*/{k} {v}/' /opt/dpi/mconf/modelswitch/xsajson/pci.cfg"
            self.cmd(cmd)

    def dpibak(self, bakpath="/home/dpibak", dpipath="/opt/dpi", force=False):
        """
        备份dpi

        Args:
            bakpath: 备份目录路径
            dpipath: DPI 程序路径
            force: 是否强制备份（添加时间戳）

        Returns:
            str: 备份路径，如果备份失败或无模式信息则返回 None
        """
        if not self.isdir(dpipath):
            logger.warn("dpi不存在，不执行备份")
            return

        if bakpath and not self.isdir(bakpath):
            self.mkdir(bakpath)

        get_version = self.get_dpiversion(dpipath=dpipath)
        if not get_version.strip():
            raise RuntimeError(f"dpi的版本号不存在，请检查")

        # 从 DPI 目录中获取模式
        get_mode = self.get_dpimode(dpipath=dpipath)

        # 无模式信息，不备份
        if not get_mode:
            logger.warning(f"⚠ 无法获取 DPI 模式信息，不执行备份")
            logger.warning(f"  → DPI 路径：{dpipath}")
            logger.warning(f"  → 可能原因：未执行模式切换，或 dpiconfig.ok 文件不存在")
            return None

        logger.info(f"→ 获取到 DPI 模式：{get_mode}")

        # 构建备份路径：包含版本号和模式
        path_bak = f"{bakpath.rstrip('/')}/dpi_bak_{get_version}_{get_mode}"

        # 如果强制备份，添加时间戳
        if force:
            path_bak = f"{path_bak}_{gettime(6)}"

        # 检查备份是否已存在
        if not force and self.isdir(path_bak):
            logger.info(f"备份目录存在，不备份：{path_bak}")
            return path_bak

        # 执行备份
        logger.info(f"备份dpi程序到：{path_bak}")
        cmd = f"cp -r {dpipath} {path_bak}"
        self.cmd(cmd)

        if self.isdir(path_bak):
            logger.info(f"备份成功：{path_bak}")
            return path_bak

    def is_agent_running(self):
        """
        检查 agent 是否正在运行

        Returns:
            bool: 正在运行返回 True，否则返回 False
        """
        # 通过 ps 命令检查 agent 进程
        cmd = "ps -ef | grep '/opt/agent/agent' | grep -v grep"
        response = self.cmd(cmd).strip()

        if response:
            # 解析进程信息
            lines = response.split('\n')
            for line in lines:
                if '/opt/agent/agent' in line:
                    # 提取 PID
                    parts = line.split()
                    if len(parts) >= 2:
                        pid = parts[1]
                        logger.debug(f"agent 正在运行，PID: {pid}")
                        return True

        return False

    def start_agent(self, timeout=30):
        """
        启动 agent 进程

        Args:
            timeout: 等待启动的超时时间（秒）

        Returns:
            bool: 启动成功返回 True，失败返回 False
        """
        # 1. 检查 agent 是否已经运行
        if self.is_agent_running():
            logger.info("agent 已经在运行中，无需启动")
            return True

        # 2. 检查控制脚本是否存在
        if not self.isfile("/etc/init.d/upms_agent_monitor"):
            logger.warning("agent 控制脚本不存在：/etc/init.d/upms_agent_monitor")
            return False

        # 3. 执行启动命令（同步等待完成）
        logger.info("启动 agent...")
        cmd = "/etc/init.d/upms_agent_monitor start"
        response = self.cmd(cmd,wait=False)
        logger.info(response)

        # 4. 等待进程启动
        time_start = time.time()
        while time.time() - time_start < timeout:
            if self.is_agent_running():
                logger.info("✓ agent 启动成功")
                return True
            time.sleep(1)

        # 5. 超时失败
        logger.error(f"✗ agent 启动超时（{timeout}s）")
        return False

    def stop_agent(self, timeout=30):
        """
        停止 agent 进程

        Args:
            timeout: 等待停止的超时时间（秒）

        Returns:
            bool: 停止成功返回 True，失败返回 False
        """
        # 1. 检查 agent 是否已经停止
        if not self.is_agent_running():
            logger.info("agent 已经停止，无需停止")
            return True

        # 2. 检查控制脚本是否存在
        if not self.isfile("/etc/init.d/upms_agent_monitor"):
            logger.warning("agent 控制脚本不存在：/etc/init.d/upms_agent_monitor")
            return False

        # 3. 执行停止命令（同步等待完成）
        logger.info("停止 agent...")
        cmd = "/etc/init.d/upms_agent_monitor stop"
        response = self.cmd(cmd, wait=False)
        logger.info(response)

        # 4. 等待进程停止
        time_start = time.time()
        while time.time() - time_start < timeout:
            if not self.is_agent_running():
                logger.info("✓ agent 停止成功")
                return True
            time.sleep(1)

        # 5. 超时失败，强制杀死进程
        logger.warning(f"⚠ agent 停止超时（{timeout}s），尝试强制杀死进程")

        # 先杀死主进程（upms_agent_monitor）
        cmd = "pkill -9 -f 'upms_agent_monitor'"
        self.cmd(cmd)
        time.sleep(1)

        # 再杀死子进程
        cmd = "pkill -9 -f '/opt/agent/agent'"
        self.cmd(cmd)
        time.sleep(2)

        # 6. 再次检查
        if not self.is_agent_running():
            logger.info("✓ agent 已强制停止")
            return True
        else:
            logger.error("✗ agent 强制停止失败")
            return False

    def restart_agent(self, timeout=60):
        """
        重启 agent 进程

        Args:
            timeout: 等待重启的超时时间（秒）

        Returns:
            bool: 重启成功返回 True，失败返回 False
        """
        logger.info("重启 agent...")

        # 1. 停止 agent
        if not self.stop_agent(timeout=timeout // 2):
            logger.error("✗ agent 停止失败，无法重启")
            return False

        # 2. 等待 2 秒确保完全停止
        time.sleep(2)

        # 3. 启动 agent
        if not self.start_agent(timeout=timeout // 2):
            logger.error("✗ agent 启动失败，重启失败")
            return False

        logger.info("✓ agent 重启成功")
        return True

    def wait_upgrade_system_complete(self, dpiversion, upgrade_start_timeout=300, upgrade_complete_timeout=1200):
        """
        等待升级系统完成升级

        Args:
            dpiversion: 目标版本号
            upgrade_start_timeout: 升级脚本启动等待超时（秒）
            upgrade_complete_timeout: 升级完成等待超时（秒）

        Returns:
            dict: {"result": bool, "mark": list}
        """
        result = {"result": True, "mark": []}
        logger.info("→ 升级系统接管升级流程...")

        # 删除旧的结果文件
        logger.info("→ 清理旧的结果文件...")
        self.cmd("rm -f /tmp/*.result")

        # 启动 agent
        logger.info("→ 启动 agent（升级系统接管）...")
        if not self.start_agent():
            logger.error("✗ agent 启动失败")
            result["result"] = False
            result["mark"].append("agent 启动失败")
            return result

        # 等待升级脚本启动
        logger.info("→ 等待升级系统开始升级...")
        time_start = time.time()
        upgrade_started = False

        while time.time() - time_start < upgrade_start_timeout:
            cmd = "ps -ef | grep 'upms_install.sh' | grep -v grep"
            response = self.cmd(cmd).strip()

            if response:
                logger.info("✓ 检测到升级脚本开始执行")
                upgrade_started = True
                break

            time.sleep(2)

        if not upgrade_started:
            logger.error(f"✗ 升级脚本启动超时（{upgrade_start_timeout}s）")
            result["result"] = False
            result["mark"].append(f"升级脚本启动超时（{upgrade_start_timeout}s）")
            self.stop_agent()
            return result

        # 等待升级脚本运行结束
        logger.info(f"→ 等待升级脚本执行完成（最长 {upgrade_complete_timeout}s）...")
        time_start = time.time()
        upgrade_completed = False

        while time.time() - time_start < upgrade_complete_timeout:
            cmd = "ps -ef | grep 'upms_install.sh' | grep -v grep"
            response = self.cmd(cmd).strip()

            if not response:
                logger.info("✓ 升级脚本已执行完成")
                upgrade_completed = True
                break

            time.sleep(5)

        if not upgrade_completed:
            logger.error(f"✗ 升级脚本执行超时（{upgrade_complete_timeout}s）")
            result["result"] = False
            result["mark"].append(f"升级脚本执行超时（{upgrade_complete_timeout}s）")
            self.stop_agent()
            return result

        # 查找结果文件
        logger.info("→ 查找升级结果文件...")
        time.sleep(2)  # 等待文件写入完成
        cmd = "ls -t /tmp/*.result 2>/dev/null | head -n 1"
        result_file = self.cmd(cmd).strip()

        if not result_file:
            logger.error("✗ 未找到升级结果文件")
            result["result"] = False
            result["mark"].append("未找到升级结果文件")
            self.stop_agent()
            return result

        logger.info(f"✓ 找到结果文件：{result_file}")

        # 检查升级结果
        logger.info("→ 检查升级结果...")
        cmd = f"cat {result_file}"
        response = self.cmd(cmd).strip()

        lines = response.split('\n')
        if len(lines) >= 2:
            status_code = lines[0].strip()
            status_message = lines[1].strip()

            logger.info(f"  → 状态码：{status_code}")
            logger.info(f"  → 状态信息：{status_message}")

            if status_code == "0":
                logger.info("✓ 升级成功")
            else:
                logger.error(f"✗ 升级失败：{status_message}")
                result["result"] = False
                result["mark"].append(f"升级失败：{status_message}")
                self.stop_agent()
                return result
        else:
            logger.error("✗ 结果文件格式错误")
            result["result"] = False
            result["mark"].append("结果文件格式错误")
            self.stop_agent()
            return result

        # 停止 agent
        logger.info("→ 停止 agent...")
        self.stop_agent()

        return result

    def upms_install(self, dpiversion, path, dpipath_bak=None, rmvarbak=False, xsa_modify_dict=None, timeout=5, use_upgrade_system=False, upgrade_start_timeout=300, upgrade_complete_timeout=1200):
        """
        安装upms

        Args:
            dpiversion: 目标版本号
            path: 升级脚本路径
            dpipath_bak: 备份目录路径
            rmvarbak: 是否删除/var/dpi下的备份（默认 False）
            xsa_modify_dict: xsa修改项，{"dpi.vlan_multiplexing": 2, "flow.ipv4_hash_ksize": 302}
            timeout: 等待启动超时时间
            use_upgrade_system: 是否启用升级系统
            upgrade_start_timeout: 升级脚本启动等待超时（秒）
            upgrade_complete_timeout: 升级完成等待超时（秒）

        Returns:
            dict: {"result": bool, "mark": list}
        """
        result = {"result": True, "mark": []}
        logger.info(f"dpi程序升级：{path}")
        if self.isdir("/opt/dpi"):
            xsa_json_s = self.json_get("/opt/dpi/xsaconf/xsa.json")
            xdr_template_json_s = self.json_get("/opt/dpi/xdrconf/rule/xdr_template.json")
            dpimode = self.get_dpimode()
            mod_switch = self.getfo(
                "/opt/dpi/mconf/modelswitch/%s_mod_switch.sh" % dpimode.split("_")[1]).read().decode("utf-8")
            modified_param = dict(re.findall(r"^(\w+)=(\d)\s*$", mod_switch, re.MULTILINE))
            # dpiversion = self.get_dpiversion()

            # 备份dpi
            self.dpibak(bakpath=dpipath_bak)

            # 删除var目录下的dpi（默认关闭）
            if rmvarbak:
                tmpdir = "/var/dpi/dpi." + dpiversion[1:].replace(".", "")
                logger.info(f"删除var目录下备份同名dpi目录：{tmpdir}")
                self.rm(tmpdir)

            # ==================== 升级系统接管 ====================
            if use_upgrade_system:
                # 启动 agent
                logger.info("→ 启动 agent（升级系统接管）...")
                if not self.start_agent():
                    logger.error("✗ agent 启动失败")
                    result["result"] = False
                    result["mark"].append("agent 启动失败")
                    return result

                # 等待升级脚本启动
                logger.info("→ 等待升级系统接管升级...")
                time_start = time.time()
                upgrade_started = False

                while time.time() - time_start < upgrade_start_timeout:
                    cmd = "ps -ef | grep 'upms_install.sh' | grep -v grep"
                    response = self.cmd(cmd).strip()

                    if response:
                        logger.info("✓ 检测到升级脚本开始执行")
                        upgrade_started = True
                        break

                    time.sleep(2)

                if not upgrade_started:
                    logger.error(f"✗ 升级脚本启动超时（{upgrade_start_timeout}s）")
                    result["result"] = False
                    result["mark"].append(f"升级脚本启动超时（{upgrade_start_timeout}s）")
                    self.stop_agent()
                    return result

                # 等待升级完成
                logger.info(f"→ 等待升级完成（最长 {upgrade_complete_timeout}s）...")
                dir_name = os.path.basename(os.path.dirname(path))
                result_file = f"/tmp/{dir_name}.result"

                time_start = time.time()
                upgrade_completed = False

                while time.time() - time_start < upgrade_complete_timeout:
                    if self.isfile(result_file):
                        logger.info(f"✓ 检测到升级结果文件：{result_file}")
                        upgrade_completed = True
                        break

                    cmd = "ps -ef | grep 'upms_install.sh' | grep -v grep"
                    response = self.cmd(cmd).strip()

                    if not response:
                        logger.warning("⚠ 升级脚本已结束，但未找到结果文件")
                        break

                    time.sleep(5)

                if not upgrade_completed:
                    logger.error(f"✗ 升级完成超时（{upgrade_complete_timeout}s）")
                    result["result"] = False
                    result["mark"].append(f"升级完成超时（{upgrade_complete_timeout}s）")
                    self.stop_agent()
                    return result

                # 检查升级结果
                logger.info("→ 检查升级结果...")
                cmd = f"cat {result_file}"
                response = self.cmd(cmd).strip()

                lines = response.split('\n')
                if len(lines) >= 2:
                    status_code = lines[0].strip()
                    status_message = lines[1].strip()

                    logger.info(f"  → 状态码：{status_code}")
                    logger.info(f"  → 状态信息：{status_message}")

                    if status_code == "0":
                        logger.info("✓ 升级成功")
                    else:
                        logger.error(f"✗ 升级失败：{status_message}")
                        result["result"] = False
                        result["mark"].append(f"升级失败：{status_message}")
                        self.stop_agent()
                        return result
                else:
                    logger.error("✗ 结果文件格式错误")
                    result["result"] = False
                    result["mark"].append("结果文件格式错误")
                    self.stop_agent()
                    return result

                # 停止 agent
                logger.info("→ 停止 agent...")
                self.stop_agent()

            # ==================== 当前升级流程 ====================
            else:
                # 升级
                logger.info(f"开始升级：{path}")
                dir, basename = os.path.split(path)
                response = self.cmd(["sudo", "bash", basename], cwd=dir, shell=False, bufsize=40960)
                logger.info(response)
                logger.info("开始完成")
        else:
            raise Exception("无dpi程序，无法升级")

        # 先检查升级结果（仅当前升级流程需要），失败则直接返回，不等待启动
        if not use_upgrade_system and "升级成功" not in response:
            result["result"] = False
            result["mark"].append(f"升级失败")
            return result

        logger.info(f"DPI启动中,等待超时时间：{timeout}s")
        if not self.wait_alive(timeout=timeout):
            result["result"] = False
            result["mark"].append(f"DPI启动等待{timeout}s超时失败")
            return result

        # 对比xsa.json升级后的变化
        if xsa_modify_dict:
            logger.info("对比xsa.json")
            xsa_json_d = self.json_get("/opt/dpi/xsaconf/xsa.json")

            for key, v_s in xsa_modify_dict.items():
                tmp = xsa_json_d
                key_list = key.strip().split(".")
                key_list = list(map(lambda x: int(x) if x.isdigit() else x, key_list))
                continue_flag = False
                for i in key_list:
                    if i in tmp:
                        if i in tmp:
                            tmp = tmp[i]
                        else:
                            info = f"升级后配置{key}不存在"
                            logger.info(info)
                            result["mark"].append(info)
                            continue_flag = True
                            break
                    else:
                        info = f"升级后配置{key}不存在"
                        logger.info(info)
                        result["mark"].append(info)
                        continue_flag = True
                        break
                if continue_flag:
                    continue
                v_d = tmp
                if v_s == v_d:
                    logger.info(f"升级后配置{key}一致：{v_s}-->{v_d}")
                else:
                    info = f"升级后配置{key}不一致：{v_s}-->{v_d}"
                    logger.info(info)
                    result["mark"].append(info)

        # 对比xdr_template.json升级后的变化
        logger.info("对比xdr_template.json")
        xdr_template_json_d = self.json_get("/opt/dpi/xdrconf/rule/xdr_template.json")
        comparer = DictComparer(xdr_template_json_s, xdr_template_json_d, ignore_fields=None, time_fields=None,
                                length_fields=None)
        logger.info(f"升级后xdr_template.json变化：{comparer.differences}")
        result["mark"].extend(comparer.differences)

        logger.info("对比mod_switch中开关")
        # 对比mod_switch中开关
        logger.info("对比切换mod_switch.sh中开关")
        for k, v_s in modified_param.items():
            cmd = """cat %s_mod_switch.sh|grep ^%s=|head -n 1""" % (dpimode.split("_")[1], k)
            response = self.cmd(cmd, cwd="/opt/dpi/mconf/modelswitch").strip()
            v_cur_list = re.findall(r"\w+=(\d)\s*", response)
            v_cur = v_cur_list[0] if v_cur_list else ""
            if str(v_s) != v_cur:
                # logger.info([str(v_s), v_cur])
                logger.info(f"升级后切换开关{k}不一致：{v_s}-->{v_cur}")
                result["mark"].append(f"升级后切换开关{k}不一致：{v_s}-->{v_cur}")
            else:
                logger.info(f"升级后切换开关{k}一致：{v_s}-->{v_cur}")

        logger.info("对比版本号")
        # 对比版本号
        cur_version = self.get_dpiversion()
        if cur_version != dpiversion:
            logger.info(f"升级后预期版本不准确：期望{dpiversion}-->实际{cur_version}")
            result["mark"].append(f"升级后预期版本不准确：期望{dpiversion}-->实际{cur_version}")
        else:
            logger.info(f"升级后预期版本准确：期望{dpiversion}-->实际{cur_version}")

        logger.info("对比dpimode")
        # 对比dpimode
        cur_dpimode = self.get_dpimode()
        if cur_dpimode != dpimode:
            logger.info(f"升级后预期版本不准确：期望{dpimode}-->实际{cur_dpimode}")
            result["mark"].append(f"升级后预期版本不准确：期望{dpimode}-->实际{cur_dpimode}")
        else:
            logger.info(f"升级后预期版本准确：期望{dpimode}-->实际{cur_dpimode}")
        if result["mark"]:
            result["result"] = False
        return result

    def install(self, dpipath, dpipath_bak=None):
        logger.info(f"dpi程序安装：{dpipath}")
        if self.isdir("/opt/dpi"):
            logger.info("备份原dpi程序")
            logger.info(f"备份路径：{self.dpibak(bakpath=dpipath_bak)}")
            logger.info("停止dpi程序")
            self.stop()
            logger.info("删除原dpi程序")
            self.rm("/opt/dpi")
        dir, basename = os.path.split(dpipath)
        logger.info(f"执行命令：./{basename}")
        logger.info(self.cmd(f"cd {dir};./{basename}", cwd=dir, bufsize=40960))
        if self.isfile("/opt/dpi/syscfg.json"):
            raise RuntimeError("执行完install.sh后dpi存在syscfg.json")

    def mod_switch(self, mode=None, args=("idc31",), modified_param=None, force=False, pcicfg=None, timeout=600):
        """
        切换dpi模式
        :param mode:模式，如：com_cmcc_is、com_cucc_isbns、com_ctcc_isbns 等
        :param args:执行切换命令时的自定义参数，如：idc31
        :param modified_param:修改syscfg.json中的参数，如：{"wlan_switch": "1", "oversea_switch": "1","S_modle_is": "1", "S_modle_bns": "1"}
        :param force:强制切换，默认False
        :param pcicfg:pcip配置信息，如：{"raw_port": "0", "src_mac": "00:00:00:00:00:00", "dst_mac": "00:00:00:00:00:00", "pci_list": ["0000:03:00.0", "0000:03:00.2"]}
        :param timeout:等待dpi启动的超时时间，默认600s
        :return:
        """
        logger.info(
            f"切换信息，mode: {mode}， args: {args}， modified_param: {modified_param}， force: {force}， pcicfg: {pcicfg} timeout: {timeout}")
        result = {"result": True, "mark": []}
        modified_param_exe = copy.deepcopy(modified_param)
        dpiversion = self.get_dpiversion()
        pcicfgfile = self.get_pcicfg()
        # 判断模式是否需要切换
        if mode is None:
            mode = self.get_dpimode()
            forceflag = False
        elif self.get_dpimode() != mode:
            forceflag = True
        elif pcicfg and pcicfg != pcicfgfile:
            forceflag = True
        else:
            forceflag = False

        # 根据pcicfg来配置pci.cfg
        if pcicfg and pcicfg != pcicfgfile:
            self.config_pcicfg(pcicfg)
            self.stop()
            self.rm(path="/opt/dpi/syscfg.json")

        logger.info(f"切换dpi模式为：{mode}")
        path = "/opt/dpi/mconf/modelswitch"
        dpimode_list = mode.split("_")

        # 判断修改开关后是否需要重启
        if not modified_param:
            modified_param = dict()

        if not forceflag and modified_param:
            for k, v in list(modified_param.items()):
                cmd = r"cat %s_mod_switch.sh |grep '%s\s*='" % (dpimode_list[1], k)
                res = self.cmd(cmd, cwd=path).strip()
                if not res:
                    raise RuntimeError(f"未找到参数：{k}")

                cmd = r"cat %s_mod_switch.sh |grep '%s\s*='|awk -F '=' '{print $2}'" % (dpimode_list[1], k)
                res = self.cmd(cmd, cwd=path).strip()
                if v != res:
                    forceflag = True
                else:
                    modified_param.pop(k)

        # 根据参数修改开关
        if modified_param:
            for k, v in modified_param.items():
                cmd = r"sed -i 's/%s\s*=.*/%s=%s/' %s_mod_switch.sh" % (k, k, v, dpimode_list[1])
                logger.info(cmd)
                self.cmd(cmd, cwd=path)

        if force or forceflag:
            # 清理日志信息
            self.cmd(args="truncate -s 0 /var/log/dpi.log")
            # 执行切换
            # cmd = f"./{dpimode_list[1]}_mod_switch.sh {dpimode_list[2]} {' '.join(args)}"
            cmd = ["sudo", "bash", f"{dpimode_list[1]}_mod_switch.sh", dpimode_list[2]] + list(args)
            logger.info(cmd)
            # logger.info(self.cmd(cmd, cwd=path, wait=True))
            logger.info(self.cmd(cmd, cwd=path, shell=False, bufsize=40960))

            # 等待程序启动
            logger.info("等待DPI启动")
            if not self.wait_alive(timeout=timeout):
                result["result"] = False
                result["mark"].append(f"DPI启动等待{timeout}s超时失败")
                return result
        else:
            logger.info("无需切换dpi模式。")

        # 对比mod_switch中开关
        logger.info("对比切换mod_switch.sh中开关")
        for k, v_d in modified_param_exe.items():
            cmd = """cat %s_mod_switch.sh|grep ^%s=|head -n 1""" % (mode.split("_")[1], k)
            response = self.cmd(cmd, cwd="/opt/dpi/mconf/modelswitch").strip()
            v_cur_list = re.findall(r"\w+=(\d)\s*", response)
            v_cur = v_cur_list[0] if v_cur_list else ""
            if str(v_d) != v_cur:
                logger.info([str(v_d), v_cur])
                logger.info(f"切换后开关{k}不一致：{v_d}-->{v_cur}")
                result["mark"].append(f"切换后开关{k}不一致：{v_d}-->{v_cur}")
            else:
                logger.info(f"切换后开关{k}一致：{v_d}-->{v_cur}")

        logger.info("对比版本号")
        # 对比版本号
        cur_version = self.get_dpiversion()
        if cur_version != dpiversion:
            logger.info(f"切换后预期版本不准确：期望{dpiversion}-->实际{cur_version}")
            result["mark"].append(f"切换后预期版本不准确：期望{dpiversion}-->实际{cur_version}")
        else:
            logger.info(f"切换后预期版本准确：期望{dpiversion}-->实际{cur_version}")

        logger.info("对比dpimode")
        # 对比dpimode
        cur_dpimode = self.get_dpimode()
        if cur_dpimode != mode:
            logger.info(f"切换后预期版本不准确：期望{mode}-->实际{cur_dpimode}")
            result["mark"].append(f"升级后预期版本不准确：期望{mode}-->实际{cur_dpimode}")
        else:
            logger.info(f"切换后预期版本准确：期望{mode}-->实际{cur_dpimode}")

        if result["mark"]:
            result["result"] = False
        return result

    def wait_pcapdump_writeover(self, timeout=60):
        logger.info(f"等待pcapdump写文件完成超时({timeout}s)")
        cmd = "cat /dev/shm/xsa/pcapdump.stat|grep all|tail -n 1|awk '{print $10}'"
        if not wait_until(func=self.cmd, args=cmd, expect_value='0\n', timeout=timeout):
            raise RuntimeError("等待pcapdump写文件超时失败，等待时间：%ss" % timeout)

def get_action_from_marex(marex):
    """eu_plc   0247546 proto.pid==5&&ip.dst==172.31.138.249 with action.do{eu_plc,type=monit,hid=66483,blk=disable,log=enable,lvl=3849,cid=1277,way=2,time=2022-07-19 20:21:18|2052-07-19 23:59:59}"""
    response = re.search(r"action\.do\s*{(\w+),", marex)
    if response:
        res = response.group(1)
    else:
        res = None
    return res

def get_type_from_marex(marex):
    """eu_plc   0247546 proto.pid==5&&ip.dst==172.31.138.249 with action.do{eu_plc,type=monit,hid=66483,blk=disable,log=enable,lvl=3849,cid=1277,way=2,time=2022-07-19 20:21:18|2052-07-19 23:59:59}"""
    response = re.search(r"action\.do\s*{\w+?,type=(\w+),", marex)
    if response:
        res = response.group(1)
    else:
        res = None
    return res

def get_xdrtxtlog2name_frommarex(marex):
    r"""0247546 proto.pid==5&&ip.dst==172.31.138.249 with action.do{eu_plc,type=monit,hid=66483,blk=disable,log=enable,lvl=3849,cid=1277,way=2,time=2022-07-19 20:21:18|2052-07-19 23:59:59}
    5721070 http.url~"^172\.31\.140\.52:8000/MiitDataCheck/page/dialingTest/targetFile/test\.ogg$" with action.do{eu_plc,type=filt,hid=66483,blk=enable,log=enable,lvl=3200,cid=1290,way=1,time=2022-07-20 15:14:46|2052-07-20 23:59:59}
0028582 ip.dst==172.31.140.52&&pkt.dstport==8000 with action.do{pcapdump,f=flow,hid=66483,way=1,p=1,prex=1306,darea=2,ct=1,lvl=9992,time=2022-07-20 00:00:00|2052-07-20 00:00:00}
0028639 ip.dst==172.31.140.52&&pkt.dstport==8000 with action.do{mirr,uid=0,g=1,time=2022-07-21 00:00:00|2052-07-21 00:00:00,d=both,f=flow,t=sip+sport+dip+dport,match-offset=0,match-method=include,match-len=1024,match-ctnt-len=1024,cut=10000,way=1,cid=1322,darea=2,p=1,hid=66483,ct=1,lvl=9992}
    :param marex:
    :return:
    """
    # darea
    # 1-信安
    # 2-数安
    # 3-网安
    # 4-深度合成
    action = get_action_from_marex(marex)
    if action == "eu_plc":
        response = re.search(r"%s,type=(\w+)," % action, marex)
        if response and response.group(1) == "monit":
            res = "MONITOR--MONITORXDR"
        elif response and response.group(1) == "filt":
            res = "FILTER--MONITORXDR"
        else:
            res = None
    elif action == "pcapdump":
        response = re.search(r"darea=(\w+),", marex)
        if response and response.group(1) == "1":
            res = "PCAPDUMP_IS--PCAPXDR"
        elif response and response.group(1) == "2":
            res = "PCAPDUMP_DS--PCAPXDR"
        elif response and response.group(1) == "3":
            res = "PCAPDUMP_NS--PCAPXDR"
        else:
            res = None
    elif action == "mirr":
        response = re.search(r"darea=(\w+),", marex)
        if response and response.group(1) == "1":
            res = "MIRRORVLAN_IS--MIRRORXDR"
        elif response and response.group(1) == "2":
            res = "MIRRORVLAN_DS--MIRRORXDR"
        elif response and response.group(1) == "3":
            res = "MIRRORVLAN_NS--MIRRORXDR"
        else:
            res = None
    else:
        res = None
    return res






if __name__ == '__main__':
    # ssh = SSHManager(host="172.31.140.173", user="root", passwd="yahong123&", port=22)
    a = Dpi(("10.12.131.32", 9000))
    print(a.json_get("/opt/dpi/xsaconf/xsa.json"))
    # print(a.start_agent())
    # print(a.is_agent_running())
    # print(a.stop_agent())
    # print(a.is_agent_running())
    # logger.info([a.listdir(path="/home/dpibak", args="-type f -name ver.txt", maxdepth=2)])
    # xdr_template_json_s = a.json_get("/opt/dpi/xdrconf/rule/xdr_template.json")
    # dpimode = a.get_dpimode()
    # mod_switch = a.getfo("/opt/dpi/mconf/modelswitch/%s_mod_switch.sh" % dpimode.split("_")[1]).read().decode(
    #     "utf-8")
    # modified_param = dict(re.findall(r"^(\w+)=(\d)\s*$", mod_switch, re.MULTILINE))
    # print(modified_param)
    # print(a.mod_switch(mode="com_cmcc_ircs", args=("ircs20",), modified_param=None, force=False, pcicfg={}, timeout=600))
    # xsa_json2dict = a.json_get(path="/opt/dpi/xsaconf/xsa.json")
    # dev_ip = xsa_json2dict.get("devinfo", {}).get("dev_ip", "")
    # print(dev_ip)
    # logger.info([a.modcfg2dict().get("adms", 0)])
    # logger.info([xsa_json2dict.get("adms", {}).get("idc_flag", None)])
    # dir_numa = a.cmd("dirname `find / -name numa.sh|head -n 1`").strip()
    # print(a.wait_alive(timeout=600))
    # print([a.cmd("find / -type f -name ACT-DPI-ISE-1.0.5.2-2_20250427161928.tar.gz -print -quit")])
    # print([a.cmd("cat /dev/shm/xsa/datarpt_conn.stat |grep 10.12.131.32|grep 60001|awk '{print $3}'")])
    # wait_not_until(a.cmd, '\n', step=1, timeout=10, args="cat /dev/shm/xsa/datarpt_conn.stat |grep 10.12.131.32|grep 60001|awk '{print $3}'")
    # logger.info(a.mod_switch(mode="com_cmcc_is", modified_param={"wlan_switch": "0", "oversea_switch": "0"}))

    # policys = [b"1001188  ip.dstv6==2e03::1208 with action.do{eu_plc,type=filt,hid=56782,blk=enable,log=enable,lvl=3073,cid=10001188,way=2,time=2024-03-27 13:47:04|2054-03-27 23:59:59,report=enable}"] *5000
    # a.marex_policy_update(policy=policys, path="/opt/dpi/euconf/rule/eu_policy.rule")
    # logger.info([a.create_cpuxsajson("/tmp/3.json", xdrstator_cpu=21, datarpt_rpt_cpus="22,23")])
    # b = [b"9553100  ip.dstv6==2e02::2&&pkt.dstport==80 with action.do{eu_plc,type=filt,hid=54038,blk=enable,log=enable,lvl=3075,cid=1547158,way=2,time=2023-04-24 10:47:10|2053-04-24 23:59:59}",b"9553200  ip.dstv6==2e02::2&&pkt.dstport==80 with action.do{eu_plc,type=filt,hid=54038,blk=enable,log=enable,lvl=3075,cid=1547158,way=2,time=2023-04-24 10:47:10|2053-04-24 23:59:59}"]
    # logger.info(a.json_get(path="/opt/dpi/xsaconf/xsa.json")["flow"]["tcp_fin_timeout_ms"])
    # aa = """0028639 ip.dst==172.31.140.52&&pkt.dstport==8000 with action.do{mirr,uid=0,g=1,time=2022-07-21 00:00:00|2052-07-21 00:00:00,d=both,f=flow,t=sip+sport+dip+dport,match-offset=0,match-method=include,match-len=1024,match-ctnt-len=1024,cut=10000,way=1,cid=1322,darea=2,p=1,hid=66483,ct=1,lvl=9992}
# """
#     logger.info(get_xdrtxtlog2name_frommarex(aa))
#     cmd = "cat /dev/shm/xsa/pcapdump.stat|tail -n 1|awk '{print $6}'"
#     logger.info(cmd)
#     wait_not_until(a.cmd, 0, step=1, timeout=7, args=cmd)
#     a.restart(timeout=180)
    # logger.info(a.cmd("ps -ef|grep /opt/dpi/xsa|wc -l"))
    # dpi = Dpi(self.server2sl["dpi"])
    # if dpi.modify_xsajson(
    #         kwargs={"dpi.loglevel": 7, "eu.compool_blk_posi": 3, "eu.uri_len": 1500, "flow.uri_field_len": 2048,
    #                 "mirrorvlan.icmp_enable": 1,
    #                 "mirrorvlan.vlantab": "0,202,202,1002,1002,202,202,101,101,303,303,101,101,303,303"}):
    #     dpi.restart(timeout=300)

    # logger.info(a.modify_xsajson(updatevalue={"dpi.loglevel": 7, "eu.compool_blk_posi": 3, "eu.uri_len": 1500, "flow.uri_field_len": 2048,
    #                 "mirrorvlan.icmp_enable": 1,
    #                 "mirrorvlan.vlantab": "0,202,202,1002,1002,202,202,101,101,303,303,101,101,303,303"}))