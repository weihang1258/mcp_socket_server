#!/usr/bin/env python
# -*- coding: utf-8 -*-
# @Time    : 2024/4
# @Author  : weihang
# @File    : constants.py
# @Desc    : 共享常量定义（仅包含原始 main_exe.py 中存在的数据）

"""
本模块包含所有业务文件共享的常量定义。

**重要原则：只保留原始文件中实际存在的数据，禁止发散生成。**

数据来源：
- main_exe.py:34-50  - DPI 规则文件路径
- main_exe.py:53     - 日志源到日志类型映射 (src2logtype)
- main_exe.py:55-60  - 省ID到省份ID映射 (provinceId2provID)
- main_exe.py:62-68  - DPI模式到版本映射 (dpimode2mod_switch_version)
- main_exe.py:7023   - 动作到策略文件映射 (action2policyfile)
"""

# ============== DPI 规则文件路径（来自 main_exe.py:34-50）==============
uploadfile = "/opt/dpi/xsaconf/rule/upload.rule"
reportfile = "/opt/dpi/xdrconf/rule/report.rule"
house_ipsegsfile = "/opt/dpi/xsaconf/rule/house_ipsegs.txt"
pcip_ipsegsfile = "/opt/dpi/xsaconf/rule/pcip_ipsegs.txt"
comon_inifile = "/opt/dpi/xsaconf/common.ini"
ydcommoninfo_rulefile = "/opt/dpi/euconf/rule/ydcommoninfo.rule"
commoninfo_rulefile = "/opt/dpi/euconf/rule/commoninfo.rule"
access_log_rulefile = "/opt/dpi/euconf/rule/access_log.rule"
eu_active_resource_rulefile = "/opt/dpi/euconf/rule/eu_active_resource.rule"
xsa_jsonfile = "/opt/dpi/xsaconf/xsa.json"
fz_block_rulefile = "/opt/dpi/xsaconf/rule/fz_block.rule"
fz_block_add_rulefile = "/opt/dpi/xsaconf/rule/fz_block_add.rule"
fz_block_del_rulefile = "/opt/dpi/xsaconf/rule/fz_block_del.rule"
ip_block_rulefile = "/opt/dpi/xsaconf/rule/ip_block.rule"
ip_block_add_rulefile = "/opt/dpi/xsaconf/rule/ip_block_add.rule"
ip_block_del_rulefile = "/opt/dpi/xsaconf/rule/ip_block_del.rule"
fz_monitor_rulefile = "/opt/dpi/xsaconf/rule/fz_monitor.rule"
fz_monitor_add_rulefile = "/opt/dpi/xsaconf/rule/fz_monitor_add.rule"
fz_monitor_del_rulefile = "/opt/dpi/xsaconf/rule/fz_monitor_del.rule"
ip_monitor_rulefile = "/opt/dpi/xsaconf/rule/ip_monitor.rule"
ip_monitor_add_rulefile = "/opt/dpi/xsaconf/rule/ip_monitor_add.rule"
ip_monitor_del_rulefile = "/opt/dpi/xsaconf/rule/ip_monitor_del.rule"
fz_blurmatch_rulefile = "/opt/dpi/xsaconf/rule/fz_blurmatch.rule"
fz_blurmatch_add_rulefile = "/opt/dpi/xsaconf/rule/fz_blurmatch_add.rule"
overseaip_ipsegsfile = "/opt/dpi/xsaconf/rule/overseaip_ipsegs.txt"
xdr_filter_rulefile = "/opt/dpi/xdrconf/rule/xdr_filter.rule"
bzip_ipsegsfile = "/opt/dpi/xsaconf/rule/zcip_ipsegs.txt"
fz_action_txtfile = "/opt/dpi/xsaconf/rule/fz_action.txt"
fz_template_txtfile = "/opt/dpi/xsaconf/rule/fz_template.txt"
ip_segment_txtfile = "/opt/dpi/xsaconf/rule/ip_segment.txt"

# ============== darea 到 pcap 源路径映射 ==============
DAREA2PCAP_SRC = {
    "1": "/dev/shm/sess/pcap/0x04a1",  # 信安
    "2": "/dev/shm/sess/pcap/0x04a5",  # 数安
    "3": "/dev/shm/sess/pcap/0x04a3",  # 网安
}

# ============== 动作到策略文件映射（来自 main_exe.py:7023，仅原始4项）==============
# 注意：原始只有这4项，不包含 block, reset, forward, drop, alert, tariff
action2policyfile = {
    "eu_plc": "/opt/dpi/euconf/rule/eu_policy.rule",
    "pcapdump": "/opt/dpi/xsaconf/rule/pcapdump.rule",
    "mirr": "/opt/dpi/xsaconf/rule/mirror.rule",
    "vpn_block": "/opt/dpi/xsaconf/rule/vpn_block.rule"
}

# ============== 日志源到日志类型映射（来自 main_exe.py:53，仅原始2项）==============
# 注意：原始只有这2项，不包含 FILTER, MONITOR
src2logtype = {
    "/dev/shm/sess/ACCESSTempt/EU_ACCESS_LOG": "3",
    "/dev/shm/sess/IS/AUDIT": "35"
}

# ============== 省ID到省份ID映射（来自 main_exe.py:55-60）==============
provinceId2provID = {
    "11": "100", "44": "200", "31": "210", "12": "220", "50": "230",
    "21": "240", "32": "250", "42": "270", "43": "731", "51": "280",
    "61": "290", "13": "311", "14": "351", "41": "371", "22": "431",
    "23": "451", "15": "471", "37": "531", "34": "551", "33": "571",
    "35": "591", "46": "731", "45": "771", "36": "791", "52": "851",
    "53": "871", "54": "891", "62": "931", "64": "951", "63": "971",
    "65": "991"
}

# ============== DPI 模式到版本映射（来自 main_exe.py:62-68）==============
dpimode2mod_switch_version = {
    "com_cmcc_is": "idc31", "com_cmcc_bns": "idc31", "com_cmcc_ns": "idc31",
    "com_cmcc_bnsns": "idc31", "com_cmcc_ircs": "ircs20",
    "com_cucc_is": "idc31", "com_cucc_isbns": "idc31", "com_cucc_bns": "idc31",
    "com_cucc_ns": "idc31", "com_cucc_bnsns": "idc31", "com_cucc_ircs": "ircs20",
    "com_ctcc_is": "idc31", "com_ctcc_isbns": "idc31", "com_ctcc_bns": "idc31",
    "com_ctcc_ns": "idc31", "com_ctcc_bnsns": "idc31", "com_ctcc_ircs": "ircs20"
}

# ============== 别名（兼容旧代码）==============
# 保持与原始代码的命名兼容性
ACTION_TO_POLICY = action2policyfile
SRC_TO_LOGTYPE = src2logtype
PROVINCE_ID_MAPPING = provinceId2provID
DPI_MODE_TO_VERSION = dpimode2mod_switch_version
