"""中央升级编排：查询/下载 GitHub release、推送二进制到靶机、每日兜底检查。

socket_server 1.8.0 起靶机侧 GitHub 联网全部移除，查询/下载/推送收敛在本模块：
靶机零外呼；中央失败退避（1h→2h→4h 封顶），失败只打一条 warning 后转 debug，
网络恢复打一条 info——不刷屏。日志一行制。

实际升级下发在 server.upgrade_run 工具（推包 -> dt20 -> 轮询 dt14 确认）。
"""
from __future__ import annotations

import hashlib
import logging
import os
import re
import threading
import time

import httpx

logger = logging.getLogger(__name__)

REPO = "weihang1258/socket_server"
RAW_VERSION_URL = f"https://raw.githubusercontent.com/{REPO}/main/socket_server/version.py"

# 版本探测退避：失败后 1h→2h→4h 封顶；期间失败只记 debug，恢复后打 1 条 info。
# raw.githubusercontent 走 CDN 无配额压力，无需 ETag——24h 一次查询即可。
_BACKOFF_STEPS = (3600, 7200, 14400)

_VERSION_RE = re.compile(r"^\d+(\.\d+){1,3}$")

_fail_streak = 0
_announced: str | None = None
_daily_thread: threading.Thread | None = None


def version_ok(version: str) -> bool:
    """版本号格式校验（数字+点，如 1.8.0），同时用于防路径穿越。"""
    return bool(_VERSION_RE.match(version))


def fetch_latest_version(proxy: str | None = None, timeout: int = 10) -> str | None:
    """查最新版本号：raw version.py（不走 API 配额）。失败返回 None（含退避日志策略）。"""
    global _fail_streak
    try:
        resp = httpx.get(RAW_VERSION_URL, timeout=timeout, proxy=proxy,
                         follow_redirects=True)
        resp.raise_for_status()
        m = re.search(r'VERSION\s*=\s*"([^"]+)"', resp.text)
        if not m:
            logger.warning("raw version.py 未解析到 VERSION")
            return None
        if _fail_streak:
            logger.info(f"版本查询已恢复（此前连续失败 {_fail_streak} 次）")
            _fail_streak = 0
        return m.group(1)
    except Exception as e:
        _fail_streak += 1
        if _fail_streak == 1:
            logger.warning(f"版本查询失败: {e}；后续按退避重试，期间不再刷失败日志")
        else:
            logger.debug(f"版本查询失败（连续第 {_fail_streak} 次，"
                         f"退避 {_BACKOFF_STEPS[min(_fail_streak - 1, len(_BACKOFF_STEPS) - 1)]}s）: {e}")
        return None


def backoff_seconds() -> int:
    """当前失败连击对应的退避秒数（供每日检查线程拉长间隔）。"""
    return _BACKOFF_STEPS[min(_fail_streak, len(_BACKOFF_STEPS) - 1)]


def _sha256_file(path: str) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def ensure_release_binary(version: str, download_dir: str,
                          proxy: str | None = None,
                          timeout: int = 300) -> tuple[str | None, str]:
    """确保本地有 <download_dir>/socket_server/v<版本>/socket_server，返回 (路径, sha256)。

    已存在直接复用（幂等）；否则从 GitHub Release 下载二进制 + .sha256 并校验，
    校验通过才落盘（防半截文件误存）。失败返回 (None, 原因)。
    """
    version = version.strip().lstrip("v")
    if not version_ok(version):
        return None, f"版本号非法: {version!r}"
    vdir = os.path.join(download_dir, "socket_server", f"v{version}")
    binary = os.path.join(vdir, "socket_server")
    if os.path.isfile(binary) and os.access(binary, os.X_OK):
        return binary, _sha256_file(binary)
    base = f"https://github.com/{REPO}/releases/download/v{version}"
    try:
        os.makedirs(vdir, exist_ok=True)
        logger.info(f"下载 {base}/socket_server（{'proxy' if proxy else '直连'}）")
        r = httpx.get(f"{base}/socket_server", timeout=timeout, proxy=proxy,
                      follow_redirects=True)
        r.raise_for_status()
        content = r.content
        r2 = httpx.get(f"{base}/socket_server.sha256", timeout=30, proxy=proxy,
                       follow_redirects=True)
        r2.raise_for_status()
        expected = r2.text.strip().split()[0]
        actual = hashlib.sha256(content).hexdigest()
        if actual != expected:
            return None, f"下载校验失败: 期望 {expected}, 实际 {actual}"
        tmp = binary + ".tmp"
        with open(tmp, "wb") as f:
            f.write(content)
        os.chmod(tmp, 0o755)
        os.replace(tmp, binary)
        logger.info(f"已下载 v{version} -> {binary} ({len(content)}B)")
        return binary, actual
    except Exception as e:
        return None, f"下载 v{version} 失败: {e}"


def push_binary(host: str, binary_path: str, version: str,
                http_port: int = 9001, timeout: int = 300) -> tuple[bool, str]:
    """经靶机 :9001 HTTP 文件服务推二进制到 versions/<版本>/.staging/socket_server。

    返回 (True, staging路径) 或 (False, 原因)。需靶机 1.7.0+（:9001 已上线）。
    """
    if ":" in host and not host.startswith("["):
        host = f"[{host}]"  # IPv6 裸地址
    url = f"http://{host}:{http_port}/files"
    staging = f"/opt/socket/versions/{version}/.staging/socket_server"
    try:
        with open(binary_path, "rb") as f:
            content = f.read()
        resp = httpx.post(url, data={"path": staging},
                          files={"file": (os.path.basename(binary_path), content)},
                          timeout=timeout)
        resp.raise_for_status()
        data = resp.json()
        if not data.get("ok"):
            return False, f"推送失败: {data}"
        return True, staging
    except Exception as e:
        return False, f"推送失败（需靶机 1.7.0+ 开启 :9001）: {e}"


def start_daily_check(proxy: str | None, get_version) -> None:
    """启动每日兜底版本检查线程：有新版记 1 条 info，绝不自动升级。

    先睡 24h 再查（刚部署没必要立刻查）；查询失败按 fetch_latest_version 的
    退避节奏拉长重试间隔。get_version() 返回桥自身参照版本（仅用于日志展示）。
    """
    global _daily_thread
    if _daily_thread and _daily_thread.is_alive():
        return

    def _loop():
        global _announced
        while True:
            time.sleep(86400)
            v = fetch_latest_version(proxy)
            if v and v != _announced:
                logger.info(f"socket_server 最新版 v{v}（本桥 {get_version()}；"
                            f"仅提示，不会自动升级，需要时调 upgrade_run）")
                _announced = v

    _daily_thread = threading.Thread(target=_loop, daemon=True,
                                     name="upgrade-daily-check")
    _daily_thread.start()
