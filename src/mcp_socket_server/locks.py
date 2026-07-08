"""状态锁管理器:per-target 多模式锁(fail-fast)。

LockClass 定义在 commands.py,本模块执行。锁策略:
  - NONE:跳过,自由并发
  - CAPTURE:按 (target, path) 排他;capture_start 持锁到 capture_stop
  - FILE_IO/SHELL/BROWSER:per-target 排他(lock_key_fields=() 时)
  - SYSTEM:全局排他(stub,本期不实现)

冲突:fail-fast(非阻塞 try);冲突->该 target failed,reason 标注冲突类+key。
"""
from __future__ import annotations

import threading
from typing import Optional

from .commands import LockClass


class LockConflict(Exception):
    def __init__(self, target: str, lock_class: LockClass, key: Optional[str] = None):
        self.target = target
        self.lock_class = lock_class
        self.key = key
        parts = [f"靶机 {target}", f"锁类 {lock_class.value}"]
        if key:
            parts.append(f"key={key}")
        parts.append("冲突")
        super().__init__(" ".join(parts))


class TargetLock:
    """单靶机锁状态。"""

    def __init__(self):
        self._lock = threading.Lock()
        # CAPTURE: {(path,): count}
        self._captures: dict[tuple, int] = {}
        # 排他锁:FILE_IO/SHELL/BROWSER 任意一个持有后,同靶机其他非 NONE 操作阻塞
        self._exclusive_holder: Optional[LockClass] = None
        self._exclusive_count: int = 0

    def acquire(self, lock_class: LockClass, key: Optional[tuple] = None) -> bool:
        """尝试获取锁。成功返回 True;冲突抛出 LockConflict。"""
        if lock_class == LockClass.NONE:
            return True
        if lock_class == LockClass.CAPTURE:
            return self._acquire_capture(key)
        # FILE_IO / SHELL / BROWSER / SYSTEM: per-target 排他
        return self._acquire_exclusive(lock_class)

    def release(self, lock_class: LockClass, key: Optional[tuple] = None) -> None:
        if lock_class == LockClass.NONE:
            return
        if lock_class == LockClass.CAPTURE:
            self._release_capture(key)
        else:
            self._release_exclusive(lock_class)

    def _acquire_capture(self, key: Optional[tuple]) -> bool:
        cap_key = key or ()
        with self._lock:
            if self._exclusive_holder is not None:
                raise LockConflict("?", LockClass.CAPTURE, str(cap_key))
            if cap_key in self._captures:
                raise LockConflict("?", LockClass.CAPTURE, str(cap_key))
            self._captures[cap_key] = 1
            return True

    def _release_capture(self, key: Optional[tuple]) -> None:
        cap_key = key or ()
        with self._lock:
            self._captures.pop(cap_key, None)

    def _acquire_exclusive(self, lock_class: LockClass) -> bool:
        with self._lock:
            if self._exclusive_holder is not None:
                raise LockConflict("?", lock_class)
            if self._captures:
                raise LockConflict("?", lock_class, str(list(self._captures.keys())))
            self._exclusive_holder = lock_class
            self._exclusive_count += 1
            return True

    def _release_exclusive(self, lock_class: LockClass) -> None:
        with self._lock:
            if self._exclusive_holder == lock_class:
                self._exclusive_count -= 1
                if self._exclusive_count <= 0:
                    self._exclusive_holder = None

    def has_active(self) -> bool:
        with self._lock:
            return bool(self._captures) or self._exclusive_holder is not None

    def active_captures(self) -> list[tuple]:
        with self._lock:
            return list(self._captures.keys())


class LockManager:
    """全局锁管理器,管理所有靶机的锁状态。单例。"""

    def __init__(self):
        self._locks: dict[str, TargetLock] = {}
        self._global_lock = threading.Lock()

    def _get_target_lock(self, target: str) -> TargetLock:
        with self._global_lock:
            tl = self._locks.get(target)
            if tl is None:
                tl = TargetLock()
                self._locks[target] = tl
            return tl

    def acquire(self, target: str, lock_class: LockClass,
                key: Optional[tuple] = None) -> None:
        """尝试获取锁。冲突抛 LockConflict。"""
        if lock_class == LockClass.NONE:
            return
        if lock_class == LockClass.SYSTEM:
            raise LockConflict(target, lock_class, "SYSTEM 本期 stub")
        tl = self._get_target_lock(target)
        tl.acquire(lock_class, key)

    def release(self, target: str, lock_class: LockClass,
                key: Optional[tuple] = None) -> None:
        if lock_class == LockClass.NONE:
            return
        tl = self._locks.get(target)
        if tl is None:
            return
        tl.release(lock_class, key)

    def has_active(self, target: str) -> bool:
        tl = self._locks.get(target)
        if tl is None:
            return False
        return tl.has_active()

    def release_target(self, target: str, lock_class: LockClass,
                       key: Optional[tuple] = None) -> None:
        """安全释放:捕获 LockConflict 不传播。"""
        try:
            self.release(target, lock_class, key)
        except Exception:
            pass


_lock_manager: Optional[LockManager] = None


def get_lock_manager() -> LockManager:
    global _lock_manager
    if _lock_manager is None:
        _lock_manager = LockManager()
    return _lock_manager