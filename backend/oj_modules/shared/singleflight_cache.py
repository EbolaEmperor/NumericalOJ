"""进程内短时只读缓存与有界 single-flight 原语。"""

from __future__ import annotations

from dataclasses import dataclass, field
import threading
import time
from typing import Callable, Generic, TypeVar, cast


_T = TypeVar("_T")
_MISSING = object()


class SingleFlightTimeout(TimeoutError):
    """已有加载正在进行，调用方在有界等待内没有取得结果。"""


@dataclass
class _Flight(Generic[_T]):
    generation: int
    event: threading.Event = field(default_factory=threading.Event)
    result: object = _MISSING
    error: BaseException | None = None


def _clone_exception(error: BaseException) -> BaseException:
    """避免多个线程反复修改同一个异常对象的 traceback。"""
    try:
        return type(error)(*error.args)
    except Exception:
        return RuntimeError(str(error))


class BoundedSingleFlightTTLCache(Generic[_T]):
    """合并并发加载，且绝不在状态锁内执行 ``loader``。

    有过期值时采用 stale-while-refresh；冷启动 waiter 只做有界等待。加载失败会
    扇出给同批 waiter，并在极短冷却期内快速失败，避免数据库故障时逐个接力重试。
    ``invalidate`` 通过 generation 阻止失效前的慢加载重新发布旧值。
    """

    def __init__(
        self,
        *,
        ttl_seconds: float,
        wait_timeout_seconds: float = 0.05,
        failure_cooldown_seconds: float = 0.25,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        if ttl_seconds <= 0:
            raise ValueError("缓存 TTL 必须大于零")
        if wait_timeout_seconds < 0:
            raise ValueError("single-flight 等待时间不能为负数")
        if failure_cooldown_seconds < 0:
            raise ValueError("single-flight 失败冷却时间不能为负数")
        self._ttl_seconds = float(ttl_seconds)
        self._wait_timeout_seconds = float(wait_timeout_seconds)
        self._failure_cooldown_seconds = float(failure_cooldown_seconds)
        self._clock = clock
        self._lock = threading.Lock()
        self._generation = 0
        self._value: object = _MISSING
        self._expires_at = 0.0
        self._flight: _Flight[_T] | None = None
        self._failure: tuple[float, int, BaseException] | None = None

    def invalidate(self) -> None:
        """清空可见值并切断旧 flight；旧 owner 完成后不得回填。"""
        with self._lock:
            self._generation += 1
            self._value = _MISSING
            self._expires_at = 0.0
            self._failure = None
            self._flight = None

    def get(
        self,
        loader: Callable[[], _T],
        *,
        wait_timeout_seconds: float | None = None,
    ) -> _T:
        timeout = (
            self._wait_timeout_seconds
            if wait_timeout_seconds is None
            else float(wait_timeout_seconds)
        )
        if timeout < 0:
            raise ValueError("single-flight 等待时间不能为负数")

        now = self._clock()
        with self._lock:
            if self._value is not _MISSING and now < self._expires_at:
                return cast(_T, self._value)

            stale = self._value
            failure = self._failure
            if failure is not None:
                failed_until, failed_generation, error = failure
                if failed_generation == self._generation and now < failed_until:
                    if stale is not _MISSING:
                        return cast(_T, stale)
                    raise _clone_exception(error)
                self._failure = None

            flight = self._flight
            if flight is not None and flight.generation == self._generation:
                if stale is not _MISSING:
                    return cast(_T, stale)
                owner = False
            else:
                flight = _Flight[_T](generation=self._generation)
                self._flight = flight
                owner = True

        if not owner:
            if timeout == 0 or not flight.event.wait(timeout):
                raise SingleFlightTimeout("只读缓存正在加载，请稍后重试")
            if flight.error is not None:
                raise _clone_exception(flight.error)
            if flight.result is _MISSING:
                raise RuntimeError("single-flight 完成但没有发布结果")
            return cast(_T, flight.result)

        try:
            loaded = loader()
        except BaseException as error:
            with self._lock:
                if self._flight is flight:
                    self._flight = None
                flight.error = error
                if (
                    flight.generation == self._generation
                    and isinstance(error, Exception)
                ):
                    self._failure = (
                        self._clock() + self._failure_cooldown_seconds,
                        self._generation,
                        error,
                    )
                    stale = self._value
                else:
                    stale = _MISSING
                flight.event.set()
            if stale is not _MISSING and isinstance(error, Exception):
                return cast(_T, stale)
            raise

        with self._lock:
            if self._flight is flight:
                self._flight = None
            flight.result = loaded
            if flight.generation == self._generation:
                self._value = loaded
                self._expires_at = self._clock() + self._ttl_seconds
                self._failure = None
            flight.event.set()
        return loaded


__all__ = ["BoundedSingleFlightTTLCache", "SingleFlightTimeout"]
