"""提交评测幂等锁。

该能力由普通评测、书面作业、重测和停机恢复共同使用，因此不属于任一 Celery
任务实现。锁客户端 fail-open：Redis 暂时不可用时不阻断提交评测。
"""

import uuid

from oj_modules.config import EVALUATE_SUBMISSION_LOCK_TTL_SECONDS
from oj_modules.infrastructure.redis import create_optional_redis_client


LOCK_TTL_SECONDS = max(60, int(EVALUATE_SUBMISSION_LOCK_TTL_SECONDS))
_lock_redis_client = None


def _get_lock_redis_client():
    global _lock_redis_client
    if _lock_redis_client is None:
        _lock_redis_client = create_optional_redis_client()
    return _lock_redis_client


def submission_lock_key(submission_id):
    return f"submission:{submission_id}:lock"


def acquire_submission_lock(submission_id):
    client = _get_lock_redis_client()
    if client is None:
        return None, None, None

    key = submission_lock_key(submission_id)
    token = uuid.uuid4().hex
    try:
        acquired = client.set(key, token, nx=True, ex=LOCK_TTL_SECONDS)
    except Exception:
        return None, None, None

    if not acquired:
        return client, key, None
    return client, key, token


def release_submission_lock(client, key, token):
    if client is None or not key or not token:
        return
    try:
        client.eval(
            "if redis.call('get', KEYS[1]) == ARGV[1] then "
            "return redis.call('del', KEYS[1]) else return 0 end",
            1,
            key,
            token,
        )
    except Exception:
        pass


def clear_submission_lock(submission_id):
    """无条件清除已确认不再被运行中任务持有的评测锁。"""

    client = _get_lock_redis_client()
    if client is None:
        return
    try:
        client.delete(submission_lock_key(submission_id))
    except Exception:
        pass


def has_submission_lock(submission_id):
    """返回某条提交是否仍持有评测幂等锁。"""

    client = _get_lock_redis_client()
    if client is None:
        return False
    try:
        return bool(client.exists(submission_lock_key(submission_id)))
    except Exception:
        return False


__all__ = [
    "LOCK_TTL_SECONDS",
    "acquire_submission_lock",
    "clear_submission_lock",
    "has_submission_lock",
    "release_submission_lock",
    "submission_lock_key",
]
