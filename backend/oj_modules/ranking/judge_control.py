"""Judge 评测停止的共享业务边界；执行控制由组合根或任务层注入。"""

from contextlib import contextmanager
import secrets

from backend.oj_modules.agents.sessions import get_judge_session_for_attempt

_TERMINAL = {'completed', 'failed', 'canceled', 'cancelled'}
_COMPARE_DELETE = (
    "if redis.call('get', KEYS[1]) == ARGV[1] then "
    "return redis.call('del', KEYS[1]) else return 0 end"
)


class JudgeCancellationError(RuntimeError):
    """尚未确认所有 Judge 轮次停止，调用方不得旋转 attempt 或删除提交。"""


@contextmanager
def stopped_judge_submission(submission, scoring_mode, *, redis_client, terminate_agent):
    """禁止新阶段派发，确认通用会话停止，并持锁覆盖调用方的 attempt 变更。

    通用队列等待仍占端点名额；只有全部轮次停止且完成业务变更后才 CAS 放回。
    任何取消失败都保留原 attempt 和池名额，允许从同一业务记录重试。
    """
    if scoring_mode not in {'agent_judge', 'reverse_judge'}:
        yield
        return
    if redis_client is None:
        raise JudgeCancellationError('Redis 不可用，暂时无法确认评测已停止')
    sid = int(submission['id'])
    attempt_id = submission.get('judge_attempt_id')
    prefix = 'reverse_judge' if scoring_mode == 'reverse_judge' else 'judge'
    lock_key = f'ranking:{prefix}:lock:{sid}:{attempt_id or "legacy"}'
    token = secrets.token_hex(16)
    if not redis_client.set(lock_key, token, nx=True, ex=300):
        raise JudgeCancellationError('评测正在推进，请稍后重试停止操作')
    confirmed = set()
    all_stopped = False
    try:
        for kind in ('agent_judge', 'reverse_quality', 'reverse_answer'):
            session = get_judge_session_for_attempt(sid, attempt_id, kind)
            if not session or not session.get('current_task_id'):
                continue
            task_id = session['current_task_id']
            if str(session.get('status') or '').lower() not in _TERMINAL:
                if not callable(terminate_agent):
                    raise JudgeCancellationError('通用 Agent 停止入口尚未初始化')
                result = terminate_agent(task_id)
                if not isinstance(result, dict) or result.get('errors'):
                    errors = result.get('errors') if isinstance(result, dict) else None
                    raise JudgeCancellationError('；'.join(errors or ['通用 Agent 尚未确认停止']))
                refreshed = get_judge_session_for_attempt(sid, attempt_id, kind)
                if not refreshed or str(refreshed.get('status') or '').lower() not in _TERMINAL:
                    raise JudgeCancellationError('通用 Agent 停止状态尚未确认，请稍后重试')
            confirmed.add(task_id)
        all_stopped = True
        yield
    finally:
        try:
            if all_stopped and confirmed:
                for key in redis_client.scan_iter(match='aj:ep:*:slot:*', count=200):
                    value = redis_client.get(key)
                    text = value.decode() if isinstance(value, bytes) else str(value or '')
                    parts = text.split('|', 2)
                    if len(parts) == 3 and parts[0] == 'turn' and parts[2] in confirmed:
                        redis_client.eval(_COMPARE_DELETE, 1, key, value)
        finally:
            redis_client.eval(_COMPARE_DELETE, 1, lock_key, token)


__all__ = ['JudgeCancellationError', 'stopped_judge_submission']
