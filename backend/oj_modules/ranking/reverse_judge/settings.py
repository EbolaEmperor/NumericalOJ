"""反向评测的比赛级审核时限。"""

from backend.oj_modules import config

QUALITY_GATE_TIMEOUT_DEFAULT = 1800
QUALITY_GATE_TIMEOUT_MIN = 60
QUALITY_GATE_TIMEOUT_MAX = 7200


def normalize_quality_gate_timeout(value):
    if isinstance(value, bool) or not isinstance(value, (int, str)):
        raise ValueError('审核时限必须是 60 到 7200 秒之间的整数')
    if isinstance(value, str):
        value = value.strip()
        if not value.isascii() or not value.isdigit():
            raise ValueError('审核时限必须是 60 到 7200 秒之间的整数')
    timeout = int(value)
    if not QUALITY_GATE_TIMEOUT_MIN <= timeout <= QUALITY_GATE_TIMEOUT_MAX:
        raise ValueError('审核时限必须是 60 到 7200 秒之间的整数')
    return timeout


def quality_gate_timeout_seconds(competition):
    value = (competition or {}).get('reverse_quality_gate_timeout_seconds')
    if value is None:
        value = getattr(config, 'REVERSE_QUALITY_GATE_TIMEOUT_SECONDS', QUALITY_GATE_TIMEOUT_DEFAULT)
    return normalize_quality_gate_timeout(value)
