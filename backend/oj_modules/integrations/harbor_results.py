"""Harbor 奖励与平台分数的纯转换；独立执行进程不导入站点配置。"""

import json
import math
from pathlib import Path

RESULT_FILENAME = "numoj_result.json"


def normalize_harbor_rewards(rewards):
    if not isinstance(rewards, dict) or not rewards:
        raise ValueError("Harbor verifier 未返回有效 reward")
    normalized = {}
    for name, value in rewards.items():
        if isinstance(value, bool) or not isinstance(value, (int, float)):
            raise ValueError("Harbor reward 必须是数字")
        if isinstance(value, float) and not math.isfinite(value):
            raise ValueError("Harbor reward 必须是有限数字")
        normalized[str(name)] = value
    main = next((normalized[key] for key in ("reward", "score") if key in normalized), None)
    if main is None and any(not 0 <= value <= 1 for value in normalized.values()):
        raise ValueError("Harbor 指标包含非归一化数值，请用 reward 或 score 明确提供 0 到 1 的主分，不能推测指标量纲")
    score = main if main is not None else sum(normalized.values()) / len(normalized)
    if not 0 <= score <= 1:
        raise ValueError("Harbor 主分必须是 0 到 1 之间的数字")
    return {"max_score": 1.0, "score": score, "rewards": normalized,
            "test_points": {name: {"description": name, "max_score": 1.0, "score": value}
                            for name, value in normalized.items() if 0 <= value <= 1}}


def load_harbor_result(trial_dir):
    path = Path(trial_dir) / RESULT_FILENAME
    if path.is_symlink() or not path.is_file() or path.stat().st_size > 2 * 1024 * 1024:
        raise ValueError("Harbor 持久结果不存在或无效")
    result = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(result, dict) or not isinstance(result.get("ok"), bool):
        raise ValueError("Harbor 持久结果格式无效")
    if result["ok"]:
        result["result"] = normalize_harbor_rewards((result.get("result") or {}).get("rewards"))
    return result


def write_harbor_result(trial_dir, result):
    path = Path(trial_dir) / RESULT_FILENAME
    temporary = path.with_suffix(".tmp")
    temporary.write_text(json.dumps(result, ensure_ascii=False, allow_nan=False), encoding="utf-8")
    temporary.replace(path)
