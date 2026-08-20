#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
《学号bmp AI 评测流程设计》打榜赛 · 评测脚本

上传系统约定：
    python grader.py <user_answer.json> <reference.json> <max_score>
脚本必须在 stdout 打印一行合法 JSON：
    {"score": <number>, "details": <object|string>}

评分口径（与本次比赛设计一致）：
- 参考答案（由人工标注得到）和选手答案均为形如：
      [{"username": "...", "score": 0 或 1, "reason": "..."}, ...]
  的 JSON 数组，score 为二元标签（1=图片与学号一致，0=不一致）。
- 对参考答案中每个 username，取选手提交结果中对应条目的 score 进行比对；
  若选手遗漏某个 username，或其 score 非 0/1，则该样本记为错误。
- 最终得分 = 准确率 × max_score；
  准确率 = (TP + TN) / 参考样本总数。
- details 字段包含混淆矩阵、精确率、召回率、F1 等信息，便于复盘。

异常处理：
- JSON 解析失败 / 结构不合法 → score=0，details 说明原因。
- 选手提交文件远大于 max_score 允许的样本数时，仍仅按参考答案里出现的
  username 计分；多余条目被忽略。
"""

import json
import os
import sys
import traceback


def _load_json_list(path, label):
    if not os.path.isfile(path):
        raise RuntimeError(f"{label} 文件不存在：{path}")
    with open(path, "r", encoding="utf-8") as f:
        data = json.load(f)
    if not isinstance(data, list):
        raise RuntimeError(f"{label} 顶层必须是 JSON 数组，实际类型：{type(data).__name__}")
    return data


def _as_map(rows, label):
    """[{username, score, ...}, ...] → {username: score_int_or_None}。"""
    out = {}
    for idx, row in enumerate(rows):
        if not isinstance(row, dict):
            raise RuntimeError(f"{label}[{idx}] 不是对象：{row!r}")
        username = row.get("username")
        if not isinstance(username, str) or not username.strip():
            raise RuntimeError(f"{label}[{idx}] 缺少合法的 username 字段")
        username = username.strip()
        raw = row.get("score")
        score = None
        if isinstance(raw, bool):
            score = 1 if raw else 0
        else:
            try:
                score = int(raw)
            except (TypeError, ValueError):
                score = None
            if score is not None and score not in (0, 1):
                score = None
        # 后出现的覆盖先出现的（容错）
        out[username] = score
    return out


def _grade(user_rows, ref_rows, max_score):
    ref_map = _as_map(ref_rows, "reference")
    user_map = _as_map(user_rows, "user")

    total = len(ref_map)
    if total == 0:
        return 0.0, {"error": "参考答案为空，无法评分。"}

    tp = tn = fp = fn = missing = invalid = 0
    wrong_samples = []
    for username, true_label in ref_map.items():
        if true_label not in (0, 1):
            # 参考答案本身异常，跳过（不计入总数更保险，但实际上参考应保证合法）
            total -= 1
            continue
        pred = user_map.get(username)
        if pred is None:
            if username in user_map:
                invalid += 1
                wrong_samples.append({"username": username, "truth": true_label, "pred": None, "kind": "invalid"})
            else:
                missing += 1
                wrong_samples.append({"username": username, "truth": true_label, "pred": None, "kind": "missing"})
            continue
        if pred == true_label:
            if true_label == 1:
                tp += 1
            else:
                tn += 1
        else:
            if true_label == 1 and pred == 0:
                fn += 1
            else:  # true=0, pred=1
                fp += 1
            wrong_samples.append({"username": username, "truth": true_label, "pred": pred, "kind": "wrong"})

    correct = tp + tn
    accuracy = correct / total if total else 0.0
    precision = tp / (tp + fp) if (tp + fp) else 0.0
    recall = tp / (tp + fn) if (tp + fn) else 0.0
    f1 = 2 * precision * recall / (precision + recall) if (precision + recall) else 0.0

    score = round(accuracy * float(max_score), 4)

    details = {
        "metric": "accuracy * max_score",
        "total_reference_samples": total,
        "correct": correct,
        "accuracy": round(accuracy, 6),
        "confusion_matrix": {"TP": tp, "TN": tn, "FP": fp, "FN": fn},
        "precision": round(precision, 6),
        "recall": round(recall, 6),
        "f1": round(f1, 6),
        "missing_predictions": missing,
        "invalid_score_values": invalid,
        "max_score": float(max_score),
        # 仅保留前若干条错误样本，避免 stdout 过长
        "wrong_sample_preview": wrong_samples[:20],
        "wrong_sample_count": len(wrong_samples),
    }
    return score, details


def main():
    if len(sys.argv) < 3:
        print(json.dumps({
            "score": 0,
            "details": f"用法错误：python grader.py <user.json> <reference.json> [max_score]   (argv={sys.argv})",
        }, ensure_ascii=False))
        return

    user_path = sys.argv[1]
    ref_path = sys.argv[2]
    try:
        max_score = float(sys.argv[3]) if len(sys.argv) >= 4 else 100.0
    except ValueError:
        max_score = 100.0

    try:
        user_rows = _load_json_list(user_path, "user")
        ref_rows = _load_json_list(ref_path, "reference")
        score, details = _grade(user_rows, ref_rows, max_score)
    except Exception as e:
        print(json.dumps({
            "score": 0,
            "details": {
                "error": str(e),
                "trace": traceback.format_exc()[-1500:],
            },
        }, ensure_ascii=False))
        return

    # 必须把最终 JSON 打印到 stdout 最末一行
    print(json.dumps({"score": score, "details": details}, ensure_ascii=False))


if __name__ == "__main__":
    main()
