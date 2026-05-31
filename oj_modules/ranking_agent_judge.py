#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""打榜赛 Agent-as-Judge 模式的纯逻辑（无 DB / Redis / Docker 依赖，便于单测）。

规则裁决核心：
  - 每条规则 raw 结果只有 pass/failed；
  - 依赖即评分门槛：被依赖规则的 effective ∈ {failed, skipped, error} → 本规则 skipped(0 分)；
  - live 阶段未上报的规则为 pending；finalize 时仍未上报的判 error(0 分)。
"""
import json

RESULT_PASS = 'pass'
RESULT_FAILED = 'failed'
_VALID_RAW = (RESULT_PASS, RESULT_FAILED)

EFF_PASS = 'pass'
EFF_FAILED = 'failed'
EFF_SKIPPED = 'skipped'
EFF_ERROR = 'error'
EFF_PENDING = 'pending'
_GATE_FAIL = (EFF_FAILED, EFF_SKIPPED, EFF_ERROR)


def normalize_rules(rules):
    """校验并归一规则列表。每条 = {rule_id:int>0, rule_text:str, value:float>=0, dependencies:[int]}。
    校验：rule_id 唯一正整数；依赖指向存在的规则；无自依赖；无环；value>=0。返回归一后的新列表。
    任何不合法抛 ValueError。"""
    if not isinstance(rules, list):
        raise ValueError('规则必须是列表')
    out = []
    seen = set()
    for idx, r in enumerate(rules):
        if not isinstance(r, dict):
            raise ValueError(f'第 {idx + 1} 条规则格式非法')
        try:
            rid = int(r.get('rule_id'))
        except (TypeError, ValueError):
            raise ValueError(f'第 {idx + 1} 条规则缺少合法 rule_id')
        if rid <= 0:
            raise ValueError(f'rule_id 必须为正整数：{rid}')
        if rid in seen:
            raise ValueError(f'rule_id 重复：{rid}')
        seen.add(rid)
        text = str(r.get('rule_text') or '').strip()
        if not text:
            raise ValueError(f'规则 {rid} 描述不能为空')
        try:
            value = float(r.get('value'))
        except (TypeError, ValueError):
            raise ValueError(f'规则 {rid} 分值非法')
        if value < 0:
            raise ValueError(f'规则 {rid} 分值不能为负')
        deps_raw = r.get('dependencies') or []
        if not isinstance(deps_raw, list):
            raise ValueError(f'规则 {rid} 依赖必须是列表')
        deps = []
        for d in deps_raw:
            try:
                d = int(d)
            except (TypeError, ValueError):
                raise ValueError(f'规则 {rid} 依赖项非整数：{d!r}')
            if d == rid:
                raise ValueError(f'规则 {rid} 不能依赖自身')
            deps.append(d)
        out.append({'rule_id': rid, 'rule_text': text, 'value': value,
                    'dependencies': deps, 'ordering': idx})
    ids = {r['rule_id'] for r in out}
    for r in out:
        for d in r['dependencies']:
            if d not in ids:
                raise ValueError(f'规则 {r["rule_id"]} 依赖了不存在的规则 {d}')
    topo_order(out)  # 无环则成功，有环抛 ValueError
    return out


def topo_order(rules):
    """返回 rule_id 的拓扑序（依赖在前）。有环抛 ValueError。"""
    indeg = {r['rule_id']: 0 for r in rules}
    adj = {r['rule_id']: [] for r in rules}
    for r in rules:
        for d in r['dependencies']:
            adj[d].append(r['rule_id'])
            indeg[r['rule_id']] += 1
    queue = sorted([rid for rid, deg in indeg.items() if deg == 0])
    order = []
    while queue:
        rid = queue.pop(0)
        order.append(rid)
        for nxt in adj[rid]:
            indeg[nxt] -= 1
            if indeg[nxt] == 0:
                queue.append(nxt)
        queue.sort()
    if len(order) != len(rules):
        raise ValueError('规则依赖存在环')
    return order


def compute_results(rules, raw_by_id, finalize=False):
    """按依赖门槛裁决每条规则的 effective 与 score。
    rules: normalize_rules 的输出；raw_by_id: {rule_id: 'pass'|'failed'}（仅已上报的）。
    finalize=False（live）：未上报且依赖未失败 → pending；
    finalize=True（终态）：未上报 → error。"""
    by_id = {r['rule_id']: r for r in rules}
    results = {}
    for rid in topo_order(rules):
        rule = by_id[rid]
        dep_effs = [results.get(d, {}).get('effective') for d in rule['dependencies']]
        # 门槛：任一依赖 effective 已失败 → skipped（立即生效，不必等其它依赖）
        if any(e in _GATE_FAIL for e in dep_effs):
            results[rid] = {'effective': EFF_SKIPPED, 'score': 0.0}
            continue
        # 保守：仍有依赖处于 pending（结论未知）时，本规则也保持 pending，
        # 避免先判 pass、依赖后续失败再翻成 skipped 造成分数闪烁。
        if EFF_PENDING in dep_effs:
            results[rid] = {'effective': EFF_PENDING, 'score': 0.0}
            continue
        raw = raw_by_id.get(rid)
        if raw == RESULT_PASS:
            results[rid] = {'effective': EFF_PASS, 'score': float(rule['value'])}
        elif raw == RESULT_FAILED:
            results[rid] = {'effective': EFF_FAILED, 'score': 0.0}
        else:
            results[rid] = {'effective': EFF_ERROR if finalize else EFF_PENDING, 'score': 0.0}
    return results


def max_score(rules):
    return float(sum(float(r['value']) for r in rules))


def total_score(results):
    return float(sum(v.get('score', 0.0) for v in results.values()))


def parse_result_line(line):
    """解析 result.jsonl 的一行 → {'rule_id':int,'result':'pass'|'failed','evidence':str} 或 None。"""
    if not line or not isinstance(line, str):
        return None
    line = line.strip()
    if not line:
        return None
    try:
        obj = json.loads(line)
    except Exception:
        return None
    if not isinstance(obj, dict):
        return None
    try:
        rid = int(obj.get('rule_id'))
    except (TypeError, ValueError):
        return None
    result = str(obj.get('result') or '').strip().lower()
    if result not in _VALID_RAW:
        return None
    evidence = obj.get('evidence')
    evidence = '' if evidence is None else str(evidence)
    return {'rule_id': rid, 'result': result, 'evidence': evidence}


def build_rules_json(rules):
    """构造写入容器的 rules.json。"""
    return [{'rule_id': r['rule_id'], 'rule': r['rule_text'],
             'value': float(r['value']), 'dependence': list(r['dependencies'])}
            for r in rules]


def build_prompt(competition_title):
    """构造容器内 `claude -p` 的提示词（pass/failed 两态 + 依赖门槛 + report 上报）。"""
    title = str(competition_title or '').strip() or '本场打榜赛'
    return (
        f'这是打榜赛《{title}》中参赛者的提交。比赛描述见 description.md，'
        '附件见 attachment/ 目录，参赛者代码见 submission/ 目录。'
        '请帮我评测参赛者提交的代码，评分规则见 rules.json。\n\n'
        '如果参赛者使用了当前环境中没有的包，请用 apt、pip、npm 等方式把依赖安装好。\n\n'
        'rules.json 中有多条规则，每条有 rule_id、rule（描述）、value（分值）、'
        'dependence（前置规则的 rule_id 列表）。请逐条核对：根据规则描述检测并运行参赛者代码，'
        '判断是否满足规则要求。\n\n'
        '依赖门槛：对于一条评分规则，如果它的 dependence 里有任何一条前置规则不通过，'
        '那么这条规则的得分直接设为 0，result 记为 failed，并在 evidence 里注明'
        '"因前置规则未通过"。\n\n'
        '每评测完一条规则，就调用一次命令 report <rule_id> <pass|failed> "<evidence>"，'
        '把该条结果写入 result.jsonl。evidence 要写清楚你是如何运行参赛者代码、'
        '如何判断是否满足规则的，给出能让参赛者信服的证据。请对每一条规则都恰好 report 一次。'
    )
