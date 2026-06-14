#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""本地端到端测试：申诉功能（用真实 SQLite 引擎跑真实 SQL，不连 MySQL/不碰生产）。

与旧版「内存假 DB」最大的区别：这里**不再 monkeypatch 任何 DB 层函数**。
而是把 `get_db_connection` 换成一个 pymysql→SQLite 适配层（见 _Shim），让
`ensure_ranking_tables / ensure_agent_judge_tables / create_appeal /
get_appeal_by_submission / list_appeals / get_appeal_stats / resolve_appeal /
apply_rule_overrides / upsert_judge_result / update_submission_result /
get_user_by_username / get_competition / get_ranking_submission` 的**真实
SQL 真正在 SQLite 上执行**（CREATE TABLE / INSERT IGNORE / ON DUPLICATE KEY
UPDATE / LEFT JOIN / UNIQUE 约束 / 分页 / 迁移 ALTER 全部真跑）。

适配层做的最小翻译（仅覆盖本仓库 ranking 路径用到的 MySQL 方言）：
  - `%s` 占位符        → `?`
  - `INSERT IGNORE`    → `INSERT OR IGNORE`
  - `ON DUPLICATE KEY UPDATE col=VALUES(col)` → `ON CONFLICT(<唯一键>) DO UPDATE SET col=excluded.col`
  - `INT AUTO_INCREMENT PRIMARY KEY` → `INTEGER PRIMARY KEY AUTOINCREMENT`
  - 去掉 `ENGINE=InnoDB DEFAULT CHARSET=utf8mb4` / `ON UPDATE CURRENT_TIMESTAMP`
  - CREATE 里的 `INDEX ...` 子句丢弃；`UNIQUE KEY name (cols)` → `UNIQUE (cols)`
  - `ALTER TABLE ... ADD COLUMN a, ADD COLUMN b, ADD INDEX ...`（MySQL 多列/索引）
    拆成多条单列 `ALTER TABLE ... ADD COLUMN`，丢弃 `ADD INDEX`、去掉 `AFTER x`
  - `SHOW COLUMNS FROM t LIKE 'c'` → `PRAGMA table_info(t)` 过滤（驱动迁移分支）

注意：DATETIME/TIMESTAMP 列 SQLite 返回字符串、pymysql 返回 datetime 对象，
两者对申诉路由无影响（申诉路由从不对时间列做算术），故不覆盖配额窗口（涉及
`now - anchor` 时间运算）；配额来源（source）改动属另一条路径，本测试不混入。
"""
import os
import re
import sys
import json
import sqlite3
from datetime import datetime

sys.path.insert(0, '/Users/wenchong/code/NumericalOJ')
os.chdir('/Users/wenchong/code/NumericalOJ')

PASS, FAIL = 0, 0
def check(name, cond):
    global PASS, FAIL
    if cond:
        PASS += 1
        print(f"  PASS  {name}")
    else:
        FAIL += 1
        print(f"  FAIL  {name}")


# ============================================================
#  pymysql → SQLite 适配层
# ============================================================
def _split_top_level(s):
    """按括号深度为 0 的逗号切分（列定义里的 VARCHAR(16)/INDEX(a,b) 不被误切）。"""
    parts, depth, cur = [], 0, ''
    for ch in s:
        if ch == '(':
            depth += 1; cur += ch
        elif ch == ')':
            depth -= 1; cur += ch
        elif ch == ',' and depth == 0:
            parts.append(cur); cur = ''
        else:
            cur += ch
    if cur.strip():
        parts.append(cur)
    return parts


class _Shim:
    """记录建表时发现的唯一键，供 ON DUPLICATE KEY UPDATE 推断冲突目标。"""
    def __init__(self):
        self.unique = {}   # table -> [cols]  （来自 UNIQUE KEY 子句）
        self.pk = {}       # table -> [col]   （来自单列内联 PRIMARY KEY，非自增 id）

    def unique_for(self, table):
        return self.unique.get(table) or self.pk.get(table) or ['id']

    # ---- 文本级通用修补（去 ENGINE / ON UPDATE / INSERT IGNORE）----
    @staticmethod
    def _pre(sql):
        s = re.sub(r'\)\s*ENGINE=\w+(\s+DEFAULT\s+CHARSET=\w+)?', ')', sql, flags=re.I)
        s = re.sub(r'\bON\s+UPDATE\s+CURRENT_TIMESTAMP\b', '', s, flags=re.I)
        s = re.sub(r'\bINSERT\s+IGNORE\s+INTO\b', 'INSERT OR IGNORE INTO', s, flags=re.I)
        return s

    def translate_create(self, sql):
        s = self._pre(sql)
        m = re.match(r'\s*CREATE\s+TABLE\s+IF\s+NOT\s+EXISTS\s+(\w+)\s*\((.*)\)\s*;?\s*$',
                     s, re.I | re.S)
        if not m:
            return s  # 退化：原样（不应发生）
        table, inner = m.group(1), m.group(2)
        out = []
        for raw in _split_top_level(inner):
            c = raw.strip()
            cu = c.upper()
            if cu.startswith('INDEX ') or cu.startswith('KEY '):
                continue  # SQLite 不支持内联 INDEX
            mu = re.match(r'UNIQUE\s+KEY\s+\w+\s*\((.*)\)\s*$', c, re.I)
            if mu:
                cols = [x.strip() for x in mu.group(1).split(',')]
                self.unique[table] = cols
                out.append('UNIQUE (' + ', '.join(cols) + ')')
                continue
            # 列定义：自增主键 + 去掉残留 AUTO_INCREMENT
            c = re.sub(r'\bINT\s+AUTO_INCREMENT\s+PRIMARY\s+KEY\b',
                       'INTEGER PRIMARY KEY AUTOINCREMENT', c, flags=re.I)
            c = re.sub(r'\s+AUTO_INCREMENT\b', '', c, flags=re.I)
            # 单列内联 PRIMARY KEY（非自增）记为冲突目标候选
            mp = re.match(r'(\w+)\s+.*\bPRIMARY\s+KEY\b', c, re.I)
            if mp and 'AUTOINCREMENT' not in c.upper():
                self.pk[table] = [mp.group(1)]
            out.append(c)
        return 'CREATE TABLE IF NOT EXISTS %s (\n  %s\n)' % (table, ',\n  '.join(out))

    def translate_alter(self, sql):
        s = self._pre(sql)
        m = re.match(r'\s*ALTER\s+TABLE\s+(\w+)\s+(.*)$', s, re.I | re.S)
        table, rest = m.group(1), m.group(2)
        stmts = []
        for raw in _split_top_level(rest):
            p = raw.strip()
            pu = p.upper()
            if pu.startswith('ADD INDEX') or pu.startswith('ADD KEY') or pu.startswith('ADD UNIQUE'):
                continue  # SQLite ALTER 不支持加索引；测试无关
            if pu.startswith('ADD COLUMN'):
                coldef = p[len('ADD COLUMN'):].strip()
            elif pu.startswith('ADD'):
                coldef = p[len('ADD'):].strip()
            else:
                continue
            coldef = re.sub(r'\s+AFTER\s+\w+\s*$', '', coldef, flags=re.I)
            stmts.append('ALTER TABLE %s ADD COLUMN %s' % (table, coldef))
        return stmts

    def translate_upsert(self, sql):
        s = self._pre(sql)
        m = re.match(r'(\s*INSERT\s+INTO\s+(\w+).*?)\s+ON\s+DUPLICATE\s+KEY\s+UPDATE\s+(.*)$',
                     s, re.I | re.S)
        head, table, setpart = m.group(1), m.group(2), m.group(3)
        setpart = re.sub(r'VALUES\s*\(\s*(\w+)\s*\)', r'excluded.\1', setpart, flags=re.I)
        cols = self.unique_for(table)
        target = '(' + ', '.join(cols) + ')'
        return '%s ON CONFLICT%s DO UPDATE SET %s' % (head, target, setpart)


class _FakeCursor:
    def __init__(self, raw, shim):
        self._raw = raw
        self._shim = shim
        self._rows = None  # 非 None 时表示 SHOW COLUMNS 的拦截结果

    @property
    def lastrowid(self):
        return self._raw.lastrowid

    @property
    def rowcount(self):
        return self._raw.rowcount

    def execute(self, sql, params=None):
        self._rows = None
        stmt = sql.strip()
        up = stmt.upper()

        m = re.match(r"SHOW\s+COLUMNS\s+FROM\s+(\w+)\s+LIKE\s+'([^']+)'", stmt, re.I)
        if m:
            table, col = m.group(1), m.group(2)
            self._raw.execute("PRAGMA table_info(%s)" % table)
            cols = [dict(r) for r in self._raw.fetchall()]
            self._rows = [cc for cc in cols if cc.get('name') == col]
            return

        if up.startswith('CREATE TABLE'):
            self._raw.execute(self._shim.translate_create(stmt))
            return
        if up.startswith('ALTER TABLE'):
            for s in self._shim.translate_alter(stmt):
                self._raw.execute(s)
            return
        if 'ON DUPLICATE KEY UPDATE' in up:
            tsql = self._shim.translate_upsert(stmt)
        else:
            tsql = self._shim._pre(stmt)
        tsql = tsql.replace('%s', '?')
        self._raw.execute(tsql, tuple(params) if params else ())

    def fetchone(self):
        if self._rows is not None:
            return self._rows.pop(0) if self._rows else None
        row = self._raw.fetchone()
        return dict(row) if row is not None else None

    def fetchall(self):
        if self._rows is not None:
            rows, self._rows = self._rows, []
            return rows
        return [dict(r) for r in self._raw.fetchall()]

    def close(self):
        try:
            self._raw.close()
        except Exception:
            pass

    def __enter__(self):
        return self

    def __exit__(self, *a):
        self.close()


class _FakeConn:
    """对外表现得像 pymysql 连接；close() 不真正关闭共享的 SQLite 连接。"""
    def __init__(self, sqlite_conn, shim):
        self._c = sqlite_conn
        self._shim = shim

    def cursor(self):
        return _FakeCursor(self._c.cursor(), self._shim)

    def commit(self):
        self._c.commit()

    def rollback(self):
        self._c.rollback()

    def ping(self, reconnect=True):
        pass

    def close(self):
        pass  # 共享连接，整轮测试存活

    def __enter__(self):
        return self

    def __exit__(self, *a):
        pass


# ---- 建立共享 SQLite 连接 + 安装适配层 ----
sqlite3.register_adapter(datetime, lambda dt: dt.strftime('%Y-%m-%d %H:%M:%S'))
_SHIM = _Shim()
_SQLITE = sqlite3.connect(':memory:', check_same_thread=False)
_SQLITE.row_factory = sqlite3.Row
_SQLITE.create_function('CURDATE', 0, lambda: datetime.now().strftime('%Y-%m-%d'))


def _get_conn():
    return _FakeConn(_SQLITE, _SHIM)


import oj_modules.db_services as DBS
import oj_modules.ranking_db as RDB
import oj_modules.ranking_agent_judge_db as AJDB
import oj_modules.ranking_agent_judge as AJ
import oj_modules.routes.ranking_routes as R

# 把三个模块各自持有的 get_db_connection 引用都换成 SQLite 适配层
DBS.get_db_connection = _get_conn
RDB.get_db_connection = _get_conn
AJDB.get_db_connection = _get_conn


# ============================================================
#  种子数据（真 SQL 建表 + 直插 SQLite）
# ============================================================
def _seed_raw(sql, params=()):
    cur = _SQLITE.cursor()
    cur.execute(sql, params)
    _SQLITE.commit()


# 真跑迁移建表（CREATE/ALTER/UNIQUE 全部经适配层落到 SQLite）
RDB._ranking_tables_ready = False
AJDB._aj_tables_ready = False
RDB.ensure_ranking_tables()
AJDB.ensure_agent_judge_tables()

# users 表（auth 用，本路径无懒建）
_seed_raw("CREATE TABLE IF NOT EXISTS users ("
          " id INTEGER PRIMARY KEY AUTOINCREMENT, username TEXT UNIQUE, is_admin INTEGER NOT NULL DEFAULT 0)")
_seed_raw("INSERT INTO users (username, is_admin) VALUES ('stud', 0), ('admin', 1)")

# 比赛（agent_judge 模式）
_seed_raw("INSERT INTO ranking_competitions"
          " (id, title, summary, description, answer_format, scoring_mode, max_score, is_active, submission_method, created_at)"
          " VALUES (7, 'T', 's', 'D', 'json', 'agent_judge', 110, 1, 'git', '2026-06-14 09:00:00')")

# 提交（已判完，50 分；rule1 pass(50)/rule2 failed(0)）
def _seed_submission():
    _seed_raw("DELETE FROM ranking_submissions WHERE id = 2061")
    _seed_raw("INSERT INTO ranking_submissions"
              " (id, competition_id, username, status, score, grade_details, base_model, source, created_at)"
              " VALUES (2061, 7, 'stud', 'Accepted', 50.0, ?, 'm', 'self', '2026-06-14 10:00:00')",
              (json.dumps({'timed_out': False}),))

def _seed_rules():
    _seed_raw("DELETE FROM ranking_judge_rules WHERE competition_id = 7")
    _seed_raw("INSERT INTO ranking_judge_rules (competition_id, rule_id, rule_text, value, dependencies, ordering)"
              " VALUES (7,1,'r1',50.0,'[]',1),(7,2,'r2',60.0,'[]',2)")

def _seed_results():
    _seed_raw("DELETE FROM ranking_judge_results WHERE submission_id = 2061")
    _seed_raw("INSERT INTO ranking_judge_results (submission_id, rule_id, raw_result, effective_result, score, evidence)"
              " VALUES (2061,1,'pass','pass',50.0,'e1'),(2061,2,'failed','failed',0.0,'e2')")

_seed_submission()
_seed_rules()
_seed_results()


# ============================================================
#  A) apply_rule_overrides —— 真实 SQL 计分逻辑
# ============================================================
print("== A) apply_rule_overrides 计分逻辑（真 SQL）==")
total, maxs, payloads = R.apply_rule_overrides(2061, {1: 'failed', 2: 'pass'})
check("rule1 pass->failed 得 0 分", any(p['rule_id'] == 1 and p['effective'] == 'failed' and p['score'] == 0 for p in payloads))
check("rule2 failed->pass 得满分 60", any(p['rule_id'] == 2 and p['effective'] == 'pass' and p['score'] == 60 for p in payloads))
check("总分=60", total == 60.0)
check("满分=110", maxs == 110.0)
# 直接回查 SQLite 确认结果真的写进了 ranking_judge_results
_back = {int(r['rule_id']): r for r in AJDB.list_judge_results(2061)}
check("SQL 落库：rule2 effective=pass、score=60", _back[2]['effective_result'] == 'pass' and float(_back[2]['score']) == 60.0)
check("SQL 落库：rule1 effective=failed、score=0", _back[1]['effective_result'] == 'failed' and float(_back[1]['score']) == 0.0)
# 复位，供路由测试从干净态开始
_seed_results()
_seed_submission()


# ============================================================
#  B) 路由端到端（申诉生命周期，真 SQL）
# ============================================================
print("== B) 路由端到端（申诉生命周期，真 SQL）==")
from flask import Flask
app = Flask(__name__, template_folder=os.path.abspath('templates'))
app.secret_key = 'test'
app.register_blueprint(R.ranking_bp)
c = app.test_client()

def login(name):
    with c.session_transaction() as s:
        s['username'] = name

# 1) 学生查状态：无申诉
login('stud')
r = c.get('/ranking/7/submission/2061/appeal_status')
d = r.get_json()
check("初始 appeal_status has_appeal=false", r.status_code == 200 and d.get('ok') and d.get('has_appeal') is False)

# 2) 学生发起申诉（真 INSERT IGNORE 落库）
r = c.post('/ranking/7/submission/2061/appeal', data={'reason': '规则2我已实现，请复核'})
d = r.get_json()
check("发起申诉 ok + pending", r.status_code == 200 and d.get('ok') and d.get('status') == 'pending')

# 3) 再次申诉 → 一次性拦截（路由层 get_appeal_by_submission 命中）
r = c.post('/ranking/7/submission/2061/appeal', data={'reason': '再申诉一次'})
d = r.get_json()
check("重复申诉被拦(409 already)", r.status_code == 409 and d.get('already') is True)

# 3b) DB 级一次性：直接再 INSERT IGNORE 应返回 0（UNIQUE(submission_id) 真的生效）
check("DB 级一次性：create_appeal 重复返回 0", R.create_appeal(7, 2061, 'stud', 'x') == 0)

# 4) 学生查状态：pending + 理由
r = c.get('/ranking/7/submission/2061/appeal_status')
d = r.get_json()
check("状态=pending 且回显理由", d.get('has_appeal') and d.get('status') == 'pending' and '规则2' in (d.get('reason') or ''))

a_row = R.get_appeal_by_submission(2061)
aid = a_row['id']

# 5) 管理员可查
login('admin')
r = c.get('/ranking/7/submission/2061/appeal_status')
check("管理员可查状态", r.get_json().get('has_appeal'))

# 6) 管理员申诉列表 JSON（真 LEFT JOIN + 渲染 _ranking_appeal_rows）
r = c.get('/ranking/7/appeals_json')
d = r.get_json()
rows = d.get('rows_html', '')
check("appeals_json 渲染含提交号 #2061", '2061' in rows)
check("appeals_json 渲染含状态『待处理』", '待处理' in rows)
check("appeals_json 渲染含申诉理由片段", '规则2' in rows)

# 7) 管理员处理：改规则状态 + 回复 + resolved（这步把覆盖写进 ranking_judge_results）
r = c.post('/ranking/7/appeal/%d/handle' % aid,
           json={'decision': 'resolved', 'admin_response': '已复核，规则2确实通过',
                 'overrides': {'1': 'failed', '2': 'pass'}})
d = r.get_json()
check("handle ok + 返回 redirect", r.status_code == 200 and d.get('ok') and 'appeals' in d.get('redirect', ''))
# 回查 SQLite
sub_after = R.get_ranking_submission(2061)
check("提交分数已更新为 60", float(sub_after['score']) == 60.0)
res_after = {int(x['rule_id']): x for x in AJDB.list_judge_results(2061)}
check("rule1 被改为 failed(0)", res_after[1]['effective_result'] == 'failed' and float(res_after[1]['score']) == 0.0)
check("rule2 被改为 pass(60)", res_after[2]['effective_result'] == 'pass' and float(res_after[2]['score']) == 60.0)
ap_after = R.get_appeal(aid)
check("申诉状态=resolved + 回复入库", ap_after['status'] == 'resolved' and ap_after['admin_response'] == '已复核，规则2确实通过')

# 8) 学生回看：已处理 + 管理员回复
login('stud')
r = c.get('/ranking/7/submission/2061/appeal_status')
d = r.get_json()
check("学生看到 status_label=已处理", d.get('status_label') == '已处理')
check("学生看到管理员回复", '已复核' in (d.get('admin_response') or ''))

# 9) 处理后仍不能再申诉（终态锁定）
r = c.post('/ranking/7/submission/2061/appeal', data={'reason': '我还想再申诉'})
check("终态后再申诉仍被拦(409)", r.status_code == 409)

# 10) 申诉统计（真 SUM(CASE WHEN ...)）
stats = R.get_appeal_stats(7)
check("get_appeal_stats: total=1 resolved=1 pending=0", stats == {'total': 1, 'pending': 0, 'rejected': 0, 'resolved': 1})


# ============================================================
#  C) 新模板渲染（带真实数据；模板无需 DB）
# ============================================================
print("== C) 新模板渲染（带真实数据）==")
import jinja2
def fake_url_for(ep, **kw):
    return '/' + ep.replace('.', '/') + '/' + '/'.join(str(v) for v in kw.values())
env = jinja2.Environment(loader=jinja2.ChoiceLoader([
    jinja2.DictLoader({'layout.html': '{% block title %}{% endblock %}{% block content %}{% endblock %}'}),
    jinja2.FileSystemLoader(os.path.abspath('templates')),
]), autoescape=True)
env.globals['url_for'] = fake_url_for
snapshot = {'total_score': 50.0, 'max_score': 110.0, 'status': 'Accepted', 'timed_out': False,
            'rules': [{'rule_id': 1, 'value': 50.0, 'effective': 'pass', 'score': 50.0, 'rule_text': 'r1', 'rule_html': '<p>r1</p>', 'evidence': 'e1', 'evidence_html': '<p>e1</p>'},
                      {'rule_id': 2, 'value': 60.0, 'effective': 'failed', 'score': 0.0, 'rule_text': 'r2', 'rule_html': '<p>r2</p>', 'evidence': 'e2', 'evidence_html': '<p>e2</p>'}]}
appeal_obj = {'id': 101, 'submission_id': 2061, 'username': 'stud', 'reason': '规则2我已实现',
              'status': 'pending', 'admin_response': None, 'admin_username': None, 'created_at': '2026-06-14 11:00:00'}
comp_obj = {'id': 7, 'title': 'T', 'description': 'D', 'scoring_mode': 'agent_judge', 'max_score': 110}
sub_obj = R.get_ranking_submission(2061)
try:
    html = env.get_template('ranking_appeal_review.html').render(
        snapshot=snapshot, appeal=appeal_obj, submission=sub_obj, competition=comp_obj,
        user={'username': 'admin', 'is_admin': 1}, is_admin=True)
    check("审阅页渲染含『用户申诉意见』", '用户申诉意见' in html)
    check("审阅页含可点击状态(ap-rule-status)", 'ap-rule-status' in html)
    check("审阅页含驳回/处理按钮", '驳回' in html and '处理' in html and 'apReject' in html and 'apResolve' in html)
    check("审阅页含重测", '重测' in html)
    check("审阅页含申诉理由原文", '规则2我已实现' in html)
except Exception as e:
    check("审阅页渲染无异常", False); print("    ERR:", repr(e))

try:
    rows = env.get_template('_ranking_appeal_rows.html').render(
        all_appeals=[dict(appeal_obj, sub_score=50.0, sub_status='Accepted', base_model='m')], competition=comp_obj)
    check("申诉列表片段渲染含提交号", '2061' in rows and '待处理' in rows)
except Exception as e:
    check("申诉列表片段渲染无异常", False); print("    ERR:", repr(e))

print("\n==== 结果：%d passed, %d failed ====" % (PASS, FAIL))
sys.exit(1 if FAIL else 0)
