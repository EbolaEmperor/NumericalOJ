#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
sketcher 打榜赛 · ELO 评分脚本

调用方式（ELO 模式约定）：
    python <script> <submission_a.zip> <submission_b.zip>
stdout 输出一行 JSON：
    {"winner": 0 | 1 | 2,
     "details": {"format": "text", "content": "<评测详情文本>"}}
其中 winner=0 表示平局（最终统计后双方实力相当）。

评分逻辑：
  1. 解压两份提交的作品 zip 到独立临时目录，只读取 summaries/
     目录下直接包含的 .tex 文件，并按 basename 建立索引。
  2. 以服务器附件目录 ~/oj/static/articles/ 中的 .pdf 列表作为评判论文集；
     该目录不存在时退化为两份提交里 .tex 文件名的并集。
  3. 三篇论文并发处理（3 线程），对每篇论文：
       - 先用 xelatex 本地试编译两份 .tex（-interaction=nonstopmode -halt-on-error），
         编译失败的提交在该篇上视为 "未提交"。
       - 双方都编译通过：为了消除大模型的位置偏好，调用 LLM 比较两次——一次以
         (A, B) 顺序、一次以 (B, A) 顺序，结果一致才采纳该结果；两次不一致则
         该篇判为平局（不给任何一方加胜局）。
       - 只有一方编译通过：另一方失分。
       - 双方都失败/缺失：跳过该篇。
  4. 多数胜局者胜出；wins_a == wins_b 时按 (编译成功篇数 → tex 总字数) 打破平局；
     若全部维度都打平，最终返回 winner=0（真正的平局）。

注：LaTeX 排版的 "可编译性" 已经由 xelatex 实际编译来 gate，因此 LLM 评分维度不再
包含排版项；prompt 里也明确告知 LLM 仅评估内容。
"""

import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import zipfile
from concurrent.futures import ThreadPoolExecutor

# 让脚本能 import 到 NumericalOJ 项目根目录下的 config.py
_OJ_ROOT = os.environ.get('OJ_ROOT_PATH', '/home/ebola/oj')
if _OJ_ROOT not in sys.path:
    sys.path.insert(0, _OJ_ROOT)

DASHSCOPE_API_KEY = "<DASHSCOPE_API_KEY>"
DASHSCOPE_BASE_URL = "https://token-plan-cn.xiaomimimo.com/v1"

ARTICLES_DIR = os.path.join(_OJ_ROOT, 'static', 'articles')
MODEL = 'mimo-v2.5-pro'
PER_TEX_CHAR_LIMIT = 16000          # 单份 .tex 截断长度，控制 token 用量
PAPER_REF_CHAR_LIMIT = 200000       # 原文（.tex 优先 / .txt 兜底）截断长度，仅作 OOM 兜底，
                                    # 当前三篇都 < 45K 字符可全文进 prompt
COMPARE_TEMPERATURE = 0.0
PER_CALL_TIMEOUT_SECONDS = 60
XELATEX_TIMEOUT_SECONDS = 60        # 单次 xelatex 编译上限
PAPER_CONCURRENCY = 3               # 并发处理的论文数（每篇内部 2 次 LLM 调用串行）
SUMMARIES_DIR_NAME = 'summaries'


# ---------- 文件层 ----------

def _list_paper_basenames():
    """读取 articles 目录里所有 PDF 文件名（去 .pdf 后缀）。"""
    if not os.path.isdir(ARTICLES_DIR):
        return []
    bases = []
    for fn in os.listdir(ARTICLES_DIR):
        if fn.lower().endswith('.pdf'):
            bases.append(os.path.splitext(fn)[0])
    return sorted(bases)


def _extract_zip(zip_path, extract_root):
    """把 zip_path 解压到 extract_root 下；成功返回 True，否则 False。"""
    if not (zip_path and os.path.isfile(zip_path)):
        return False
    try:
        with zipfile.ZipFile(zip_path) as zf:
            zf.extractall(extract_root)
        return True
    except (zipfile.BadZipFile, RuntimeError):
        return False
    except Exception:
        return False


def _find_tex_paths(extract_root):
    """返回 summaries/ 直接包含的 ``basename -> .tex 绝对路径``。"""
    found = {}
    summaries_dir = os.path.join(extract_root, SUMMARIES_DIR_NAME)
    if not os.path.isdir(summaries_dir):
        return found
    for fn in sorted(os.listdir(summaries_dir)):
        path = os.path.join(summaries_dir, fn)
        if os.path.isfile(path) and fn.lower().endswith('.tex'):
            found[os.path.splitext(fn)[0]] = path
    return found


def _read_text(path, limit_chars):
    try:
        with open(path, 'r', encoding='utf-8', errors='ignore') as f:
            return f.read()[:limit_chars]
    except Exception:
        return ''


def _load_paper_reference(basename):
    """读取与论文同 basename 的原文事实底，按以下优先级：
       1. <ARTICLES_DIR>/<basename>.tex —— 人工/AI 转写的 LaTeX，公式更完整；
       2. <ARTICLES_DIR>/<basename>.txt —— pdftotext 抽出的纯文本（兜底）。
    都缺失时返回空串（不致命，仍能比较，只是 LLM 没有事实底）。"""
    if not basename:
        return ''
    tex_path = os.path.join(ARTICLES_DIR, basename + '.tex')
    if os.path.isfile(tex_path):
        return _read_text(tex_path, PAPER_REF_CHAR_LIMIT)
    txt_path = os.path.join(ARTICLES_DIR, basename + '.txt')
    return _read_text(txt_path, PAPER_REF_CHAR_LIMIT)


# ---------- xelatex 编译 gate ----------

def _compile_xelatex(tex_path):
    """尝试用 xelatex 编译 tex_path（在文件所在目录运行，aux 写入临时输出目录）。
    返回 (ok: bool, reason: str)；reason 只在失败时填充到最终详情文本。"""
    if not (tex_path and os.path.isfile(tex_path)):
        return False, 'no such file'
    src_dir = os.path.dirname(tex_path)
    src_name = os.path.basename(tex_path)
    out_dir = tempfile.mkdtemp(prefix='xetex_out_')
    try:
        try:
            proc = subprocess.run(
                [
                    'xelatex',
                    '-interaction=nonstopmode',
                    '-halt-on-error',
                    f'-output-directory={out_dir}',
                    src_name,
                ],
                cwd=src_dir,
                capture_output=True,
                text=True,
                timeout=XELATEX_TIMEOUT_SECONDS,
            )
        except subprocess.TimeoutExpired:
            return False, 'xelatex timeout'
        except FileNotFoundError:
            return False, 'xelatex not installed'
        if proc.returncode == 0:
            return True, ''
        # 截一点尾巴帮调试
        tail = ((proc.stdout or '') + (proc.stderr or ''))[-500:]
        return False, f'xelatex exit {proc.returncode}: {tail}'
    finally:
        shutil.rmtree(out_dir, ignore_errors=True)


# ---------- LLM 比较 ----------

def _build_client():
    from openai import OpenAI
    return OpenAI(
        api_key=DASHSCOPE_API_KEY,
        base_url=DASHSCOPE_BASE_URL,
        timeout=PER_CALL_TIMEOUT_SECONDS,
    )


def _extract_json_object(text):
    """从一段可能含有 markdown 代码块/前后噪声的 LLM 回复中抽出第一个能 json.loads 的对象。"""
    if not text:
        return None
    # 先去 markdown 围栏
    cleaned = re.sub(r'```(?:json)?\s*', '', text)
    cleaned = cleaned.replace('```', '')
    cleaned = cleaned.strip()
    # 直接试整段
    try:
        obj = json.loads(cleaned)
        if isinstance(obj, dict):
            return obj
    except (ValueError, TypeError):
        pass
    # 退化：从第一个 '{' 起，逐步缩短 end 直到能解析成功
    start = cleaned.find('{')
    if start < 0:
        return None
    end = cleaned.rfind('}')
    while end > start:
        try:
            obj = json.loads(cleaned[start:end + 1])
            if isinstance(obj, dict):
                return obj
        except (ValueError, TypeError):
            pass
        end = cleaned.rfind('}', start, end)
    return None


def _compare_pair(client, paper_basename, tex_a, tex_b, paper_reference=''):
    """返回 (winner, reason)。winner ∈ {0,1,2}（0 表示无法判断/调用失败），
    reason 为大模型给出的判断理由文字（成功时来自模型，失败时是诊断信息）。

    paper_reference 是论文原文的纯文本（由 pdftotext 抽出后截断）；可选，
    缺失时 LLM 只能凭两份解读的内部一致性判断，准确性会下降。"""
    a_clip = (tex_a or '')[:PER_TEX_CHAR_LIMIT]
    b_clip = (tex_b or '')[:PER_TEX_CHAR_LIMIT]
    ref_clip = (paper_reference or '')[:PAPER_REF_CHAR_LIMIT]

    if ref_clip:
        ref_section = (
            "下面是原论文的 latex 源码，出于篇幅考虑，只给出正文与定理表述，详细的证明已经被隐藏。"
            f"----- 论文原文（节选）-----\n{ref_clip}\n\n"
        )
        ref_hint = "并对照原文核查事实是否准确（如：研究方向、关键假设、定理结论是否被忠实复述）。"
    else:
        ref_section = ""
        ref_hint = "（本场未提供论文原文文本，请仅根据两份解读自身的清晰度与一致性判断。）"

    prompt = (
        f"你是数学论文阅读专家。请评判两份针对同一篇论文 \"{paper_basename}.pdf\" 的中文 LaTeX 解读，"
        "分别命名为 A 和 B。\n\n"
        f"{ref_section}"
        f"评判维度（仅就内容；{ref_hint}）：\n"
        "1. 论文背景介绍是否清晰、动机阐述是否到位\n"
        "2. 问题模型与符号说明是否准确、完整、与原文一致\n"
        "3. 主要结论是否抓住核心要点、不歪曲不遗漏关键定理\n"
        "4. 中文表达是否通顺、易懂\n\n"
        "请只输出一段 JSON：{\"winner\": 1, \"reason\": \"<判断理由，请用中文，简洁，约 80–200 字>\"} "
        "或 {\"winner\": 2, \"reason\": \"...\"}。"
        "1 表示 A 整体更优，2 表示 B 整体更优；JSON 之外不要输出其他文字。\n\n"
        f"----- A -----\n{a_clip}\n"
        f"----- B -----\n{b_clip}\n"
    )
    try:
        resp = client.chat.completions.create(
            model=MODEL,
            messages=[{'role': 'user', 'content': prompt}],
            temperature=COMPARE_TEMPERATURE,
        )
        text = (resp.choices[0].message.content or '').strip()
    except Exception as e:
        return 0, f'API error: {e}'

    obj = _extract_json_object(text)
    if not obj:
        return 0, f'no JSON in response: {text[:200]}'
    raw_winner = obj.get('winner')
    try:
        winner = int(raw_winner)
    except (TypeError, ValueError):
        return 0, f'invalid winner field: {raw_winner!r}'
    if winner not in (1, 2):
        return 0, f'winner not 1/2: {winner}'
    reason = str(obj.get('reason') or '').strip()
    return winner, reason


# ---------- 主流程 ----------

def _decide(wins_a, wins_b, compiled_a, compiled_b, size_a, size_b):
    """聚合三篇论文的胜负，返回 winner ∈ {0, 1, 2}。
    0 表示真正的平局（胜局数、编译篇数、tex 字数三个维度全部相等）。"""
    if wins_a > wins_b:
        return 1
    if wins_b > wins_a:
        return 2
    if compiled_a > compiled_b:
        return 1
    if compiled_b > compiled_a:
        return 2
    if size_a > size_b:
        return 1
    if size_b > size_a:
        return 2
    return 0  # 全维度相等，真平局


def _reconcile_swapped(w_forward, w_swapped):
    """把"正向 (A,B)"和"反向 (B,A)"两次 LLM 比较的结果对齐到正向坐标，
    返回 (final_winner, agreement)：
      - final_winner ∈ {0, 1, 2}；0 表示无法判定（位置偏好或双调用都失败）。
      - agreement ∈ {'agree', 'disagree', 'forward_only', 'swapped_only', 'both_failed'}。
    反向调用里 winner=1 表示"反向位的 A 胜"= 原 B 胜，故映射 1->2, 2->1, 0->0。"""
    flip = {1: 2, 2: 1, 0: 0}
    w_swapped_norm = flip[int(w_swapped)] if int(w_swapped) in flip else 0
    f = int(w_forward)
    s = w_swapped_norm
    if f == 0 and s == 0:
        return 0, 'both_failed'
    if f == 0:
        # 正向调用失败，反向有结果 —— 单调用不足以排除位置偏好，仍判平局，
        # 但记 swapped_only 便于排查。
        return 0, 'swapped_only'
    if s == 0:
        return 0, 'forward_only'
    if f == s:
        return f, 'agree'
    return 0, 'disagree'


def _judge_paper(client, base, tex_a_paths, tex_b_paths):
    """单篇论文的完整评判流程：编译 → （双向 LLM 比较）→ 返回结果 dict。
    在 ThreadPoolExecutor 里并发调用，每篇内部的两次 LLM 调用仍是串行。

    返回 dict 字段：
      paper, winner (0/1/2), ok_a, ok_b,
      size_a, size_b,           # tex 总字数（用于打破最终平局）
      detail: per-paper 在最终详情文本中展示的子对象。"""
    path_a = tex_a_paths.get(base)
    path_b = tex_b_paths.get(base)

    ok_a, reason_a = (False, 'missing')
    ok_b, reason_b = (False, 'missing')
    if path_a:
        ok_a, reason_a = _compile_xelatex(path_a)
    if path_b:
        ok_b, reason_b = _compile_xelatex(path_b)

    size_a = 0
    size_b = 0

    if ok_a and ok_b:
        content_a = _read_text(path_a, PER_TEX_CHAR_LIMIT)
        content_b = _read_text(path_b, PER_TEX_CHAR_LIMIT)
        size_a = len(content_a)
        size_b = len(content_b)
        paper_ref = _load_paper_reference(base)
        # 双向比对：先 (A, B)，再 (B, A)；两次结果对齐后一致才采纳。
        w1, reason1 = _compare_pair(client, base, content_a, content_b, paper_reference=paper_ref)
        w2, reason2 = _compare_pair(client, base, content_b, content_a, paper_reference=paper_ref)
        final_w, agreement = _reconcile_swapped(w1, w2)
        return {
            'paper': base,
            'winner': final_w,
            'ok_a': ok_a, 'ok_b': ok_b,
            'size_a': size_a, 'size_b': size_b,
            'detail': {
                'paper': base, 'winner': final_w, 'compile': 'AB ok',
                'agreement': agreement,
                'forward_winner': int(w1), 'forward_reason': reason1,
                'swapped_winner_raw': int(w2),   # 原始反向调用 winner，未对齐
                'swapped_reason': reason2,
                'paper_ref_chars': len(paper_ref),
            },
        }
    if ok_a:
        return {
            'paper': base, 'winner': 1,
            'ok_a': ok_a, 'ok_b': ok_b,
            'size_a': size_a, 'size_b': size_b,
            'detail': {
                'paper': base, 'winner': 1,
                'note': 'B unusable',
                'b_reason': reason_b,
            },
        }
    if ok_b:
        return {
            'paper': base, 'winner': 2,
            'ok_a': ok_a, 'ok_b': ok_b,
            'size_a': size_a, 'size_b': size_b,
            'detail': {
                'paper': base, 'winner': 2,
                'note': 'A unusable',
                'a_reason': reason_a,
            },
        }
    return {
        'paper': base, 'winner': 0,
        'ok_a': ok_a, 'ok_b': ok_b,
        'size_a': size_a, 'size_b': size_b,
        'detail': {
            'paper': base, 'winner': 0,
            'note': 'both unusable',
            'a_reason': reason_a,
            'b_reason': reason_b,
        },
    }


def main():
    if len(sys.argv) < 3:
        print(json.dumps({
            'winner': 1,
            'details': {
                'format': 'text',
                'content': '评分脚本参数不足：需要 submission_a 和 submission_b',
            },
        }, ensure_ascii=False))
        return

    submission_a, submission_b = sys.argv[1], sys.argv[2]

    extract_a = tempfile.mkdtemp(prefix='sketcher_a_')
    extract_b = tempfile.mkdtemp(prefix='sketcher_b_')
    try:
        ok_extract_a = _extract_zip(submission_a, extract_a)
        ok_extract_b = _extract_zip(submission_b, extract_b)

        tex_a_paths = _find_tex_paths(extract_a) if ok_extract_a else {}
        tex_b_paths = _find_tex_paths(extract_b) if ok_extract_b else {}

        paper_bases = _list_paper_basenames()
        articles_dir_used = bool(paper_bases)
        if not paper_bases:
            paper_bases = sorted(set(tex_a_paths.keys()) | set(tex_b_paths.keys()))

        client = _build_client()

        wins_a = 0
        wins_b = 0
        draws = 0
        compiled_a = 0
        compiled_b = 0
        size_a = 0
        size_b = 0

        # 三篇论文并发评判（每篇内部串行做两次 LLM 调用以消除位置偏好）。
        # 用 paper_bases 的次序回排结果，保证详情中的 per_paper 顺序稳定。
        with ThreadPoolExecutor(max_workers=PAPER_CONCURRENCY) as pool:
            results = list(pool.map(
                lambda base: _judge_paper(client, base, tex_a_paths, tex_b_paths),
                paper_bases,
            ))

        per_paper = []
        for r in results:
            per_paper.append(r['detail'])
            if r['ok_a']:
                compiled_a += 1
            if r['ok_b']:
                compiled_b += 1
            size_a += r['size_a']
            size_b += r['size_b']
            w = r['winner']
            if w == 1:
                wins_a += 1
            elif w == 2:
                wins_b += 1
            else:
                draws += 1

        winner = _decide(wins_a, wins_b, compiled_a, compiled_b, size_a, size_b)

        detail_data = {
            'model': MODEL,
            'articles_dir_used': articles_dir_used,
            'wins_a': wins_a,
            'wins_b': wins_b,
            'draws': draws,
            'compiled_a': compiled_a,
            'compiled_b': compiled_b,
            'tex_a_total_chars': size_a,
            'tex_b_total_chars': size_b,
            'per_paper': per_paper,
        }
        print(json.dumps({
            'winner': winner,
            'details': {
                'format': 'text',
                'content': json.dumps(detail_data, ensure_ascii=False, indent=2),
            },
        }, ensure_ascii=False))
    finally:
        shutil.rmtree(extract_a, ignore_errors=True)
        shutil.rmtree(extract_b, ignore_errors=True)


if __name__ == '__main__':
    main()
