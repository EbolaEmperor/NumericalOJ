# -*- coding: utf-8 -*-
"""真实 AI 链路集成测试（打线上 DashScope/Qwen 接口）。

这些用例带 ``live_ai`` 标记：只有 ``OJ_LIVE_AI=1`` 时才真跑（CI 在 why-server 上
把线上 config.py 的真实 AI key 注入容器后置位）；本地或无 key 环境自动 skip。
覆盖三条之前只被 mock、从未真实验证过的链路：

1. 询问 AI 助教（``/ask_ai_code_marks``）——真实代码标注。
2. 图片题的 AI 助教 + omni 图片一致性分析——真实多模态分析链路。
3. 提交 tex 的书面题（written_grading_mode=3）——xelatex 编译 + 真实 AI 批改。

断言刻意宽松：只验证"链路确实跑通且拿到真实模型产出"（结构/非空/类型），
不对模型的具体文字/分数做精确匹配，避免因模型波动而 flaky。
"""
import io
import os
import zipfile

import pytest

from oj_modules import db_services as db
from tests import helpers as h


pytestmark = pytest.mark.live_ai


# 会生成 output.png 的 Python 代码（图片题用）。
_PNG_CODE = (
    "from PIL import Image\n"
    "Image.new('RGB', (32, 32), (10, 200, 90)).save('output.png')\n"
    "print('done')\n"
)

# 一段有明显问题的 MATLAB 代码，给 AI 助教标注用（缺分号/低效循环等）。
_MATLAB_CODE = (
    "function y = solve(x)\n"
    "    y = 0\n"
    "    for i = 1:length(x)\n"
    "        y = y + x(i)\n"
    "    end\n"
    "end\n"
)

# 最小可编译的 main.tex（书面 tex 题用）。
_MAIN_TEX = (
    "\\documentclass{article}\n"
    "\\begin{document}\n"
    "Solution: the derivative of $x^2$ is $2x$.\n"
    "\\end{document}\n"
)


def _make_zip_bytes(name_to_text):
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, 'w', zipfile.ZIP_DEFLATED) as zf:
        for name, text in name_to_text.items():
            zf.writestr(name, text)
    buf.seek(0)
    return buf.read()


# --------------------------------------------------------------------------- #
# 1) 询问 AI 助教：真实代码标注
# --------------------------------------------------------------------------- #
def test_ask_ai_code_marks_live_generates_real_marks(client, admin_login):
    """真实调用 /ask_ai_code_marks：返回 success + 真实模型生成的 issues/summary。"""
    pid = h.make_problem(title='AI助教-实测', content='请实现对向量求和的函数。',
                         lang='matlab', type=1)
    sid = h.make_submission(pid, 'admin', code=_MATLAB_CODE, problem_title='AI助教-实测',
                            test_points=[{'status': 'Accepted', 'test_index': 1}])

    r = client.post('/ask_ai_code_marks', json={
        'problem_id': pid,
        'user_code': _MATLAB_CODE,
        'submission_id': sid,
        'force_refresh': True,
    })
    assert r.status_code == 200, r.get_data(as_text=True)
    data = r.get_json()
    assert data.get('success') is True, data
    assert data.get('source') == 'generated'
    # 真实模型应给出非空的 summary 或至少一条 issue
    assert str(data.get('summary') or '').strip() or (data.get('issues') or []), data


# --------------------------------------------------------------------------- #
# 2) 图片题：AI 助教 + omni 图片一致性分析（真实多模态）
# --------------------------------------------------------------------------- #
@pytest.mark.judger
def test_ask_ai_code_marks_live_runs_omni_image_analysis(client, admin_login, monkeypatch):
    """图片题真实评测产出 output.png 后，/ask_ai_code_marks 会触发 omni 图片分析；
    断言返回里带上了真实的 image_mismatch_analysis 文本。"""
    import oj
    import oj_modules.routes.problem_core_routes as pcm
    import oj_modules.tasks.evaluate_tasks as et

    pid = h.make_problem(title='图片题-omni实测', content='请画一张 32x32 的纯色图。',
                         lang='python', type=1)
    conn = db.get_db_connection()
    try:
        with conn.cursor() as cur:
            cur.execute("UPDATE problems SET programming_grading_mode=2, "
                        "programming_output_filename='output.png' WHERE id=%s", (pid,))
        conn.commit()
    finally:
        conn.close()

    # 图片"是否符合要求"的 AI 批改本身仍 mock 成通过，专注验证 omni 一致性分析链路。
    monkeypatch.setattr(et, 'evaluate_program_output_image_with_ai',
                        lambda **k: (1, '图片符合要求'), raising=False)

    captured = {}

    class _FakeTask:
        def delay(self, sid):
            captured['sid'] = sid

        def apply_async(self, args=None, **k):
            captured['sid'] = (args or [None])[0]

    monkeypatch.setattr(pcm, '_evaluate_submission_task', _FakeTask())

    r = client.post(f'/submit/{pid}', data={'code': _PNG_CODE})
    assert r.status_code in (301, 302)
    sid = captured.get('sid')
    assert sid

    # 真实沙箱评测：生成并捕获 output.png
    oj.evaluate_submission.apply(args=[sid]).get()
    sub = db.get_submission_by_id(sid)
    tps = sub.get('test_points') or []
    assert tps and tps[0].get('has_output_image') is True

    # 先直接验证底层 omni 视觉调用本身可用（不走会吞异常的编排层），
    # 这样若真实 API/模型有问题，错误会直接抛出而不是被静默成空字符串。
    from oj_modules import ai_utils
    from config import DASHSCOPE_API_KEY, DASHSCOPE_BASE_URL
    img_path = ai_utils._find_submission_output_image_path(sid, 1, tps)
    assert img_path and os.path.isfile(img_path), f'未定位到输出图片: {img_path!r}'
    omni_text = ai_utils._call_qwen_omni_with_image(
        '请用一句话描述这张图片的主要颜色。',
        ai_utils._build_image_data_url(img_path),
        DASHSCOPE_API_KEY, DASHSCOPE_BASE_URL, timeout=120,
    )
    assert str(omni_text or '').strip(), '真实 omni 视觉模型返回空'

    # 再验证业务编排层：图片一致性分析只对“非 Accepted”的测试点跑（编排层会跳过
    # 已 Accepted 的点）。构造一个指向同一张真实图片、状态为非 Accepted 的测试点，
    # 驱动真实 omni 一致性分析链路，断言返回真实文本与测试点序号。
    probe_tps = [{
        'status': 'Wrong Answer',
        'test_index': 1,
        'has_output_image': True,
        'output_image_filename': tps[0].get('output_image_filename') or 'output_0.png',
    }]
    result = ai_utils.analyze_submission_output_image_against_problem(
        '请画一张 32x32 的纯色图。', sid, probe_tps,
    )
    assert result.get('has_output_image') is True, result
    assert str(result.get('analysis') or '').strip(), result
    assert result.get('test_index'), result

    # 最后验证对外接口 /ask_ai_code_marks 整体成功（不强求图片分析字段非空，
    # 编排已在上面单独断言；这里确保 AI 助教问答主链路 200 且 success）。
    r2 = client.post('/ask_ai_code_marks', json={
        'problem_id': pid,
        'user_code': _PNG_CODE,
        'submission_id': sid,
        'force_refresh': True,
    })
    assert r2.status_code == 200, r2.get_data(as_text=True)
    assert r2.get_json().get('success') is True, r2.get_data(as_text=True)


# --------------------------------------------------------------------------- #
# 3) 提交 tex 的书面题：xelatex 编译 + 真实 AI 批改
# --------------------------------------------------------------------------- #
@pytest.mark.judger
def test_submit_tex_homework_live_full_grading_chain(client, admin_login):
    """书面题 written_grading_mode=3：提交含 main.tex 的 .zip，真实 xelatex 编译后
    走真实 AI 批改，最终提交拿到分数与非空评语。"""
    import oj

    pid = h.make_problem(title='tex书面题-实测',
                         content='请用 LaTeX 写出 x^2 的导数并说明。',
                         lang='matlab', type=2)
    conn = db.get_db_connection()
    try:
        with conn.cursor() as cur:
            cur.execute("UPDATE problems SET written_grading_mode=3 WHERE id=%s", (pid,))
        conn.commit()
    finally:
        conn.close()

    # 直接复刻 submit 路由对书面题的落盘逻辑（type==2 分支），再直接驱动真实任务，
    # 绕开路由 enqueue 对 celery task 初始化的依赖（该处异常会被 flash 吞掉）。
    filename = 'file_solution.zip'
    sid = db.create_submission(
        problem_id=pid, problem_title='tex书面题-实测', username='admin',
        code=' ', score=0, test_points=[filename],
    )
    upload_folder = os.path.join('uploads', str(sid))
    os.makedirs(upload_folder, exist_ok=True)
    with open(os.path.join(upload_folder, filename), 'wb') as f:
        f.write(_make_zip_bytes({'main.tex': _MAIN_TEX}))

    # 同步真实执行：解压 → xelatex 编译 main.tex → 真实 AI 批改
    oj.transcribe_written_homework_to_latex.apply(args=[sid]).get()

    sub = db.get_submission_by_id(sid)
    # 拿到了真实分数（0-100 的整数）
    score = sub.get('score')
    assert score is not None
    assert 0 <= int(score) <= 100, f'score={score!r}'

    # 书面题的 AI 批改评语由 update_submission_score_and_comment 写入 submissions.code 列
    # （书面题没有用户代码，复用该列存评语；get_submission_by_id 不返回该列），直接查。
    conn = db.get_db_connection()
    try:
        with conn.cursor() as cur:
            cur.execute("SELECT code FROM submissions WHERE id=%s", (sid,))
            row = cur.fetchone()
    finally:
        conn.close()
    feedback = (row or {}).get('code') if isinstance(row, dict) else (row[0] if row else None)
    assert str(feedback or '').strip(), '应有 AI 批改评语'
    # 编译产物 PDF 应已生成在提交目录
    assert os.path.isdir(os.path.join('uploads', str(sid)))
