#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import json
from datetime import datetime

from flask import Blueprint, Response, jsonify, request, session

from config import DASHSCOPE_API_KEY, DASHSCOPE_APP_ID, QWEN_TEXT_MODEL
from oj_modules.ai_utils import (
    generate_ai_code_marks_from_submission_context,
)
from oj_modules.db_services import (
    get_cached_ai_code_marks_for_submission,
    get_problem,
    get_submission_by_id,
    get_user_by_username,
    save_submission_ai_code_marks_json,
)
from oj_modules.repository_services import extract_includes_from_code, get_user_repository_files_by_names


ai_bp = Blueprint('ai', __name__)


def current_user():
    username = session.get('username')
    if not username:
        return None
    return get_user_by_username(username)


def is_admin(user):
    return user and user.get('is_admin') == 1


def generate_completion_stream(prompt, model="Qwen3"):
    import requests

    app_id = DASHSCOPE_APP_ID
    api_key = DASHSCOPE_API_KEY

    url = f"https://dashscope.aliyuncs.com/api/v1/apps/{app_id}/completion"
    headers = {
        "Authorization": f"Bearer {api_key}",
        "Content-Type": "application/json",
        "X-DashScope-SSE": "enable",
        "User-Agent": "Mozilla/5.0",
    }

    role = """
你是一个小猫，你会说人话，你温柔可爱、学术水平高超，你需要帮小朋友分析他的代码有什么问题。
你需要特别关注小朋友的测试点得分情况。如果有 Compile Error 或者 Error，则你只需要分析语法错误，不用关注问题本身。
如果有 Time Limit Exceed，则应该分析复杂度和计算效率，而不是分析代码的正确性。
如果有 Runtime Error，则应该分析可能的内存越界、堆栈溢出等问题，另外非零返回也会被系统判断为 RE。
如果有 Wrong Answer，则需要分析代码的正确性。
""".strip()

    data = {
        "input": {"prompt": f"{role}\n\n{prompt}"},
        "parameters": {
            "incremental_output": True,
            "has_thoughts": True,
        },
        "debug": {},
    }

    in_thinking = False

    with requests.post(url, headers=headers, json=data, stream=True) as r:
        r.raise_for_status()
        for line in r.iter_lines(decode_unicode=True):
            if not line:
                continue
            if line.startswith(":"):
                continue
            if not line.startswith("data:"):
                continue

            payload = line[5:].strip()
            if payload in ("", "[DONE]"):
                continue

            try:
                packet = json.loads(payload)
            except json.JSONDecodeError:
                continue

            output = packet.get("output", {}) or {}

            reason_stream = ""
            thoughts = output.get("thoughts") or []
            for t in thoughts:
                if t.get("action_type") == "reasoning":
                    reason_stream = t.get("thought") or ""
                    break

            if reason_stream:
                if not in_thinking:
                    yield "<think>"
                    in_thinking = True
                yield reason_stream

            text_stream = output.get("text") or ""
            if text_stream:
                if in_thinking:
                    yield "</think>"
                    in_thinking = False
                yield text_stream

        if in_thinking:
            yield "</think>"


@ai_bp.route('/ask_ai_code_marks', methods=['POST'])
def ask_ai_code_marks():
    data = request.get_json()
    if not data:
        return jsonify(success=False, message="缺少请求体"), 400

    problem_id = data.get('problem_id', '')
    problem = get_problem(problem_id)
    if not problem:
        return jsonify(success=False, message="题目不存在"), 404

    problem_content = problem.get('content') or ''
    if not problem_content:
        return jsonify(success=False, message="缺少题目内容"), 400

    raw_code = data.get('user_code', '')
    if raw_code is None:
        raw_code = ''
    user_code = str(raw_code).replace('\r\n', '\n').replace('\r', '\n')
    if not user_code.strip():
        return jsonify(success=False, message="缺少用户代码"), 400

    sid = data.get('submission_id', '')
    submission = get_submission_by_id(sid)
    if not submission:
        return jsonify(success=False, message="提交记录不存在"), 404

    user = current_user()
    if not user:
        return jsonify(success=False, message="未登录"), 401
    if submission['username'] != user['username'] and not is_admin(user):
        return jsonify(success=False, message="无权访问该提交"), 403

    force_refresh = bool(data.get('force_refresh'))
    if not force_refresh:
        cached_result = get_cached_ai_code_marks_for_submission(submission)
        if cached_result:
            return jsonify(**cached_result, source='cache')

    test_points = '\n'.join([json.dumps(tp, ensure_ascii=False) for tp in (submission.get("test_points") or [])])

    included_files = extract_includes_from_code(user_code)
    repository_files = {}
    if included_files:
        repository_files = get_user_repository_files_by_names(user['id'], included_files)

    try:
        result = generate_ai_code_marks_from_submission_context(
            problem_content=problem_content,
            user_code=user_code,
            test_points_text=test_points,
            repository_files=repository_files,
            submission_id=sid,
            test_points=submission.get("test_points") or [],
            max_issues=8,
            timeout=240,
        )
        issues = result.get('issues') or []
        summary = str(result.get('summary') or '').strip()
        code_used = str(result.get('code_used') or user_code)
        image_mismatch_analysis = str(result.get('image_mismatch_analysis') or '').strip()
        image_analysis_test_index = result.get('image_analysis_test_index')
        cache_payload = {
            "issues": issues,
            "summary": summary,
            "code_used": code_used,
            "image_mismatch_analysis": image_mismatch_analysis,
            "image_analysis_test_index": image_analysis_test_index,
            "generated_at": datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ"),
            "model": QWEN_TEXT_MODEL,
        }
        save_submission_ai_code_marks_json(sid, cache_payload)
        return jsonify(
            success=True,
            issues=issues,
            summary=summary,
            code_used=code_used,
            image_mismatch_analysis=image_mismatch_analysis,
            image_analysis_test_index=image_analysis_test_index,
            source='generated',
        )
    except Exception as e:
        return jsonify(success=False, message=f"标注生成失败：{str(e)}"), 500


@ai_bp.route('/ask_ai', methods=['POST'])
def ask_ai():
    data = request.get_json()
    if not data:
        return jsonify(success=False, message="缺少请求体"), 400

    problem_id = data.get('problem_id', '')
    problem = get_problem(problem_id)
    problem_content = problem['content']
    user_code = data.get('user_code', '').strip()
    sid = data.get('submission_id', '')
    submission = get_submission_by_id(sid)
    test_points = '\n'.join([json.dumps(tp, ensure_ascii=False) for tp in submission["test_points"]])

    if not problem_content:
        return jsonify(success=False, message="缺少题目内容"), 400
    if not user_code:
        return jsonify(success=False, message="缺少用户代码"), 400

    user = current_user()
    if not user:
        return jsonify(success=False, message="未登录"), 401

    included_files = extract_includes_from_code(user_code)
    repository_files = {}
    if included_files:
        repository_files = get_user_repository_files_by_names(user['id'], included_files)

    repository_context = ""
    if repository_files:
        repository_context = "\n\n小朋友还在代码仓库中定义了以下头文件/源文件：\n\n"
        for filename, content in repository_files.items():
            repository_context += f"文件名：{filename}\n```\n{content}\n```\n\n"

    lang = (problem.get('lang') or 'matlab').lower()
    code_lang = 'matlab' if lang == 'matlab' else lang if lang in ['c', 'cpp', 'python', 'py'] else 'text'

    prompt = f"""## 角色定位
你是一只会说人话的AI助教小猫🐱，温柔可爱、学术精湛。你的任务是帮助同学分析代码问题，给出改进建议。

## 题目信息
{problem_content}

## 同学的代码
```{code_lang}
{user_code}
```{repository_context}

## 评测结果
```
{test_points}
```

## 分析要求

### 1. 根据评测结果分类分析
- **全是 Compile Error/Error**：重点分析语法错误、编译问题，不需要深入算法逻辑
- **包含 Time Limit Exceeded**：如果其他测试点 Accepted，说明逻辑正确但效率不足，请从时间复杂度、循环优化、算法改进角度分析
- **包含 Runtime Error**：分析可能的内存越界、数组下标、空指针、堆栈溢出、非零返回值等运行时问题
- **包含 Wrong Answer**：逐个分析可能出错的测试场景，结合题目要求指出逻辑漏洞，**引用具体的代码行**说明问题所在

### 2. 代码仓库文件分析
如果同学使用了代码仓库中的头文件/源文件，请**重点关注**：
- 自定义函数的实现是否正确
- 头文件中的数据结构定义是否合理
- 多文件之间的逻辑配合是否存在问题

### 3. 分析深度
- 先快速定位最关键的1-2个问题
- 如果问题明显，直接指出并说明原因
- 如果需要深入分析，可以结合具体测试点展开
- 不要试图找出所有问题，聚焦于解决当前最重要的错误

### 4. 回复原则
- ✅ 可以：指出错误位置、解释错误原因、提示改进方向、举简单例子
- ❌ 禁止：直接给出完整正确代码、详细的算法实现步骤
- 💡 如果代码完全偏离题意：温柔地建议同学重新理解题目，给予鼓励

### 5. 回复格式
请按以下格式输出（可以使用 emoji 让回复更友好）：
1. 开头给一句可爱的猫咪问候
2. 简要总结评测情况（通过几个/总共几个测试点）
3. 核心问题分析（指出代码行、说明原因）
4. 改进建议（方向性指导，不要给完整代码）
5. 结尾鼓励

现在请开始分析吧！喵～🐾
"""

    def generate_answer():
        try:
            for chunk in generate_completion_stream(prompt):
                yield chunk
        except Exception as e:
            yield f"\n[服务端异常] {str(e)}"

    return Response(generate_answer(), mimetype='text/plain')


@ai_bp.route('/ask_ai_for_ac', methods=['POST'])
def ask_ai_for_ac():
    data = request.get_json()
    if not data:
        return jsonify(success=False, message="缺少请求体"), 400

    problem_id = data.get('problem_id', '')
    problem = get_problem(problem_id)
    problem_content = problem['content']
    user_code = data.get('user_code', '').strip()

    if not problem_content:
        return jsonify(success=False, message="缺少题目内容"), 400
    if not user_code:
        return jsonify(success=False, message="缺少用户代码"), 400

    user = current_user()
    if not user:
        return jsonify(success=False, message="未登录"), 401

    included_files = extract_includes_from_code(user_code)
    repository_files = {}
    if included_files:
        repository_files = get_user_repository_files_by_names(user['id'], included_files)

    repository_context = ""
    if repository_files:
        repository_context = "\n\n同学还在代码仓库中定义了以下头文件/源文件：\n\n"
        for filename, content in repository_files.items():
            repository_context += f"文件名：{filename}\n```\n{content}\n```\n\n"

    lang = (problem.get('lang') or 'matlab').lower()
    code_lang = 'matlab' if lang == 'matlab' else lang if lang in ['c', 'cpp', 'python', 'py'] else 'text'

    prompt = f"""## 角色定位
你是一只会说人话的AI助教小猫🐱，温柔可爱、善于鼓励。同学刚刚通过了这道题目，你的任务是给予肯定和鼓励，同时温和地指出可以改进的地方。

## 题目信息
{problem_content}

## 同学的通过代码
```{code_lang}
{user_code}
```{repository_context}

## 分析要求

### 1. 分析原则 ⭐
- **鼓励为主**：这是同学的成功时刻，要让他感到自豪和快乐
- **肯定优点**：找出代码中做得好的地方（算法思路、代码结构、边界处理等）
- **温和建议**：如果有改进空间，用温和、建议性的语气提出，而不是批评性的
- **保持轻松**：语气要轻松活泼，充满正能量

### 2. 必须分析的内容
#### 2.1 代码优点（至少找出 2-3 个亮点）
- ✅ 算法选择是否合理
- ✅ 代码逻辑是否清晰
- ✅ 边界情况处理是否得当
- ✅ 变量命名是否规范
- ✅ 代码结构是否良好
- ✅ 使用的编程技巧（如果有）

#### 2.2 可优化的地方（可选，仅在必要时提及）
**注意：只有在存在明显的改进空间时才提及，且必须用温和的语气**
- 💡 时间复杂度优化（如果当前实现较慢但能通过）
- 💡 空间复杂度优化（如果内存使用较多）
- 💡 代码可读性提升（如果命名或结构可以更好）
- 💡 代码健壮性（如果可以增加容错处理）

**禁止提及的改进建议**：
- ❌ 不要批评已经足够好的代码
- ❌ 不要过度追求完美主义
- ❌ 不要提出对当前题目意义不大的优化

### 3. 代码仓库文件分析
如果同学使用了代码仓库中的头文件/源文件：
- 🌟 这是值得表扬的！说明同学懂得代码复用和模块化
- 👍 重点肯定自定义函数的设计和实现
- 💡 如果文件结构很好，一定要表扬

### 4. 回复格式
请按以下格式输出（语气要充满正能量和鼓励）：

1. **开场祝贺** 🎉
   - 可爱的猫咪问候
   - 热烈祝贺通过题目
   - 表达为同学感到高兴

2. **代码亮点分析** ✨
   - 列出 2-3 个代码做得好的地方
   - 每个亮点都要具体说明（引用代码片段更好）
   - 真诚地表达赞赏

3. **温和的改进建议** 💭（可选）
   - **仅在确实有必要时提及**
   - 用"如果想让代码更好，可以考虑..."这样的句式
   - 1-2 条即可，不要列太多
   - 保持轻松的语气，不要给压力

4. **鼓励与展望** 🚀
   - 再次肯定同学的成就
   - 鼓励继续学习
   - 温暖的结束语

### 5. 语气和措辞示例
- ✅ "太棒了！你的代码逻辑非常清晰..."
- ✅ "这个边界处理做得真好，考虑得很周到..."
- ✅ "如果想让代码跑得更快一点，可以试试..."
- ✅ "总的来说，这是一个很优秀的解决方案！"
- ❌ "这里有问题..."
- ❌ "应该改成..."
- ❌ "效率太低..."

现在请用充满正能量的方式分析这段代码吧！记住：今天是同学的庆祝日！喵～🎊
"""

    def generate_answer():
        try:
            for chunk in generate_completion_stream(prompt):
                yield chunk
        except Exception as e:
            yield f"\n[服务端异常] {str(e)}"

    return Response(generate_answer(), mimetype='text/plain')
