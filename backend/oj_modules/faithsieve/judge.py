"""将完整数学任务交给站内 Judge；Lean 编译和原稿渲染由代码执行。

每次调用只提交或读取一次持久轮次。等待状态通过 FaithSievePending 交给
Celery 重试，不能占住 Agent worker 同步等待另一个 Agent。
"""

from __future__ import annotations

import base64
from contextlib import contextmanager
import json
import os
from pathlib import Path, PurePosixPath
import platform
import re
import stat
import subprocess
import tempfile
from uuid import uuid4

from backend.oj_modules.agents.judge import submit_judge_turn
from backend.oj_modules.agents.sessions import get_agent_session, get_agent_session_turns
from backend.oj_modules.agents.workspace import open_agent_workspace_file
from backend.oj_modules.config import (
    AGENT_JUDGE_CPU_LIMIT, AGENT_JUDGE_DOCKER_IMAGE, AGENT_JUDGE_MEM_LIMIT,
    AGENT_JUDGE_PIDS_LIMIT,
)
from backend.oj_modules.judging import sandbox
from backend.oj_modules.problems.agent_runs import agent_run_trace_dir

from .checkpoints import atomic_write
from .budgets import SOURCE_TIMEOUT_SECONDS
from .json_repair import strict_equal
from .artifacts import FaithSieveProtocolError, parse_json_response
from .local_diagnostics import (
    LOCAL_DIAGNOSTIC_KINDS, LOCAL_DIAGNOSTIC_STATUSES,
    validate_local_diagnostic_version, validate_local_verifier_result,
)
from .result_metadata import project_role_result, validate_result_projection_version
from .external_results import validate_external_results_version
from backend.oj_modules.submissions.faithsieve import RUN_TIMEOUT_SECONDS


_TEXT_LIMIT = 2 * 1024 * 1024
_PDF_LIMIT = 20 * 1024 * 1024
_ROLES = {
    "local-verifier": {"passed", "refuted", "inconclusive"},
    "numeric-evaluator": {"passed", "refuted", "inconclusive"},
    "statement-formalizer": {"ok", "inconclusive"},
    "proof-searcher": {"passed", "refuted", "inconclusive"},
    "source-extractor": {"ok", "inconclusive"},
}
_TERMINAL = {"completed", "failed", "error", "canceled", "cancelled", "timeout", "cleanupfailed", "quotaexhausted"}


class FaithSieveJudgeError(RuntimeError):
    """Judge 未可靠完成、工件不安全或持久身份不一致。"""


class FaithSievePending(Exception):
    def __init__(self, *, session_id, task_id, role, invocation_key, countdown=5):
        super().__init__(f"FaithSieve {role} Judge 正在执行")
        self.session_id = session_id
        self.task_id = task_id
        self.role = role
        self.invocation_key = invocation_key
        self.countdown = countdown


def _relative_path(value):
    text = str(value or "")
    path = PurePosixPath(text)
    if not text or path.is_absolute() or '..' in path.parts or '\\' in text or '\x00' in text or text in {'.', '..'}:
        raise FaithSieveJudgeError("FaithSieve 文件路径无效")
    return path.as_posix()


def _validate_result_projection_scope(version, *, role, proof_graph_version, diagnostic_version):
    validate_result_projection_version(version)
    if version is not None and (role != 'local-verifier' or type(proof_graph_version) is not int
                                or proof_graph_version != 3 or type(diagnostic_version) is not int
                                or diagnostic_version != 1):
        raise FaithSieveJudgeError('结果元数据投影仅适用于新版图像局部验证')


def _local_verifier_payload(payload, *, diagnostic_version, projection_version):
    """只为严格校验投影声明字段，原始回传留给编排器隔离元数据。"""
    canonical = payload
    if projection_version is not None:
        canonical, _metadata = project_role_result({'result': payload}, {'status', 'artifact', 'report', 'diagnostics'})
        canonical = canonical['result']
    validate_local_verifier_result(canonical, diagnostic_version=diagnostic_version)
    return canonical


def _private_read(path, limit):
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    with os.fdopen(fd, 'rb') as stream:
        info = os.fstat(stream.fileno())
        if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or info.st_size > limit:
            raise FaithSieveJudgeError("FaithSieve 持久材料不是安全的普通文件")
        return stream.read(limit + 1)


def _file_bytes(content):
    if isinstance(content, bytes):
        return content
    if isinstance(content, str):
        return content.encode('utf-8')
    raise FaithSieveJudgeError("FaithSieve 文件必须是文本或字节")


class DockerFaithSieveTools:
    """可信镜像上的一次性纯工具容器；只有 /workspace 可写。"""

    def __init__(self, workspace, *, image=None):
        self.workspace = Path(workspace).resolve()
        self.image = str(image or AGENT_JUDGE_DOCKER_IMAGE)
        self._ready = False

    @contextmanager
    def _directory(self, persistent):
        self.workspace.mkdir(parents=True, exist_ok=True)
        if persistent is not None:
            directory = Path(persistent).resolve()
            if not directory.is_relative_to(self.workspace):
                raise FaithSieveJudgeError("工具输出目录越界")
            directory.mkdir(parents=True, exist_ok=True)
            yield directory
        else:
            with tempfile.TemporaryDirectory(dir=self.workspace, prefix='.tool-') as directory:
                yield Path(directory)

    def run(self, operation, payload, *, files=None, workspace=None, timeout_seconds=120):
        if operation not in {'preflight', 'compile', 'numeric', 'extract'}:
            raise FaithSieveJudgeError("未知 FaithSieve 工具操作")
        if operation != 'preflight' and not self._ready:
            preflight_path = self.workspace / 'faithsieve-work' / 'tool-preflight.json'
            checked = None
            if preflight_path.exists():
                saved = json.loads(_private_read(preflight_path, _TEXT_LIMIT))
                if saved.get('image') == self.image and saved.get('result', {}).get('ready') is True:
                    checked = saved['result']
            if checked is None:
                checked = self.run('preflight', {}, timeout_seconds=40)
                atomic_write(preflight_path, json.dumps({'image': self.image, 'result': checked}, ensure_ascii=False).encode())
            if checked.get('ready') is not True:
                raise FaithSieveJudgeError("Judge 镜像未完成数学与 PDF 渲染工具预装")
            self._ready = True
        with self._directory(workspace) as directory:
            for relative, content in (files or {}).items():
                target = directory / _relative_path(relative)
                target.parent.mkdir(parents=True, exist_ok=True)
                atomic_write(target, _file_bytes(content))
            runtime = directory / '.runtime'
            runtime.mkdir(mode=0o700, exist_ok=True)
            packed = {**payload, 'workspace': '/workspace'}
            atomic_write(directory / '.tool-input.json', json.dumps(packed, ensure_ascii=False).encode())
            user = '0:0' if platform.system() == 'Darwin' else f'{os.getuid()}:{os.getgid()}'
            name = f'numoj-faithsieve-{uuid4().hex}'
            args = [
                'docker', 'run', '--rm', '-i', '--name', name,
                '--read-only', '--cap-drop', 'ALL', '--security-opt', 'no-new-privileges',
                '--network', 'none', '--ipc', 'none', '--pids-limit', str(AGENT_JUDGE_PIDS_LIMIT),
                '--memory', str(AGENT_JUDGE_MEM_LIMIT), '--cpus', str(AGENT_JUDGE_CPU_LIMIT),
                '--user', user, '--volume', f'{directory}:/workspace:rw', '--workdir', '/workspace',
            ]
            for key in ('HOME', 'XDG_CACHE_HOME', 'XDG_CONFIG_HOME', 'XDG_DATA_HOME', 'TMPDIR', 'TMP', 'TEMP'):
                args.extend(['--env', f'{key}=/workspace/.runtime'])
            args += [self.image, 'python3', '-I', '/usr/local/share/numoj/faithsieve_tool.py', operation, '@/workspace/.tool-input.json']
            proc = None
            try:
                proc = subprocess.Popen(args, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                stdout, stderr, truncated_out, truncated_err = sandbox._communicate_bounded(proc, input_bytes=b'', timeout_sec=int(timeout_seconds))
                if proc.returncode != 0 or truncated_out or truncated_err:
                    raise FaithSieveJudgeError("FaithSieve Docker 工具失败、超时或输出被截断")
                try:
                    result = json.loads(stdout.decode('utf-8'))
                except (ValueError, UnicodeError):
                    raise FaithSieveJudgeError("FaithSieve Docker 工具没有返回有效 JSON") from None
                if not isinstance(result, dict) or result.get('protocol') != 'faithsieve-tools-v1' or result.get('error'):
                    raise FaithSieveJudgeError("FaithSieve Docker 工具协议无效")
                return {**result, 'tool_executed': True, 'container_command': args}
            except subprocess.TimeoutExpired:
                raise FaithSieveJudgeError("FaithSieve Docker 工具执行超时") from None
            finally:
                # 无论工具结果是否正常，都确认容器已停止；清理失败禁止继续评分。
                if proc is not None:
                    if proc.poll() is None:
                        proc.kill()
                    sandbox._force_remove_container(name)
                    proc.wait(timeout=5)


def render_submission_images(pdf, *, workspace, tools, timeout_seconds=600):
    """保留同源 PDF，仅把逐页图像和页清单交给模型。"""
    if not isinstance(pdf, bytes) or not pdf.startswith(b'%PDF-') or len(pdf) > _PDF_LIMIT:
        raise FaithSieveJudgeError("原稿不是有效 PDF 或超过 20 MiB")
    source = Path(workspace)
    source.mkdir(parents=True, exist_ok=True)
    pdf_path, record_path = source / 'submission.pdf', source / 'extraction.json'
    if pdf_path.exists():
        if _private_read(pdf_path, _PDF_LIMIT) != pdf:
            raise FaithSieveJudgeError("重入 PDF 与原稿不一致")
    else:
        atomic_write(pdf_path, pdf)
    if record_path.exists():
        result = json.loads(_private_read(record_path, _TEXT_LIMIT))
    else:
        result = tools.run('extract', {'pdf': base64.b64encode(pdf).decode(), 'timeout_seconds': int(timeout_seconds)},
                           workspace=source, timeout_seconds=int(timeout_seconds) + 10)
        atomic_write(record_path, json.dumps(result, ensure_ascii=False).encode())
    if not isinstance(result, dict):
        raise FaithSieveJudgeError("PDF 逐页渲染工具协议无效")
    pages = result.get('pages')
    page_count = result.get('page_count')
    if (isinstance(page_count, bool) or not isinstance(page_count, int) or not 1 <= page_count <= 100
            or not isinstance(pages, list) or len(pages) != page_count
            or isinstance(result.get('exit_code'), bool) or result.get('exit_code') != 0):
        raise FaithSieveJudgeError("PDF 逐页渲染工具协议无效")
    files, visible_pages = {}, []
    for number, page in enumerate(pages, 1):
        if (not isinstance(page, dict) or isinstance(page.get('page'), bool)
                or page.get('page') != number or page.get('rendered') is not True):
            raise FaithSieveJudgeError("PDF 页面未完整渲染")
        data = _private_read(source / f'page-{number}.png', 32 * 1024 * 1024)
        if not data.startswith(b'\x89PNG\r\n\x1a\n'):
            raise FaithSieveJudgeError("PDF 页面没有真实 PNG")
        name = f'source-pages/page-{number}.png'
        files[name] = data
        visible_pages.append({'page': number, 'rendered': True, 'image_path': name})
    files['pages.json'] = json.dumps(visible_pages, ensure_ascii=False)
    return files, visible_pages


def _role_instruction(role, prompt, result_path, proof_graph_version, *, legacy_environment=False,
                      local_diagnostic_version=None, external_results_version=None):
    validate_external_results_version(external_results_version)
    absolute_result_path = f"/workspace/{result_path}"
    instruction = (
        '工作目录：/workspace；所有相对文件路径以此目录为准。\n'
        '环境已预装 Lean、mathlib、SymPy 和 PDF 渲染工具，无需安装环境。\n'
        'Lean 命令：/usr/local/bin/lean；Python 命令：python3；mathlib 源码：/opt/numoj-lean-project。\n'
        'Lean 导入优先选择任务实际需要的 Mathlib 模块；完整 mathlib 也已预装。\n'
        '只能编辑任务要求的输出，不能修改输入工件。\n\n' + str(prompt)
    )
    if proof_graph_version == 3 and not legacy_environment:
        instruction = instruction.replace(
            '环境已预装 Lean、mathlib、SymPy 和 PDF 渲染工具，无需安装环境。\n',
            '环境已预装 Lean、mathlib、SymPy 和 PDF 渲染工具。禁止安装、更新或探查环境版本。\n'
            '直接使用 /usr/local/bin/lean /workspace/你的文件.lean；该入口已配置全部预编译 mathlib 依赖，'
            '不需要 lake env lean、lake update、lake build、cache get 或手工设置 LEAN_PATH。\n'
            '禁止查询 Lean/Lake 版本、lean-toolchain、Git commit；这些不属于数学验证任务。\n'
            '只有 /workspace 可写；临时文件放 /workspace/.runtime，不能写 /tmp 或 /opt。\n'
            '优先导入实际需要的 Mathlib 模块，避免反复加载全库。\n'
        )
    if role == 'numeric-evaluator' and proof_graph_version == 1:
        instruction += (
            f'\n\n将忠实解析的封闭精确数值关系写入 {result_path}.expressions.json，格式为 '
            '{"relations":[{"lhs":"精确 SymPy 表达式","relation":"eq|ne|lt|le|gt|ge","rhs":"精确 SymPy 表达式"}]}。'
            '只用工具支持的精确表达，不以近似决定真伪。无法忠实解析时 relations 写空列表并返回 inconclusive。'
        )
    elif role == 'numeric-evaluator':
        instruction += (
            '\n\n自主验证全部直接前提共同推出完整目标的局部推理，选择适合该命题的计算或验证方法。'
            '不能只检查目标真假，也不能把前提尚未建立当成局部推理不成立。'
            '由你给出 passed、refuted 或 inconclusive，并在数学报告中记录方法、依据和不确定性。'
            '不要求使用固定表达式协议、特定数值工具或输出额外复验文件。'
        )
    elif role == 'local-verifier':
        instruction += (
            '\n\n原稿以 pages.json 中列出的全部 PNG 文件提供，直接使用图像工具阅读。'
            '以完整目标和全部列明的直接前提为局部责任，自主完成验证及必要的搜索、计算、Lean 代码与编译。'
            '可以生成验证所需的工作文件；原稿图片、题面及目标和前提文件必须只读。'
            '不要转录或整理原稿，不生成原句引文、位置或局部摘录作为其他步骤的输入。'
        )
    if external_results_version is not None:
        instruction += (
            '\n\n外部结果与局部 Lean 规则以本次外部结果协议为准：使用必要已有定理必须已列为 external 直接前驱。'
            '列明前驱的完整声明可用 sorry 引入，使用 premise_N编号 / external_N编号 并在报告中映射。'
            '完整当前目标命名 FaithSieveProof；目标、定义及其他未列辅助结论不得使用 sorry、admit、axiom 或占位。'
            '实际证明定理应用所需条件、当前目标和完整编译；必要外部结果尚未登记时返回 graph_defect/missing_premise。'
        )
    report_language = 'report 一律使用中文。' if proof_graph_version == 3 else 'report 一律使用中文；原稿转录和原文引用保留原语言。'
    diagnostic = local_diagnostic_version is not None
    result_fields = 'status、artifact、report、diagnostics' if diagnostic else 'status、artifact、report'
    result_field_check = ('assert isinstance(result, dict) and set(result) == {"status", "artifact", "report", "diagnostics"}\n'
                          if diagnostic else 'assert isinstance(result, dict) and set(result) == {"status", "artifact", "report"}\n')
    result_statuses = LOCAL_DIAGNOSTIC_STATUSES if diagnostic else _ROLES[role]
    if diagnostic:
        instruction += (
            '\n\n构图诊断协议：结论转写错误、原稿条件遗漏、量词或绑定变化必须返回 graph_defect，'
            '不得把构图错误记为 refuted 或 inconclusive，也不得修改输入 DAG。'
            'diagnostics 为数组，每条仅含 kind、affected_node_ids、reason；'
            f'kind 仅可为 {", ".join(sorted(LOCAL_DIAGNOSTIC_KINDS))}。'
            'affected_node_ids 只列出目标或列明前提中的现有节点编号，reason 用中文说明差异。'
            'graph_defect 必须有非空 diagnostics；passed、refuted、inconclusive 的 diagnostics 必须为空数组。'
        )
    instruction += (
        f'\n\n结果元数据 JSON 的唯一绝对位置是 {absolute_result_path}。'
        f'该文件只保存 {result_fields}；artifact 指定的数学工件另行写入其约定路径，'
        'artifact 字段仍使用相对于 /workspace 的路径。'
        + report_language +
        '不得把结果元数据放到 artifact 所在目录或其他位置，也不得因切换工作目录而改变结果路径。'
        '\n结束前必须执行下列 Python 核对，确认该绝对位置的文件存在、可解析且字段正确；核对通过后才能结束：\n'
        '```python\nimport json\n'
        f'with open({json.dumps(absolute_result_path, ensure_ascii=False)}, encoding="utf-8") as stream:\n'
        '    result = json.load(stream)\n'
        + result_field_check +
        f'assert result["status"] in {sorted(result_statuses)!r}\n'
        'assert isinstance(result["artifact"], str) and result["artifact"]\n'
        'assert isinstance(result["report"], str)\n'
        + ('assert isinstance(result["diagnostics"], list)\n'
           'assert bool(result["diagnostics"]) == (result["status"] == "graph_defect")\n'
           'for item in result["diagnostics"]:\n'
           '    assert isinstance(item, dict) and set(item) == {"kind", "affected_node_ids", "reason"}\n'
           f'    assert item["kind"] in {sorted(LOCAL_DIAGNOSTIC_KINDS)!r}\n'
           '    assert isinstance(item["affected_node_ids"], list) and item["affected_node_ids"]\n'
           '    assert all(isinstance(node, str) and node for node in item["affected_node_ids"])\n'
           '    assert len(set(item["affected_node_ids"])) == len(item["affected_node_ids"])\n'
           '    assert isinstance(item["reason"], str) and item["reason"].strip()\n'
           if diagnostic else '') + '```'
    )
    return instruction


def _continuation_prompt(result_path, *, external_results_version=None):
    validate_external_results_version(external_results_version)
    instruction = (
        '继续完成原来的完整局部数学验证，复用同一会话、原稿图片、完整条件、目标和已有工作文件。'
        '保持原命题全部条件、量词、依赖与作用域；局部结果或编译成功不能替代完整验证。'
        '自行选择合适的方法；无法可靠完成时如实返回 inconclusive，不能省略条件或弱化目标。\n'
        '环境已预装。直接执行 /usr/local/bin/lean /workspace/你的文件.lean，入口已配置 mathlib 缓存和依赖。'
        '禁止 lake env lean、安装、更新、手工配置 LEAN_PATH，禁止查询 Lean/Lake 版本、lean-toolchain、Git commit。'
        '优先导入实际需要的 Mathlib 模块。只有 /workspace 可写，临时文件放 /workspace/.runtime。'
        '编译检查真实退出码，不以管道末端命令的成功当作编译成功。\n'
        f'完整数学报告仍写在原约定位置，结果 JSON 仍为 /workspace/{result_path}。'
        '用 Python 核对结果可解析、精确含 status/artifact/report，status 为 passed/refuted/inconclusive 后结束。'
    )
    if external_results_version is not None:
        instruction += ('\n保留原外部结果协议：列明直接前驱和 external 完整声明可用 sorry，'
                        '目标 FaithSieveProof、定义及未列辅助引理不得有占位；只实际证明当前完整局部步骤，'
                        '核对声明与节点映射、定理适用条件及真实编译结果。缺少必要外部前驱返回 graph_defect/missing_premise。')
        instruction += ('\n本次结果核对以原构图诊断协议为准，结果 JSON 精确包含 status、artifact、report、diagnostics，'
                        'status 为 passed/refuted/inconclusive/graph_defect，只有 graph_defect 的 diagnostics 非空。')
    return instruction


def validate_native_continuation(value, frozen, *, authorization=None):
    """新续聊使用当前指令；旧续聊只允许复用已核对的完整管理员授权。"""
    fields = {'kind', 'session_id', 'failed_task_id', 'original_timeout_seconds',
              'continuation_task_id', 'continuation_timeout_seconds', 'continuation_prompt'}
    if authorization is not None and not strict_equal(value, authorization):
        raise FaithSieveJudgeError('Judge 续跑与完整管理员授权不一致')
    expected_prompt = (authorization.get('continuation_prompt') if type(authorization) is dict
                       else _continuation_prompt(frozen['result_path'],
                                                 external_results_version=frozen.get('external_results_version')))
    if (type(value) is not dict or set(value) != fields or value['kind'] != 'native_timeout'
            or type(value['session_id']) is not str or type(value['failed_task_id']) is not str
            or value['session_id'] != frozen['session_id'] or value['failed_task_id'] != frozen['task_id']
            or type(value['original_timeout_seconds']) is not int or value['original_timeout_seconds'] != frozen['timeout_seconds']
            or type(value['continuation_task_id']) is not str
            or value['continuation_task_id'] != frozen['task_id'] + '-c1'
            or type(value['continuation_timeout_seconds']) is not int
            or not 1 <= value['continuation_timeout_seconds'] <= RUN_TIMEOUT_SECONDS
            or type(value['continuation_prompt']) is not str or not value['continuation_prompt'].strip()
            or value['continuation_prompt'] != expected_prompt):
        raise FaithSieveJudgeError('Judge 超时续跑的冻结身份或指令不一致')
    return value


def _cleanup_native_continuation_authorization(workspace, run, key):
    """只读核对原授权与原调用；清理现有会话不重新授予执行时间。"""
    from .checkpoints import CheckpointStore
    from .recovery import validate_recovery_run

    permission = validate_recovery_run(workspace, run)
    if not permission or permission['target_key'] != key or 'native_timeout' not in permission:
        return None
    record, _size = CheckpointStore(workspace)._read_record(key, strict=True)
    request = record.get('request') if type(record) is dict else None
    if (type(request) is not dict or record.get('state') not in {'pending', 'completed'}
            or type(request.get('proof_graph_version')) is not int or request['proof_graph_version'] != 3
            or request.get('role') != 'local-verifier'
            or not strict_equal(permission['request'], request)):
        raise FaithSieveJudgeError('Judge 清理续聊的原授权与冻结调用不一致')
    return permission['native_timeout']


def _inspect_original_native_request(workspace, run, key, record):
    """只读核对工作流请求、原生请求和完整材料；不创建工作区。"""
    request = record.get('request', {}) if type(record) is dict else {}
    if (type(record) is not dict or type(request) is not dict or record.get('state') != 'pending'
            or request.get('proof_graph_version') != 3 or type(request.get('proof_graph_version')) is not int
            or request.get('role') != 'local-verifier' or not re.fullmatch(r'role-[0-9]{6,}-attempt-1', key)):
        raise FaithSieveJudgeError('仅支持原图局部 Judge 的首次超时续跑')
    directory = Path(workspace) / 'faithsieve-work/judge-invocations'
    frozen = parse_json_response(_private_read(directory / f'{key}.json', 8 * 1024 * 1024).decode('utf-8'), strict_constants=True)
    endpoint = request.get('endpoint', {})
    diagnostic_version = request.get('local_diagnostic_version')
    validate_local_diagnostic_version(diagnostic_version)
    if (not strict_equal(frozen.get('local_diagnostic_version'), diagnostic_version)
            or ('local_diagnostic_version' in frozen) != ('local_diagnostic_version' in request)):
        raise FaithSieveJudgeError('Judge 原始构图诊断协议不一致')
    external_version = request.get('external_results_version')
    validate_external_results_version(external_version)
    if (external_version is not None and diagnostic_version is None
            or not strict_equal(frozen.get('external_results_version'), external_version)
            or ('external_results_version' in frozen) != ('external_results_version' in request)):
        raise FaithSieveJudgeError('Judge 原始外部结果协议不一致')
    projection_version = request.get('result_projection_version')
    _validate_result_projection_scope(projection_version, role=request.get('role'),
                                      proof_graph_version=request.get('proof_graph_version'),
                                      diagnostic_version=diagnostic_version)
    if (not strict_equal(frozen.get('result_projection_version'), projection_version)
            or ('result_projection_version' in frozen) != ('result_projection_version' in request)):
        raise FaithSieveJudgeError('Judge 原始结果元数据投影协议不一致')
    if (frozen.get('role') != 'local-verifier' or type(frozen.get('proof_graph_version')) is not int
            or frozen['proof_graph_version'] != 3 or type(frozen.get('timeout_seconds')) is not int
            or not 1 <= frozen['timeout_seconds'] <= RUN_TIMEOUT_SECONDS or frozen.get('session_id') != f"fs-{run['attempt_id']}-{key}"
            or frozen.get('task_id') != f"ft-{run['attempt_id']}-{key}"
            or frozen.get('result_path') != request.get('expected_result_path')
            or frozen.get('harness') != run.get('harness') or frozen.get('endpoint_id') != run.get('endpoint_id')
            or frozen.get('endpoint_model') != endpoint.get('model')):
        raise FaithSieveJudgeError('Judge 超时续跑的原始身份不一致')
    expected_prompts = [_role_instruction('local-verifier', request.get('agent_prompt'), frozen['result_path'], 3,
                                         legacy_environment=legacy, local_diagnostic_version=diagnostic_version,
                                         external_results_version=external_version)
                        for legacy in (False, True)]
    if frozen.get('prompt') not in expected_prompts:
        raise FaithSieveJudgeError('Judge 超时续跑的完整原指令不一致')
    files = dict(request.get('files', {}))
    try:
        files.update({p: base64.b64decode(data, validate=True) for p, data in request['images'].items()})
    except (KeyError, ValueError, TypeError):
        raise FaithSieveJudgeError('Judge 超时续跑原图无效') from None
    expected_files = []
    for path, value in sorted(files.items()):
        path = _relative_path(path)
        data = _file_bytes(value)
        if _private_read(directory / key / 'inputs' / path, 32 * 1024 * 1024) != data:
            raise FaithSieveJudgeError('Judge 超时续跑的原始材料不一致')
        expected_files.append({'path': path, 'type': 'bytes' if type(value) is bytes else 'text', 'size': len(data)})
    if not strict_equal(frozen.get('files'), expected_files):
        raise FaithSieveJudgeError('Judge 超时续跑的完整文件清单不一致')
    return directory, frozen, files


def inspect_native_timeout(workspace, run, key, record):
    """只读确认旧短时限任务可在原会话续跑；不把失败当成数学证据。"""
    directory, frozen, _files = _inspect_original_native_request(workspace, run, key, record)
    if frozen['timeout_seconds'] != 600:
        raise FaithSieveJudgeError('仅可续跑旧短时限超时任务')
    if (directory / key / 'continuation.json').exists():
        raise FaithSieveJudgeError('局部 Judge 已使用一次续跑机会')
    agent = object.__new__(FaithSieveJudgeAgent)
    agent.run, agent.endpoint = dict(run), {'id': frozen['endpoint_id'], 'model': frozen['endpoint_model'], 'revision': frozen['endpoint_revision']}
    session = get_agent_session(frozen['session_id'])
    if not session or session.get('status') != 'Failed' or session.get('message') != 'Agent harness 超时':
        raise FaithSieveJudgeError('仅可续跑安全结束的旧短时限超时任务')
    turn = agent._audit(session, session_id=frozen['session_id'], task_id=frozen['task_id'], prompt=frozen['prompt'], frozen=frozen)
    if turn.get('status') != 'Failed' or not session.get('native_session_id'):
        raise FaithSieveJudgeError('Judge 原生会话或失败轮次无法确认')
    for name in ('harness', 'endpoint_id', 'endpoint_model'):
        if str(turn.get(name)) != str(frozen.get(name)):
            raise FaithSieveJudgeError('Judge 失败轮次的实际执行参数不一致')
    try:
        stream, _metadata = open_agent_workspace_file(frozen['session_id'], frozen['result_path'])
    except FileNotFoundError:
        pass
    else:
        stream.close()
        raise FaithSieveJudgeError('Judge 已有数学结果，不能续跑')
    remaining = RUN_TIMEOUT_SECONDS - int(run.get('elapsed_seconds') or 0)
    if remaining <= 0:
        raise FaithSieveJudgeError('FaithSieve 已超过原整体时限')
    return validate_native_continuation({
        'kind': 'native_timeout', 'session_id': frozen['session_id'], 'failed_task_id': frozen['task_id'],
        'original_timeout_seconds': 600, 'continuation_task_id': frozen['task_id'] + '-c1',
        'continuation_timeout_seconds': remaining,
        'continuation_prompt': _continuation_prompt(frozen['result_path'],
                                                    external_results_version=frozen.get('external_results_version')),
    }, frozen)


def inspect_completed_native(workspace, run, key, record):
    """只读确认后续待回读 Judge 的真实完成结果，绝不重派或改写材料。"""
    directory, frozen, files = _inspect_original_native_request(workspace, run, key, record)
    agent = object.__new__(FaithSieveJudgeAgent)
    agent.run, agent.endpoint = dict(run), {'id': frozen['endpoint_id'], 'model': frozen['endpoint_model'],
                                          'revision': frozen['endpoint_revision']}
    session = get_agent_session(frozen['session_id'])
    if not session or session.get('status') != 'Completed':
        raise FaithSieveJudgeError('后续局部 Judge 尚未正常完成')
    continuation = None
    continuation_path = directory / key / 'continuation.json'
    if continuation_path.exists():
        from .recovery import read_native_timeout_authorization
        permission = read_native_timeout_authorization(workspace, run, key, record, record['request'])
        continuation = validate_native_continuation(
            parse_json_response(_private_read(continuation_path, 8 * 1024 * 1024).decode('utf-8'), strict_constants=True),
            frozen, authorization=permission)
        if not strict_equal(permission, continuation):
            raise FaithSieveJudgeError('已完成续聊缺少原授权')
    turn = agent._audit(session, session_id=frozen['session_id'], task_id=frozen['task_id'], prompt=frozen['prompt'],
                        frozen=frozen, continuation=continuation)
    if turn.get('status') != 'Completed':
        raise FaithSieveJudgeError('后续局部 Judge 轮次未完成')
    for relative, content in files.items():
        if agent._read_binary(frozen['session_id'], relative) != _file_bytes(content):
            raise FaithSieveJudgeError('Judge 修改了原始材料')
    payload = parse_json_response(agent._read_result(frozen['session_id'], frozen['result_path']), strict_constants=True)
    try:
        canonical = _local_verifier_payload(payload, diagnostic_version=frozen.get('local_diagnostic_version'),
                                            projection_version=frozen.get('result_projection_version'))
    except FaithSieveProtocolError as exc:
        raise FaithSieveJudgeError('后续局部 Judge 结果协议无效：' + str(exc)) from None
    artifact = _relative_path(canonical['artifact'])
    return {'result': payload, 'artifacts': {artifact: agent._read_result(frozen['session_id'], artifact)},
            'execution': {'provider': 'numoj-agent-judge', 'session_id': frozen['session_id'],
                          'task_id': continuation['continuation_task_id'] if continuation else frozen['task_id'],
                          'harness': frozen['harness'], 'endpoint_id': frozen['endpoint_id'], 'decision_source': 'agent'},
            'control': {}}


class FaithSieveJudgeAgent:
    def __init__(self, *, run, endpoint, workspace, celery_app=None, problem=None, tool_runner=None):
        self.run = dict(run)
        self.endpoint = dict(endpoint)
        self.workspace = Path(workspace).resolve()
        self.celery_app = celery_app
        self.problem = dict(problem or {})
        self.tools = tool_runner or DockerFaithSieveTools(self.workspace)
        self.directory = self.workspace / 'faithsieve-work' / 'judge-invocations'
        self.directory.mkdir(parents=True, exist_ok=True)

    def __enter__(self):
        return self

    def __exit__(self, *_exc):
        return False

    def _identity(self, invocation_key):
        if not isinstance(invocation_key, str) or not re.fullmatch(r'[a-z0-9-]+', invocation_key):
            raise FaithSieveJudgeError("Judge 调用编号无效")
        attempt = str(self.run.get('attempt_id') or '')
        session_id, task_id = f'fs-{attempt}-{invocation_key}', f'ft-{attempt}-{invocation_key}'
        if any(not re.fullmatch(r'[A-Za-z0-9_.-]{1,64}', value) for value in (session_id, task_id)):
            raise FaithSieveJudgeError("Judge 持久任务编号无效")
        return session_id, task_id

    def _freeze_request(self, key, request, files):
        path = self.directory / f'{key}.json'
        inputs = self.directory / key / 'inputs'
        metadata = []
        total = 0
        for relative, content in sorted(files.items()):
            relative = _relative_path(relative)
            data = _file_bytes(content)
            total += len(data)
            if len(data) > 32 * 1024 * 1024 or total > 128 * 1024 * 1024:
                raise FaithSieveJudgeError("Judge 输入材料超过大小限制")
            target = inputs / relative
            if target.exists():
                if _private_read(target, 32 * 1024 * 1024) != data:
                    raise FaithSieveJudgeError("Judge 重入材料与已保存原文不一致")
            else:
                atomic_write(target, data)
            metadata.append({'path': relative, 'type': 'bytes' if isinstance(content, bytes) else 'text', 'size': len(data)})
        request = {**request, 'files': metadata}
        if path.exists():
            try:
                existing = json.loads(_private_read(path, 8 * 1024 * 1024))
            except ValueError:
                raise FaithSieveJudgeError("Judge 持久请求无法解析") from None
            if not strict_equal(existing, request):
                raise FaithSieveJudgeError("Judge 重入请求与持久身份不一致")
        else:
            atomic_write(path, json.dumps(request, ensure_ascii=False, indent=2).encode())

    def _audit(self, session, *, session_id, task_id, prompt, frozen=None, continuation=None):
        frozen = frozen or {'endpoint_model': self.endpoint['model'], 'endpoint_revision': self.endpoint.get('revision') or 1}
        expected = {
            'session_id': session_id, 'current_task_id': continuation['continuation_task_id'] if continuation else task_id, 'task_kind': 'judge',
            'judge_kind': 'faithsieve', 'attempt_id': self.run['attempt_id'],
            'submission_id': self.run['submission_id'], 'requested_by': self.run['requested_by'],
            'competition_id': None, 'harness': self.run['harness'],
            'problem_id': self.run.get('problem_id'), 'access_role': 'user',
            'endpoint_id': int(self.endpoint['id']), 'endpoint_model': frozen['endpoint_model'],
            'endpoint_revision': frozen['endpoint_revision'],
        }
        if any(str(session.get(key)) != str(value) for key, value in expected.items()):
            raise FaithSieveJudgeError("Judge 会话冻结元数据不一致")
        turns = get_agent_session_turns(session_id)
        if len(turns) != (2 if continuation else 1) or turns[0].get('task_id') != task_id or turns[0].get('user_message') != prompt:
            raise FaithSieveJudgeError("Judge 轮次身份或完整指令不一致")
        if continuation and (turns[0].get('status') != 'Failed'
                             or turns[1].get('task_id') != continuation['continuation_task_id']
                             or turns[1].get('user_message') != continuation['continuation_prompt']):
            raise FaithSieveJudgeError('Judge 续跑轮次与原失败历史不一致')
        turn = turns[-1]
        if str(turn.get('status') or '').lower() == 'completed':
            turn_expected = {'harness': self.run['harness'], 'endpoint_id': int(self.endpoint['id']), 'endpoint_model': frozen['endpoint_model']}
            if any(str(turn.get(key)) != str(value) for key, value in turn_expected.items()):
                raise FaithSieveJudgeError("Judge 已完成轮次的实际执行参数不一致")
        return turn

    def _read_binary(self, session_id, relative, limit=32 * 1024 * 1024):
        try:
            stream, metadata = open_agent_workspace_file(session_id, _relative_path(relative))
            with stream:
                if metadata['size'] > limit or os.fstat(stream.fileno()).st_nlink != 1:
                    raise FaithSieveJudgeError("Judge 结果工件过大或是硬链接")
                return stream.read(limit + 1)
        except (OSError, ValueError) as exc:
            raise FaithSieveJudgeError("Judge 结果文件无法安全读取") from exc

    def _read_result(self, session_id, relative):
        try:
            return self._read_binary(session_id, relative, _TEXT_LIMIT).decode('utf-8')
        except UnicodeError:
            raise FaithSieveJudgeError("Judge 结果不是 UTF-8 文本") from None

    def render_submission_images(self, pdf, *, invocation_key="image-render", timeout_seconds=600):
        """代码渲染原 PDF；不创建转录或原稿整理 Judge。"""
        if not isinstance(invocation_key, str) or not re.fullmatch(r"[a-z0-9-]+", invocation_key):
            raise FaithSieveJudgeError("图像渲染调用编号无效")
        files, pages = render_submission_images(
            pdf, workspace=self.directory / invocation_key / "rendered",
            tools=self.tools, timeout_seconds=timeout_seconds,
        )
        return {"files": files, "pages": pages}

    def run_role(self, role, prompt, files, expected_result_path, timeout_seconds=None, *, invocation_key,
                 proof_graph_version=1, local_diagnostic_version=None, result_projection_version=None,
                 external_results_version=None):
        if role not in _ROLES:
            raise FaithSieveJudgeError("不支持的 FaithSieve Judge 角色")
        if type(proof_graph_version) is not int or proof_graph_version not in {1, 2, 3}:
            raise FaithSieveJudgeError("Judge 证明图协议版本无效")
        if role == "local-verifier" and proof_graph_version != 3:
            raise FaithSieveJudgeError("图像局部验证必须使用新证明图协议")
        validate_local_diagnostic_version(local_diagnostic_version)
        if local_diagnostic_version is not None and (role != 'local-verifier' or proof_graph_version != 3):
            raise FaithSieveJudgeError("构图诊断仅适用于图像局部验证")
        _validate_result_projection_scope(result_projection_version, role=role, proof_graph_version=proof_graph_version,
                                          diagnostic_version=local_diagnostic_version)
        validate_external_results_version(external_results_version)
        if external_results_version is not None and (role != 'local-verifier' or proof_graph_version != 3
                                                    or local_diagnostic_version is None):
            raise FaithSieveJudgeError("外部结果仅适用于新版图像局部验证")
        session_id, task_id = self._identity(invocation_key)
        saved_request = None
        saved_path = self.directory / f'{invocation_key}.json'
        if saved_path.exists():
            saved_request = parse_json_response(_private_read(saved_path, 8 * 1024 * 1024).decode('utf-8'), strict_constants=True)
        if timeout_seconds is None:
            timeout_seconds = saved_request['timeout_seconds'] if saved_request else (
                RUN_TIMEOUT_SECONDS - int(self.run.get('elapsed_seconds') or 0) if role == 'local-verifier' else 600)
        limit = RUN_TIMEOUT_SECONDS if proof_graph_version == 3 else 3600
        if type(timeout_seconds) is not int or not 1 <= timeout_seconds <= limit:
            raise FaithSieveJudgeError(f'Judge 执行超时必须是 1 至 {limit} 秒的整数')
        result_path = _relative_path(expected_result_path)
        absolute_result_path = f'/workspace/{result_path}'
        instruction = _role_instruction(role, prompt, result_path, proof_graph_version,
                                        local_diagnostic_version=local_diagnostic_version,
                                        external_results_version=external_results_version)
        if saved_request and saved_request.get('prompt') == _role_instruction(
                role, prompt, result_path, proof_graph_version, legacy_environment=True,
                local_diagnostic_version=local_diagnostic_version,
                external_results_version=external_results_version):
            instruction = saved_request['prompt']
        request = {'session_id': session_id, 'task_id': task_id, 'role': role, 'prompt': instruction,
                   'result_path': result_path, 'timeout_seconds': int(timeout_seconds),
                   'harness': self.run['harness'], 'endpoint_id': self.endpoint['id'],
                   'endpoint_model': self.endpoint['model'], 'endpoint_revision': self.endpoint.get('revision') or 1}
        if proof_graph_version in {2, 3}:
            request['proof_graph_version'] = proof_graph_version
        if local_diagnostic_version is not None:
            request['local_diagnostic_version'] = local_diagnostic_version
        if result_projection_version is not None:
            request['result_projection_version'] = result_projection_version
        if external_results_version is not None:
            request['external_results_version'] = external_results_version
        self._freeze_request(invocation_key, request, files)
        session = get_agent_session(session_id)
        continuation = None
        if proof_graph_version == 3 and role == 'local-verifier':
            from .recovery import read_native_timeout_authorization
            from .checkpoints import CheckpointStore
            try:
                record, _size = CheckpointStore(self.workspace)._read_record(invocation_key, strict=True)
            except FileNotFoundError:
                record = None
            if record:
                continuation = read_native_timeout_authorization(self.workspace, self.run, invocation_key, record, record['request'])
            continuation_path = self.directory / invocation_key / 'continuation.json'
            if continuation_path.exists():
                saved_continuation = parse_json_response(_private_read(continuation_path, 8 * 1024 * 1024).decode('utf-8'), strict_constants=True)
                validate_native_continuation(saved_continuation, {**request, 'files': []}, authorization=continuation)
                if continuation is None or not strict_equal(continuation, saved_continuation):
                    raise FaithSieveJudgeError('Judge 续跑缺少一致的原恢复授权')
            elif continuation:
                validate_native_continuation(continuation, request, authorization=continuation)
                inspect_native_timeout(self.workspace, self.run, invocation_key, record)
                atomic_write(continuation_path, json.dumps(continuation, ensure_ascii=False).encode('utf-8'))
            if continuation and session is None:
                raise FaithSieveJudgeError('Judge 续跑的原始会话不存在')
            if continuation and session and session.get('current_task_id') == task_id:
                submit_judge_turn(
                    session_id=session_id, task_id=continuation['continuation_task_id'],
                    requested_by=self.run['requested_by'], judge_kind='faithsieve', submission_id=self.run['submission_id'],
                    attempt_id=self.run['attempt_id'], competition_id=None, harness=self.run['harness'], endpoint=self.endpoint,
                    prompt=continuation['continuation_prompt'], files=None, title='FaithSieve local-verifier',
                    timeout_seconds=continuation['continuation_timeout_seconds'], celery_app=self.celery_app,
                    problem_id=self.run.get('problem_id'), problem_title=self.problem.get('title'), project_skill=False,
                )
                raise FaithSievePending(session_id=session_id, task_id=continuation['continuation_task_id'], role=role, invocation_key=invocation_key)
        if session is None:
            submit_judge_turn(
                session_id=session_id, task_id=task_id, requested_by=self.run['requested_by'],
                judge_kind='faithsieve', submission_id=self.run['submission_id'],
                attempt_id=self.run['attempt_id'], competition_id=None, harness=self.run['harness'],
                endpoint=self.endpoint, prompt=instruction, files=files,
                title=f'FaithSieve {role}', timeout_seconds=int(timeout_seconds),
                celery_app=self.celery_app, problem_id=self.run.get('problem_id'),
                problem_title=self.problem.get('title'), project_skill=False,
            )
            raise FaithSievePending(session_id=session_id, task_id=task_id, role=role, invocation_key=invocation_key)
        turn = self._audit(session, session_id=session_id, task_id=task_id, prompt=instruction, continuation=continuation)
        active_task_id = continuation['continuation_task_id'] if continuation else task_id
        statuses = [str(record.get('status') or '').lower().replace('_', '') for record in (session, turn)]
        if any(status in _TERMINAL and status != 'completed' for status in statuses):
            raise FaithSieveJudgeError("Judge 未正常完成，无法得出可靠结论")
        if any(status != 'completed' for status in statuses):
            raise FaithSievePending(session_id=session_id, task_id=active_task_id, role=role, invocation_key=invocation_key)
        for relative, content in files.items():
            if self._read_binary(session_id, relative) != _file_bytes(content):
                raise FaithSieveJudgeError("Judge 修改了输入材料，结果无法信任")
        try:
            raw = self._read_result(session_id, result_path)
            payload = parse_json_response(raw, strict_constants=True) if proof_graph_version in {2, 3} else json.loads(raw)
        except ValueError:
            raise FaithSieveJudgeError("Judge 角色结果不是有效 JSON") from None
        if role == 'local-verifier':
            try:
                canonical = _local_verifier_payload(payload, diagnostic_version=local_diagnostic_version,
                                                    projection_version=result_projection_version)
            except FaithSieveProtocolError as exc:
                raise FaithSieveJudgeError("Judge 角色结果协议无效：" + str(exc)) from None
        elif (not isinstance(payload, dict) or set(payload) != {'status', 'artifact', 'report'}
              or payload.get('status') not in _ROLES[role] or not isinstance(payload.get('report'), str)):
            raise FaithSieveJudgeError("Judge 角色结果协议无效")
        artifact_path = _relative_path(canonical['artifact'] if role == 'local-verifier' else payload['artifact'])
        artifacts = {artifact_path: self._read_result(session_id, artifact_path)}
        execution = {'provider': 'numoj-agent-judge', 'session_id': session_id, 'task_id': active_task_id,
                     'harness': self.run['harness'], 'endpoint_id': self.endpoint['id']}
        if role == 'numeric-evaluator' and proof_graph_version == 1:
            expression_path = f'{result_path}.expressions.json'
            try:
                expressions = self._read_result(session_id, expression_path)
                relations = json.loads(expressions)
            except (ValueError, FaithSieveJudgeError):
                relations, expressions = {'relations': []}, '{"relations":[]}'
            checked = self.tools.run('numeric', {'expressions': relations}, timeout_seconds=min(int(timeout_seconds), 60))
            if checked.get('exit_code') != 0 or isinstance(checked.get('exit_code'), bool):
                raise FaithSieveJudgeError("独立符号复验没有成功执行")
            artifacts[expression_path] = expressions
            observed = checked.get('status', 'inconclusive')
            if observed != payload['status']:
                payload = {**payload, 'status': 'inconclusive', 'report': payload['report'] + '；独立符号复验与 Agent 结论不一致'}
            execution.update(checked)
            execution.update(tool_executed=True, verified=observed in {'passed', 'refuted'}, command_count=1)
            artifacts[artifact_path] += '\n\n## 独立符号复验原始记录\n\n```json\n' + json.dumps(checked, ensure_ascii=False, indent=2) + '\n```\n'
        elif role in {'numeric-evaluator', 'local-verifier'}:
            execution['decision_source'] = 'agent'
        return {'result': payload, 'artifacts': artifacts, 'execution': execution, 'control': {}}

    def compile_lean(self, files, statement_path, timeout_seconds=300):
        result = self.tools.run('compile', {'path': _relative_path(statement_path), 'timeout_seconds': int(timeout_seconds)},
                                files=files, timeout_seconds=int(timeout_seconds) + 10)
        if isinstance(result.get('exit_code'), bool) or not isinstance(result.get('exit_code'), int):
            raise FaithSieveJudgeError("Lean 工具缺少实际退出码")
        return {**result, 'diagnostics': str(result.get('stdout') or '') + str(result.get('stderr') or ''), 'tool_executed': True}

    def _viewed_source_pages(self, task_id):
        """只采信 Harness 落盘的调用/结果，原稿 Agent 的文字报告不是工具证据。"""
        viewed, calls, results = set(), {}, {}
        path = agent_run_trace_dir(task_id) / 'numoj_trace_v1.jsonl'
        if not path.exists():
            return viewed
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
        with os.fdopen(fd, 'rb') as stream:
            info = os.fstat(stream.fileno())
            if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or info.st_size > 256 * 1024 * 1024:
                return viewed
            for line in iter(lambda: stream.readline(16 * 1024 * 1024 + 1), b''):
                if len(line) > 16 * 1024 * 1024:
                    return set()
                try:
                    record = json.loads(line)
                except ValueError:
                    return set()
                if not isinstance(record, dict) or record.get('type') != 'numoj_trace' or record.get('version') != 1:
                    continue
                event = record.get('event')
                if not isinstance(event, dict):
                    continue
                native_id = str(event.get('id') or '')
                if not native_id or len(native_id) > 512:
                    continue
                kind = event.get('kind')
                if kind in {'tool', 'tool_call'} and native_id.endswith(':call'):
                    name = str(event.get('meta') or '').lower()
                    if name not in {'read', 'read_file', 'view_image', 'functions.view_image'}:
                        continue
                    try:
                        args = json.loads(event.get('text') or '{}')
                    except ValueError:
                        continue
                    if not isinstance(args, dict):
                        continue
                    match = re.fullmatch(r'(?:/workspace/)?source-pages/page-([1-9][0-9]*)\.png', str(args.get('path') or args.get('file_path') or ''))
                    if match:
                        identity = native_id[:-5]
                        value = (int(match.group(1)), name in {'view_image', 'functions.view_image'})
                        if identity in calls and calls[identity] != value:
                            return set()
                        calls[identity] = value
                elif kind in {'tool_result', 'tool-result'} and native_id.endswith(':result'):
                    identity = native_id[:-7]
                    value = (str(event.get('text') or ''), bool(event.get('is_error')))
                    if identity in results and results[identity] != value:
                        return set()
                    results[identity] = value
        for identity, (page, image_tool) in calls.items():
            if identity not in results:
                continue
            text, failed = results[identity]
            has_image = image_tool or bool(re.search(r'''["']type["']\s*:\s*["'](?:image|image_url|input_image)["']''', text))
            if not failed and has_image:
                viewed.add(page)
        return viewed

    def extract_submission(self, pdf, *, problem_text='', invocation_key='source-extraction', timeout_seconds=SOURCE_TIMEOUT_SECONDS):
        if not isinstance(pdf, bytes) or not pdf.startswith(b'%PDF-') or len(pdf) > _PDF_LIMIT:
            raise FaithSieveJudgeError("原稿不是有效 PDF 或超过 20 MiB")
        if self.endpoint.get('category') != 'omni':
            return {'status': 'inconclusive', 'text': '', 'report': '逐页原稿图像核对需要选择全模态 LLM 节点；当前节点无法可靠查看数学原稿。', 'execution': {}}
        self._identity(invocation_key)
        source = self.directory / invocation_key / 'rendered'
        files, pages = render_submission_images(pdf, workspace=source, tools=self.tools, timeout_seconds=timeout_seconds)
        prompt = (
            '学生原稿仅以逐页 PNG 图像提供，完整页清单见 pages.json。'
            '必须用图像工具逐页查看，核对完整数学陈述、记号和顺序后忠实整理为 `faithsieve-work/source/submission.md`。'
            '不要调用 PDF 文本提取或 OCR。'
            '本任务只确认图像中实际写出的字符，不判断数学正确性，不猜测作者的正确意图。'
            '转录只以页清单和原稿图像为依据，不使用题面或其他定义校正原稿。'
            '按原图保留全部记号及其位置，'
            '不得按预期定义或数学惯例改写原稿。'
            '清晰可辨的符号即使与数学预期冲突或疑似原稿笔误，也必须照原样保留，'
            '在中文 report 中记录位置和原样读法，不得修正；不得仅因此返回 inconclusive。'
            '字符形状确实无法分辨时，先对相应区域裁剪或放大并用图像工具重新查看；'
            '仍无法确定实际字符时才写 `[无法辨认]` 并返回 inconclusive，禁止猜测。'
            '保留每页标题 `## 第 N 页` 和段落位置。'
            '图像工具不可用、缺页、无法辨认或不能完整核对时返回 inconclusive，禁止猜测。\n'
            '将 {"status":"ok|inconclusive","artifact":"faithsieve-work/source/submission.md","report":"逐页图像核对记录及未能辨认的内容"}'
            ' 写入 /workspace/source-result.json。该结果 JSON 与转录工件是两个独立文件。'
            '仅完整核对且没有无法辨认内容时可返回 ok。'
        )
        prepared = self.run_role('source-extractor', prompt, files, 'source-result.json', timeout_seconds, invocation_key=invocation_key)
        text = prepared['artifacts'].get('faithsieve-work/source/submission.md', '')
        status = prepared['result']['status']
        viewed = self._viewed_source_pages(prepared['execution']['task_id'])
        image_checked = all(page['page'] in viewed for page in pages)
        if not text or '[无法辨认' in text or any(f'## 第 {page["page"]} 页' not in text for page in pages):
            status = 'inconclusive'
        if not image_checked:
            status = 'inconclusive'
        execution = {**prepared['execution'], 'image_verified': image_checked, 'viewed_pages': sorted(viewed)}
        report = f'已直接渲染 {len(pages)} 页原稿图像。\n' + prepared['result']['report']
        if not image_checked:
            report += '\n未找到每页成功读取图像的实际 Harness 工具轨迹，无法确认原稿已完整核对。'
        return {'status': status, 'text': text, 'report': report, 'execution': execution}

    def cancel_pending(self):
        from backend.oj_modules.tasks.agent.control import build_agent_run_terminator
        terminator = build_agent_run_terminator(self.celery_app)
        for path in sorted(self.directory.glob('*.json')):
            record = json.loads(_private_read(path, 8 * 1024 * 1024))
            session = get_agent_session(record['session_id'])
            if session is None:
                continue
            continuation = None
            continuation_path = self.directory / path.stem / 'continuation.json'
            if continuation_path.exists():
                permission = _cleanup_native_continuation_authorization(self.workspace, self.run, path.stem)
                continuation = validate_native_continuation(
                    parse_json_response(_private_read(continuation_path, 8 * 1024 * 1024).decode('utf-8'), strict_constants=True),
                    record, authorization=permission)
            self._audit(session, session_id=record['session_id'], task_id=record['task_id'], prompt=record['prompt'], frozen=record,
                        continuation=continuation)
            if str(session.get('status') or '').lower().replace('_', '') not in _TERMINAL:
                result = terminator(continuation['continuation_task_id'] if continuation else record['task_id'])
                if result.get('errors') or not result.get('canceled'):
                    raise FaithSieveJudgeError("无法确认待处理 Judge 已安全终止")


__all__ = ['FaithSieveJudgeAgent', 'FaithSieveJudgeError', 'FaithSievePending', 'DockerFaithSieveTools', 'render_submission_images']
