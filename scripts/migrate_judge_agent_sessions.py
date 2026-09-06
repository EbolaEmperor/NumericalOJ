#!/usr/bin/env python3
"""停服备份后一次性导入历史 Judge；导入会话并搬迁旧运行目录，不补扣费用。"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import zipfile
from tempfile import NamedTemporaryFile, TemporaryDirectory, mkdtemp

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from backend.oj_modules.agents.judge import judge_session_id
from backend.oj_modules.agents.sessions import (
    create_agent_session, get_agent_session, get_agent_session_runtime_config,
)
from backend.oj_modules.agents.trace_store import (
    ingest_agent_trace_records, save_agent_trace_token_usage,
    _normalize_canonical_record, _normalized_token_usage,
)
from backend.oj_modules.agents.workspace import ensure_agent_workspace
from backend.oj_modules.db_services import upsert_agent_run_snapshot
from backend.oj_modules.infrastructure.mysql import get_db_connection
from backend.oj_modules.ranking.db import submission_dir
from backend.oj_modules.ranking.reverse_judge.traces import collect_agent_trace_messages, collect_agent_token_usage
from backend.oj_modules.shared.archive import ArchiveExtractionError, extract_zip, ZipExtractionPolicy
from backend.oj_modules import config
from deploy.backup.orchestrator import read_manifest, validate_manifest_artifact
from deploy.preflight import validate_production_config

MIGRATION_VERSION = 1


def _progress(message):
    print(f'[judge-history] {_display_text(message)}', flush=True)


def _display_text(value):
    """日志和 JSON 展示使用转义文字，磁盘上的原始名称保持不变。"""
    return str(value).encode('utf-8', errors='backslashreplace').decode('utf-8')


def _safe_attempt(attempt):
    return re.sub(r'[^A-Za-z0-9_.-]+', '_', str(attempt or 'legacy')).strip('._')[:96] or 'legacy'


def _is_directory(path):
    """只用于选择旧材料布局；无法读取时走缺失材料的回退。"""
    try:
        return path.is_dir()
    except OSError:
        return False


def _available_source(path, missing, label):
    """读取不了的旧材料记入报告，不影响其他历史会话。"""
    try:
        return path.open('rb')
    except OSError as exc:
        reason = '权限不足' if isinstance(exc, PermissionError) else ('文件已不存在' if isinstance(exc, FileNotFoundError) else str(exc))
        missing.append(f'历史材料不可读取（{reason}）：{label}')
        return None


def _rows():
    conn = get_db_connection()
    try:
        with conn.cursor() as cursor:
            cursor.execute("""SELECT s.*, c.scoring_mode, c.title AS competition_title
                FROM ranking_submissions s JOIN ranking_competitions c ON c.id=s.competition_id
                WHERE c.scoring_mode IN ('agent_judge', 'reverse_judge') ORDER BY s.id""")
            submissions = cursor.fetchall() or []
            cursor.execute('SELECT * FROM ranking_reverse_judge_steps ORDER BY submission_id, step_order')
            steps = cursor.fetchall() or []
            cursor.execute('SELECT * FROM ranking_judge_results ORDER BY submission_id, rule_id')
            results = cursor.fetchall() or []
            cursor.execute("""SELECT submission_id, judge_kind, attempt_id FROM agent_sessions
                WHERE task_kind='judge' AND session_id LIKE 'jd-%-history'""")
            historical = cursor.fetchall() or []
    finally:
        conn.close()
    by_submission = {}
    for result in results:
        by_submission.setdefault(result['submission_id'], []).append(result)
    historical_by_submission = {}
    for session in historical:
        historical_by_submission.setdefault(session['submission_id'], []).append(session)
    for submission in submissions:
        submission['judge_results'] = by_submission.get(submission['id'], [])
        submission['historical_sessions'] = historical_by_submission.get(submission['id'], [])
    return submissions, {(row['submission_id'], row['step_key']): row for row in steps}


def _directories(root, missing=None):
    def unavailable(exc):
        if missing is not None:
            missing.append(f'无法枚举历史目录（{type(exc).__name__}）：{root}')
    _, names, _ = next(os.walk(root, onerror=unavailable), (root, [], []))
    return [root / name for name in names]


def _sources(submission, steps, missing=None):
    """发现当前记录、轨迹、答案归档和仅剩 workspace 的旧 attempt。"""
    sid = submission['id']
    current = _safe_attempt(submission.get('judge_attempt_id'))
    root = Path(submission_dir(sid))
    historical = submission.get('historical_sessions') or []
    if submission['scoring_mode'] == 'agent_judge':
        trace_root = root / 'agent_judge_trace'
        workspace_root = Path(config.AGENT_JUDGE_WORKSPACE_ROOT) / str(sid)
        attempts = {current} | {path.name for path in _directories(trace_root, missing)}
        attempts.update(str(row['attempt_id'] or 'legacy') for row in historical if row['judge_kind'] == 'agent_judge'
                        and not str(row['attempt_id']).startswith('unknown-workspace-'))
        known_workspaces = set()
        for attempt in sorted(attempts):
            raw = _actual_attempt(submission, attempt)
            key = hashlib.sha256(str(raw or 'legacy').encode()).hexdigest()[:16]
            known_workspaces.add(key)
            yield 'agent_judge', attempt, trace_root / attempt, submission if attempt == current else {}, workspace_root / key
        workspaces = {path.name: path for path in _directories(workspace_root, missing)}
        for row in historical:
            attempt = str(row['attempt_id'] or '')
            if row['judge_kind'] == 'agent_judge' and attempt.startswith('unknown-workspace-'):
                name = attempt.removeprefix('unknown-workspace-')
                workspaces[name] = workspace_root / name
        for path in workspaces.values():
            if path.name not in known_workspaces:
                yield 'agent_judge', f'unknown-workspace-{path.name}', None, {}, path
    else:
        trace_root = root / 'reverse_agent_trace'
        workspace_root = Path(config.REVERSE_JUDGE_WORKSPACE_ROOT) / str(sid)
        attempts = {current} | {path.name for path in _directories(trace_root, missing)} | {path.name for path in _directories(workspace_root, missing)}
        attempts.update(str(row['attempt_id'] or 'legacy') for row in historical if row['judge_kind'] != 'agent_judge')
        quality_attempts = {str(row['attempt_id'] or 'legacy') for row in historical if row['judge_kind'] == 'reverse_quality'}
        archives = root / 'reverse_agent_answers'
        try:
            attempts.update(path.stem for path in archives.iterdir() if path.suffix == '.zip')
        except OSError as exc:
            if missing is not None:
                missing.append(f'无法枚举历史答案归档（{type(exc).__name__}）：{archives}')
        for attempt in sorted(attempts):
            workspace = workspace_root / attempt
            quality = steps.get((sid, 'quality_gate'), {}) if attempt == current else {}
            yield 'reverse_answer', attempt, trace_root / attempt, steps.get((sid, 'agent_answer'), {}) if attempt == current else {}, workspace
            if quality and quality.get('status') != 'pending' or attempt in quality_attempts or _is_directory(workspace / 'quality_gate_source'):
                yield 'reverse_quality', attempt, None, quality, workspace


def _extract_copy(archive, output, staging, missing, label):
    archive_copy = Path(staging) / (output.name + '.zip')
    source = _available_source(archive, missing, label)
    if source is None:
        return False
    try:
        with source, archive_copy.open('wb') as copied:
            shutil.copyfileobj(source, copied)
        extract_zip(archive_copy, output, policy=ZipExtractionPolicy(
            max_members=config.REVERSE_PACKAGE_MAX_MEMBERS, max_file_bytes=config.REVERSE_PACKAGE_MAX_FILE_BYTES,
            max_total_bytes=config.REVERSE_PACKAGE_MAX_TOTAL_BYTES, max_compression_ratio=config.REVERSE_PACKAGE_MAX_COMPRESSION_RATIO,
            unsafe_member_action='raise', cleanup_on_error=True,
        ))
    except (OSError, ArchiveExtractionError, zipfile.BadZipFile) as exc:
        missing.append(f'历史归档无法安全解包：{label}（{exc}）')
        return False
    return True


def _uploaded_material(submission, staging, missing):
    """执行 workspace 已清理时，从仍保留的提交副本恢复输入，明确区分执行产物。"""
    uploaded = submission.get('code_path')
    target = Path(staging) / 'uploaded'
    if not uploaded:
        return target
    source = Path(uploaded)
    stream = _available_source(source, missing, '原提交')
    if stream is None:
        return target
    try:
        with stream:
            zipped = zipfile.is_zipfile(stream)
            if not zipped:
                stream.seek(0)
                target.mkdir()
                (target / source.name).write_bytes(stream.read())
    except OSError as exc:
        missing.append(f'原提交无法复制：{exc}')
        return target
    if zipped and not _extract_copy(source, target, staging, missing, '原提交'):
        return target
    missing.append('执行 workspace 已缺失；已从原提交恢复输入副本，不代表最终执行文件')
    return target


def _workspace_materials(submission, kind, attempt, source, staging, missing, *, output=None):
    if kind == 'agent_judge':
        if _is_directory(source):
            return {'historical_workspace': (source, True)}
        if output is not None and _is_directory(output / 'historical_workspace'):
            return {}
        return {'historical_workspace/submission': (_uploaded_material(submission, staging, missing), True)}
    if kind == 'reverse_quality' and _is_directory(source / 'quality_gate_source'):
        return {'audit': (source / 'quality_gate_source', True)}
    # 先为 AI 作答复制公开材料，再把共用的完整材料搬给质量会话。
    package = source / 'package'
    if not _is_directory(package):
        if kind == 'reverse_quality' and output is not None and _is_directory(output / 'audit'):
            return {}
        package = _uploaded_material(submission, staging, missing)
    roots = [package] + _directories(package, missing)
    material = next((path for path in roots if _is_directory(path / 'problem')), package)
    if kind == 'reverse_quality':
        return {'audit': (material, True)}
    materials = {'problem': (material / 'problem', False)}
    archive = Path(submission_dir(submission['id'])) / 'reverse_agent_answers' / f'{attempt}.zip'
    output = Path(staging) / 'answer'
    if _extract_copy(archive, output, staging, missing, '该轮 AI 答案归档'):
        materials['template'] = (output, True)
    else:
        missing.append('该轮 AI 答案归档不可取得；模板副本不代表最终作答')
        materials['template'] = (material / 'template', False)
    return materials


def _trace_records(task_id, trace, staging, missing):
    records = []
    if trace is None:
        missing.append('历史执行轨迹不可取得')
        return records, None
    # 先复制到临时目录，再沿用旧格式解析器读取轨迹。
    safe_trace = Path(staging) / 'trace'
    _transfer_path(trace, safe_trace, missing, f'{task_id} 复制轨迹')
    canonical = safe_trace / 'numoj_trace_v1.jsonl'
    stream = _available_source(canonical, missing, '规范轨迹')
    if stream is not None:
        seen = set()
        try:
            with stream:
                for line in stream:
                    try:
                        record = json.loads(line)
                        event = record.get('event') or {}
                        source_id = event.get('id')
                        if record.get('type') != 'numoj_trace' or source_id in seen:
                            continue
                        record['sequence'] = len(records) + 1
                        if _normalize_canonical_record(task_id, record) is None:
                            continue
                        seen.add(source_id)
                        records.append(record)
                    except (ValueError, TypeError, AttributeError):
                        missing.append('规范轨迹包含无法解析的记录，已跳过')
        except OSError as exc:
            missing.append(f'规范轨迹读取失败，保留已读取记录：{exc}')
    else:
        messages = collect_agent_trace_messages(str(safe_trace), full_history=True)
        missing.append('旧格式轨迹已全量扫描；文本沿用历史展示截断规则，图片与非文本内容未导入，原始轨迹仍保留原目录')
        for index, message in enumerate(messages, 1):
            record = {'version': 1, 'type': 'numoj_trace', 'sequence': index, 'event': {**message, 'id': f'history-{index}'}}
            if _normalize_canonical_record(task_id, record):
                records.append(record)
    if not records:
        missing.append('历史执行轨迹没有可转换事件')
    return records, collect_agent_token_usage(str(safe_trace))


def _identity(submission, kind, actual_attempt):
    return {'task_kind': 'judge', 'judge_kind': kind, 'requested_by': submission['username'],
                'submission_id': submission['id'], 'competition_id': submission['competition_id'], 'attempt_id': actual_attempt}


def _actual_attempt(submission, attempt):
    if attempt == _safe_attempt(submission.get('judge_attempt_id')):
        return submission.get('judge_attempt_id')
    for row in submission.get('historical_sessions') or []:
        if str(row['attempt_id'] or 'legacy') == attempt:
            return row['attempt_id']
    return attempt


def _run_file_command(command, missing, label):
    try:
        result = subprocess.run(command, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
        if result.returncode == 0:
            return True
        detail = result.stderr.decode('utf-8', errors='backslashreplace').strip()
    except OSError as exc:
        detail = str(exc)
    message = f'{label}失败，继续处理其他材料：{detail}'
    missing.append(_display_text(message))
    _progress(message)
    return False


def _transfer_path(source, target, missing, label, *, move=False):
    """交给系统 cp -R / mv 搬整个目录，不逐文件枚举或检查。"""
    try:
        target.parent.mkdir(parents=True, exist_ok=True)
        if not move:
            destination = target.parent if os.path.lexists(target) and source.name == target.name else target
            return _run_file_command(['cp', '-RP', '--', str(source), str(destination)], missing, label)
        if not os.path.lexists(target):
            return _run_file_command(['mv', '--', str(source), str(target)], missing, label)
        # 旧版本可能已复制部分内容；先搬出源目录，成功后才替换旧副本。
        holding = Path(mkdtemp(prefix='.history-move-', dir=target.parent))
        pending = holding / 'material'
        if not _run_file_command(['mv', '--', str(source), str(pending)], missing, label):
            holding.rmdir()
            return False
        if (not _run_file_command(['rm', '-rf', '--', str(target)], missing, label)
                or not _run_file_command(['mv', '--', str(pending), str(target)], missing, label)):
            _run_file_command(['mv', '--', str(pending), str(source)], missing, f'{label}恢复源目录（暂存位置 {pending}）')
            return False
        holding.rmdir()
        return True
    except OSError as exc:
        missing.append(_display_text(f'{label}失败，继续处理其他材料：{exc}'))
        return False


def _copy_workspace_materials(session_id, materials, missing, *, move_allowed=True):
    root = ensure_agent_workspace(session_id, check_quota=False)
    transferred = 0
    for relative, (source, move) in materials.items():
        move = move and move_allowed
        _progress(f'{session_id}：{"移动" if move else "复制"} {relative}')
        transferred += _transfer_path(source, root / relative, missing, f'{session_id} 搬迁 {relative}', move=move)
    return root, transferred, transferred == len(materials) and move_allowed


def _history_record(kind, record, missing):
    fields = ('status', 'score', 'grade_details', 'judge_results', 'error_message') if kind == 'agent_judge' else ('status', 'score', 'max_score', 'result_json', 'error_message')
    return {'result': {key: record.get(key) for key in fields}, 'missing': sorted({_display_text(item) for item in missing})}


def _save_runtime(session_id, runtime):
    conn = get_db_connection()
    try:
        with conn.cursor() as cursor:
            cursor.execute('UPDATE agent_sessions SET runtime_config_json=%s WHERE session_id=%s',
                           (json.dumps(runtime, ensure_ascii=True), session_id))
        conn.commit()
    finally:
        conn.close()


def migrate_one(submission, kind, attempt, trace, record, source, *, move_allowed=True):
    actual_attempt = _actual_attempt(submission, attempt)
    canonical_id = judge_session_id(submission['id'], actual_attempt, kind)
    native = get_agent_session(canonical_id)
    identity = _identity(submission, kind, actual_attempt)
    if native:
        if any(native.get(key) != value for key, value in identity.items()):
            raise RuntimeError(f'正式会话身份核验失败：{canonical_id}')
        return {'session_id': canonical_id, 'existing_native_session': True}
    session_id = canonical_id + '-history'
    existing = get_agent_session(session_id)
    runtime = get_agent_session_runtime_config(session_id) if existing else {}
    if existing and (not runtime.get('historical_import') or any(existing.get(key) != value for key, value in identity.items())):
        raise RuntimeError(f'历史会话 ID 已被非导入会话占用：{session_id}')
    if runtime.get('historical_import_completed') == MIGRATION_VERSION:
        if not runtime.get('workspace_moved'):
            missing = list(runtime.get('missing') or [])
            complete = True
            if _is_directory(source):
                with TemporaryDirectory(prefix='numoj-judge-history-') as staging:
                    output = ensure_agent_workspace(session_id, check_quota=False)
                    materials = _workspace_materials(submission, kind, attempt, source, Path(staging), missing, output=output)
                    _, transferred, complete = _copy_workspace_materials(session_id, materials, missing, move_allowed=move_allowed)
                    runtime['transferred_paths'] = transferred
            runtime.update(workspace_moved=complete, missing=missing)
            _save_runtime(session_id, runtime)
        _progress(f'{session_id}：已完成，跳过')
        return {'session_id': session_id, 'existing': True, 'material_complete': runtime['workspace_moved']}
    if not existing:
        create_agent_session(
            session_id=session_id, task_id=session_id, requested_by=submission['username'],
            harness=submission.get('agent_endpoint_harness') or 'claude_code',
            endpoint_id=submission.get('agent_endpoint_id') or 0, endpoint_revision=1,
            endpoint_model=submission.get('agent_endpoint_model') or '历史节点未知',
            user_message='导入历史评测记录（不重新执行）', task_kind='judge',
            judge_kind=kind, submission_id=submission['id'], attempt_id=actual_attempt,
            competition_id=submission['competition_id'], title=f'历史 Judge · {submission["id"]} · {kind}'[:64],
            runtime_config={'historical_import': True},
        )
    missing = []
    _progress(f'{session_id}：准备历史轨迹和材料')
    if attempt.startswith('unknown-workspace-'):
        missing.append('旧 workspace 的原始评测 attempt 无法恢复，使用独立历史标识')
    if not record:
        missing.append('该历史 attempt 的原始评测结果不可取得')
    with TemporaryDirectory(prefix='numoj-judge-history-') as staging:
        staging = Path(staging).resolve()
        records, usage = _trace_records(session_id, trace, staging, missing)
        if not usage:
            missing.append('历史用量不可取得；未推算或补记费用')
        output = ensure_agent_workspace(session_id, check_quota=False)
        materials = _workspace_materials(submission, kind, attempt, source, staging, missing, output=output)
        output, transferred, material_complete = _copy_workspace_materials(session_id, materials, missing, move_allowed=move_allowed)
        history = _history_record(kind, record, missing)
        conclusion = '历史评测导入；原有费用不重复记账。\n\n' + json.dumps(history, ensure_ascii=False, default=str, indent=2)
        (output / 'historical_record.json').write_text(
            json.dumps(history, ensure_ascii=True, default=str, indent=2), encoding='utf-8',
        )
    ingest_agent_trace_records(session_id, records, final=True)
    if usage:
        save_agent_trace_token_usage(session_id, usage)
    upsert_agent_run_snapshot({
        'task_id': session_id, 'session_id': session_id, 'requested_by': submission['username'],
        'task_kind': 'judge', 'harness': submission.get('agent_endpoint_harness') or 'claude_code',
        'endpoint_id': submission.get('agent_endpoint_id'), 'status': 'Completed', 'stage': 'finished',
        'harness_status': 'completed', 'message': '历史评测已归档', 'conclusion': conclusion,
    })
    runtime = {'historical_import': True, 'historical_import_completed': MIGRATION_VERSION,
               'missing': history['missing'], 'transferred_paths': transferred, 'material_complete': material_complete,
               'workspace_moved': material_complete,
               'trace_events': len(records), 'token_usage': _normalized_token_usage(usage)}
    _save_runtime(session_id, runtime)
    _progress(f'{session_id}：完成，搬迁 {transferred} 个目录、{len(records)} 条轨迹，{len(history["missing"])} 项缺失说明')
    return {'session_id': session_id, **runtime}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--confirm-writers-stopped', action='store_true', required=True)
    parser.add_argument('--backup-manifest', type=Path, required=True)
    parser.add_argument('--backup-plan', type=Path, required=True)
    parser.add_argument('--report', type=Path, required=True)
    args = parser.parse_args(argv)
    _progress('校验生产配置和部署前数据库备份')
    validate_production_config(ROOT / '.env')
    backup = read_manifest(args.backup_manifest)
    if backup.get('backup_status') != 'complete' or not backup.get('completed_at'):
        raise ValueError('必须先完成并核验数据库备份')
    if not (backup.get('gzip_crc_verified') is True or backup.get('prepared') is True):
        raise ValueError('备份未通过完整性核验')
    validate_manifest_artifact(args.backup_manifest, backup, plan_path=args.backup_plan)
    _progress('数据库备份核验通过，读取历史提交')
    report = []
    missing = []
    completed = False
    current = None
    try:
        submissions, steps = _rows()
        _progress(f'发现 {len(submissions)} 条评测提交；会话按类别和历史 attempt 分别导入')
        for index, submission in enumerate(submissions, 1):
            current = {'submission_id': submission['id']}
            _progress(f'提交 {index}/{len(submissions)}（ID {submission["id"]}），已处理 {len(report)} 个会话')
            workspace_results = {}
            for source in list(_sources(submission, steps, missing)):
                current.update(judge_kind=source[0], attempt=source[1])
                workspace = source[-1]
                # AI 公开副本尚未复制完时，质量材料先复制，下一次再搬走共享目录。
                result = migrate_one(submission, *source, move_allowed=workspace_results.get(workspace, True))
                report.append(result)
                workspace_results[workspace] = workspace_results.get(workspace, True) and result.get('material_complete', False)
            for workspace, complete in workspace_results.items():
                if complete:
                    _run_file_command(['rm', '-rf', '--', str(workspace)], missing, f'清理旧工作目录 {workspace}')
        completed = True
    finally:
        args.report.parent.mkdir(parents=True, exist_ok=True)
        with NamedTemporaryFile(mode='w', encoding='utf-8', dir=args.report.parent, prefix='.judge-migration-', delete=False) as stream:
            temporary_report = Path(stream.name)
            json.dump({'version': MIGRATION_VERSION, 'completed': completed, 'sessions': report,
                       'discovery_missing': sorted(set(missing)), 'interrupted_at': None if completed else current},
                      stream, ensure_ascii=True, indent=2)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary_report, args.report)
    _progress(f'Judge 历史迁移完成：{len(report)} 个会话；报告 {args.report}')
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
