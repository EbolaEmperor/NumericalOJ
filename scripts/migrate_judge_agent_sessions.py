#!/usr/bin/env python3
"""停服备份后一次性导入历史 Judge；只新增会话/副本，不删除旧数据或补扣费用。"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import sys
import zipfile
from tempfile import NamedTemporaryFile, TemporaryDirectory

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from backend.oj_modules.agents.judge import judge_session_id
from backend.oj_modules.agents.sessions import (
    create_agent_session, get_agent_session, get_agent_session_runtime_config,
)
from backend.oj_modules.agents.trace_store import (
    ingest_agent_trace_records, save_agent_trace_token_usage,
    _normalize_canonical_record, get_agent_trace_token_usage, _normalized_token_usage,
)
from backend.oj_modules.agents.workspace import (
    inject_agent_workspace_files, ensure_agent_workspace, open_agent_workspace_file, build_agent_workspace_tree,
)
from backend.oj_modules.db_services import upsert_agent_run_snapshot
from backend.oj_modules.infrastructure.mysql import get_db_connection
from backend.oj_modules.ranking.db import submission_dir
from backend.oj_modules.ranking.reverse_judge.traces import collect_agent_trace_messages, collect_agent_token_usage
from backend.oj_modules.shared.archive import extract_zip, ZipExtractionPolicy
from backend.oj_modules import config
from deploy.backup.orchestrator import read_manifest, validate_manifest_artifact
from deploy.preflight import validate_production_config

MIGRATION_VERSION = 1
TRACE_FIELDS = ('event_id', 'event_order', 'kind', 'title', 'text', 'meta', 'format', 'is_error', 'message_id')


def _safe_attempt(attempt):
    return re.sub(r'[^A-Za-z0-9_.-]+', '_', str(attempt or 'legacy')).strip('._')[:96] or 'legacy'


def _safe_directory(path):
    """历史路径任何祖先都不得是软链接；材料只读，不替换原目录。"""
    try:
        return all(stat.S_ISDIR(part.lstat().st_mode) for part in (path.absolute(), *path.absolute().parents))
    except FileNotFoundError:
        return False


def _open_source(path):
    absolute = path.absolute()
    fd = os.open(absolute.anchor, os.O_RDONLY | os.O_DIRECTORY)
    try:
        for part in absolute.parts[1:-1]:
            child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
            os.close(fd)
            fd = child
        source_fd = os.open(absolute.name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=fd)
    finally:
        os.close(fd)
    info = os.fstat(source_fd)
    if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
        os.close(source_fd)
        raise ValueError(f'历史材料不是独立普通文件：{path}')
    return os.fdopen(source_fd, 'rb')


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
    finally:
        conn.close()
    by_submission = {}
    for result in results:
        by_submission.setdefault(result['submission_id'], []).append(result)
    for submission in submissions:
        submission['judge_results'] = by_submission.get(submission['id'], [])
    return submissions, {(row['submission_id'], row['step_key']): row for row in steps}


def _directories(root):
    return [path for path in root.iterdir() if _safe_directory(path)] if _safe_directory(root) else []


def _sources(submission, steps):
    """发现当前记录、轨迹、答案归档和仅剩 workspace 的旧 attempt。"""
    sid = submission['id']
    current = _safe_attempt(submission.get('judge_attempt_id'))
    root = Path(submission_dir(sid))
    if submission['scoring_mode'] == 'agent_judge':
        trace_root = root / 'agent_judge_trace'
        workspace_root = Path(config.AGENT_JUDGE_WORKSPACE_ROOT) / str(sid)
        attempts = {current} | {path.name for path in _directories(trace_root)}
        known_workspaces = set()
        for attempt in sorted(attempts):
            raw = submission.get('judge_attempt_id') if attempt == current else attempt
            key = hashlib.sha256(str(raw or 'legacy').encode()).hexdigest()[:16]
            known_workspaces.add(key)
            yield 'agent_judge', attempt, trace_root / attempt, submission if attempt == current else {}, workspace_root / key
        for path in _directories(workspace_root):
            if path.name not in known_workspaces:
                yield 'agent_judge', f'unknown-workspace-{path.name}', None, {}, path
    else:
        trace_root = root / 'reverse_agent_trace'
        workspace_root = Path(config.REVERSE_JUDGE_WORKSPACE_ROOT) / str(sid)
        attempts = {current} | {path.name for path in _directories(trace_root)} | {path.name for path in _directories(workspace_root)}
        archives = root / 'reverse_agent_answers'
        if _safe_directory(archives):
            attempts.update(path.stem for path in archives.glob('*.zip') if stat.S_ISREG(path.lstat().st_mode))
        for attempt in sorted(attempts):
            workspace = workspace_root / attempt
            quality = steps.get((sid, 'quality_gate'), {}) if attempt == current else {}
            if quality and quality.get('status') != 'pending' or _safe_directory(workspace / 'quality_gate_source'):
                yield 'reverse_quality', attempt, None, quality, workspace
            yield 'reverse_answer', attempt, trace_root / attempt, steps.get((sid, 'agent_answer'), {}) if attempt == current else {}, workspace


def _regular_files(source, prefix, missing, *, include_hidden=False):
    if not _safe_directory(source):
        missing.append(f'workspace 材料缺失或目录含链接：{prefix}')
        return {}
    files = {}
    for parent, directories, names in os.walk(source, followlinks=False):
        parent = Path(parent)
        directories[:] = sorted(name for name in directories if not (parent / name).is_symlink() and (include_hidden or not name.startswith('.')))
        for name in sorted(names):
            path = parent / name
            relative = path.relative_to(source)
            if not include_hidden and any(part.startswith('.') for part in relative.parts):
                continue
            info = path.lstat()
            if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
                missing.append(f'已跳过链接或特殊文件：{prefix}/{relative}')
                continue
            files[f'{prefix}/{relative.as_posix()}'] = path
    return files


def _extract_copy(archive, output, staging):
    archive_copy = Path(staging) / (output.name + '.zip')
    with _open_source(archive) as source, archive_copy.open('wb') as copied:
        while chunk := source.read(1024 * 1024):
            copied.write(chunk)
    extract_zip(archive_copy, output, policy=ZipExtractionPolicy(
        max_members=config.REVERSE_PACKAGE_MAX_MEMBERS, max_file_bytes=config.REVERSE_PACKAGE_MAX_FILE_BYTES,
        max_total_bytes=config.REVERSE_PACKAGE_MAX_TOTAL_BYTES, max_compression_ratio=config.REVERSE_PACKAGE_MAX_COMPRESSION_RATIO,
        unsafe_member_action='raise', cleanup_on_error=True,
    ))


def _uploaded_material(submission, staging, missing):
    """执行 workspace 已清理时，从仍保留的提交副本恢复输入，明确区分执行产物。"""
    uploaded = submission.get('code_path')
    target = Path(staging) / 'uploaded'
    if not uploaded:
        return target
    source = Path(uploaded)
    with _open_source(source) as stream:
        zipped = zipfile.is_zipfile(stream)
    if zipped:
        _extract_copy(source, target, staging)
    else:
        target.mkdir()
        with _open_source(source) as stream:
            (target / source.name).write_bytes(stream.read())
    missing.append('执行 workspace 已缺失；已从原提交恢复输入副本，不代表最终执行文件')
    return target


def _workspace_files(submission, kind, attempt, source, staging, missing):
    if kind == 'agent_judge':
        if _safe_directory(source):
            return _regular_files(source, 'historical_workspace', missing)
        return _regular_files(_uploaded_material(submission, staging, missing), 'historical_workspace/submission', missing)
    if kind == 'reverse_quality' and _safe_directory(source / 'quality_gate_source'):
        return _regular_files(source / 'quality_gate_source', 'audit', missing)
    # AI 作答只能取得题面、模板和该 attempt 的 AI 输出，不复制 solution/judge.sh/审核副本。
    package = source / 'package'
    if not _safe_directory(package):
        package = _uploaded_material(submission, staging, missing)
    roots = [package] + _directories(package)
    material = next((path for path in roots if _safe_directory(path / 'problem')), package)
    if kind == 'reverse_quality':
        return _regular_files(material, 'audit', missing)
    files = _regular_files(material / 'problem', 'problem', missing)
    archive = Path(submission_dir(submission['id'])) / 'reverse_agent_answers' / f'{attempt}.zip'
    if archive.exists():
        output = Path(staging) / 'answer'
        _extract_copy(archive, output, staging)
        files.update(_regular_files(output, 'template', missing))
    else:
        missing.append('该轮 AI 答案归档不可取得；模板副本不代表最终作答')
        files.update(_regular_files(material / 'template', 'template', missing))
    return files


def _trace_records(task_id, trace, staging, missing):
    records = []
    if trace is None or not _safe_directory(trace):
        missing.append('历史执行轨迹不可取得')
        return records, None
    # 先复制经过文件类型校验的轨迹到私有临时目录，旧解析器不直接遍历原文件树。
    safe_trace = Path(staging) / 'trace'
    for relative, path in _regular_files(trace, 'trace', missing, include_hidden=True).items():
        target = Path(staging) / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        with _open_source(path) as source, target.open('wb') as destination:
            while chunk := source.read(1024 * 1024):
                destination.write(chunk)
    canonical = safe_trace / 'numoj_trace_v1.jsonl'
    if canonical.is_file():
        seen = set()
        with canonical.open('rb') as stream:
            for line in stream:
                try:
                    record = json.loads(line)
                    event = record.get('event') or {}
                    source_id = event.get('id')
                    if record.get('type') != 'numoj_trace' or source_id in seen:
                        continue
                    record['sequence'] = len(records) + 1
                    # 与实际存储使用同一规范化器，核验数不包含会被通用层丢弃的空事件。
                    if _normalize_canonical_record(task_id, record) is None:
                        continue
                    seen.add(source_id)
                    records.append(record)
                except (ValueError, TypeError, AttributeError):
                    missing.append('规范轨迹包含无法解析的记录，已跳过')
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


def _digest(stream):
    digest = hashlib.sha256()
    size = 0
    while chunk := stream.read(1024 * 1024):
        digest.update(chunk)
        size += len(chunk)
    return {'size': size, 'sha256': digest.hexdigest()}


def _trace_digest(rows):
    normalized = [{key: bool(row.get(key)) if key == 'is_error' else row.get(key) for key in TRACE_FIELDS} for row in rows]
    return hashlib.sha256(json.dumps(normalized, ensure_ascii=False, sort_keys=True).encode()).hexdigest()


def _identity(submission, kind, actual_attempt):
    return {'task_kind': 'judge', 'judge_kind': kind, 'requested_by': submission['username'],
                'submission_id': submission['id'], 'competition_id': submission['competition_id'], 'attempt_id': actual_attempt}


def _verify(session_id, expected, *, submission, kind, actual_attempt):
    session = get_agent_session(session_id)
    identity = _identity(submission, kind, actual_attempt)
    if not session or any(session.get(key) != value for key, value in identity.items()) or session.get('status') != 'Completed':
        raise RuntimeError(f'历史会话状态或访问权限核验失败：{session_id}')
    def files_in_tree(nodes):
        return {path for node in nodes for path in (files_in_tree(node.get('children', [])) if node['type'] == 'directory' else {node['path']})}
    if files_in_tree(build_agent_workspace_tree(session_id)) != set(expected['workspace_manifest']):
        raise RuntimeError(f'历史 workspace 文件集合核验失败：{session_id}')
    for relative, metadata in expected['workspace_manifest'].items():
        stream, _ = open_agent_workspace_file(session_id, relative)
        with stream:
            if _digest(stream) != metadata:
                raise RuntimeError(f'历史 workspace 副本核验失败：{session_id}/{relative}')
    if get_agent_trace_token_usage(session_id) != expected.get('token_usage'):
        raise RuntimeError(f'历史用量核验失败：{session_id}')
    conn = get_db_connection()
    try:
        with conn.cursor() as cursor:
            cursor.execute('SELECT COUNT(*) AS n FROM agent_usage_ledger WHERE task_id=%s', (session_id,))
            if (cursor.fetchone() or {}).get('n', 0):
                raise RuntimeError(f'历史导入不应产生费用流水：{session_id}')
            cursor.execute('SELECT status FROM agent_session_turns WHERE session_id=%s AND task_id=%s', (session_id, session_id))
            if (cursor.fetchone() or {}).get('status') != 'Completed':
                raise RuntimeError(f'历史轮次终态核验失败：{session_id}')
            cursor.execute('SELECT status FROM agent_session_messages WHERE session_id=%s', (session_id,))
            messages = cursor.fetchall() or []
            if len(messages) != 1 or messages[0].get('status') != 'sent':
                raise RuntimeError(f'历史会话 outbox 终态核验失败：{session_id}')
            cursor.execute(f"SELECT {', '.join(TRACE_FIELDS)} FROM agent_trace_events WHERE task_id=%s ORDER BY event_order", (session_id,))
            rows = cursor.fetchall() or []
            if len(rows) != expected['trace_events'] or _trace_digest(rows) != expected['trace_sha256']:
                raise RuntimeError(f'历史轨迹持久化核验失败：{session_id}')
    finally:
        conn.close()


def _history_record(kind, record, missing):
    fields = ('status', 'score', 'grade_details', 'judge_results', 'error_message') if kind == 'agent_judge' else ('status', 'score', 'max_score', 'result_json', 'error_message')
    return {'result': {key: record.get(key) for key in fields}, 'missing': sorted(set(missing))}


def migrate_one(submission, kind, attempt, trace, record, source):
    actual_attempt = submission.get('judge_attempt_id') if attempt == _safe_attempt(submission.get('judge_attempt_id')) else attempt
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
        _verify(session_id, runtime, submission=submission, kind=kind, actual_attempt=actual_attempt)
        return {'session_id': session_id, 'verified': True, 'existing': True, **runtime}
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
    if attempt.startswith('unknown-workspace-'):
        missing.append('旧 workspace 的原始评测 attempt 无法恢复，使用独立历史标识')
    if not record:
        missing.append('该历史 attempt 的原始评测结果不可取得')
    with TemporaryDirectory(prefix='numoj-judge-history-') as staging:
        staging = Path(staging).resolve()
        records, usage = _trace_records(session_id, trace, staging, missing)
        if not usage:
            missing.append('历史用量不可取得；未推算或补记费用')
        ensure_agent_workspace(session_id)
        files = _workspace_files(submission, kind, attempt, source, staging, missing)
        history = _history_record(kind, record, missing)
        conclusion = '历史评测导入；原有费用不重复记账。\n\n' + json.dumps(history, ensure_ascii=False, default=str, indent=2)
        files['historical_record.json'] = json.dumps(history, ensure_ascii=False, default=str, indent=2).encode()
        manifest = {}
        for relative, content in files.items():
            if isinstance(content, Path):
                with _open_source(content) as stream:
                    manifest[relative] = _digest(stream)
            else:
                manifest[relative] = {'size': len(content), 'sha256': hashlib.sha256(content).hexdigest()}
        inject_agent_workspace_files(session_id, files)
    ingest_agent_trace_records(session_id, records, final=True)
    if usage:
        save_agent_trace_token_usage(session_id, usage)
    upsert_agent_run_snapshot({
        'task_id': session_id, 'session_id': session_id, 'requested_by': submission['username'],
        'task_kind': 'judge', 'harness': submission.get('agent_endpoint_harness') or 'claude_code',
        'endpoint_id': submission.get('agent_endpoint_id'), 'status': 'Completed', 'stage': 'finished',
        'harness_status': 'completed', 'message': '历史评测已归档', 'conclusion': conclusion,
    })
    runtime.update({'historical_import': True, 'historical_import_completed': MIGRATION_VERSION,
                    'missing': history['missing'], 'trace_events': len(records), 'token_usage': _normalized_token_usage(usage),
                    'trace_sha256': _trace_digest([_normalize_canonical_record(session_id, item) for item in records]),
                    'workspace_manifest': manifest})
    _verify(session_id, runtime, submission=submission, kind=kind, actual_attempt=actual_attempt)
    conn = get_db_connection()
    try:
        with conn.cursor() as cursor:
            cursor.execute('UPDATE agent_sessions SET runtime_config_json=%s WHERE session_id=%s',
                           (json.dumps(runtime, ensure_ascii=False), session_id))
        conn.commit()
    finally:
        conn.close()
    return {'session_id': session_id, 'verified': True, **runtime}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--confirm-writers-stopped', action='store_true', required=True)
    parser.add_argument('--backup-manifest', type=Path, required=True)
    parser.add_argument('--backup-plan', type=Path, required=True)
    parser.add_argument('--report', type=Path, required=True)
    args = parser.parse_args(argv)
    validate_production_config(ROOT / '.env')
    backup = read_manifest(args.backup_manifest)
    if backup.get('backup_status') != 'complete' or not backup.get('completed_at'):
        raise ValueError('必须先完成并核验数据库备份')
    if not (backup.get('gzip_crc_verified') is True or backup.get('prepared') is True):
        raise ValueError('备份未通过完整性核验')
    validate_manifest_artifact(args.backup_manifest, backup, plan_path=args.backup_plan)
    submissions, steps = _rows()
    report = []
    verified = False
    try:
        for submission in submissions:
            for source in _sources(submission, steps):
                report.append(migrate_one(submission, *source))
        verified = True
    finally:
        args.report.parent.mkdir(parents=True, exist_ok=True)
        with NamedTemporaryFile(mode='w', encoding='utf-8', dir=args.report.parent, prefix='.judge-migration-', delete=False) as stream:
            temporary_report = Path(stream.name)
            json.dump({'version': MIGRATION_VERSION, 'verified': verified, 'sessions': report}, stream, ensure_ascii=False, indent=2)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary_report, args.report)
    print(f'Judge 历史迁移完成并核验：{len(report)} 个会话；报告 {args.report}')
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
