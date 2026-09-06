#!/usr/bin/env python3
"""停服备份后一次性导入历史 Judge；只新增会话/副本，不删除旧数据或补扣费用。"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import stat
import sys
import time
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
SOURCE_UNAVAILABLE = (PermissionError, FileNotFoundError)


def _progress(message):
    print(f'[judge-history] {_display_text(message)}', flush=True)


def _display_text(value):
    """日志和 JSON 展示使用转义文字，磁盘上的原始名称保持不变。"""
    return str(value).encode('utf-8', errors='backslashreplace').decode('utf-8')


def _file_progress(label):
    last = time.monotonic()
    def progress(completed, total):
        nonlocal last
        now = time.monotonic()
        if now - last >= 5:
            _progress(f'{label}：{completed}/{total} 个文件')
            last = now
    return progress


def _safe_attempt(attempt):
    return re.sub(r'[^A-Za-z0-9_.-]+', '_', str(attempt or 'legacy')).strip('._')[:96] or 'legacy'


def _safe_directory(path, missing=None):
    """历史路径任何祖先都不得是软链接；材料只读，不替换原目录。"""
    try:
        return all(stat.S_ISDIR(part.lstat().st_mode) for part in (path.absolute(), *path.absolute().parents))
    except PermissionError:
        if missing is not None:
            missing.append(f'无法检查历史目录（PermissionError）：{path}')
        return False
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


def _available_source(path, missing, label):
    """读取不了的旧材料记入报告，不影响其他历史会话。"""
    try:
        return _open_source(path)
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
    finally:
        conn.close()
    by_submission = {}
    for result in results:
        by_submission.setdefault(result['submission_id'], []).append(result)
    for submission in submissions:
        submission['judge_results'] = by_submission.get(submission['id'], [])
    return submissions, {(row['submission_id'], row['step_key']): row for row in steps}


def _directories(root, missing=None):
    try:
        return [path for path in root.iterdir() if _safe_directory(path, missing)] if _safe_directory(root, missing) else []
    except SOURCE_UNAVAILABLE as exc:
        if missing is not None:
            missing.append(f'无法枚举历史目录（{type(exc).__name__}）：{root}')
        return []


def _sources(submission, steps, missing=None):
    """发现当前记录、轨迹、答案归档和仅剩 workspace 的旧 attempt。"""
    sid = submission['id']
    current = _safe_attempt(submission.get('judge_attempt_id'))
    root = Path(submission_dir(sid))
    if submission['scoring_mode'] == 'agent_judge':
        trace_root = root / 'agent_judge_trace'
        workspace_root = Path(config.AGENT_JUDGE_WORKSPACE_ROOT) / str(sid)
        attempts = {current} | {path.name for path in _directories(trace_root, missing)}
        known_workspaces = set()
        for attempt in sorted(attempts):
            raw = submission.get('judge_attempt_id') if attempt == current else attempt
            key = hashlib.sha256(str(raw or 'legacy').encode()).hexdigest()[:16]
            known_workspaces.add(key)
            yield 'agent_judge', attempt, trace_root / attempt, submission if attempt == current else {}, workspace_root / key
        for path in _directories(workspace_root, missing):
            if path.name not in known_workspaces:
                yield 'agent_judge', f'unknown-workspace-{path.name}', None, {}, path
    else:
        trace_root = root / 'reverse_agent_trace'
        workspace_root = Path(config.REVERSE_JUDGE_WORKSPACE_ROOT) / str(sid)
        attempts = {current} | {path.name for path in _directories(trace_root, missing)} | {path.name for path in _directories(workspace_root, missing)}
        archives = root / 'reverse_agent_answers'
        if _safe_directory(archives, missing):
            try:
                attempts.update(path.stem for path in archives.iterdir() if path.suffix == '.zip' and stat.S_ISREG(path.lstat().st_mode))
            except SOURCE_UNAVAILABLE as exc:
                if missing is not None:
                    missing.append(f'无法枚举历史答案归档（{type(exc).__name__}）：{archives}')
        for attempt in sorted(attempts):
            workspace = workspace_root / attempt
            quality = steps.get((sid, 'quality_gate'), {}) if attempt == current else {}
            if quality and quality.get('status') != 'pending' or _safe_directory(workspace / 'quality_gate_source'):
                yield 'reverse_quality', attempt, None, quality, workspace
            yield 'reverse_answer', attempt, trace_root / attempt, steps.get((sid, 'agent_answer'), {}) if attempt == current else {}, workspace


def _regular_files(source, prefix, missing, *, include_hidden=False):
    if not _safe_directory(source):
        missing.append(f'workspace 材料缺失、目录不可读或含链接：{prefix}')
        return {}
    files = {}
    def unavailable(exc):
        if not isinstance(exc, SOURCE_UNAVAILABLE):
            raise exc
        relative = Path(exc.filename).relative_to(source) if exc.filename else Path('.')
        missing.append(f'历史目录不可读取（{type(exc).__name__}）：{prefix}/{relative}')
    for parent, directories, names in os.walk(source, followlinks=False, onerror=unavailable):
        parent = Path(parent)
        directories[:] = sorted(name for name in directories if not (parent / name).is_symlink() and (include_hidden or not name.startswith('.')))
        for name in sorted(names):
            path = parent / name
            relative = path.relative_to(source)
            if not include_hidden and any(part.startswith('.') for part in relative.parts):
                continue
            try:
                info = path.lstat()
            except SOURCE_UNAVAILABLE as exc:
                missing.append(f'历史材料无法检查（{type(exc).__name__}）：{prefix}/{relative}')
                continue
            if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
                missing.append(f'已跳过链接或特殊文件：{prefix}/{relative}')
                continue
            files[f'{prefix}/{relative.as_posix()}'] = path
    return files


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
    roots = [package] + _directories(package, missing)
    material = next((path for path in roots if _safe_directory(path / 'problem')), package)
    if kind == 'reverse_quality':
        return _regular_files(material, 'audit', missing)
    files = _regular_files(material / 'problem', 'problem', missing)
    archive = Path(submission_dir(submission['id'])) / 'reverse_agent_answers' / f'{attempt}.zip'
    output = Path(staging) / 'answer'
    if _extract_copy(archive, output, staging, missing, '该轮 AI 答案归档'):
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
    files = _regular_files(trace, 'trace', missing, include_hidden=True)
    _copy_files(files, Path(staging), missing, f'{task_id} 复制轨迹')
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


def _identity(submission, kind, actual_attempt):
    return {'task_kind': 'judge', 'judge_kind': kind, 'requested_by': submission['username'],
                'submission_id': submission['id'], 'competition_id': submission['competition_id'], 'attempt_id': actual_attempt}


def _copy_files(files, root, missing, label):
    """原样复制；临时文件替换保证失败时不破坏上次已经复制的内容。"""
    copied = 0
    progress = _file_progress(label)
    for index, (relative, source) in enumerate(files.items(), 1):
        target = root / relative
        temporary = None
        try:
            target.parent.mkdir(parents=True, exist_ok=True)
            with NamedTemporaryFile(dir=target.parent, prefix='.history-copy-', delete=False) as stream:
                temporary = Path(stream.name)
            shutil.copyfile(source, temporary)
            os.replace(temporary, target)
            temporary = None
            copied += 1
        except OSError as exc:
            message = f'复制失败，保留原材料和已有副本：{relative}（{exc}）'
            missing.append(_display_text(message))
            _progress(message)
        finally:
            if temporary is not None:
                try:
                    temporary.unlink(missing_ok=True)
                except OSError:
                    pass
        progress(index, len(files))
    return copied


def _copy_workspace_files(session_id, files, missing):
    """停服历史导入直接复制字节和原始名称；不做格式、配额或摘要核验。"""
    root = ensure_agent_workspace(session_id, check_quota=False)
    return root, _copy_files(files, root, missing, f'{session_id} 复制材料')


def _history_record(kind, record, missing):
    fields = ('status', 'score', 'grade_details', 'judge_results', 'error_message') if kind == 'agent_judge' else ('status', 'score', 'max_score', 'result_json', 'error_message')
    return {'result': {key: record.get(key) for key in fields}, 'missing': sorted({_display_text(item) for item in missing})}


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
        _progress(f'{session_id}：已完成，跳过')
        return {'session_id': session_id, 'existing': True}
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
        files = _workspace_files(submission, kind, attempt, source, staging, missing)
        _progress(f'{session_id}：复制 {len(files)} 个文件')
        output, copied = _copy_workspace_files(session_id, files, missing)
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
               'missing': history['missing'], 'copied_files': copied,
               'trace_events': len(records), 'token_usage': _normalized_token_usage(usage)}
    conn = get_db_connection()
    try:
        with conn.cursor() as cursor:
            cursor.execute('UPDATE agent_sessions SET runtime_config_json=%s WHERE session_id=%s',
                           (json.dumps(runtime, ensure_ascii=False), session_id))
        conn.commit()
    finally:
        conn.close()
    _progress(f'{session_id}：完成，复制 {copied} 个文件、{len(records)} 条轨迹，{len(history["missing"])} 项缺失说明')
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
            for source in _sources(submission, steps, missing):
                current.update(judge_kind=source[0], attempt=source[1])
                report.append(migrate_one(submission, *source))
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
