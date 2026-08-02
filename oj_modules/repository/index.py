#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import hashlib
import json
import os
import shutil
import uuid
import fcntl
from contextlib import contextmanager
from datetime import datetime, timedelta

import numpy as np
import requests

from oj_modules.ai.client import _call_qwen_text
from oj_modules.ai.parsing import _extract_first_json_object_relaxed
from oj_modules.infrastructure.mysql import get_db_connection
from oj_modules.repository.settings import (
    DEFAULT_SEARCH_SCORE_THRESHOLD as _DEFAULT_SEARCH_SCORE_THRESHOLD,
    DEFAULT_SEARCH_TOP_K as _DEFAULT_SEARCH_TOP_K,
)
from config import (
    AI_TUTOR_MODEL,
    DASHSCOPE_API_KEY,
    DASHSCOPE_BASE_URL,
    QWEN_TEXT_MODEL,
    REPOSITORY_EMBEDDING_BATCH_SIZE,
    REPOSITORY_EMBEDDING_DIM,
    REPOSITORY_EMBEDDING_PROVIDER,
    REPOSITORY_EMBEDDING_TIMEOUT,
    REPOSITORY_FAISS_INDEX_ROOT,
    REPOSITORY_QWEN_EMBEDDING_MODEL,
    REPOSITORY_SENTENCE_MODEL,
    REPOSITORY_STRUCTURED_MODEL,
    REPOSITORY_STRUCTURED_TIMEOUT,
    REPOSITORY_VECTOR_BACKEND,
)

try:
    from sentence_transformers import SentenceTransformer
except Exception:
    SentenceTransformer = None

try:
    import faiss
except Exception:
    faiss = None

try:
    from tree_sitter import Language, Parser
    import tree_sitter_cpp
except Exception:
    Language = None
    Parser = None
    tree_sitter_cpp = None


_ALLOWED_REPO_EXTENSIONS = ('.h', '.hpp', '.c', '.cpp')
_ALLOWED_ACCESS = {'public', 'private', 'protected'}
_ALLOWED_FUNC_KIND = {'function', 'method', 'constructor', 'destructor', 'operator'}

_DEFAULT_EMBEDDING_DIM = int(REPOSITORY_EMBEDDING_DIM)
_DEFAULT_SENTENCE_MODEL = str(REPOSITORY_SENTENCE_MODEL or '').strip()
_DEFAULT_QWEN_EMBEDDING_MODEL = str(REPOSITORY_QWEN_EMBEDDING_MODEL or '').strip()
_DEFAULT_PROVIDER = str(REPOSITORY_EMBEDDING_PROVIDER or '').strip().lower()
_DEFAULT_LLM_MODEL = str(REPOSITORY_STRUCTURED_MODEL or '').strip() or str(QWEN_TEXT_MODEL or '').strip()
_STRUCTURED_ENTITY_MODEL = str(AI_TUTOR_MODEL or '').strip() or _DEFAULT_LLM_MODEL
_DEFAULT_LLM_TIMEOUT_SECONDS = int(REPOSITORY_STRUCTURED_TIMEOUT)
_DEFAULT_EMBEDDING_TIMEOUT_SECONDS = int(REPOSITORY_EMBEDDING_TIMEOUT)
_DEFAULT_EMBEDDING_BATCH_SIZE = max(1, int(REPOSITORY_EMBEDDING_BATCH_SIZE))
_VECTOR_DB_BACKEND = str(REPOSITORY_VECTOR_BACKEND or '').strip().lower()
_FAISS_INDEX_ROOT = os.path.abspath(str(REPOSITORY_FAISS_INDEX_ROOT or os.path.join('tmp', 'repository_vector_index')))
_PARSER_SCHEMA_VERSION = 'treesitter-cpp-structured-v3'
_EMBEDDING_SCHEMA_VERSION = 'repository-semantic-v1'
REPOSITORY_INDEX_TASK_SOFT_TIME_LIMIT_SECONDS = 1500
REPOSITORY_INDEX_TASK_HARD_TIME_LIMIT_SECONDS = 1800
REPOSITORY_INDEX_TASK_STALE_GRACE_SECONDS = 300
REPOSITORY_INDEX_TASK_STALE_AFTER_SECONDS = (
    REPOSITORY_INDEX_TASK_HARD_TIME_LIMIT_SECONDS
    + REPOSITORY_INDEX_TASK_STALE_GRACE_SECONDS
)

_sentence_model_cache = {}
_tree_sitter_parser_cache = {}


class RepositoryIndexJobCancelled(Exception):
    pass


def ensure_repository_index_tables():
    return None


def _expire_stale_repository_index_jobs(cursor, user_id):
    """原子终结超过明确租约的 queued/running 任务。

    queued 的最大等待租约与 running 一致；迟到的 broker 消息随后会因终态而无法
    `_try_mark...`。running 的阈值严格大于 Celery hard limit，并额外留 5 分钟，
    因而不会抢先终止仍可能正常存活的 worker。
    """

    cutoff = datetime.now() - timedelta(
        seconds=REPOSITORY_INDEX_TASK_STALE_AFTER_SECONDS
    )
    message = (
        '结构化整理任务超过执行租约，已自动终结；'
        '上一版可用索引保持不变，请重新整理。'
    )
    cursor.execute(
        """
        UPDATE repository_index_jobs
        SET status = 'failed',
            error_message = %s,
            progress_message = %s,
            finished_at = %s
        WHERE user_id = %s
          AND status IN ('queued', 'running')
          AND updated_at < %s
        """,
        (
            message,
            _format_repository_progress_message('failed', message),
            datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
            int(user_id),
            cutoff.strftime('%Y-%m-%d %H:%M:%S'),
        ),
    )
    return int(cursor.rowcount)


def _safe_int(value, default=0):
    try:
        return int(value)
    except Exception:
        return int(default)


def _safe_bool(value, default=False):
    if isinstance(value, bool):
        return value
    if isinstance(value, (int, float)):
        return bool(value)
    text = str(value or '').strip().lower()
    if text in ('true', '1', 'yes', 'y', 'on'):
        return True
    if text in ('false', '0', 'no', 'n', 'off'):
        return False
    return bool(default)


def _safe_str(value, default=''):
    text = str(value if value is not None else default)
    return text.strip()


def _normalize_access(value, default=''):
    text = _safe_str(value).lower()
    if text in _ALLOWED_ACCESS:
        return text
    return _safe_str(default).lower() if _safe_str(default).lower() in _ALLOWED_ACCESS else ''


def _normalize_kind(value, default='function'):
    text = _safe_str(value).lower()
    if text in _ALLOWED_FUNC_KIND:
        return text
    return default


def _detect_language_from_filename(filename):
    name = _safe_str(filename).lower()
    if name.endswith('.c'):
        return 'c'
    if name.endswith('.h'):
        return 'cpp'
    if name.endswith('.hpp'):
        return 'cpp'
    if name.endswith('.cpp'):
        return 'cpp'
    return 'cpp'


def _sha256_text(text):
    return hashlib.sha256(str(text or '').encode('utf-8')).hexdigest()


def create_repository_index_job(user_id):
    conn = get_db_connection()
    try:
        with conn.cursor() as cursor:
            cursor.execute(
                """
                INSERT INTO repository_index_jobs (
                    user_id, status, total_files, processed_files, total_chunks, total_classes, progress_message
                )
                VALUES (%s, 'queued', 0, 0, 0, 0, %s)
                """,
                (int(user_id), '等待调度执行'),
            )
            conn.commit()
            return int(cursor.lastrowid)
    finally:
        conn.close()


def get_or_create_active_repository_index_job(user_id):
    """按用户串行地取得或创建唯一 queued/running 整理任务。"""
    user_id = int(user_id)
    conn = get_db_connection()
    try:
        with conn.cursor() as cursor:
            # users 主键行作为稳定的每用户事务锁，堵住 route 层
            # “先查再建”产生两个 queued job 的竞态。
            cursor.execute(
                "SELECT id FROM users WHERE id = %s FOR UPDATE",
                (user_id,),
            )
            if not cursor.fetchone():
                raise RuntimeError("用户不存在，无法创建结构化整理任务")
            _expire_stale_repository_index_jobs(cursor, user_id)
            cursor.execute(
                """
                SELECT id, user_id, base_repository_generation, status, task_id,
                       cancel_requested, created_at, updated_at
                FROM repository_index_jobs
                WHERE user_id = %s
                  AND status IN ('queued', 'running')
                ORDER BY id DESC
                LIMIT 1
                FOR UPDATE
                """,
                (user_id,),
            )
            row = cursor.fetchone()
            if row:
                conn.commit()
                return {'created': False, 'job': row, 'job_id': int(row['id'])}
            cursor.execute(
                """
                INSERT INTO repository_index_jobs (
                    user_id, status, total_files, processed_files,
                    total_chunks, total_classes, progress_message
                )
                VALUES (%s, 'queued', 0, 0, 0, 0, %s)
                """,
                (user_id, '等待调度执行'),
            )
            job_id = int(cursor.lastrowid)
        conn.commit()
        return {
            'created': True,
            'job_id': job_id,
            'job': {
                'id': job_id,
                'user_id': user_id,
                'status': 'queued',
                'task_id': None,
                'cancel_requested': 0,
            },
        }
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


def update_repository_index_job(job_id, **fields):
    if not fields:
        return
    allowed = {
        'status',
        'base_repository_generation',
        'total_files',
        'processed_files',
        'total_chunks',
        'total_classes',
        'error_message',
        'progress_message',
        'task_id',
        'cancel_requested',
        'finished_at',
    }
    items = []
    params = []
    for key, value in fields.items():
        if key not in allowed:
            continue
        items.append(f"{key} = %s")
        params.append(value)
    if not items:
        return

    conn = get_db_connection()
    try:
        with conn.cursor() as cursor:
            sql = f"UPDATE repository_index_jobs SET {', '.join(items)} WHERE id = %s"
            cursor.execute(sql, tuple(params + [int(job_id)]))
        conn.commit()
    finally:
        conn.close()


def fail_repository_index_job_dispatch(job_id, user_id, error_message):
    """把尚未被 worker 领取的 dispatch 失败任务终结，避免永久 queued。

    只允许 ``queued -> failed``。若 Celery 已经领取并改为 ``running``，这里不
    反向覆盖运行态；调用方可根据返回值判断是否实际终结。
    """

    message = _safe_str(error_message) or '结构化整理任务调度失败'
    conn = get_db_connection()
    try:
        with conn.cursor() as cursor:
            cursor.execute(
                """
                UPDATE repository_index_jobs
                SET status = 'failed',
                    error_message = %s,
                    progress_message = %s,
                    finished_at = %s
                WHERE id = %s
                  AND user_id = %s
                  AND status = 'queued'
                """,
                (
                    message,
                    _format_repository_progress_message('failed', message),
                    datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                    int(job_id),
                    int(user_id),
                ),
            )
            changed = int(cursor.rowcount)
        conn.commit()
        return changed == 1
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


def get_repository_index_job(job_id, user_id):
    conn = get_db_connection()
    try:
        with conn.cursor() as cursor:
            _expire_stale_repository_index_jobs(cursor, user_id)
            cursor.execute(
                """
                SELECT id, user_id, base_repository_generation, status,
                       total_files, processed_files, total_chunks, total_classes,
                       error_message, progress_message, task_id, cancel_requested, created_at, updated_at, finished_at
                FROM repository_index_jobs
                WHERE id = %s AND user_id = %s
                LIMIT 1
                """,
                (int(job_id), int(user_id)),
            )
            row = cursor.fetchone()
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()

    if not row:
        return None
    for key in ('created_at', 'updated_at', 'finished_at'):
        if row.get(key):
            row[key] = row[key].strftime('%Y-%m-%d %H:%M:%S')
    total = max(0, _safe_int(row.get('total_files'), 0))
    done = max(0, _safe_int(row.get('processed_files'), 0))
    row['progress'] = int(round((done / total) * 100)) if total > 0 else (100 if row.get('status') == 'success' else 0)
    return row


def get_latest_active_repository_index_job(user_id):
    conn = get_db_connection()
    try:
        with conn.cursor() as cursor:
            _expire_stale_repository_index_jobs(cursor, user_id)
            cursor.execute(
                """
                SELECT id
                FROM repository_index_jobs
                WHERE user_id = %s AND status IN ('queued', 'running')
                ORDER BY id DESC
                LIMIT 1
                """,
                (int(user_id),),
            )
            row = cursor.fetchone()
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()

    if not row:
        return None
    return get_repository_index_job(job_id=row.get('id'), user_id=user_id)


def _get_repository_index_job_runtime(job_id, user_id=None):
    conn = get_db_connection()
    try:
        with conn.cursor() as cursor:
            if user_id is None:
                cursor.execute(
                    """
                    SELECT id, user_id, status, task_id, cancel_requested
                    FROM repository_index_jobs
                    WHERE id = %s
                    LIMIT 1
                    """,
                    (int(job_id),),
                )
            else:
                cursor.execute(
                    """
                    SELECT id, user_id, status, task_id, cancel_requested
                    FROM repository_index_jobs
                    WHERE id = %s AND user_id = %s
                    LIMIT 1
                    """,
                    (int(job_id), int(user_id)),
                )
            return cursor.fetchone()
    finally:
        conn.close()


def _try_mark_repository_index_job_running(job_id):
    conn = get_db_connection()
    try:
        with conn.cursor() as cursor:
            cursor.execute(
                """
                UPDATE repository_index_jobs
                SET status = 'running', error_message = NULL, finished_at = NULL,
                    updated_at = NOW()
                WHERE id = %s AND cancel_requested = 0 AND status IN ('queued', 'running')
                """,
                (int(job_id),),
            )
            # PyMySQL 默认返回 changed rows，而不是 matched rows。Celery redelivery
            # 领取一个本来就是 running 的 job 时，即使 WHERE 命中，affected rows
            # 也可能为 0；必须在同一事务、仍持有行锁时回读状态，不能据 rowcount
            # 把合法重投误判为取消。
            cursor.execute(
                """
                SELECT status, cancel_requested
                FROM repository_index_jobs
                WHERE id = %s
                LIMIT 1
                """,
                (int(job_id),),
            )
            row = cursor.fetchone()
            claimed = bool(
                row
                and str(row.get('status') or '').strip().lower() == 'running'
                and _safe_int(row.get('cancel_requested'), 0) == 0
            )
        conn.commit()
        return claimed
    finally:
        conn.close()


def _is_repository_index_job_cancel_requested(job_id):
    row = _get_repository_index_job_runtime(job_id=job_id, user_id=None)
    if not row:
        return True
    if _safe_int(row.get('cancel_requested'), 0) == 1:
        return True
    return str(row.get('status') or '').strip().lower() == 'canceled'


def request_cancel_repository_index_job(job_id, user_id=None, reason='用户取消任务'):
    """线性化取消请求，并让 running job 保持活跃直到 worker 确认退出。

    发布路径和这里都以 ``FOR UPDATE`` 锁定同一 job 行：发布先提交时取消会读到
    ``success`` 并保持成功；取消先提交时发布会看到 ``cancel_requested=1`` 并拒绝
    激活候选 generation。尚未被 worker 领取的 queued job 可以直接进入终态。
    """

    message = str(reason or '用户取消任务')
    conn = get_db_connection()
    try:
        with conn.cursor() as cursor:
            if user_id is None:
                cursor.execute(
                    """
                    SELECT id, user_id, status, task_id, cancel_requested
                    FROM repository_index_jobs
                    WHERE id = %s
                    LIMIT 1
                    FOR UPDATE
                    """,
                    (int(job_id),),
                )
            else:
                cursor.execute(
                    """
                    SELECT id, user_id, status, task_id, cancel_requested
                    FROM repository_index_jobs
                    WHERE id = %s AND user_id = %s
                    LIMIT 1
                    FOR UPDATE
                    """,
                    (int(job_id), int(user_id)),
                )
            row = cursor.fetchone()
            if not row:
                conn.commit()
                return None

            status = str(row.get('status') or '').strip().lower()
            if status == 'running':
                cursor.execute(
                    """
                    UPDATE repository_index_jobs
                    SET cancel_requested = 1,
                        error_message = NULL,
                        progress_message = %s
                    WHERE id = %s AND status = 'running'
                    """,
                    (
                        _format_repository_progress_message(
                            'canceling',
                            f'{message} 正在等待 worker 安全停止。',
                        ),
                        int(job_id),
                    ),
                )
                row['cancel_requested'] = 1
                row['error_message'] = None
                row['progress_message'] = _format_repository_progress_message(
                    'canceling',
                    f'{message} 正在等待 worker 安全停止。',
                )
            elif status == 'queued':
                finished_at = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
                cursor.execute(
                    """
                    UPDATE repository_index_jobs
                    SET cancel_requested = 1,
                        status = 'canceled',
                        finished_at = %s,
                        error_message = %s,
                        progress_message = %s
                    WHERE id = %s AND status = 'queued'
                    """,
                    (
                        finished_at,
                        message,
                        _format_repository_progress_message('canceled', message),
                        int(job_id),
                    ),
                )
                row['status'] = 'canceled'
                row['cancel_requested'] = 1
                row['finished_at'] = finished_at
                row['error_message'] = message
                row['progress_message'] = _format_repository_progress_message(
                    'canceled',
                    message,
                )
        conn.commit()
        return row
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


def _load_repository_index_snapshot(user_id):
    """在同一仓库读锁下取得可索引文件和对应 repository_generation。"""
    from oj_modules.repository.tree import get_repository_tree_snapshot

    tree_state = get_repository_tree_snapshot(int(user_id), include_content=True)
    rows = [
        item
        for item in tree_state.get('entries') or []
        if item.get('kind') == 'file'
    ]
    result = []
    for row in rows:
        filename = str(row.get('relative_path') or row.get('filename') or '')
        if not filename:
            continue
        if not filename.lower().endswith(_ALLOWED_REPO_EXTENSIONS):
            continue
        result.append({
            'id': int(row.get('id')),
            'filename': filename,
            'relative_path': filename,
            'content': str(row.get('content') or ''),
            'source_hash': _safe_str(row.get('sha256') or row.get('content_sha256')),
            'file_version': _safe_int(row.get('file_version'), 0),
        })
    return int(tree_state.get('repository_generation') or 0), result


def _load_user_repository_files(user_id, file_id=None):
    _generation, files = _load_repository_index_snapshot(user_id)
    if file_id is None:
        return files
    target = _safe_int(file_id, 0)
    return [item for item in files if _safe_int(item.get('id'), 0) == target]


def _get_cpp_tree_sitter_parser():
    parser = _tree_sitter_parser_cache.get('cpp')
    if parser is not None:
        return parser
    if (Language is None) or (Parser is None) or (tree_sitter_cpp is None):
        raise RuntimeError('未安装 tree-sitter 解析依赖（tree-sitter + tree-sitter-cpp）。')
    language = Language(tree_sitter_cpp.language())
    parser = Parser(language)
    _tree_sitter_parser_cache['cpp'] = parser
    return parser


def _ts_node_text(source_bytes, node):
    if node is None:
        return ''
    return source_bytes[node.start_byte:node.end_byte].decode('utf-8', errors='replace')


def _ts_compact_text(text):
    return _safe_str(' '.join(str(text or '').replace('\n', ' ').replace('\t', ' ').split()))


def _ts_iter_nodes(node):
    if node is None:
        return
    yield node
    for child in node.children:
        for sub in _ts_iter_nodes(child):
            yield sub


def _ts_find_first_descendant(node, target_types):
    for sub in _ts_iter_nodes(node):
        if sub.type in target_types:
            return sub
    return None


def _ts_find_descendants(node, target_types):
    for sub in _ts_iter_nodes(node):
        if sub.type in target_types:
            yield sub


def _ts_select_declarator_for_function_definition(function_node):
    if function_node is None:
        return None
    if _safe_str(function_node.type) != 'function_definition':
        return _ts_find_first_descendant(function_node, {'function_declarator'})

    for child in function_node.children:
        if _safe_str(child.type) == 'function_declarator':
            return child

    for child in function_node.children:
        child_type = _safe_str(child.type)
        if child_type in ('compound_statement', 'try_statement'):
            break
        if child_type in ('class_specifier', 'struct_specifier', 'comment'):
            continue
        cand = _ts_find_first_descendant(child, {'function_declarator'})
        if cand is not None:
            return cand

    return _ts_find_first_descendant(function_node, {'function_declarator'})


def _ts_infer_owner_from_function_definition(function_node, source_bytes):
    if function_node is None:
        return ''
    for child in function_node.children:
        if _safe_str(child.type) not in ('class_specifier', 'struct_specifier'):
            continue
        name_node = None
        for sub in child.children:
            if _safe_str(sub.type) in ('type_identifier', 'identifier'):
                name_node = sub
                break
        owner = _ts_compact_text(_ts_node_text(source_bytes, name_node))
        if owner:
            return owner
    return ''


def _ts_nearest_ancestor_of_types(node, target_types):
    parent = node.parent if node is not None else None
    while parent is not None:
        if parent.type in target_types:
            return parent
        parent = parent.parent
    return None


def _ts_same_node(left, right):
    if left is None or right is None:
        return False
    return (
        _safe_str(left.type) == _safe_str(right.type)
        and int(left.start_byte) == int(right.start_byte)
        and int(left.end_byte) == int(right.end_byte)
    )


def _ts_collect_class_member_nodes(body_node, class_node):
    collected = []
    if body_node is None or class_node is None:
        return collected
    for sub in _ts_iter_nodes(body_node):
        if sub.type not in ('field_declaration', 'function_definition'):
            continue
        nearest_class = _ts_nearest_ancestor_of_types(sub, {'class_specifier', 'struct_specifier'})
        if _ts_same_node(nearest_class, class_node):
            collected.append(sub)
    return collected


def _ts_line_of(node):
    return max(1, int((node.start_point[0] if node is not None else 0) + 1))


def _ts_end_line_of(node):
    return max(1, int((node.end_point[0] if node is not None else 0) + 1))


def _ts_line_of_byte(source_bytes, byte_offset):
    try:
        end = max(0, min(int(byte_offset), len(source_bytes)))
    except Exception:
        end = 0
    return int(source_bytes[:end].count(b'\n')) + 1


def _ts_child_index(parent, child):
    if parent is None or child is None:
        return -1
    for idx, node in enumerate(parent.children):
        if _ts_same_node(node, child):
            return idx
    return -1


def _ts_extract_callable_code_with_recovery(source_bytes, callable_node):
    code_text = _ts_node_text(source_bytes, callable_node)
    if callable_node is None:
        return code_text, 1, 1

    start_byte = int(callable_node.start_byte)
    end_byte = int(callable_node.end_byte)
    spill_anchor = callable_node

    parent = callable_node.parent
    if (
        _safe_str(getattr(callable_node, 'type', '')) == 'declaration'
        and _safe_str(getattr(parent, 'type', '')) == 'labeled_statement'
    ):
        label_node = parent.child_by_field_name('label')
        if label_node is None and parent.children:
            first = parent.children[0]
            if _safe_str(getattr(first, 'type', '')) == 'statement_identifier':
                label_node = first
        label_text = _ts_compact_text(_ts_node_text(source_bytes, label_node)).lower()
        if label_text in _ALLOWED_ACCESS:
            spill_anchor = parent

    scope_parent = spill_anchor.parent
    sibling_index = _ts_child_index(scope_parent, spill_anchor)
    if scope_parent is not None and sibling_index >= 0:
        lookahead = 0
        for sibling in scope_parent.children[sibling_index + 1:]:
            lookahead += 1
            sibling_type = _safe_str(getattr(sibling, 'type', ''))
            sibling_text = _ts_compact_text(_ts_node_text(source_bytes, sibling))
            if sibling_type == 'ERROR' and sibling_text == '}':
                recovered_end = int(sibling.end_byte)
                if recovered_end > end_byte:
                    end_byte = recovered_end
                break
            if sibling_type in (
                'function_definition',
                'class_specifier',
                'struct_specifier',
                'namespace_definition',
                'declaration',
                'labeled_statement',
            ):
                break
            if lookahead >= 32:
                break

    recovered_text = ''
    if end_byte > start_byte:
        recovered_text = source_bytes[start_byte:end_byte].decode('utf-8', errors='replace')
    if _safe_str(recovered_text):
        code_text = recovered_text

    start_line = _ts_line_of_byte(source_bytes, start_byte)
    end_line = _ts_line_of_byte(source_bytes, end_byte)
    return code_text, max(1, int(start_line)), max(1, int(end_line))


def _ts_collect_comment_nodes(root, source_bytes):
    comments = []
    for sub in _ts_iter_nodes(root):
        if _safe_str(sub.type) != 'comment':
            continue
        text = _ts_node_text(source_bytes, sub)
        if not _safe_str(text):
            continue
        comments.append({
            'start_line': _ts_line_of(sub),
            'end_line': _ts_end_line_of(sub),
            'text': text,
        })
    comments.sort(key=lambda x: (int(x.get('start_line') or 0), int(x.get('end_line') or 0)))
    return comments


def _ts_build_comment_context(comment_nodes):
    comments = comment_nodes if isinstance(comment_nodes, list) else []
    line_to_comment = {}
    for idx, item in enumerate(comments):
        start_line = max(1, _safe_int(item.get('start_line'), 1))
        end_line = max(start_line, _safe_int(item.get('end_line'), start_line))
        for line_no in range(start_line, end_line + 1):
            line_to_comment[int(line_no)] = int(idx)
    return {
        'comments': comments,
        'line_to_comment': line_to_comment,
    }


def _ts_strip_comment_markers(raw_comment):
    text = str(raw_comment or '')
    if not text:
        return ''
    lines = text.splitlines()
    cleaned = []
    for line in lines:
        row = str(line).strip()
        if row.startswith('//'):
            row = row[2:].lstrip()
        if row.startswith('/*'):
            row = row[2:].lstrip()
        if row.endswith('*/'):
            row = row[:-2].rstrip()
        if row.startswith('*'):
            row = row[1:].lstrip()
        cleaned.append(row)
    return '\n'.join(cleaned).strip()


def _ts_extract_leading_comment_for_node(node, source_lines, comment_context):
    if node is None:
        return ''
    source_rows = source_lines if isinstance(source_lines, list) else []
    comments = (comment_context or {}).get('comments') if isinstance(comment_context, dict) else []
    line_to_comment = (comment_context or {}).get('line_to_comment') if isinstance(comment_context, dict) else {}
    if not comments or not isinstance(line_to_comment, dict):
        return ''

    line = _ts_line_of(node) - 1
    if line <= 0:
        return ''

    collected_ids = []
    blank_lines_before = 0
    max_blank_lines_before = 1
    while line >= 1:
        row_text = source_rows[line - 1] if 1 <= line <= len(source_rows) else ''
        if not _safe_str(row_text):
            if collected_ids:
                break
            blank_lines_before += 1
            if blank_lines_before > max_blank_lines_before:
                break
            line -= 1
            continue

        comment_id = line_to_comment.get(int(line))
        if comment_id is None:
            break

        if (not collected_ids) or (comment_id != collected_ids[-1]):
            collected_ids.append(int(comment_id))
        comment_item = comments[int(comment_id)]
        line = max(0, _safe_int(comment_item.get('start_line'), line) - 1)

    if not collected_ids:
        return ''

    collected_ids = sorted(set(collected_ids), key=lambda x: _safe_int(comments[x].get('start_line'), 0))
    plain_blocks = []
    raw_blocks = []
    for cid in collected_ids:
        raw_text = _safe_str(comments[cid].get('text'))
        if not raw_text:
            continue
        raw_blocks.append(raw_text)
        plain_text = _ts_strip_comment_markers(raw_text)
        if plain_text:
            plain_blocks.append(plain_text)

    if plain_blocks:
        return '\n'.join(plain_blocks).strip()
    return '\n'.join(raw_blocks).strip()


def _ts_find_best_declarator_name_node(declarator_node):
    if declarator_node is None:
        return None
    rank = {
        'qualified_identifier': 0,
        'operator_name': 1,
        'destructor_name': 2,
        'field_identifier': 3,
        'identifier': 4,
    }
    best_node = None
    best_rank = 1_000_000
    stack = [declarator_node]
    while stack:
        node = stack.pop()
        node_type = _safe_str(node.type)
        if node_type == 'parameter_list':
            continue
        if node_type in rank:
            node_rank = int(rank.get(node_type, 1_000_000))
            if node_rank < best_rank:
                best_node = node
                best_rank = node_rank
                if best_rank == 0:
                    return best_node
        for child in reversed(node.children):
            stack.append(child)
    return best_node


def _ts_extract_function_name_and_owner(declarator_node, source_bytes):
    if declarator_node is None:
        return '', ''

    target_node = _ts_find_best_declarator_name_node(declarator_node)
    if target_node is None:
        return '', ''

    if target_node.type == 'qualified_identifier':
        qualified_text = _ts_compact_text(_ts_node_text(source_bytes, target_node))
        if '::' in qualified_text:
            parts = [p for p in qualified_text.split('::') if _safe_str(p)]
            if len(parts) >= 2:
                return _safe_str(parts[-1]), _safe_str('::'.join(parts[:-1]))
        return qualified_text, ''

    if target_node.type == 'operator_name':
        op_text = _ts_compact_text(_ts_node_text(source_bytes, target_node))
        if op_text.startswith('operator'):
            suffix = op_text[len('operator'):].replace(' ', '')
            return _safe_str(f"operator{suffix}"), ''
        return op_text, ''

    if target_node.type == 'destructor_name':
        return _ts_compact_text(_ts_node_text(source_bytes, target_node)), ''

    if target_node.type in ('field_identifier', 'identifier'):
        return _ts_compact_text(_ts_node_text(source_bytes, target_node)), ''
    return _ts_compact_text(_ts_node_text(source_bytes, target_node)), ''


def _ts_extract_param_items(parameter_list_node, source_bytes):
    params = []
    if parameter_list_node is None:
        return params
    for param_decl in parameter_list_node.children:
        if param_decl.type not in (
            'parameter_declaration',
            'optional_parameter_declaration',
            'variadic_parameter_declaration',
        ):
            continue
        param_text = _ts_compact_text(_ts_node_text(source_bytes, param_decl))
        if (not param_text) or (param_text == 'void'):
            continue
        param_text_no_default = _safe_str(param_text.split('=', 1)[0])
        param_name = ''
        for id_node in _ts_find_descendants(param_decl, {'identifier', 'field_identifier'}):
            param_name = _ts_compact_text(_ts_node_text(source_bytes, id_node))
        param_type = param_text_no_default
        if param_name and param_type.endswith(param_name):
            param_type = _safe_str(param_type[:len(param_type) - len(param_name)])
        params.append({
            'name': _safe_str(param_name),
            'type': _safe_str(param_type),
            'default_value': None,
            'description': '',
        })
    return params


def _ts_build_signature_from_callable_node(callable_node, source_bytes, declarator_node=None):
    node = callable_node
    if node is None:
        return ''

    # Build signature directly from syntax nodes before the function body,
    # avoiding fragile text truncation when default args contain braces.
    if node.type == 'function_definition':
        if declarator_node is not None:
            decl_text = _ts_compact_text(_ts_node_text(source_bytes, declarator_node))
            if decl_text:
                prefix_parts = []
                suffix_parts = []
                seen_decl = False
                for child in node.children:
                    child_type = _safe_str(child.type)
                    if child_type in ('compound_statement', 'try_statement'):
                        break
                    if _ts_same_node(child, declarator_node):
                        seen_decl = True
                        continue
                    if child_type in ('comment', 'class_specifier', 'struct_specifier'):
                        continue
                    text = _ts_compact_text(_ts_node_text(source_bytes, child))
                    if not text:
                        continue
                    if seen_decl:
                        suffix_parts.append(text)
                    else:
                        prefix_parts.append(text)
                return _safe_str(' '.join(prefix_parts + [decl_text] + suffix_parts))
        parts = []
        for child in node.children:
            if child.type in ('compound_statement', 'try_statement'):
                break
            text = _ts_compact_text(_ts_node_text(source_bytes, child))
            if text:
                parts.append(text)
        return _safe_str(' '.join(parts))

    text = _ts_compact_text(_ts_node_text(source_bytes, node))
    if node.type == 'field_declaration' and text.endswith(';'):
        text = _safe_str(text[:-1])
    return text


def _ts_is_valid_method_declaration_field_node(field_node, source_bytes):
    if field_node is None or _safe_str(field_node.type) != 'field_declaration':
        return False
    text = _safe_str(_ts_node_text(source_bytes, field_node))
    if not text:
        return False
    # Keep only declaration-like members; reject error-recovered large fragments.
    if ('{' in text) or ('}' in text):
        return False
    if not text.endswith(';'):
        return False
    return True


def _ts_build_method_item_from_node(
    method_node,
    source_bytes,
    class_name,
    access_text,
    has_body,
    source_lines=None,
    comment_context=None,
):
    if _safe_str(getattr(method_node, 'type', '')) == 'function_definition':
        declarator_node = _ts_select_declarator_for_function_definition(method_node)
    else:
        declarator_node = _ts_find_first_descendant(method_node, {'function_declarator'})
    param_list_node = _ts_find_first_descendant(declarator_node, {'parameter_list'}) if declarator_node else None
    method_name, owner_name = _ts_extract_function_name_and_owner(declarator_node, source_bytes)
    effective_class = _safe_str(owner_name) or _safe_str(class_name)
    if not method_name:
        return None
    code_text, start_line, end_line = _ts_extract_callable_code_with_recovery(source_bytes, method_node)
    signature = _ts_build_signature_from_callable_node(
        method_node,
        source_bytes,
        declarator_node=declarator_node,
    ) or _ts_compact_text(code_text)
    kind = 'method'
    short_class = _safe_str(effective_class.split('::')[-1]) if effective_class else ''
    if method_name.startswith('~'):
        kind = 'destructor'
    elif method_name.startswith('operator'):
        kind = 'operator'
    elif short_class and method_name == short_class:
        kind = 'constructor'
    return_type = _return_type_from_signature(signature, method_name, kind)
    return {
        'kind': kind,
        'name': method_name,
        'qualified_name': f"{effective_class}::{method_name}" if effective_class else method_name,
        'signature': signature,
        'return_type': return_type,
        'params': _ts_extract_param_items(param_list_node, source_bytes),
        'access': _normalize_access(access_text, default=''),
        'is_static': False,
        'is_virtual': False,
        'is_const': (' const' in f" {signature}"),
        'is_pure_virtual': False,
        'start_line': max(1, int(start_line)),
        'end_line': max(1, int(end_line)),
        'has_body': bool(has_body),
        'code': code_text,
        '_leading_comment': _ts_extract_leading_comment_for_node(
            declarator_node if declarator_node is not None else method_node,
            source_lines=source_lines,
            comment_context=comment_context,
        ),
    }


def _extract_classes_and_functions_from_treesitter(filename, content):
    source = str(content or '')
    source_lines = source.splitlines()
    source_bytes = source.encode('utf-8', errors='replace')
    parser = _get_cpp_tree_sitter_parser()
    tree = parser.parse(source_bytes)
    root = tree.root_node
    comment_nodes = _ts_collect_comment_nodes(root, source_bytes)
    comment_context = _ts_build_comment_context(comment_nodes)

    classes = []
    functions = []
    method_access_by_range = {}
    seen_function_keys = set()

    for node in _ts_iter_nodes(root):
        if node.type not in ('class_specifier', 'struct_specifier'):
            continue
        class_name_node = None
        for child in node.children:
            if child.type in ('type_identifier', 'identifier'):
                class_name_node = child
                break
        class_name = _ts_compact_text(_ts_node_text(source_bytes, class_name_node))
        if not class_name:
            continue

        class_kind = 'class'
        prefix_text = _ts_compact_text(_ts_node_text(source_bytes, node)[:12]).lower()
        if prefix_text.startswith('struct'):
            class_kind = 'struct'

        base_items = []
        base_clause = _ts_find_first_descendant(node, {'base_class_clause'})
        if base_clause is not None:
            current_access = 'public'
            for bc in base_clause.children:
                if bc.type == 'access_specifier':
                    current_access = _normalize_access(_ts_compact_text(_ts_node_text(source_bytes, bc)), default='public') or 'public'
                elif bc.type in ('type_identifier', 'qualified_identifier', 'template_type'):
                    base_name = _ts_compact_text(_ts_node_text(source_bytes, bc))
                    if base_name:
                        base_items.append({
                            'base_name': base_name,
                            'access': current_access,
                            'is_virtual': False,
                        })

        body_node = None
        for child in node.children:
            if child.type == 'field_declaration_list':
                body_node = child
                break
        if body_node is None:
            continue

        default_access = 'private' if class_kind == 'class' else 'public'
        current_access = default_access
        member_vars = []
        member_methods = []
        member_var_decls = []
        member_method_decls = []

        for child in body_node.children:
            if child.type == 'access_specifier':
                current_access = _normalize_access(_ts_compact_text(_ts_node_text(source_bytes, child)), default=current_access) or current_access
                continue

            for member_node in _ts_collect_class_member_nodes(child, node):
                if member_node.type == 'field_declaration':
                    method_decl_node = _ts_find_first_descendant(member_node, {'function_declarator'})
                    if method_decl_node is not None and _ts_is_valid_method_declaration_field_node(member_node, source_bytes):
                        field_has_body = _ts_find_first_descendant(
                            member_node,
                            {'compound_statement', 'initializer_list', 'try_statement'},
                        ) is not None
                        method_item = _ts_build_method_item_from_node(
                            method_node=member_node,
                            source_bytes=source_bytes,
                            class_name=class_name,
                            access_text=current_access,
                            has_body=field_has_body,
                            source_lines=source_lines,
                            comment_context=comment_context,
                        )
                        if method_item is not None:
                            member_methods.append(method_item)
                            decl = _build_member_method_decl_for_prompt(method_item)
                            if decl:
                                member_method_decls.append(decl)
                            if field_has_body:
                                key = (
                                    _safe_str(method_item.get('kind')),
                                    _safe_str(method_item.get('name')),
                                    _safe_str(method_item.get('signature')),
                                    int(method_item.get('start_line') or 0),
                                    int(method_item.get('end_line') or 0),
                                )
                                method_access_by_range[key] = _normalize_access(current_access, default=default_access) or default_access
                                functions.append(_build_function_item_from_member_method(class_name, method_item))
                        continue

                    type_text = ''
                    if member_node.children:
                        type_text = _ts_compact_text(_ts_node_text(source_bytes, member_node.children[0]))
                    for field_id in _ts_find_descendants(member_node, {'field_identifier'}):
                        var_name = _ts_compact_text(_ts_node_text(source_bytes, field_id))
                        if not var_name:
                            continue
                        var_item = {
                            'name': var_name,
                            'type': type_text,
                            'class_name': class_name,
                            'access': _normalize_access(current_access, default=default_access) or default_access,
                            'is_static': False,
                            'line': _ts_line_of(field_id),
                        }
                        member_vars.append(var_item)
                        decl = _build_member_variable_decl_for_prompt(var_item)
                        if decl:
                            member_var_decls.append(decl)
                    continue

                if member_node.type == 'function_definition':
                    method_item = _ts_build_method_item_from_node(
                        method_node=member_node,
                        source_bytes=source_bytes,
                        class_name=class_name,
                        access_text=current_access,
                        has_body=True,
                        source_lines=source_lines,
                        comment_context=comment_context,
                    )
                    if method_item is None:
                        continue
                    member_methods.append(method_item)
                    decl = _build_member_method_decl_for_prompt(method_item)
                    if decl:
                        member_method_decls.append(decl)
                    key = (
                        _safe_str(method_item.get('kind')),
                        _safe_str(method_item.get('name')),
                        _safe_str(method_item.get('signature')),
                        int(method_item.get('start_line') or 0),
                        int(method_item.get('end_line') or 0),
                    )
                    method_access_by_range[key] = _normalize_access(current_access, default=default_access) or default_access
                    functions.append(_build_function_item_from_member_method(class_name, method_item))

        classes.append({
            'class_name': class_name,
            'qualified_name': class_name,
            'kind': class_kind,
            'bases': base_items,
            'member_variables': member_vars,
            'member_methods': member_methods,
            '_prompt_member_variable_decls': member_var_decls,
            '_prompt_member_method_decls': member_method_decls,
            '_clang_decl_id': '',
        })

    for node in _ts_iter_nodes(root):
        if node.type != 'function_definition':
            continue
        parent = node.parent
        inside_class = False
        while parent is not None:
            if parent.type in ('class_specifier', 'struct_specifier'):
                inside_class = True
                break
            parent = parent.parent
        if inside_class:
            continue

        declarator_node = _ts_select_declarator_for_function_definition(node)
        if declarator_node is None:
            continue
        param_list_node = _ts_find_first_descendant(declarator_node, {'parameter_list'})
        node_name, owner_name = _ts_extract_function_name_and_owner(declarator_node, source_bytes)
        if not node_name:
            continue
        class_name = _safe_str(owner_name) or _safe_str(_ts_infer_owner_from_function_definition(node, source_bytes))
        kind = 'function'
        short_class = _safe_str(class_name.split('::')[-1]) if class_name else ''
        if node_name.startswith('~'):
            kind = 'destructor'
        elif node_name.startswith('operator'):
            kind = 'operator'
        elif short_class and node_name == short_class:
            kind = 'constructor'
        elif class_name:
            kind = 'method'
        code_text, start_line, end_line = _ts_extract_callable_code_with_recovery(source_bytes, node)
        signature = _ts_build_signature_from_callable_node(
            node,
            source_bytes,
            declarator_node=declarator_node,
        ) or _ts_compact_text(code_text)
        return_type = _return_type_from_signature(signature, node_name, kind)
        access_key = (kind, node_name, signature, start_line, end_line)
        func_key = (
            _safe_str(f"{class_name}::{node_name}" if class_name else node_name),
            _safe_str(signature),
            int(start_line),
            int(end_line),
        )
        if func_key in seen_function_keys:
            continue
        seen_function_keys.add(func_key)
        functions.append({
            'kind': kind,
            'qualified_name': f"{class_name}::{node_name}" if class_name else node_name,
            'class_name': class_name,
            'access': _normalize_access(method_access_by_range.get(access_key), default=''),
            'signature': signature,
            'params': _ts_extract_param_items(param_list_node, source_bytes),
            'returns': {
                'type': return_type,
                'description': '',
            },
            'summary': '',
            'location': {
                'start_line': max(0, int(start_line)),
                'end_line': max(0, int(end_line)),
            },
            'code': code_text,
            '_leading_comment': _ts_extract_leading_comment_for_node(
                declarator_node if declarator_node is not None else node,
                source_lines=source_lines,
                comment_context=comment_context,
            ),
        })

    # Recovery path: some class methods may be degraded to declaration nodes under
    # public:/private:/protected: labeled statements when tree-sitter hits errors.
    if classes:
        default_class_name = _safe_str((classes[0] or {}).get('qualified_name') or (classes[0] or {}).get('class_name')) if len(classes) == 1 else ''
    else:
        default_class_name = ''
    for node in _ts_iter_nodes(root):
        if node.type != 'declaration':
            continue
        declarator_node = _ts_find_first_descendant(node, {'function_declarator'})
        if declarator_node is None:
            continue
        declarator_text = _ts_compact_text(_ts_node_text(source_bytes, declarator_node))
        if not declarator_text or '(' not in declarator_text:
            continue
        parent = node.parent
        if parent is None or _safe_str(parent.type) != 'labeled_statement':
            continue
        parent_text = _ts_compact_text(_ts_node_text(source_bytes, parent)).lower()
        if not (
            parent_text.startswith('public:')
            or parent_text.startswith('private:')
            or parent_text.startswith('protected:')
        ):
            continue

        node_name, owner_name = _ts_extract_function_name_and_owner(declarator_node, source_bytes)
        if not node_name:
            continue
        class_name = _safe_str(owner_name) or default_class_name
        kind = 'function'
        short_class = _safe_str(class_name.split('::')[-1]) if class_name else ''
        if node_name.startswith('~'):
            kind = 'destructor'
        elif node_name.startswith('operator'):
            kind = 'operator'
        elif short_class and node_name == short_class:
            kind = 'constructor'
        elif class_name:
            kind = 'method'

        prefix_parts = []
        for child in node.children:
            child_type = _safe_str(child.type)
            if child_type in ('init_declarator', 'function_declarator'):
                break
            if child_type in (
                'storage_class_specifier',
                'type_qualifier',
                'primitive_type',
                'sized_type_specifier',
                'type_identifier',
                'qualified_identifier',
                'template_type',
            ):
                text_part = _ts_compact_text(_ts_node_text(source_bytes, child))
                if text_part:
                    prefix_parts.append(text_part)
        signature = _safe_str(' '.join(prefix_parts + [declarator_text])) or declarator_text
        return_type = _return_type_from_signature(signature, node_name, kind)
        code_text, start_line, end_line = _ts_extract_callable_code_with_recovery(source_bytes, node)
        func_key = (
            _safe_str(f"{class_name}::{node_name}" if class_name else node_name),
            _safe_str(signature),
            int(start_line),
            int(end_line),
        )
        if func_key in seen_function_keys:
            continue
        seen_function_keys.add(func_key)
        functions.append({
            'kind': kind,
            'qualified_name': f"{class_name}::{node_name}" if class_name else node_name,
            'class_name': class_name,
            'access': _normalize_access(parent_text.split(':', 1)[0], default=''),
            'signature': signature,
            'params': _ts_extract_param_items(
                _ts_find_first_descendant(declarator_node, {'parameter_list'}),
                source_bytes,
            ),
            'returns': {
                'type': return_type,
                'description': '',
            },
            'summary': '',
            'location': {
                'start_line': max(0, int(start_line)),
                'end_line': max(0, int(end_line)),
            },
            'code': code_text,
            '_leading_comment': _ts_extract_leading_comment_for_node(
                declarator_node,
                source_lines=source_lines,
                comment_context=comment_context,
            ),
        })

    return classes, functions


def _iter_ast_nodes(node):
    if not isinstance(node, dict):
        return
    yield node
    for child in (node.get('inner') or []):
        if isinstance(child, dict):
            for sub in _iter_ast_nodes(child):
                yield sub


def _return_type_from_signature(signature, node_name, func_kind):
    if func_kind in ('constructor', 'destructor'):
        return ''
    text = _safe_str(signature)
    if not text:
        return ''
    if func_kind == 'operator':
        op_pos = text.find('operator')
        if op_pos > 0:
            return _safe_str(text[:op_pos])
        return ''
    marker = _safe_str(node_name)
    if not marker:
        return ''
    pos = text.find(marker)
    if pos <= 0:
        return ''
    return _safe_str(text[:pos])


def _build_member_method_decl_for_prompt(method):
    access = _safe_str(method.get('access')) or 'private'
    signature = _safe_str(method.get('signature'))
    if not signature:
        return ''
    return f"{access}: {signature};"


def _build_member_variable_decl_for_prompt(member):
    access = _safe_str(member.get('access')) or 'private'
    m_type = _safe_str(member.get('type'))
    m_name = _safe_str(member.get('name'))
    if m_type and m_name:
        return f"{access}: {m_type} {m_name};"
    if m_name:
        return f"{access}: {m_name};"
    return ''


def _call_qwen_structured_function_entity(function_item):
    leading_comment = _safe_str((function_item or {}).get('_leading_comment'))
    comment_block = leading_comment if leading_comment else '(无)'
    prompt = (
        "你是代码结构化整理助手。请基于给定“单个函数/方法”信息补充结构化说明。\n"
        "要求：\n"
        "1. 只输出一个 JSON 对象，不要输出解释。\n"
        "2. 只允许输出这些字段：summary, params, returns。\n"
        "3. params 仅输出 name 和 description；returns 仅输出 description。\n"
        "4. 不要改动参数名，不要虚构参数。\n"
        "5. summary 必须使用中文，描述函数的功能用途，如果算法比较特别可以说一下它适用的场景，但绝对不描述内部实现方式。如果已经有人工注释，就尽可能用人工注释的原话去描述。\n"
        "6. 如果代码里已经有人工注释，请尽可能保留注释里的有效信息，你也可以增加必要补充说明。\n\n"
        "JSON 格式：\n"
        "{\n"
        "  \"summary\": \"代码功能说明，使用中文\",\n"
        "  \"params\": [{\"name\": \"\", \"description\": \"\"}],\n"
        "  \"returns\": {\"description\": \"\"}\n"
        "}\n\n"
        f"[函数前人工注释]\n{comment_block}\n\n"
        f"[函数代码]\n{function_item.get('code')}\n"
    )
    text = _call_qwen_text(
        prompt_text=prompt,
        timeout=_DEFAULT_LLM_TIMEOUT_SECONDS,
        model=_STRUCTURED_ENTITY_MODEL,
        enable_thinking=False,
    )
    data = _extract_first_json_object_relaxed(text)
    if not isinstance(data, dict):
        raise RuntimeError(
            f"函数结构化补充失败：{function_item.get('qualified_name')}"
        )
    return data


def _call_qwen_structured_class_entity(class_item):
    payload = {
        'class_name': class_item.get('class_name'),
        'qualified_name': class_item.get('qualified_name'),
        'kind': class_item.get('kind'),
        'bases': class_item.get('bases') or [],
        'member_variables_decl': class_item.get('_prompt_member_variable_decls') or [],
        'member_methods_decl': class_item.get('_prompt_member_method_decls') or [],
    }
    prompt = (
        "你是代码结构化整理助手。请基于给定“单个类/结构体声明信息”输出结构化 JSON。\n"
        "注意：成员函数只给了声明，没有实现；禁止编造成员函数实现细节。\n"
        "只输出一个 JSON 对象，字段必须为：\n"
        "class_name, qualified_name, kind, bases, member_variables, member_methods。\n\n"
        "JSON 中 member_variables 元素格式：\n"
        "{\"name\":\"\",\"type\":\"\",\"class_name\":\"\",\"access\":\"public|private|protected\",\"is_static\":false,\"line\":0}\n"
        "JSON 中 member_methods 元素格式：\n"
        "{\"name\":\"\",\"qualified_name\":\"\",\"signature\":\"\",\"return_type\":\"\",\"access\":\"public|private|protected\","
        "\"is_static\":false,\"is_virtual\":false,\"is_const\":false,\"is_pure_virtual\":false,\"start_line\":0,\"end_line\":0}\n\n"
        f"[类声明输入]\n{json.dumps(payload, ensure_ascii=False)}\n"
    )
    text = _call_qwen_text(
        prompt_text=prompt,
        timeout=_DEFAULT_LLM_TIMEOUT_SECONDS,
        model=_STRUCTURED_ENTITY_MODEL,
        enable_thinking=False,
    )
    data = _extract_first_json_object_relaxed(text)
    if not isinstance(data, dict):
        raise RuntimeError(
            f"类结构化补充失败：{class_item.get('qualified_name')}"
        )
    return data


def _merge_function_with_llm_enrichment(function_item, llm_item):
    merged = dict(function_item or {})
    llm_data = llm_item if isinstance(llm_item, dict) else {}

    merged['summary'] = _safe_str(llm_data.get('summary'), default=merged.get('summary') or '')

    param_desc = {}
    for row in (llm_data.get('params') or []):
        if not isinstance(row, dict):
            continue
        key = _safe_str(row.get('name'))
        if not key:
            continue
        param_desc[key] = _safe_str(row.get('description'))

    merged_params = []
    for param in (merged.get('params') or []):
        if not isinstance(param, dict):
            continue
        p = dict(param)
        pname = _safe_str(p.get('name'))
        if pname in param_desc and param_desc[pname]:
            p['description'] = param_desc[pname]
        merged_params.append(p)
    merged['params'] = merged_params

    returns = merged.get('returns') if isinstance(merged.get('returns'), dict) else {}
    returns = dict(returns)
    llm_returns = llm_data.get('returns') if isinstance(llm_data.get('returns'), dict) else {}
    ret_desc = _safe_str(llm_returns.get('description'))
    if ret_desc:
        returns['description'] = ret_desc
    merged['returns'] = returns
    return merged


def _build_function_item_from_member_method(class_name, method_item):
    method = method_item if isinstance(method_item, dict) else {}
    method_name = _safe_str(method.get('name'))
    qualified_name = _safe_str(method.get('qualified_name'))
    if not qualified_name:
        qualified_name = f"{class_name}::{method_name}" if class_name and method_name else method_name
    signature = _safe_str(method.get('signature'))
    params = method.get('params') if isinstance(method.get('params'), list) else []
    normalized_params = []
    for row in params:
        if not isinstance(row, dict):
            continue
        normalized_params.append({
            'name': _safe_str(row.get('name')),
            'type': _safe_str(row.get('type')),
            'default_value': row.get('default_value'),
            'description': _safe_str(row.get('description')),
        })

    start_line = _safe_int(method.get('start_line'), 0)
    end_line = _safe_int(method.get('end_line'), start_line)
    return {
        'kind': _safe_str(method.get('kind'), default='method') or 'method',
        'qualified_name': qualified_name,
        'class_name': _safe_str(class_name),
        'access': _normalize_access(method.get('access'), default=''),
        'signature': signature,
        'params': normalized_params,
        'returns': {
            'type': _safe_str(method.get('return_type')),
            'description': '',
        },
        'summary': '',
        'location': {
            'start_line': max(0, int(start_line)),
            'end_line': max(0, int(end_line)),
        },
        'code': _safe_str(method.get('code')) or (f"{signature};" if signature else ''),
        'has_body': _safe_bool(method.get('has_body'), False),
        '_leading_comment': _safe_str(method.get('_leading_comment')),
    }

def _notify_structuring_progress(progress_callback, stage, detail):
    if not callable(progress_callback):
        return
    try:
        progress_callback(str(stage or '').strip(), str(detail or '').strip())
    except Exception:
        pass


def _build_structured_with_treesitter_and_qwen(
    file_item,
    progress_callback=None,
    function_callback=None,
    *,
    strict_structuring=False,
):
    filename = str((file_item or {}).get('filename') or '')
    content = str((file_item or {}).get('content') or '')
    repo_file_id = _safe_int((file_item or {}).get('id'), 0)
    source_hash = _sha256_text(content)

    _notify_structuring_progress(progress_callback, 'syntax_parse', '正在解析语法树')
    raw_classes, raw_functions = _extract_classes_and_functions_from_treesitter(
        filename=filename,
        content=content,
    )
    _notify_structuring_progress(
        progress_callback,
        'syntax_parse',
        f'语法树解析完成：类 {len(raw_classes)} 个，函数实现 {len(raw_functions)} 个',
    )

    classes = []
    total_classes = len(raw_classes)
    for class_idx, cls in enumerate(raw_classes, start=1):
        cls_name = _safe_str(cls.get('qualified_name') or cls.get('class_name')) or '(anonymous)'
        _notify_structuring_progress(
            progress_callback,
            'class_structuring',
            f'类声明结构化 {class_idx}/{total_classes}：{cls_name}',
        )
        class_payload = dict(cls)
        for noisy_key in ('_prompt_member_variable_decls', '_prompt_member_method_decls', '_clang_decl_id'):
            class_payload.pop(noisy_key, None)
        try:
            llm_cls = _call_qwen_structured_class_entity(class_item=cls)
            if isinstance(llm_cls, dict):
                for field in ('kind', 'bases', 'member_variables', 'member_methods'):
                    if llm_cls.get(field) is not None:
                        class_payload[field] = llm_cls.get(field)
        except Exception as exc:
            if strict_structuring:
                raise RuntimeError(f'类声明结构化失败：{cls_name}；{str(exc)}') from exc
            _notify_structuring_progress(
                progress_callback,
                'class_structuring',
                f'类声明补充失败，降级使用语法树结果：{cls_name}；{str(exc)}',
            )
        normalized_cls = _normalize_class_item(
            class_payload,
            filename=filename,
            repo_file_id=repo_file_id,
            source_hash=source_hash,
        )
        if normalized_cls:
            classes.append(normalized_cls)

    functions = []
    total_functions = len(raw_functions)
    for func_idx, func in enumerate(raw_functions, start=1):
        qname = _safe_str(func.get('qualified_name')) or '(anonymous)'
        _notify_structuring_progress(
            progress_callback,
            'function_structuring',
            f'函数结构化 {func_idx}/{total_functions}：{qname}',
        )
        merged = dict(func)
        try:
            llm_func = _call_qwen_structured_function_entity(function_item=func)
            merged = _merge_function_with_llm_enrichment(func, llm_func)
        except Exception as exc:
            if strict_structuring:
                raise RuntimeError(f'函数结构化失败：{qname}；{str(exc)}') from exc
            _notify_structuring_progress(
                progress_callback,
                'function_structuring',
                f'函数补充失败，降级使用语法树结果：{qname}；{str(exc)}',
            )
        normalized_func = _normalize_function_item(
            merged,
            filename=filename,
            repo_file_id=repo_file_id,
            source_hash=source_hash,
        )
        if normalized_func:
            if callable(function_callback):
                function_callback(normalized_func, classes)
            functions.append(normalized_func)

    return {
        'functions': functions,
        'classes': classes,
        'source_hash': source_hash,
    }


def _normalize_param_item(item):
    if not isinstance(item, dict):
        return {
            'name': '',
            'type': '',
            'default_value': None,
            'description': '',
        }
    return {
        'name': _safe_str(item.get('name')),
        'type': _safe_str(item.get('type')),
        'default_value': item.get('default_value'),
        'description': _safe_str(item.get('description')),
    }


def _normalize_returns_item(item):
    if not isinstance(item, dict):
        return {'type': '', 'description': ''}
    return {
        'type': _safe_str(item.get('type')),
        'description': _safe_str(item.get('description')),
    }


def _normalize_class_item(item, filename, repo_file_id, source_hash):
    if not isinstance(item, dict):
        return None

    class_name = _safe_str(item.get('class_name'))
    qualified_name = _safe_str(item.get('qualified_name'))
    if not qualified_name:
        qualified_name = class_name
    if not class_name:
        class_name = qualified_name.split('::')[-1] if qualified_name else ''
    if not class_name:
        return None

    kind = _safe_str(item.get('kind')).lower()
    if kind not in ('class', 'struct'):
        kind = 'class'

    default_access = 'private' if kind == 'class' else 'public'

    bases = []
    for base in (item.get('bases') or []):
        if not isinstance(base, dict):
            continue
        base_name = _safe_str(base.get('base_name'))
        if not base_name:
            continue
        bases.append({
            'base_name': base_name,
            'access': _normalize_access(base.get('access'), default=default_access) or default_access,
            'is_virtual': _safe_bool(base.get('is_virtual'), False),
        })

    member_variables = []
    for var in (item.get('member_variables') or []):
        if not isinstance(var, dict):
            continue
        name = _safe_str(var.get('name'))
        if not name:
            continue
        member_variables.append({
            'name': name,
            'type': _safe_str(var.get('type')),
            'class_name': _safe_str(var.get('class_name')) or qualified_name,
            'access': _normalize_access(var.get('access'), default=default_access) or default_access,
            'is_static': _safe_bool(var.get('is_static'), False),
            'line': max(0, _safe_int(var.get('line'), 0)),
        })

    member_methods = []
    for method in (item.get('member_methods') or []):
        if not isinstance(method, dict):
            continue
        m_name = _safe_str(method.get('name'))
        m_qname = _safe_str(method.get('qualified_name'))
        if not m_qname and m_name:
            m_qname = f"{qualified_name}::{m_name}" if qualified_name else m_name
        if not m_name and m_qname:
            m_name = m_qname.split('::')[-1]
        if not m_name:
            continue

        start_line = max(0, _safe_int(method.get('start_line'), 0))
        end_line = max(start_line, _safe_int(method.get('end_line'), start_line))
        member_methods.append({
            'name': m_name,
            'qualified_name': m_qname,
            'signature': _safe_str(method.get('signature')),
            'return_type': _safe_str(method.get('return_type')),
            'access': _normalize_access(method.get('access'), default=default_access) or default_access,
            'is_static': _safe_bool(method.get('is_static'), False),
            'is_virtual': _safe_bool(method.get('is_virtual'), False),
            'is_const': _safe_bool(method.get('is_const'), False),
            'is_pure_virtual': _safe_bool(method.get('is_pure_virtual'), False),
            'start_line': start_line,
            'end_line': end_line,
        })

    return {
        'schema_version': '1.0',
        'class_id': uuid.uuid4().hex,
        'repo_file_id': int(repo_file_id),
        'filename': filename,
        'kind': kind,
        'class_name': class_name,
        'qualified_name': qualified_name or class_name,
        'bases': bases,
        'member_variables': member_variables,
        'member_methods': member_methods,
        'source_hash': source_hash,
    }


def _normalize_function_item(item, filename, repo_file_id, source_hash):
    if not isinstance(item, dict):
        return None

    kind = _normalize_kind(item.get('kind'), default='function')
    qualified_name = _safe_str(item.get('qualified_name'))
    signature = _safe_str(item.get('signature'))
    if not qualified_name:
        if signature:
            qualified_name = signature.split('(')[0].strip()
        else:
            return None

    class_name = _safe_str(item.get('class_name'))
    access = _normalize_access(item.get('access'), default='')

    location = item.get('location') if isinstance(item.get('location'), dict) else {}
    start_line = max(0, _safe_int(location.get('start_line'), _safe_int(item.get('start_line'), 0)))
    end_line = max(start_line, _safe_int(location.get('end_line'), _safe_int(item.get('end_line'), start_line)))

    params = []
    for param in (item.get('params') or []):
        params.append(_normalize_param_item(param))

    returns = _normalize_returns_item(item.get('returns'))
    summary = _safe_str(item.get('summary'))
    if not summary:
        summary = f"Function {qualified_name}"

    return {
        'schema_version': '1.0',
        'chunk_id': uuid.uuid4().hex,
        'repo_file_id': int(repo_file_id),
        'filename': filename,
        'language': _detect_language_from_filename(filename),
        'kind': kind,
        'qualified_name': qualified_name,
        'class_name': class_name,
        'access': access,
        'signature': signature,
        'params': params,
        'returns': returns,
        'summary': summary,
        'location': {
            'start_line': start_line,
            'end_line': end_line,
        },
        'source_hash': source_hash,
        'code': str(item.get('code') or ''),
    }


def _embedding_model_name(provider=None):
    use_provider = str(provider or _DEFAULT_PROVIDER).strip().lower()
    if use_provider == 'sentence_transformers':
        return _DEFAULT_SENTENCE_MODEL
    if use_provider == 'qwen_embedding':
        return _DEFAULT_QWEN_EMBEDDING_MODEL
    return _DEFAULT_QWEN_EMBEDDING_MODEL


def _normalize_l2(vectors):
    if vectors.size == 0:
        return vectors.astype(np.float32)
    arr = np.asarray(vectors, dtype=np.float32)
    norms = np.linalg.norm(arr, axis=1, keepdims=True)
    norms = np.where(norms <= 0, 1.0, norms)
    return arr / norms


def _resolve_dashscope_credentials():
    api_key = DASHSCOPE_API_KEY
    base_url = DASHSCOPE_BASE_URL
    api_key = str(api_key or '').strip()
    base_url = str(base_url or '').strip().rstrip('/')
    if (not api_key) or ('YOUR' in api_key.upper()):
        raise RuntimeError('未配置 DASHSCOPE_API_KEY，无法执行真实向量化。')
    if not base_url:
        raise RuntimeError('未配置 DASHSCOPE_BASE_URL，无法执行真实向量化。')
    return api_key, base_url


def _encode_with_qwen_embedding(texts, model_name=None):
    use_texts = [str(x or '') for x in texts]
    if not use_texts:
        return np.zeros((0, 0), dtype=np.float32), str(model_name or _DEFAULT_QWEN_EMBEDDING_MODEL)

    api_key, base_url = _resolve_dashscope_credentials()
    use_model = str(model_name or _DEFAULT_QWEN_EMBEDDING_MODEL).strip()
    headers = {
        'Authorization': f'Bearer {api_key}',
        'Content-Type': 'application/json',
    }

    vectors = []
    for i in range(0, len(use_texts), _DEFAULT_EMBEDDING_BATCH_SIZE):
        batch = use_texts[i:i + _DEFAULT_EMBEDDING_BATCH_SIZE]
        payload = {
            'model': use_model,
            'input': batch,
        }
        resp = requests.post(
            f'{base_url}/embeddings',
            headers=headers,
            json=payload,
            timeout=_DEFAULT_EMBEDDING_TIMEOUT_SECONDS,
        )
        resp.raise_for_status()
        result = resp.json() or {}
        data = result.get('data') or []
        if not isinstance(data, list) or len(data) != len(batch):
            raise RuntimeError(f'Embedding 返回格式异常: count={len(data)} expected={len(batch)}')
        ordered = sorted(data, key=lambda x: int(x.get('index', 0)))
        for item in ordered:
            embedding = item.get('embedding')
            if not isinstance(embedding, list) or not embedding:
                raise RuntimeError('Embedding 向量为空或格式错误。')
            vectors.append(embedding)

    arr = np.asarray(vectors, dtype=np.float32)
    arr = _normalize_l2(arr)
    return arr, use_model


def _get_sentence_model(model_name=None):
    use_model = str(model_name or _DEFAULT_SENTENCE_MODEL).strip()
    if use_model in _sentence_model_cache:
        return _sentence_model_cache[use_model]
    if SentenceTransformer is None:
        raise RuntimeError('未安装 sentence-transformers，无法执行真实向量化。')
    model = SentenceTransformer(use_model)
    _sentence_model_cache[use_model] = model
    return model


def _encode_with_sentence_transformers(texts, model_name=None):
    use_texts = [str(x or '') for x in texts]
    use_model = str(model_name or _DEFAULT_SENTENCE_MODEL).strip()
    if not use_texts:
        return np.zeros((0, 0), dtype=np.float32), use_model
    model = _get_sentence_model(use_model)
    vecs = model.encode(use_texts, normalize_embeddings=True)
    arr = np.asarray(vecs, dtype=np.float32)
    arr = _normalize_l2(arr)
    return arr, use_model


def encode_texts(texts, embedding_model_override=None):
    provider = _DEFAULT_PROVIDER
    if provider == 'qwen_embedding':
        return _encode_with_qwen_embedding(texts, model_name=embedding_model_override)
    if provider == 'sentence_transformers':
        return _encode_with_sentence_transformers(texts, model_name=embedding_model_override)
    raise RuntimeError(
        f'不支持的 REPOSITORY_EMBEDDING_PROVIDER={provider}。'
        '请使用 qwen_embedding 或 sentence_transformers。'
    )


def encode_texts_with_qwen_embedding(texts, embedding_model_override=None):
    return _encode_with_qwen_embedding(texts, model_name=embedding_model_override)


def _build_embedding_input(chunk, class_map):
    class_name = _safe_str(chunk.get('class_name'))
    class_meta = class_map.get(class_name) or {}
    class_context = ''
    if class_meta:
        bases = class_meta.get('bases') or []
        member_variables = class_meta.get('member_variables') or []
        class_context = f"bases={bases}; member_vars={member_variables[:8]}"

    params_text = json.dumps(chunk.get('params') or [], ensure_ascii=False)
    returns_text = json.dumps(chunk.get('returns') or {}, ensure_ascii=False)

    pieces = [
        _safe_str(chunk.get('qualified_name')),
        _safe_str(chunk.get('signature')),
        _safe_str(chunk.get('summary')),
        params_text,
        returns_text,
        class_context,
        str(chunk.get('code') or ''),
    ]
    return '\n'.join([p for p in pieces if p])


def _ensure_faiss_available():
    if _VECTOR_DB_BACKEND != 'faiss':
        raise RuntimeError(f'不支持的 REPOSITORY_VECTOR_BACKEND={_VECTOR_DB_BACKEND}。当前仅支持 faiss。')
    if faiss is None:
        raise RuntimeError('未安装 faiss，无法进行向量 KNN 检索。请安装 faiss-cpu。')


def _faiss_user_dir(user_id):
    return os.path.join(_FAISS_INDEX_ROOT, str(int(user_id)))


def _faiss_paths(user_id, index_generation=None):
    root = _faiss_user_dir(user_id)
    if index_generation is not None:
        root = os.path.join(root, 'generations', str(int(index_generation)))
    return {
        'root': root,
        'index': os.path.join(root, 'index.faiss'),
        'meta': os.path.join(root, 'meta.json'),
    }


def _fsync_faiss_generation_directories(user_id, index_generation=None):
    """持久化 generation 文件及新建目录的目录项，DB 指针发布前失败关闭。"""
    paths = _faiss_paths(user_id, index_generation=index_generation)
    candidates = [
        paths['root'],
        os.path.dirname(paths['root']),
        _faiss_user_dir(user_id),
        _FAISS_INDEX_ROOT,
        os.path.dirname(_FAISS_INDEX_ROOT),
    ]
    seen = set()
    for directory in candidates:
        normalized = os.path.abspath(directory)
        if normalized in seen:
            continue
        seen.add(normalized)
        fd = os.open(
            normalized,
            os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW,
        )
        try:
            os.fsync(fd)
        finally:
            os.close(fd)


def _write_faiss_index(
    user_id,
    chunk_ids,
    embeddings,
    embedding_model,
    *,
    index_generation=None,
):
    _ensure_faiss_available()
    paths = _faiss_paths(user_id, index_generation=index_generation)
    os.makedirs(paths['root'], exist_ok=True)

    if not chunk_ids:
        meta = {
            'embedding_model': str(embedding_model or ''),
            'vector_db_backend': 'faiss',
            'dimension': 0,
            'chunk_ids': [],
            'index_generation': (
                int(index_generation) if index_generation is not None else None
            ),
            'updated_at': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
        }
        meta_tmp = paths['meta'] + '.tmp'
        with open(meta_tmp, 'w', encoding='utf-8') as f:
            json.dump(meta, f, ensure_ascii=False)
            f.flush()
            os.fsync(f.fileno())
        os.replace(meta_tmp, paths['meta'])
        if os.path.exists(paths['index']):
            os.remove(paths['index'])
        _fsync_faiss_generation_directories(
            user_id,
            index_generation=index_generation,
        )
        return

    vectors = _normalize_l2(np.asarray(embeddings, dtype=np.float32))
    if vectors.ndim != 2 or vectors.shape[0] != len(chunk_ids):
        raise RuntimeError('向量写入失败：向量数量与 chunk 数量不一致。')
    dim = int(vectors.shape[1])
    if dim <= 0:
        raise RuntimeError('向量写入失败：向量维度非法。')

    index = faiss.IndexFlatIP(dim)
    index.add(vectors)

    meta = {
        'embedding_model': str(embedding_model or ''),
        'vector_db_backend': 'faiss',
        'dimension': dim,
        'chunk_ids': list(chunk_ids),
        'index_generation': (
            int(index_generation) if index_generation is not None else None
        ),
        'updated_at': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
    }

    # 原子写：先写到临时文件再 os.replace 落位，避免并发读者（web/agent 进程）读到半成品；
    # 索引文件先落位、meta 后落位（meta 作为“提交”标记）。配合 _load 的一致性校验自愈短暂错配。
    index_tmp = paths['index'] + '.tmp'
    meta_tmp = paths['meta'] + '.tmp'
    faiss.write_index(index, index_tmp)
    with open(index_tmp, 'rb') as f:
        os.fsync(f.fileno())
    with open(meta_tmp, 'w', encoding='utf-8') as f:
        json.dump(meta, f, ensure_ascii=False)
        f.flush()
        os.fsync(f.fileno())
    os.replace(index_tmp, paths['index'])
    os.replace(meta_tmp, paths['meta'])
    _fsync_faiss_generation_directories(
        user_id,
        index_generation=index_generation,
    )


def _load_faiss_index(user_id, index_generation=None):
    _ensure_faiss_available()
    paths = _faiss_paths(user_id, index_generation=index_generation)
    if not os.path.isfile(paths['meta']):
        return None, None
    with open(paths['meta'], 'r', encoding='utf-8') as f:
        meta = json.load(f)
    if index_generation is not None and _safe_int(meta.get('index_generation'), -1) != int(index_generation):
        return None, None
    if not (meta.get('chunk_ids') or []):
        return None, meta
    if not os.path.isfile(paths['index']):
        return None, None
    index = faiss.read_index(paths['index'])
    # 一致性校验：索引向量数与 meta 中 chunk_ids 数不一致，说明读到了写入过程中的瞬时错配
    # （或半成品），视为“尚未就绪”，让调用方回退（DB 检索/空结果），下次读取即自愈。
    try:
        if int(index.ntotal) != len(meta.get('chunk_ids') or []):
            return None, None
    except Exception:
        return None, None
    return index, meta


def _stage_faiss_generation(
    user_id,
    index_generation,
    chunk_ids,
    embeddings,
    embedding_model,
):
    """完整写好一个不可变 FAISS generation，尚不改变读者可见指针。"""
    generation = int(index_generation)
    final_paths = _faiss_paths(user_id, index_generation=generation)
    if os.path.exists(final_paths['root']):
        raise RuntimeError(f'FAISS generation 已存在：{generation}')
    # generation 尚未成为 DB active 指针，写入期间对读者不可见；writer 自身仍以
    # index.tmp/meta.tmp + meta 最后落位保证该 generation 内部完整。
    _write_faiss_index(
        user_id,
        chunk_ids,
        embeddings,
        embedding_model,
        index_generation=generation,
    )
    return final_paths


def _get_active_repository_index_generation(user_id):
    conn = get_db_connection()
    try:
        with conn.cursor() as cursor:
            cursor.execute(
                """
                SELECT active_index_generation, index_status
                FROM repository_states
                WHERE user_id = %s
                """,
                (int(user_id),),
            )
            row = cursor.fetchone() or {}
    finally:
        conn.close()
    if str(row.get('index_status') or '') not in {'ready', 'stale'}:
        return None
    generation = _safe_int(row.get('active_index_generation'), 0)
    return generation if generation > 0 else None


def _build_cumulative_embeddings(functions, embedding_map):
    if not functions:
        return np.zeros((0, 0), dtype=np.float32)
    rows = []
    for func in functions:
        chunk_id = str(func.get('chunk_id') or '')
        vector = embedding_map.get(chunk_id)
        if vector is None:
            raise RuntimeError(f'向量化失败：缺少 chunk 的向量数据（{chunk_id}）。')
        rows.append(np.asarray(vector, dtype=np.float32))
    return np.asarray(rows, dtype=np.float32)


def _build_vectorizing_target_message(func):
    qname = _safe_str((func or {}).get('qualified_name'))
    class_name = _safe_str((func or {}).get('class_name'))
    if qname and class_name:
        return f'正在向量化函数：{qname}（所属类 {class_name}）'
    if qname:
        return f'正在向量化函数：{qname}'
    if class_name:
        return f'正在向量化函数（所属类 {class_name}）'
    return '正在向量化函数'


def _format_repository_progress_message(stage, detail=''):
    stage_key = _safe_str(stage).lower() or 'processing'
    detail_text = _safe_str(detail)
    if detail_text:
        return f"[stage:{stage_key}] {detail_text}"
    return f"[stage:{stage_key}]"


def _parser_cache_key(source_hash):
    payload = '\0'.join([
        _safe_str(source_hash),
        _PARSER_SCHEMA_VERSION,
        _STRUCTURED_ENTITY_MODEL,
    ])
    return hashlib.sha256(payload.encode('utf-8')).hexdigest()


def _embedding_input_hash(text, embedding_model):
    payload = '\0'.join([
        _EMBEDDING_SCHEMA_VERSION,
        _PARSER_SCHEMA_VERSION,
        _STRUCTURED_ENTITY_MODEL,
        _DEFAULT_PROVIDER,
        _safe_str(embedding_model),
        str(_DEFAULT_EMBEDDING_DIM),
        str(text or ''),
    ])
    return hashlib.sha256(payload.encode('utf-8')).hexdigest()


def _clone_cached_structured_file(cache_item, file_item):
    """复用与路径无关的结构化结果，并重写本 generation 的路径/entry id。"""
    filename = str(file_item.get('filename') or '')
    repo_file_id = _safe_int(file_item.get('id'), 0)
    source_hash = _safe_str(file_item.get('source_hash'))
    classes = []
    for template in cache_item.get('classes') or []:
        item = dict(template)
        item['class_id'] = uuid.uuid4().hex
        item['repo_file_id'] = repo_file_id
        item['filename'] = filename
        item['source_hash'] = source_hash
        item.pop('_index_cache', None)
        classes.append(item)
    functions = []
    for template in cache_item.get('functions') or []:
        item = dict(template)
        item['chunk_id'] = uuid.uuid4().hex
        item['repo_file_id'] = repo_file_id
        item['filename'] = filename
        item['source_hash'] = source_hash
        item['language'] = _detect_language_from_filename(filename)
        item.pop('_index_cache', None)
        functions.append(item)
    return {'classes': classes, 'functions': functions, 'source_hash': source_hash}


def _load_active_repository_index_cache(user_id):
    """读取当前 active generation 的结构与向量缓存，不改变任何可见状态。"""
    active_generation = _get_active_repository_index_generation(user_id)
    if active_generation is None:
        return {}, {}

    conn = get_db_connection()
    try:
        with conn.cursor() as cursor:
            cursor.execute(
                """
                SELECT c.chunk_id, c.repo_file_id, c.source_hash, c.embedding_input_hash,
                       c.parser_version, c.structured_model, c.json_data,
                       e.embedding_model, e.vector_json
                FROM repository_function_chunks c
                LEFT JOIN repository_chunk_embeddings e
                  ON e.user_id = c.user_id
                 AND e.index_generation = c.index_generation
                 AND e.chunk_id = c.chunk_id
                WHERE c.user_id = %s AND c.index_generation = %s
                """,
                (int(user_id), int(active_generation)),
            )
            function_rows = cursor.fetchall() or []
            cursor.execute(
                """
                SELECT repo_file_id, source_hash, json_data
                FROM repository_class_metadata
                WHERE user_id = %s AND index_generation = %s
                """,
                (int(user_id), int(active_generation)),
            )
            class_rows = cursor.fetchall() or []
    finally:
        conn.close()

    grouped_file_cache = {}
    vector_cache = {}
    for row in function_rows:
        try:
            payload = json.loads(row.get('json_data') or '{}')
        except Exception:
            continue
        marker = payload.get('_index_cache') if isinstance(payload, dict) else None
        source_hash = _safe_str(row.get('source_hash'))
        expected_file_key = _parser_cache_key(source_hash)
        if (
            not isinstance(marker, dict)
            or marker.get('file_cache_key') != expected_file_key
            or _safe_str(row.get('parser_version')) != _PARSER_SCHEMA_VERSION
            or _safe_str(row.get('structured_model')) != _STRUCTURED_ENTITY_MODEL
        ):
            continue
        bucket = grouped_file_cache.setdefault(
            (expected_file_key, _safe_int(row.get('repo_file_id'), 0)),
            {'classes': [], 'functions': []},
        )
        bucket['functions'].append(payload)

        embedding_hash = _safe_str(row.get('embedding_input_hash'))
        embedding_model = _safe_str(row.get('embedding_model'))
        vector_json = row.get('vector_json')
        if embedding_hash and embedding_model and vector_json:
            try:
                vector = np.asarray(json.loads(vector_json), dtype=np.float32)
            except Exception:
                continue
            if vector.ndim == 1 and vector.size > 0:
                vector_cache[(embedding_hash, embedding_model)] = vector

    for row in class_rows:
        try:
            payload = json.loads(row.get('json_data') or '{}')
        except Exception:
            continue
        marker = payload.get('_index_cache') if isinstance(payload, dict) else None
        source_hash = _safe_str(row.get('source_hash'))
        expected_file_key = _parser_cache_key(source_hash)
        if (
            not isinstance(marker, dict)
            or marker.get('file_cache_key') != expected_file_key
            or marker.get('parser_version') != _PARSER_SCHEMA_VERSION
            or marker.get('structured_model') != _STRUCTURED_ENTITY_MODEL
        ):
            continue
        bucket = grouped_file_cache.setdefault(
            (expected_file_key, _safe_int(row.get('repo_file_id'), 0)),
            {'classes': [], 'functions': []},
        )
        bucket['classes'].append(payload)
    file_cache = {}
    for (file_key, _repo_file_id), bucket in grouped_file_cache.items():
        file_cache.setdefault(file_key, bucket)
    return file_cache, vector_cache


def _attach_index_cache_metadata(classes, functions, embedding_hashes):
    for cls in classes:
        cls['_index_cache'] = {
            'file_cache_key': _parser_cache_key(cls.get('source_hash')),
            'parser_version': _PARSER_SCHEMA_VERSION,
            'structured_model': _STRUCTURED_ENTITY_MODEL,
        }
    for func in functions:
        chunk_id = _safe_str(func.get('chunk_id'))
        func['_index_cache'] = {
            'file_cache_key': _parser_cache_key(func.get('source_hash')),
            'parser_version': _PARSER_SCHEMA_VERSION,
            'structured_model': _STRUCTURED_ENTITY_MODEL,
            'embedding_schema_version': _EMBEDDING_SCHEMA_VERSION,
            'embedding_input_hash': _safe_str(embedding_hashes.get(chunk_id)),
        }


def _insert_index_generation_rows(
    cursor,
    *,
    user_id,
    index_generation,
    classes,
    functions,
    embedding_map,
    embedding_hashes,
    embedding_model,
):
    for cls in classes:
        cursor.execute(
            """
            INSERT INTO repository_class_metadata (
                class_id, user_id, index_generation, repo_file_id, filename,
                kind, class_name, qualified_name, source_hash,
                bases_json, members_json, json_data
            ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
            """,
            (
                cls['class_id'],
                int(user_id),
                int(index_generation),
                cls.get('repo_file_id'),
                cls['filename'],
                cls['kind'],
                cls['class_name'],
                cls['qualified_name'],
                cls['source_hash'],
                json.dumps(cls.get('bases') or [], ensure_ascii=False),
                json.dumps(
                    {
                        'member_variables': cls.get('member_variables') or [],
                        'member_methods': cls.get('member_methods') or [],
                    },
                    ensure_ascii=False,
                ),
                json.dumps(cls, ensure_ascii=False),
            ),
        )

    for func in functions:
        chunk_id = _safe_str(func.get('chunk_id'))
        vector = np.asarray(embedding_map.get(chunk_id), dtype=np.float32).reshape(-1)
        if vector.size <= 0:
            raise RuntimeError(f'向量写入失败：{chunk_id} 没有候选向量')
        cursor.execute(
            """
            INSERT INTO repository_function_chunks (
                chunk_id, user_id, index_generation, repo_file_id, filename,
                language, kind, qualified_name, class_name, access_modifier,
                signature, summary, return_type, start_line, end_line,
                source_hash, embedding_input_hash, parser_version,
                structured_model, code, params_json, returns_json, json_data
            ) VALUES (
                %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s,
                %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s
            )
            """,
            (
                chunk_id,
                int(user_id),
                int(index_generation),
                func.get('repo_file_id'),
                func['filename'],
                func.get('language') or 'cpp',
                func.get('kind') or 'function',
                func['qualified_name'],
                func.get('class_name'),
                func.get('access'),
                func.get('signature') or '',
                func.get('summary') or '',
                (func.get('returns') or {}).get('type')
                if isinstance(func.get('returns'), dict) else '',
                int(func.get('location', {}).get('start_line', 0)),
                int(func.get('location', {}).get('end_line', 0)),
                func.get('source_hash') or '',
                _safe_str(embedding_hashes.get(chunk_id)),
                _PARSER_SCHEMA_VERSION,
                _STRUCTURED_ENTITY_MODEL,
                func.get('code') or '',
                json.dumps(func.get('params') or [], ensure_ascii=False),
                json.dumps(func.get('returns') or {}, ensure_ascii=False),
                json.dumps(func, ensure_ascii=False),
            ),
        )
        cursor.execute(
            """
            INSERT INTO repository_chunk_embeddings (
                chunk_id, user_id, index_generation, embedding_model,
                vector_dim, vector_json
            ) VALUES (%s, %s, %s, %s, %s, %s)
            """,
            (
                chunk_id,
                int(user_id),
                int(index_generation),
                embedding_model,
                int(vector.shape[0]),
                json.dumps(vector.tolist(), ensure_ascii=False),
            ),
        )


def _publish_repository_index_generation(
    *,
    user_id,
    job_id,
    base_repository_generation,
    classes,
    functions,
    embedding_map,
    embedding_hashes,
    embedding_model,
):
    """在一个事务中发布 DB generation，并以 state 指针作为提交点。"""
    from oj_modules.repository.tree import repository_user_lock

    with repository_user_lock(int(user_id), exclusive=False):
        conn = get_db_connection()
        try:
            with conn.cursor() as cursor:
                cursor.execute(
                    """
                    SELECT repository_generation
                    FROM repository_states
                    WHERE user_id = %s
                    FOR UPDATE
                    """,
                    (int(user_id),),
                )
                state = cursor.fetchone() or {}
                current_generation = _safe_int(state.get('repository_generation'), 0)
                if current_generation != int(base_repository_generation):
                    raise RuntimeError(
                        '仓库内容在整理期间发生变化，候选索引未发布；请重新整理。'
                    )
                cursor.execute(
                    """
                    SELECT status, cancel_requested, base_repository_generation
                    FROM repository_index_jobs
                    WHERE id = %s AND user_id = %s
                    FOR UPDATE
                    """,
                    (int(job_id), int(user_id)),
                )
                job = cursor.fetchone() or {}
                if _safe_bool(job.get('cancel_requested'), False):
                    raise RepositoryIndexJobCancelled('结构化整理任务已被取消。')
                if _safe_str(job.get('status')).lower() != 'running':
                    raise RuntimeError(
                        '结构化整理任务的运行租约已经终结，迟到 worker 不得发布候选索引。'
                    )
                if _safe_int(job.get('base_repository_generation'), -1) != int(
                    base_repository_generation
                ):
                    raise RuntimeError(
                        '结构化整理任务固定的仓库 generation 不一致，候选索引未发布。'
                    )

                _insert_index_generation_rows(
                    cursor,
                    user_id=user_id,
                    index_generation=job_id,
                    classes=classes,
                    functions=functions,
                    embedding_map=embedding_map,
                    embedding_hashes=embedding_hashes,
                    embedding_model=embedding_model,
                )
                cursor.execute(
                    """
                    UPDATE repository_states
                    SET active_index_generation = %s, index_status = 'ready'
                    WHERE user_id = %s AND repository_generation = %s
                    """,
                    (
                        int(job_id),
                        int(user_id),
                        int(base_repository_generation),
                    ),
                )
                if int(cursor.rowcount) != 1:
                    raise RuntimeError('仓库 generation 已变化，候选索引未发布')
                cursor.execute(
                    """
                    UPDATE repository_index_jobs
                    SET status = 'success',
                        processed_files = total_files,
                        total_chunks = %s,
                        total_classes = %s,
                        error_message = NULL,
                        progress_message = %s,
                        finished_at = %s
                    WHERE id = %s AND user_id = %s
                      AND status = 'running' AND cancel_requested = 0
                    """,
                    (
                        len(functions),
                        len(classes),
                        _format_repository_progress_message(
                            'completed',
                            '结构化整理与向量化已完成。',
                        ),
                        datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                        int(job_id),
                        int(user_id),
                    ),
                )
                if int(cursor.rowcount) != 1:
                    raise RuntimeError(
                        '结构化整理任务在发布期间已终结，候选索引未发布。'
                    )
            conn.commit()
        except Exception:
            conn.rollback()
            raise
        finally:
            conn.close()


def _cleanup_unpublished_faiss_generation(user_id, index_generation):
    generation = int(index_generation)
    try:
        active_generation = _get_active_repository_index_generation(user_id)
    except Exception:
        # DB 状态未知时不能证明候选未激活；宁可保留垃圾等待下次重试清理。
        return
    if _safe_int(active_generation, 0) == generation:
        return
    paths = _faiss_paths(user_id, index_generation=generation)
    if os.path.isdir(paths['root']):
        shutil.rmtree(paths['root'], ignore_errors=True)


@contextmanager
def _repository_index_build_lock(user_id, job_id):
    """按用户串行化索引构建，包括取消中的旧 worker 与后续 job。

    锁文件放在用户 FAISS 根下、generation 目录之外，因此清理半成品 generation
    不会移除锁本身。``job_id`` 仅保留为调用边界的一部分；同一用户的不同 job
    使用同一把锁，第二个执行者会在首个执行者结束后重新检查 active 指针。
    """

    user_root = _faiss_paths(int(user_id))['root']
    lock_root = os.path.join(user_root, '.build-locks')
    os.makedirs(lock_root, mode=0o700, exist_ok=True)
    lock_path = os.path.join(lock_root, 'user.lock')
    fd = os.open(lock_path, os.O_RDWR | os.O_CREAT | os.O_CLOEXEC, 0o600)
    try:
        fcntl.flock(fd, fcntl.LOCK_EX)
        yield
    finally:
        fcntl.flock(fd, fcntl.LOCK_UN)
        os.close(fd)


def _discard_unpublished_repository_index_generation(user_id, index_generation):
    """精确回收未激活代次的 DB/FAISS 候选，供崩溃后的同 job 重试。"""

    user_id = int(user_id)
    generation = int(index_generation)
    conn = get_db_connection()
    try:
        with conn.cursor() as cursor:
            cursor.execute(
                """
                SELECT active_index_generation
                FROM repository_states
                WHERE user_id = %s
                FOR UPDATE
                """,
                (user_id,),
            )
            state = cursor.fetchone() or {}
            if _safe_int(state.get('active_index_generation'), 0) == generation:
                conn.commit()
                return False
            cursor.execute(
                """
                DELETE FROM repository_chunk_embeddings
                WHERE user_id = %s AND index_generation = %s
                """,
                (user_id, generation),
            )
            cursor.execute(
                """
                DELETE FROM repository_function_chunks
                WHERE user_id = %s AND index_generation = %s
                """,
                (user_id, generation),
            )
            cursor.execute(
                """
                DELETE FROM repository_class_metadata
                WHERE user_id = %s AND index_generation = %s
                """,
                (user_id, generation),
            )
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()

    paths = _faiss_paths(user_id, index_generation=generation)
    if os.path.isdir(paths['root']):
        shutil.rmtree(paths['root'], ignore_errors=True)
    return True


def _run_repository_index_job_once(user_id, job_id, file_id=None):
    """构建并原子发布一个完整索引 generation。

    解析、LLM 结构化、向量化和 FAISS 写入全部在 active 指针之外完成；任一阶段
    失败或取消都不会删除、覆盖或部分更新当前可用 generation。单文件重建也以完整
    generation 发布，只是其余未变化文件会命中内容哈希缓存。
    """

    user_id = int(user_id)
    job_id = int(job_id)
    target_file_id = _safe_int(file_id, 0) if file_id is not None else 0
    if not _try_mark_repository_index_job_running(job_id):
        return {
            'success': False,
            'job_id': job_id,
            'cancelled': True,
            'message': '任务已取消，未执行结构化整理。',
        }

    try:
        if _is_repository_index_job_cancel_requested(job_id):
            raise RepositoryIndexJobCancelled('结构化整理任务已被取消。')

        base_generation, files = _load_repository_index_snapshot(user_id)
        if target_file_id > 0 and not any(
            _safe_int(item.get('id'), 0) == target_file_id for item in files
        ):
            raise RuntimeError(
                f'文件不存在、不可索引或无权限（file_id={target_file_id}）。'
            )
        update_repository_index_job(
            job_id,
            base_repository_generation=base_generation,
            total_files=len(files),
            processed_files=0,
            total_chunks=0,
            total_classes=0,
            progress_message=_format_repository_progress_message(
                'prepare',
                '已固定仓库代次，正在构建不可见的候选索引。',
            ),
        )

        file_cache, vector_cache = _load_active_repository_index_cache(user_id)
        all_functions = []
        all_classes = []
        reused_structured_files = 0

        for idx, file_item in enumerate(files, start=1):
            if _is_repository_index_job_cancel_requested(job_id):
                raise RepositoryIndexJobCancelled('结构化整理任务已被取消。')
            filename = str(file_item.get('filename') or '')
            content_hash = _sha256_text(file_item.get('content'))
            metadata_hash = _safe_str(file_item.get('source_hash'))
            if metadata_hash and metadata_hash != content_hash:
                raise RuntimeError(f'仓库文件摘要不一致：{filename}')
            file_item = dict(file_item)
            file_item['source_hash'] = content_hash

            def _report_file_progress(stage, detail):
                update_repository_index_job(
                    job_id,
                    processed_files=idx - 1,
                    total_chunks=len(all_functions),
                    total_classes=len(all_classes),
                    progress_message=_format_repository_progress_message(
                        stage,
                        f'{filename} - {detail}',
                    ),
                )

            cache_key = _parser_cache_key(content_hash)
            cached = file_cache.get(cache_key)
            if cached:
                normalized = _clone_cached_structured_file(cached, file_item)
                reused_structured_files += 1
                _report_file_progress(
                    'file_prepare',
                    '内容与解析器版本未变化，复用结构化结果。',
                )
            else:
                _report_file_progress('file_prepare', '开始严格结构化处理。')
                normalized = _build_structured_with_treesitter_and_qwen(
                    file_item=file_item,
                    progress_callback=_report_file_progress,
                    strict_structuring=True,
                )

            file_functions = list(normalized.get('functions') or [])
            file_classes = list(normalized.get('classes') or [])
            all_functions.extend(file_functions)
            all_classes.extend(file_classes)
            update_repository_index_job(
                job_id,
                processed_files=idx,
                total_chunks=len(all_functions),
                total_classes=len(all_classes),
                progress_message=_format_repository_progress_message(
                    'file_done',
                    f'已完成文件 {idx}/{len(files)}：{filename}',
                ),
            )

        if _is_repository_index_job_cancel_requested(job_id):
            raise RepositoryIndexJobCancelled('结构化整理任务已被取消。')

        class_map = {}
        for cls in all_classes:
            qualified = _safe_str(cls.get('qualified_name'))
            simple = _safe_str(cls.get('class_name'))
            if qualified:
                class_map[qualified] = cls
            if simple and simple not in class_map:
                class_map[simple] = cls

        embedding_model = _embedding_model_name()
        embedding_map = {}
        embedding_hashes = {}
        missing_functions = []
        missing_texts = []
        reused_vectors = 0
        for func in all_functions:
            text = _build_embedding_input(func, class_map)
            input_hash = _embedding_input_hash(text, embedding_model)
            chunk_id = _safe_str(func.get('chunk_id'))
            embedding_hashes[chunk_id] = input_hash
            cached_vector = vector_cache.get((input_hash, embedding_model))
            if cached_vector is not None:
                embedding_map[chunk_id] = np.asarray(cached_vector, dtype=np.float32)
                reused_vectors += 1
            else:
                missing_functions.append(func)
                missing_texts.append(text)

        for start in range(0, len(missing_functions), _DEFAULT_EMBEDDING_BATCH_SIZE):
            if _is_repository_index_job_cancel_requested(job_id):
                raise RepositoryIndexJobCancelled('结构化整理任务已被取消。')
            batch_functions = missing_functions[start:start + _DEFAULT_EMBEDDING_BATCH_SIZE]
            batch_texts = missing_texts[start:start + _DEFAULT_EMBEDDING_BATCH_SIZE]
            update_repository_index_job(
                job_id,
                progress_message=_format_repository_progress_message(
                    'embedding',
                    (
                        f'正在向量化函数 {start + 1}-'
                        f'{start + len(batch_functions)}/{len(missing_functions)}；'
                        f'已复用 {reused_vectors} 个向量。'
                    ),
                ),
            )
            vectors, model_used = encode_texts(
                batch_texts,
                embedding_model_override=embedding_model,
            )
            if _safe_str(model_used) != embedding_model:
                raise RuntimeError(
                    '向量服务返回的模型与候选缓存键不一致，候选索引未发布。'
                )
            if vectors.shape[0] != len(batch_functions):
                raise RuntimeError('向量化返回数量与函数数量不一致。')
            for func, vector in zip(batch_functions, vectors):
                embedding_map[_safe_str(func.get('chunk_id'))] = np.asarray(
                    vector,
                    dtype=np.float32,
                )

        _attach_index_cache_metadata(
            all_classes,
            all_functions,
            embedding_hashes,
        )
        candidate_vectors = _build_cumulative_embeddings(
            all_functions,
            embedding_map,
        )
        if _is_repository_index_job_cancel_requested(job_id):
            raise RepositoryIndexJobCancelled('结构化整理任务已被取消。')

        update_repository_index_job(
            job_id,
            progress_message=_format_repository_progress_message(
                'persist',
                '候选结构与向量已完成，正在写入不可见 FAISS generation。',
            ),
        )
        _stage_faiss_generation(
            user_id,
            job_id,
            [item['chunk_id'] for item in all_functions],
            candidate_vectors,
            embedding_model,
        )

        if _is_repository_index_job_cancel_requested(job_id):
            raise RepositoryIndexJobCancelled('结构化整理任务已被取消。')
        _publish_repository_index_generation(
            user_id=user_id,
            job_id=job_id,
            base_repository_generation=base_generation,
            classes=all_classes,
            functions=all_functions,
            embedding_map=embedding_map,
            embedding_hashes=embedding_hashes,
            embedding_model=embedding_model,
        )
        return {
            'success': True,
            'job_id': job_id,
            'repository_generation': base_generation,
            'index_generation': job_id,
            'files': len(files),
            'chunks': len(all_functions),
            'classes': len(all_classes),
            'embedding_model': embedding_model,
            'reused_structured_files': reused_structured_files,
            'reused_vectors': reused_vectors,
        }
    except RepositoryIndexJobCancelled as exc:
        # 即使 _stage_faiss_generation 在中途抛错，也可能已创建半成品目录。
        _cleanup_unpublished_faiss_generation(user_id, job_id)
        update_repository_index_job(
            job_id,
            status='canceled',
            cancel_requested=1,
            error_message=str(exc),
            finished_at=datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
            progress_message=_format_repository_progress_message('canceled', str(exc)),
        )
        return {
            'success': False,
            'job_id': job_id,
            'cancelled': True,
            'error': str(exc),
        }
    except Exception as exc:
        _cleanup_unpublished_faiss_generation(user_id, job_id)
        if _is_repository_index_job_cancel_requested(job_id):
            status = 'canceled'
            message = '结构化整理任务已被取消。'
        else:
            status = 'failed'
            message = str(exc)
        update_repository_index_job(
            job_id,
            status=status,
            cancel_requested=1 if status == 'canceled' else 0,
            error_message=message,
            finished_at=datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
            progress_message=_format_repository_progress_message(status, message),
        )
        return {
            'success': False,
            'job_id': job_id,
            'cancelled': status == 'canceled',
            'error': message,
        }


def run_repository_index_job(user_id, job_id, file_id=None):
    """串行、可重试地构建并发布一个索引 generation。"""

    user_id = int(user_id)
    job_id = int(job_id)
    with _repository_index_build_lock(user_id, job_id):
        active_generation = _get_active_repository_index_generation(user_id)
        if _safe_int(active_generation, 0) == job_id:
            job = get_repository_index_job(job_id=job_id, user_id=user_id) or {}
            return {
                'success': True,
                'job_id': job_id,
                'repository_generation': _safe_int(
                    job.get('base_repository_generation'),
                    0,
                ),
                'index_generation': job_id,
                'files': _safe_int(job.get('total_files'), 0),
                'chunks': _safe_int(job.get('total_chunks'), 0),
                'classes': _safe_int(job.get('total_classes'), 0),
                'idempotent': True,
            }

        # worker 可能在写完隐藏 FAISS 后、发布前崩溃。仅删除本 job 且未被
        # active 指针引用的候选；上一代可用索引和其他 job 均不受影响。
        _discard_unpublished_repository_index_generation(user_id, job_id)
        return _run_repository_index_job_once(
            user_id=user_id,
            job_id=job_id,
            file_id=file_id,
        )


def list_repository_classes(user_id, limit=300):
    use_limit = max(1, min(2000, _safe_int(limit, 300)))
    active_generation = _get_active_repository_index_generation(user_id)
    if active_generation is None:
        return []
    conn = get_db_connection()
    try:
        with conn.cursor() as cursor:
            cursor.execute(
                """
                SELECT class_id, filename, kind, class_name, qualified_name, source_hash, json_data, updated_at
                FROM repository_class_metadata
                WHERE user_id = %s AND index_generation = %s
                ORDER BY filename ASC, class_name ASC
                LIMIT %s
                """,
                (int(user_id), int(active_generation), use_limit),
            )
            rows = cursor.fetchall() or []
    finally:
        conn.close()

    result = []
    for row in rows:
        payload = row.get('json_data')
        try:
            data = json.loads(payload) if payload else {}
        except Exception:
            data = {}
        item = {
            'class_id': row.get('class_id'),
            'filename': row.get('filename'),
            'kind': row.get('kind'),
            'class_name': row.get('class_name'),
            'qualified_name': row.get('qualified_name'),
            'source_hash': row.get('source_hash'),
            'updated_at': row['updated_at'].strftime('%Y-%m-%d %H:%M:%S') if row.get('updated_at') else None,
            'bases': data.get('bases') or [],
            'member_variables': data.get('member_variables') or [],
            'member_methods': data.get('member_methods') or [],
        }
        result.append(item)
    return result


def _load_chunk_details_by_ids(user_id, chunk_ids, index_generation=None):
    if not chunk_ids:
        return {}
    use_ids = [str(cid or '').strip() for cid in chunk_ids if str(cid or '').strip()]
    if not use_ids:
        return {}
    generation = (
        _safe_int(index_generation, 0)
        if index_generation is not None
        else _safe_int(_get_active_repository_index_generation(user_id), 0)
    )
    if generation <= 0:
        return {}

    placeholders = ','.join(['%s'] * len(use_ids))
    conn = get_db_connection()
    try:
        with conn.cursor() as cursor:
            cursor.execute(
                f"""
                SELECT c.chunk_id, e.embedding_model,
                       c.filename, c.qualified_name, c.summary, c.signature, c.class_name, c.access_modifier,
                       c.start_line, c.end_line, c.code
                FROM repository_function_chunks c
                LEFT JOIN repository_chunk_embeddings e
                  ON e.user_id = c.user_id
                 AND e.index_generation = c.index_generation
                 AND e.chunk_id = c.chunk_id
                WHERE c.user_id = %s
                  AND c.index_generation = %s
                  AND c.chunk_id IN ({placeholders})
                """,
                tuple([int(user_id), int(generation)] + use_ids),
            )
            rows = cursor.fetchall() or []
    finally:
        conn.close()

    mapping = {}
    for row in rows:
        cid = str(row.get('chunk_id') or '').strip()
        if cid:
            mapping[cid] = row
    return mapping


def search_repository_chunks(
    user_id,
    query,
    top_k=None,
    score_threshold=None,
    query_vector=None,
    query_embedding_model=None,
):
    text = str(query or '').strip()
    if query_vector is None and not text:
        return {
            'query': text,
            'hits': [],
            'embedding_model': _embedding_model_name(),
            'vector_db_backend': _VECTOR_DB_BACKEND,
        }

    use_top_k = max(1, min(50, _safe_int(top_k, _DEFAULT_SEARCH_TOP_K)))
    try:
        use_threshold = float(_DEFAULT_SEARCH_SCORE_THRESHOLD if score_threshold is None else score_threshold)
    except Exception:
        use_threshold = float(_DEFAULT_SEARCH_SCORE_THRESHOLD)

    active_generation = _get_active_repository_index_generation(user_id)
    if active_generation is None:
        return {
            'query': text,
            'hits': [],
            'embedding_model': _embedding_model_name(),
            'vector_db_backend': _VECTOR_DB_BACKEND,
        }
    index, meta = _load_faiss_index(
        user_id,
        index_generation=active_generation,
    )
    if not isinstance(meta, dict):
        return {
            'query': text,
            'hits': [],
            'embedding_model': _embedding_model_name(),
            'vector_db_backend': _VECTOR_DB_BACKEND,
        }

    chunk_ids = meta.get('chunk_ids') or []
    if not chunk_ids:
        return {
            'query': text,
            'hits': [],
            'embedding_model': str(meta.get('embedding_model') or _embedding_model_name()),
            'vector_db_backend': _VECTOR_DB_BACKEND,
        }
    if index is None:
        return {
            'query': text,
            'hits': [],
            'embedding_model': str(meta.get('embedding_model') or _embedding_model_name()),
            'vector_db_backend': _VECTOR_DB_BACKEND,
        }

    index_dim = int(index.d)
    model_used = str(meta.get('embedding_model') or _embedding_model_name())
    if query_vector is None:
        query_vec, model_used = encode_texts([text], embedding_model_override=meta.get('embedding_model'))
        if query_vec.shape[0] == 0:
            return {
                'query': text,
                'hits': [],
                'embedding_model': model_used,
                'vector_db_backend': _VECTOR_DB_BACKEND,
            }
        q = _normalize_l2(np.asarray(query_vec, dtype=np.float32))
    else:
        raw_vec = np.asarray(query_vector, dtype=np.float32)
        if raw_vec.ndim == 1:
            raw_vec = raw_vec.reshape(1, -1)
        if raw_vec.ndim != 2 or raw_vec.shape[0] <= 0 or raw_vec.shape[1] <= 0:
            return {
                'query': text,
                'hits': [],
                'embedding_model': str(query_embedding_model or model_used or _embedding_model_name()),
                'vector_db_backend': _VECTOR_DB_BACKEND,
            }
        q = _normalize_l2(raw_vec[:1])
        if query_embedding_model:
            model_used = str(query_embedding_model)
    if q.shape[1] != index_dim:
        raise RuntimeError(
            f'查询向量维度不匹配：query_dim={q.shape[1]} index_dim={index_dim}。'
            '请重新执行“结构化整理”以重建向量库。'
        )

    k_search = min(max(use_top_k * 4, use_top_k), len(chunk_ids))
    scores, indexes = index.search(q, k_search)
    raw_scores = scores[0] if scores.size > 0 else []
    raw_indexes = indexes[0] if indexes.size > 0 else []

    candidates = []
    for idx, score in zip(raw_indexes, raw_scores):
        i = int(idx)
        if i < 0 or i >= len(chunk_ids):
            continue
        s = float(score)
        if s < use_threshold:
            continue
        candidates.append((str(chunk_ids[i]), s))

    if not candidates:
        return {
            'query': text,
            'hits': [],
            'embedding_model': str(meta.get('embedding_model') or model_used),
            'vector_db_backend': _VECTOR_DB_BACKEND,
        }

    detail_map = _load_chunk_details_by_ids(
        user_id=user_id,
        chunk_ids=[x[0] for x in candidates],
        index_generation=active_generation,
    )
    hits = []
    for cid, score in candidates:
        row = detail_map.get(cid)
        if not row:
            continue
        hits.append({
            'chunk_id': cid,
            'filename': row.get('filename'),
            'qualified_name': row.get('qualified_name'),
            'signature': row.get('signature'),
            'summary': row.get('summary') or '',
            'class_name': row.get('class_name'),
            'access': row.get('access_modifier'),
            'start_line': row.get('start_line'),
            'end_line': row.get('end_line'),
            'code': row.get('code') or '',
            'score': round(score, 6),
            'embedding_model': row.get('embedding_model') or str(meta.get('embedding_model') or model_used),
        })

    hits.sort(key=lambda x: x['score'], reverse=True)
    top_hits = hits[:use_top_k]
    model_name = top_hits[0]['embedding_model'] if top_hits else str(meta.get('embedding_model') or model_used)
    return {
        'query': text,
        'hits': top_hits,
        'embedding_model': model_name,
        'vector_db_backend': _VECTOR_DB_BACKEND,
    }
