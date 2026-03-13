#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import hashlib
import json
import os
import re
import uuid
from datetime import datetime

import numpy as np
import requests

from oj_modules.ai_utils import _call_qwen_text, _extract_first_json_object_relaxed
from oj_modules.db_services import get_db_connection
from config import (
    AGENT_REPOSITORY_KNN_SCORE_THRESHOLD,
    AGENT_REPOSITORY_KNN_TOP_K,
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
    REPOSITORY_STRUCTURED_MAX_INPUT_CHARS,
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


_ALLOWED_REPO_EXTENSIONS = ('.h', '.hpp', '.c', '.cpp')
_ALLOWED_ACCESS = {'public', 'private', 'protected'}
_ALLOWED_FUNC_KIND = {'function', 'method', 'constructor', 'destructor', 'operator'}
_ALLOWED_DOC_SOURCE = {'original_comment', 'llm_generated', 'mixed', 'none'}
_ALLOWED_QUALITY = {'high', 'medium', 'low'}

_DEFAULT_EMBEDDING_DIM = int(REPOSITORY_EMBEDDING_DIM)
_DEFAULT_SENTENCE_MODEL = str(REPOSITORY_SENTENCE_MODEL or '').strip()
_DEFAULT_QWEN_EMBEDDING_MODEL = str(REPOSITORY_QWEN_EMBEDDING_MODEL or '').strip()
_DEFAULT_PROVIDER = str(REPOSITORY_EMBEDDING_PROVIDER or '').strip().lower()
_DEFAULT_LLM_MODEL = str(REPOSITORY_STRUCTURED_MODEL or '').strip() or str(QWEN_TEXT_MODEL or '').strip()
_DEFAULT_LLM_TIMEOUT_SECONDS = int(REPOSITORY_STRUCTURED_TIMEOUT)
_DEFAULT_LLM_MAX_INPUT_CHARS = int(REPOSITORY_STRUCTURED_MAX_INPUT_CHARS)
_DEFAULT_EMBEDDING_TIMEOUT_SECONDS = int(REPOSITORY_EMBEDDING_TIMEOUT)
_DEFAULT_EMBEDDING_BATCH_SIZE = max(1, int(REPOSITORY_EMBEDDING_BATCH_SIZE))
_VECTOR_DB_BACKEND = str(REPOSITORY_VECTOR_BACKEND or '').strip().lower()
_FAISS_INDEX_ROOT = os.path.abspath(str(REPOSITORY_FAISS_INDEX_ROOT or os.path.join('tmp', 'repository_vector_index')))
try:
    _DEFAULT_SEARCH_TOP_K = max(1, int(AGENT_REPOSITORY_KNN_TOP_K))
except Exception:
    _DEFAULT_SEARCH_TOP_K = 1
try:
    _DEFAULT_SEARCH_SCORE_THRESHOLD = float(AGENT_REPOSITORY_KNN_SCORE_THRESHOLD)
except Exception:
    _DEFAULT_SEARCH_SCORE_THRESHOLD = 0.0

_sentence_model_cache = {}


class RepositoryIndexJobCancelled(Exception):
    pass


def ensure_repository_index_tables():
    conn = get_db_connection()
    try:
        with conn.cursor() as cursor:
            cursor.execute(
                """
                CREATE TABLE IF NOT EXISTS repository_index_jobs (
                    id BIGINT NOT NULL AUTO_INCREMENT,
                    user_id INT NOT NULL,
                    status VARCHAR(16) NOT NULL DEFAULT 'queued',
                    total_files INT NOT NULL DEFAULT 0,
                    processed_files INT NOT NULL DEFAULT 0,
                    total_chunks INT NOT NULL DEFAULT 0,
                    total_classes INT NOT NULL DEFAULT 0,
                    error_message TEXT NULL,
                    progress_message TEXT NULL,
                    task_id VARCHAR(64) NULL,
                    cancel_requested TINYINT(1) NOT NULL DEFAULT 0,
                    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
                    updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
                    finished_at DATETIME NULL,
                    PRIMARY KEY (id),
                    KEY idx_repository_index_jobs_user_id (user_id),
                    KEY idx_repository_index_jobs_status (status),
                    CONSTRAINT fk_repository_index_jobs_user
                        FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
                ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci
                """
            )
            cursor.execute(
                """
                CREATE TABLE IF NOT EXISTS repository_function_chunks (
                    id BIGINT NOT NULL AUTO_INCREMENT,
                    chunk_id VARCHAR(64) NOT NULL,
                    user_id INT NOT NULL,
                    repo_file_id INT NULL,
                    filename VARCHAR(255) NOT NULL,
                    language VARCHAR(32) NOT NULL DEFAULT 'cpp',
                    kind VARCHAR(32) NOT NULL DEFAULT 'function',
                    qualified_name VARCHAR(255) NOT NULL,
                    class_name VARCHAR(255) NULL,
                    access_modifier VARCHAR(16) NULL,
                    signature TEXT NOT NULL,
                    summary TEXT NULL,
                    return_type VARCHAR(255) NULL,
                    start_line INT NOT NULL DEFAULT 1,
                    end_line INT NOT NULL DEFAULT 1,
                    source_hash VARCHAR(64) NOT NULL,
                    code LONGTEXT NOT NULL,
                    params_json LONGTEXT NULL,
                    returns_json LONGTEXT NULL,
                    json_data LONGTEXT NOT NULL,
                    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
                    updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
                    PRIMARY KEY (id),
                    UNIQUE KEY uk_repository_function_chunks_chunk_id (chunk_id),
                    KEY idx_repository_function_chunks_user_file (user_id, filename),
                    KEY idx_repository_function_chunks_user_qname (user_id, qualified_name),
                    CONSTRAINT fk_repository_function_chunks_user
                        FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
                ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci
                """
            )
            cursor.execute(
                """
                CREATE TABLE IF NOT EXISTS repository_class_metadata (
                    id BIGINT NOT NULL AUTO_INCREMENT,
                    class_id VARCHAR(64) NOT NULL,
                    user_id INT NOT NULL,
                    repo_file_id INT NULL,
                    filename VARCHAR(255) NOT NULL,
                    kind VARCHAR(16) NOT NULL DEFAULT 'class',
                    class_name VARCHAR(255) NOT NULL,
                    qualified_name VARCHAR(255) NOT NULL,
                    source_hash VARCHAR(64) NOT NULL,
                    bases_json LONGTEXT NULL,
                    members_json LONGTEXT NULL,
                    json_data LONGTEXT NOT NULL,
                    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
                    updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
                    PRIMARY KEY (id),
                    UNIQUE KEY uk_repository_class_metadata_class_id (class_id),
                    KEY idx_repository_class_metadata_user_class (user_id, class_name),
                    KEY idx_repository_class_metadata_user_qname (user_id, qualified_name),
                    CONSTRAINT fk_repository_class_metadata_user
                        FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
                ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci
                """
            )
            cursor.execute(
                """
                CREATE TABLE IF NOT EXISTS repository_chunk_embeddings (
                    id BIGINT NOT NULL AUTO_INCREMENT,
                    chunk_id VARCHAR(64) NOT NULL,
                    user_id INT NOT NULL,
                    embedding_model VARCHAR(128) NOT NULL,
                    vector_dim INT NOT NULL,
                    vector_json LONGTEXT NOT NULL,
                    updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
                    PRIMARY KEY (id),
                    UNIQUE KEY uk_repository_chunk_embeddings_user_chunk (user_id, chunk_id),
                    KEY idx_repository_chunk_embeddings_user_chunk (user_id, chunk_id),
                    CONSTRAINT fk_repository_chunk_embeddings_user
                        FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
                ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci
                """
            )
            cursor.execute("SHOW COLUMNS FROM repository_index_jobs LIKE 'task_id'")
            if not cursor.fetchone():
                cursor.execute("ALTER TABLE repository_index_jobs ADD COLUMN task_id VARCHAR(64) NULL")
            cursor.execute("SHOW COLUMNS FROM repository_index_jobs LIKE 'cancel_requested'")
            if not cursor.fetchone():
                cursor.execute(
                    "ALTER TABLE repository_index_jobs "
                    "ADD COLUMN cancel_requested TINYINT(1) NOT NULL DEFAULT 0"
                )
            cursor.execute("SHOW COLUMNS FROM repository_index_jobs LIKE 'progress_message'")
            if not cursor.fetchone():
                cursor.execute("ALTER TABLE repository_index_jobs ADD COLUMN progress_message TEXT NULL")
        conn.commit()
    finally:
        conn.close()


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


def _normalize_doc_source(value):
    text = _safe_str(value).lower()
    if text in _ALLOWED_DOC_SOURCE:
        return text
    return 'none'


def _normalize_quality(value):
    text = _safe_str(value).lower()
    if text in _ALLOWED_QUALITY:
        return text
    return 'low'


def _detect_language_from_filename(filename):
    name = _safe_str(filename).lower()
    if name.endswith('.c'):
        return 'c'
    if name.endswith('.h'):
        return 'h'
    if name.endswith('.hpp'):
        return 'hpp'
    if name.endswith('.cpp'):
        return 'cpp'
    return 'cpp'


def _truncate_for_prompt(content):
    text = str(content or '')
    limit = max(8000, _safe_int(_DEFAULT_LLM_MAX_INPUT_CHARS, 120000))
    if len(text) <= limit:
        return text, False
    half = limit // 2
    clipped = (
        text[:half]
        + "\n\n/* ... 文件内容过长，中间部分已省略 ... */\n\n"
        + text[-half:]
    )
    return clipped, True


def _sha256_text(text):
    return hashlib.sha256(str(text or '').encode('utf-8')).hexdigest()


def create_repository_index_job(user_id):
    ensure_repository_index_tables()
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


def update_repository_index_job(job_id, **fields):
    if not fields:
        return
    allowed = {
        'status',
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


def get_repository_index_job(job_id, user_id):
    ensure_repository_index_tables()
    conn = get_db_connection()
    try:
        with conn.cursor() as cursor:
            cursor.execute(
                """
                SELECT id, user_id, status, total_files, processed_files, total_chunks, total_classes,
                       error_message, progress_message, task_id, cancel_requested, created_at, updated_at, finished_at
                FROM repository_index_jobs
                WHERE id = %s AND user_id = %s
                LIMIT 1
                """,
                (int(job_id), int(user_id)),
            )
            row = cursor.fetchone()
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
    ensure_repository_index_tables()
    conn = get_db_connection()
    try:
        with conn.cursor() as cursor:
            cursor.execute(
                """
                SELECT id
                FROM repository_index_jobs
                WHERE user_id = %s AND status IN ('queued', 'running') AND cancel_requested = 0
                ORDER BY id DESC
                LIMIT 1
                """,
                (int(user_id),),
            )
            row = cursor.fetchone()
    finally:
        conn.close()

    if not row:
        return None
    return get_repository_index_job(job_id=row.get('id'), user_id=user_id)


def _get_repository_index_job_runtime(job_id, user_id=None):
    ensure_repository_index_tables()
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
    ensure_repository_index_tables()
    conn = get_db_connection()
    try:
        with conn.cursor() as cursor:
            cursor.execute(
                """
                UPDATE repository_index_jobs
                SET status = 'running', error_message = NULL, finished_at = NULL
                WHERE id = %s AND cancel_requested = 0 AND status IN ('queued', 'running')
                """,
                (int(job_id),),
            )
            changed = int(cursor.rowcount)
        conn.commit()
        return changed > 0
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
    ensure_repository_index_tables()
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
            row = cursor.fetchone()
            if not row:
                conn.commit()
                return None

            status = str(row.get('status') or '').strip().lower()
            if status not in ('success', 'failed', 'canceled'):
                cursor.execute(
                    """
                    UPDATE repository_index_jobs
                    SET cancel_requested = 1, status = 'canceled', finished_at = %s, error_message = %s, progress_message = %s
                    WHERE id = %s
                    """,
                    (
                        datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                        str(reason or '用户取消任务'),
                        str(reason or '用户取消任务'),
                        int(job_id),
                    ),
                )
                row['status'] = 'canceled'
                row['cancel_requested'] = 1
                row['progress_message'] = str(reason or '用户取消任务')
        conn.commit()
        return row
    finally:
        conn.close()


def _load_user_repository_files(user_id):
    conn = get_db_connection()
    try:
        with conn.cursor() as cursor:
            cursor.execute(
                """
                SELECT id, filename, file_content
                FROM user_code_repository
                WHERE user_id = %s
                ORDER BY filename ASC
                """,
                (int(user_id),),
            )
            rows = cursor.fetchall() or []
    finally:
        conn.close()

    result = []
    for row in rows:
        filename = _safe_str(row.get('filename'))
        if not filename:
            continue
        if not filename.lower().endswith(_ALLOWED_REPO_EXTENSIONS):
            continue
        result.append({
            'id': int(row.get('id')),
            'filename': filename,
            'content': str(row.get('file_content') or ''),
        })
    return result


def _build_qwen_prompt(filename, content, truncated):
    trunc_note = "是" if truncated else "否"
    return (
        "你是一个代码结构化整理助手。请读取给定的单个 C/C++ 代码文件，并输出一个严格合法的 JSON 对象。\n"
        "要求：\n"
        "1. 只输出 JSON，不要输出解释、不要输出 Markdown 代码块。\n"
        "2. 必须覆盖函数和类信息。\n"
        "3. 类信息必须包含：类清单、继承关系、成员变量、成员函数。\n"
        "4. 成员变量必须记录所属 class_name 和访问权限 access（private/public/protected）。\n"
        "5. 对每个函数整理参数、返回值、摘要。\n"
        "6. 若代码中已有注释，优先基于原注释填充 summary/params[].description/returns.description。\n"
        "7. 若代码中没有注释，你需要分析这段代码的功能，并根据你的分析，填充 summary/params[].description/returns.description 字段。"
        "8. 无法确认的字段使用空字符串、空数组或 null，不要编造不存在的函数或类。\n\n"
        "JSON 顶层格式必须为：\n"
        "{\n"
        "  \"schema_version\": \"1.0\",\n"
        "  \"filename\": \"...\",\n"
        "  \"language\": \"c|cpp|h|hpp\",\n"
        "  \"classes\": [\n"
        "    {\n"
        "      \"class_name\": \"\",\n"
        "      \"qualified_name\": \"\",\n"
        "      \"kind\": \"class|struct\",\n"
        "      \"bases\": [{\"base_name\": \"\", \"access\": \"public|private|protected\", \"is_virtual\": false}],\n"
        "      \"member_variables\": [\n"
        "        {\"name\": \"\", \"type\": \"\", \"class_name\": \"\", \"access\": \"public|private|protected\", \"is_static\": false, \"line\": 0}\n"
        "      ],\n"
        "      \"member_methods\": [\n"
        "        {\"name\": \"\", \"qualified_name\": \"\", \"signature\": \"\", \"return_type\": \"\", \"access\": \"public|private|protected\", \"is_static\": false, \"is_virtual\": false, \"is_const\": false, \"is_pure_virtual\": false, \"start_line\": 0, \"end_line\": 0}\n"
        "      ]\n"
        "    }\n"
        "  ],\n"
        "  \"functions\": [\n"
        "    {\n"
        "      \"kind\": \"function|method|constructor|destructor|operator\",\n"
        "      \"qualified_name\": \"\",\n"
        "      \"class_name\": \"\",\n"
        "      \"access\": \"public|private|protected\",\n"
        "      \"signature\": \"\",\n"
        "      \"params\": [{\"name\": \"\", \"type\": \"\", \"default_value\": null, \"description\": \"\"}],\n"
        "      \"returns\": {\"type\": \"\", \"description\": \"\"},\n"
        "      \"summary\": \"\",\n"
        "      \"doc_source\": \"original_comment|llm_generated|mixed|none\",\n"
        "      \"quality\": \"high|medium|low\",\n"
        "      \"location\": {\"start_line\": 0, \"end_line\": 0},\n"
        "      \"code\": \"\"\n"
        "    }\n"
        "  ]\n"
        "}\n\n"
        f"文件名：{filename}\n"
        f"内容是否截断：{trunc_note}\n"
        "文件内容如下：\n"
        f"{content}\n\n"
        "如果我对这个函数以及输入输出已经有了详细的注释，那就基于我原本的注释整理成结构化的 json。"
    )


def _call_qwen_structured_file(filename, content):
    clipped_content, truncated = _truncate_for_prompt(content)
    prompt = _build_qwen_prompt(filename=filename, content=clipped_content, truncated=truncated)
    model_output = _call_qwen_text(
        prompt_text=prompt,
        timeout=_DEFAULT_LLM_TIMEOUT_SECONDS,
        model=_DEFAULT_LLM_MODEL,
        enable_thinking=False,
    )
    data = _extract_first_json_object_relaxed(model_output)
    if not isinstance(data, dict):
        raise RuntimeError(f"模型未返回合法 JSON，文件：{filename}")
    return data


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

    doc_source = _normalize_doc_source(item.get('doc_source'))
    quality = _normalize_quality(item.get('quality'))

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
        'doc_source': doc_source,
        'quality': quality,
        'location': {
            'start_line': start_line,
            'end_line': end_line,
        },
        'source_hash': source_hash,
        'code': str(item.get('code') or ''),
    }


def _normalize_llm_file_output(file_item, llm_data):
    filename = file_item['filename']
    repo_file_id = file_item['id']
    source_hash = _sha256_text(file_item['content'])

    classes = []
    raw_classes = llm_data.get('classes') if isinstance(llm_data, dict) else []
    for item in (raw_classes or []):
        normalized = _normalize_class_item(
            item=item,
            filename=filename,
            repo_file_id=repo_file_id,
            source_hash=source_hash,
        )
        if normalized:
            classes.append(normalized)

    functions = []
    raw_functions = llm_data.get('functions') if isinstance(llm_data, dict) else []
    for item in (raw_functions or []):
        normalized = _normalize_function_item(
            item=item,
            filename=filename,
            repo_file_id=repo_file_id,
            source_hash=source_hash,
        )
        if normalized:
            functions.append(normalized)

    # 若模型未把成员函数放到 functions，尝试从 class.member_methods 补齐可检索条目。
    existing_keys = set((f.get('qualified_name'), f.get('signature')) for f in functions)
    for cls in classes:
        for method in cls.get('member_methods') or []:
            qname = _safe_str(method.get('qualified_name'))
            sig = _safe_str(method.get('signature'))
            key = (qname, sig)
            if not qname or key in existing_keys:
                continue
            chunk = {
                'schema_version': '1.0',
                'chunk_id': uuid.uuid4().hex,
                'repo_file_id': int(repo_file_id),
                'filename': filename,
                'language': _detect_language_from_filename(filename),
                'kind': 'method',
                'qualified_name': qname,
                'class_name': _safe_str(cls.get('qualified_name')) or _safe_str(cls.get('class_name')),
                'access': _normalize_access(method.get('access'), default='') or '',
                'signature': sig,
                'params': [],
                'returns': {
                    'type': _safe_str(method.get('return_type')),
                    'description': '',
                },
                'summary': f"Method {qname}",
                'doc_source': 'none',
                'quality': 'low',
                'location': {
                    'start_line': max(0, _safe_int(method.get('start_line'), 0)),
                    'end_line': max(0, _safe_int(method.get('end_line'), 0)),
                },
                'source_hash': source_hash,
                'code': '',
            }
            functions.append(chunk)
            existing_keys.add(key)

    return {
        'functions': functions,
        'classes': classes,
        'source_hash': source_hash,
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
        str(chunk.get('code') or '')[:1200],
    ]
    return '\n'.join([p for p in pieces if p])


def _ensure_faiss_available():
    if _VECTOR_DB_BACKEND != 'faiss':
        raise RuntimeError(f'不支持的 REPOSITORY_VECTOR_BACKEND={_VECTOR_DB_BACKEND}。当前仅支持 faiss。')
    if faiss is None:
        raise RuntimeError('未安装 faiss，无法进行向量 KNN 检索。请安装 faiss-cpu。')


def _faiss_user_dir(user_id):
    return os.path.join(_FAISS_INDEX_ROOT, str(int(user_id)))


def _faiss_paths(user_id):
    root = _faiss_user_dir(user_id)
    return {
        'root': root,
        'index': os.path.join(root, 'index.faiss'),
        'meta': os.path.join(root, 'meta.json'),
    }


def _write_faiss_index(user_id, chunk_ids, embeddings, embedding_model):
    _ensure_faiss_available()
    paths = _faiss_paths(user_id)
    os.makedirs(paths['root'], exist_ok=True)

    if not chunk_ids:
        for p in (paths['index'], paths['meta']):
            try:
                if os.path.exists(p):
                    os.remove(p)
            except Exception:
                pass
        return

    vectors = _normalize_l2(np.asarray(embeddings, dtype=np.float32))
    if vectors.ndim != 2 or vectors.shape[0] != len(chunk_ids):
        raise RuntimeError('向量写入失败：向量数量与 chunk 数量不一致。')
    dim = int(vectors.shape[1])
    if dim <= 0:
        raise RuntimeError('向量写入失败：向量维度非法。')

    index = faiss.IndexFlatIP(dim)
    index.add(vectors)
    faiss.write_index(index, paths['index'])

    meta = {
        'embedding_model': str(embedding_model or ''),
        'vector_db_backend': 'faiss',
        'dimension': dim,
        'chunk_ids': list(chunk_ids),
        'updated_at': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
    }
    with open(paths['meta'], 'w', encoding='utf-8') as f:
        json.dump(meta, f, ensure_ascii=False)


def _load_faiss_index(user_id):
    _ensure_faiss_available()
    paths = _faiss_paths(user_id)
    if (not os.path.isfile(paths['index'])) or (not os.path.isfile(paths['meta'])):
        return None, None
    index = faiss.read_index(paths['index'])
    with open(paths['meta'], 'r', encoding='utf-8') as f:
        meta = json.load(f)
    return index, meta


def _persist_repository_index(user_id, functions, classes, embeddings, embedding_model):
    conn = get_db_connection()
    try:
        with conn.cursor() as cursor:
            cursor.execute("DELETE FROM repository_chunk_embeddings WHERE user_id = %s", (int(user_id),))
            cursor.execute("DELETE FROM repository_function_chunks WHERE user_id = %s", (int(user_id),))
            cursor.execute("DELETE FROM repository_class_metadata WHERE user_id = %s", (int(user_id),))

            for cls in classes:
                cursor.execute(
                    """
                    INSERT INTO repository_class_metadata (
                        class_id, user_id, repo_file_id, filename, kind, class_name, qualified_name,
                        source_hash, bases_json, members_json, json_data
                    ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                    """,
                    (
                        cls['class_id'],
                        int(user_id),
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

            for idx, func in enumerate(functions):
                vector = embeddings[idx].astype(np.float32)
                cursor.execute(
                    """
                    INSERT INTO repository_function_chunks (
                        chunk_id, user_id, repo_file_id, filename, language, kind, qualified_name,
                        class_name, access_modifier, signature, summary, return_type, start_line,
                        end_line, source_hash, code, params_json, returns_json, json_data
                    ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                    """,
                    (
                        func['chunk_id'],
                        int(user_id),
                        func.get('repo_file_id'),
                        func['filename'],
                        func.get('language') or 'cpp',
                        func.get('kind') or 'function',
                        func['qualified_name'],
                        func.get('class_name'),
                        func.get('access'),
                        func.get('signature') or '',
                        func.get('summary') or '',
                        (func.get('returns') or {}).get('type') if isinstance(func.get('returns'), dict) else '',
                        int(func.get('location', {}).get('start_line', 0)),
                        int(func.get('location', {}).get('end_line', 0)),
                        func.get('source_hash') or '',
                        func.get('code') or '',
                        json.dumps(func.get('params') or [], ensure_ascii=False),
                        json.dumps(func.get('returns') or {}, ensure_ascii=False),
                        json.dumps(func, ensure_ascii=False),
                    ),
                )
                cursor.execute(
                    """
                    INSERT INTO repository_chunk_embeddings (
                        chunk_id, user_id, embedding_model, vector_dim, vector_json
                    ) VALUES (%s, %s, %s, %s, %s)
                    """,
                    (
                        func['chunk_id'],
                        int(user_id),
                        embedding_model,
                        int(vector.shape[0]),
                        json.dumps(vector.tolist(), ensure_ascii=False),
                    ),
                )
        conn.commit()
    finally:
        conn.close()
    _write_faiss_index(
        user_id=user_id,
        chunk_ids=[f['chunk_id'] for f in functions],
        embeddings=embeddings,
        embedding_model=embedding_model,
    )


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


def run_repository_index_job(user_id, job_id):
    ensure_repository_index_tables()
    user_id = int(user_id)
    job_id = int(job_id)

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
        files = _load_user_repository_files(user_id)
        total_files = len(files)
        update_repository_index_job(
            job_id,
            total_files=total_files,
            processed_files=0,
            total_chunks=0,
            total_classes=0,
            progress_message='已进入执行阶段，准备读取代码仓库文件。',
        )

        all_functions = []
        all_classes = []
        embedding_map = {}
        embedding_model = _embedding_model_name()
        parse_errors = []

        for idx, file_item in enumerate(files, start=1):
            if _is_repository_index_job_cancel_requested(job_id):
                raise RepositoryIndexJobCancelled('结构化整理任务已被取消。')
            filename = str(file_item.get('filename') or '')
            update_repository_index_job(
                job_id,
                progress_message=f'正在生成结构化 JSON：{filename}',
                processed_files=idx - 1,
                total_chunks=len(all_functions),
                total_classes=len(all_classes),
            )
            try:
                llm_data = _call_qwen_structured_file(
                    filename=filename,
                    content=file_item['content'],
                )
                normalized = _normalize_llm_file_output(file_item=file_item, llm_data=llm_data)
                file_functions = normalized.get('functions') or []
                file_classes = normalized.get('classes') or []

                class_map = {}
                for cls in list(all_classes) + list(file_classes):
                    qn = _safe_str(cls.get('qualified_name'))
                    cn = _safe_str(cls.get('class_name'))
                    if qn:
                        class_map[qn] = cls
                    if cn and cn not in class_map:
                        class_map[cn] = cls

                vectors_file = None
                file_texts = []
                if file_functions:
                    for func in file_functions:
                        update_repository_index_job(
                            job_id,
                            progress_message=_build_vectorizing_target_message(func),
                            processed_files=idx - 1,
                            total_chunks=len(all_functions),
                            total_classes=len(all_classes),
                        )
                        file_texts.append(_build_embedding_input(func, class_map))
                    vectors_file, model_used = encode_texts(file_texts, embedding_model_override=embedding_model)
                    if vectors_file.shape[0] != len(file_functions):
                        raise RuntimeError('向量化失败：返回向量数量与当前文件函数数量不一致。')
                    if str(model_used or '').strip():
                        embedding_model = str(model_used).strip()
                elif file_classes:
                    class_name = _safe_str(file_classes[0].get('qualified_name') or file_classes[0].get('class_name'))
                    detail = f'当前文件仅包含类定义：{class_name}，无需生成函数向量。'
                    update_repository_index_job(
                        job_id,
                        progress_message=detail,
                        processed_files=idx - 1,
                        total_chunks=len(all_functions),
                        total_classes=len(all_classes),
                    )

                all_classes.extend(file_classes)
                all_functions.extend(file_functions)
                if vectors_file is not None:
                    for v_idx, func in enumerate(file_functions):
                        embedding_map[str(func.get('chunk_id') or '')] = vectors_file[v_idx].astype(np.float32)

                if _is_repository_index_job_cancel_requested(job_id):
                    raise RepositoryIndexJobCancelled('结构化整理任务已被取消。')
                vectors = _build_cumulative_embeddings(all_functions, embedding_map)
                update_repository_index_job(
                    job_id,
                    progress_message=f'正在写入索引（MySQL + FAISS）：{filename}',
                    processed_files=idx - 1,
                    total_chunks=len(all_functions),
                    total_classes=len(all_classes),
                )
                _persist_repository_index(
                    user_id=user_id,
                    functions=all_functions,
                    classes=all_classes,
                    embeddings=vectors,
                    embedding_model=embedding_model,
                )
            except Exception as exc:
                parse_errors.append(f"{filename}: {str(exc)}")
                # 即使该文件失败，也将当前已完成的数据落库，保证“每处理完一个文件就写一次库”。
                if _is_repository_index_job_cancel_requested(job_id):
                    raise RepositoryIndexJobCancelled('结构化整理任务已被取消。')
                vectors = _build_cumulative_embeddings(all_functions, embedding_map)
                update_repository_index_job(
                    job_id,
                    progress_message=f'文件处理失败，正在保留已完成索引：{filename}',
                    processed_files=idx - 1,
                    total_chunks=len(all_functions),
                    total_classes=len(all_classes),
                )
                _persist_repository_index(
                    user_id=user_id,
                    functions=all_functions,
                    classes=all_classes,
                    embeddings=vectors,
                    embedding_model=embedding_model,
                )

            update_repository_index_job(
                job_id,
                processed_files=idx,
                total_chunks=len(all_functions),
                total_classes=len(all_classes),
                progress_message=(
                    f'已完成文件 {idx}/{total_files}：{filename}；'
                    f'累计函数 {len(all_functions)}，类 {len(all_classes)}'
                ),
            )

        if _is_repository_index_job_cancel_requested(job_id):
            raise RepositoryIndexJobCancelled('结构化整理任务已被取消。')
        warn_msg = ''
        if parse_errors:
            warn_msg = '；'.join(parse_errors[:5])
            if len(parse_errors) > 5:
                warn_msg += f"；另有 {len(parse_errors) - 5} 个文件失败"

        update_repository_index_job(
            job_id,
            status='success',
            processed_files=len(files),
            total_files=len(files),
            total_chunks=len(all_functions),
            total_classes=len(all_classes),
            finished_at=datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
            error_message=warn_msg or None,
            progress_message='结构化整理与向量化已完成。',
        )
        return {
            'success': True,
            'job_id': job_id,
            'files': len(files),
            'chunks': len(all_functions),
            'classes': len(all_classes),
            'embedding_model': embedding_model,
            'warnings': parse_errors,
        }
    except RepositoryIndexJobCancelled as exc:
        update_repository_index_job(
            job_id,
            status='canceled',
            cancel_requested=1,
            error_message=str(exc),
            finished_at=datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
            progress_message=str(exc),
        )
        return {
            'success': False,
            'job_id': job_id,
            'cancelled': True,
            'error': str(exc),
        }
    except Exception as exc:
        if _is_repository_index_job_cancel_requested(job_id):
            update_repository_index_job(
                job_id,
                status='canceled',
                cancel_requested=1,
                error_message='结构化整理任务已被取消。',
                finished_at=datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                progress_message='结构化整理任务已被取消。',
            )
            return {
                'success': False,
                'job_id': job_id,
                'cancelled': True,
                'error': '结构化整理任务已被取消。',
            }
        update_repository_index_job(
            job_id,
            status='failed',
            error_message=str(exc),
            finished_at=datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
            progress_message=f'任务失败：{str(exc)}',
        )
        return {
            'success': False,
            'job_id': job_id,
            'error': str(exc),
        }


def list_repository_classes(user_id, limit=300):
    ensure_repository_index_tables()
    use_limit = max(1, min(2000, _safe_int(limit, 300)))
    conn = get_db_connection()
    try:
        with conn.cursor() as cursor:
            cursor.execute(
                """
                SELECT class_id, filename, kind, class_name, qualified_name, source_hash, json_data, updated_at
                FROM repository_class_metadata
                WHERE user_id = %s
                ORDER BY filename ASC, class_name ASC
                LIMIT %s
                """,
                (int(user_id), use_limit),
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


def _load_chunk_details_by_ids(user_id, chunk_ids):
    if not chunk_ids:
        return {}
    use_ids = [str(cid or '').strip() for cid in chunk_ids if str(cid or '').strip()]
    if not use_ids:
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
                  ON e.user_id = c.user_id AND e.chunk_id = c.chunk_id
                WHERE c.user_id = %s AND c.chunk_id IN ({placeholders})
                """,
                tuple([int(user_id)] + use_ids),
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
    ensure_repository_index_tables()
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

    index, meta = _load_faiss_index(user_id)
    if index is None or not isinstance(meta, dict):
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

    detail_map = _load_chunk_details_by_ids(user_id=user_id, chunk_ids=[x[0] for x in candidates])
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
