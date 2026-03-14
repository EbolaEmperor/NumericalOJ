#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import hashlib
import json
import os
import uuid
from datetime import datetime

import numpy as np
import requests

from oj_modules.ai_utils import _call_qwen_text, _extract_first_json_object_relaxed
from oj_modules.db_services import get_db_connection
from config import (
    AI_TUTOR_MODEL,
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
try:
    _DEFAULT_SEARCH_TOP_K = max(1, int(AGENT_REPOSITORY_KNN_TOP_K))
except Exception:
    _DEFAULT_SEARCH_TOP_K = 1
try:
    _DEFAULT_SEARCH_SCORE_THRESHOLD = float(AGENT_REPOSITORY_KNN_SCORE_THRESHOLD)
except Exception:
    _DEFAULT_SEARCH_SCORE_THRESHOLD = 0.0

_sentence_model_cache = {}
_tree_sitter_parser_cache = {}


class RepositoryIndexJobCancelled(Exception):
    pass


def ensure_repository_index_tables():
    return


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


def _ts_build_signature_from_callable_node(callable_node, source_bytes):
    node = callable_node
    if node is None:
        return ''

    # Build signature directly from syntax nodes before the function body,
    # avoiding fragile text truncation when default args contain braces.
    if node.type == 'function_definition':
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


def _ts_build_method_item_from_node(method_node, source_bytes, class_name, access_text, has_body):
    declarator_node = _ts_find_first_descendant(method_node, {'function_declarator'})
    param_list_node = _ts_find_first_descendant(declarator_node, {'parameter_list'}) if declarator_node else None
    method_name, owner_name = _ts_extract_function_name_and_owner(declarator_node, source_bytes)
    effective_class = _safe_str(owner_name) or _safe_str(class_name)
    if not method_name:
        return None
    code_text = _ts_node_text(source_bytes, method_node)
    signature = _ts_build_signature_from_callable_node(method_node, source_bytes) or _ts_compact_text(code_text)
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
        'start_line': _ts_line_of(method_node),
        'end_line': _ts_end_line_of(method_node),
        'has_body': bool(has_body),
        'code': code_text,
    }


def _extract_classes_and_functions_from_treesitter(filename, content):
    source = str(content or '')
    source_bytes = source.encode('utf-8', errors='replace')
    parser = _get_cpp_tree_sitter_parser()
    tree = parser.parse(source_bytes)
    root = tree.root_node

    classes = []
    functions = []
    method_access_by_range = {}

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
                    if method_decl_node is not None:
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

        declarator_node = _ts_find_first_descendant(node, {'function_declarator'})
        if declarator_node is None:
            continue
        param_list_node = _ts_find_first_descendant(declarator_node, {'parameter_list'})
        node_name, owner_name = _ts_extract_function_name_and_owner(declarator_node, source_bytes)
        if not node_name:
            continue
        class_name = _safe_str(owner_name)
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
        code_text = _ts_node_text(source_bytes, node)
        signature = _ts_build_signature_from_callable_node(node, source_bytes) or _ts_compact_text(code_text)
        return_type = _return_type_from_signature(signature, node_name, kind)
        start_line = _ts_line_of(node)
        end_line = _ts_end_line_of(node)
        access_key = (kind, node_name, signature, start_line, end_line)
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


def _call_qwen_structured_function_entity(filename, function_item):
    prompt = (
        "你是代码结构化整理助手。请基于给定“单个函数/方法”信息补充结构化说明。\n"
        "要求：\n"
        "1. 只输出一个 JSON 对象，不要输出解释。\n"
        "2. 只允许输出这些字段：summary, params, returns。\n"
        "3. params 仅输出 name 和 description；returns 仅输出 description。\n"
        "4. 不要改动参数名，不要虚构参数。\n"
        "5. summary 必须使用中文，必须描述该函数实际行为，不要输出“代码片段不完整/签名不匹配”等元描述。\n\n"
        "JSON 格式：\n"
        "{\n"
        "  \"summary\": \"代码功能说明，使用中文\",\n"
        "  \"params\": [{\"name\": \"\", \"description\": \"\"}],\n"
        "  \"returns\": {\"description\": \"\"}\n"
        "}\n\n"
        f"[文件名]\n{filename}\n\n"
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
        raise RuntimeError(f"函数结构化补充失败：{filename}#{function_item.get('qualified_name')}")
    return data


def _call_qwen_structured_class_entity(filename, class_item):
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
        f"[文件名]\n{filename}\n\n"
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
        raise RuntimeError(f"类结构化补充失败：{filename}#{class_item.get('qualified_name')}")
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
    }

def _notify_structuring_progress(progress_callback, stage, detail):
    if not callable(progress_callback):
        return
    try:
        progress_callback(str(stage or '').strip(), str(detail or '').strip())
    except Exception:
        pass


def _build_structured_with_treesitter_and_qwen(file_item, progress_callback=None, function_callback=None):
    filename = _safe_str((file_item or {}).get('filename'))
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
            llm_cls = _call_qwen_structured_class_entity(filename=filename, class_item=cls)
            if isinstance(llm_cls, dict):
                for field in ('kind', 'bases', 'member_variables', 'member_methods'):
                    if llm_cls.get(field) is not None:
                        class_payload[field] = llm_cls.get(field)
        except Exception as exc:
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
            llm_func = _call_qwen_structured_function_entity(filename=filename, function_item=func)
            merged = _merge_function_with_llm_enrichment(func, llm_func)
        except Exception as exc:
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


def _reset_repository_index_storage(user_id):
    conn = get_db_connection()
    try:
        with conn.cursor() as cursor:
            cursor.execute("DELETE FROM repository_chunk_embeddings WHERE user_id = %s", (int(user_id),))
            cursor.execute("DELETE FROM repository_function_chunks WHERE user_id = %s", (int(user_id),))
            cursor.execute("DELETE FROM repository_class_metadata WHERE user_id = %s", (int(user_id),))
        conn.commit()
    finally:
        conn.close()
    _write_faiss_index(
        user_id=user_id,
        chunk_ids=[],
        embeddings=np.zeros((0, 0), dtype=np.float32),
        embedding_model='',
    )



def _insert_repository_class_metadata_item(user_id, cls):
    conn = get_db_connection()
    try:
        with conn.cursor() as cursor:
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
        conn.commit()
    finally:
        conn.close()


def _insert_repository_function_embedding_item(user_id, func, vector, embedding_model):
    arr = np.asarray(vector, dtype=np.float32).reshape(-1)
    if arr.size <= 0:
        raise RuntimeError(f"向量写入失败：函数 {str(func.get('qualified_name') or '')} 的向量为空。")

    conn = get_db_connection()
    try:
        with conn.cursor() as cursor:
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
                    int(arr.shape[0]),
                    json.dumps(arr.tolist(), ensure_ascii=False),
                ),
            )
        conn.commit()
    finally:
        conn.close()


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
            progress_message=_format_repository_progress_message('prepare', '已进入执行阶段，准备读取代码仓库文件。'),
        )

        all_functions = []
        all_classes = []
        embedding_map = {}
        embedding_model = _embedding_model_name()
        parse_errors = []
        update_repository_index_job(
            job_id,
            progress_message=_format_repository_progress_message('prepare', '正在清理旧索引数据。'),
        )
        _reset_repository_index_storage(user_id)
        update_repository_index_job(
            job_id,
            progress_message=_format_repository_progress_message('prepare', '旧索引已清理，开始结构化与向量化。'),
        )

        for idx, file_item in enumerate(files, start=1):
            if _is_repository_index_job_cancel_requested(job_id):
                raise RepositoryIndexJobCancelled('结构化整理任务已被取消。')
            filename = str(file_item.get('filename') or '')
            def _report_file_progress(stage, detail):
                update_repository_index_job(
                    job_id,
                    progress_message=_format_repository_progress_message(stage, f"{filename} - {detail}"),
                    processed_files=idx - 1,
                    total_chunks=len(all_functions),
                    total_classes=len(all_classes),
                )

            _report_file_progress('file_prepare', '开始处理文件')
            try:
                def _on_function_ready(normalized_func, file_classes_snapshot):
                    nonlocal embedding_model
                    if _is_repository_index_job_cancel_requested(job_id):
                        raise RepositoryIndexJobCancelled('结构化整理任务已被取消。')

                    class_map = {}
                    for cls in list(all_classes) + list(file_classes_snapshot or []):
                        qn = _safe_str(cls.get('qualified_name'))
                        cn = _safe_str(cls.get('class_name'))
                        if qn:
                            class_map[qn] = cls
                        if cn and cn not in class_map:
                            class_map[cn] = cls

                    classes_total_preview = len(all_classes) + len(file_classes_snapshot or [])
                    update_repository_index_job(
                        job_id,
                        progress_message=_format_repository_progress_message(
                            'embedding',
                            f"{filename} - {_build_vectorizing_target_message(normalized_func)}",
                        ),
                        processed_files=idx - 1,
                        total_chunks=len(all_functions),
                        total_classes=classes_total_preview,
                    )
                    text = _build_embedding_input(normalized_func, class_map)
                    vectors_one, model_used = encode_texts([text], embedding_model_override=embedding_model)
                    if vectors_one.shape[0] != 1:
                        raise RuntimeError('向量化失败：单函数向量化返回数量异常。')
                    vector = np.asarray(vectors_one[0], dtype=np.float32)
                    if str(model_used or '').strip():
                        embedding_model = str(model_used).strip()

                    update_repository_index_job(
                        job_id,
                        progress_message=_format_repository_progress_message(
                            'persist',
                            (
                                f"{filename} - 已向量化并写入函数："
                                f"{_safe_str(normalized_func.get('qualified_name')) or '(anonymous)'}"
                            ),
                        ),
                        processed_files=idx - 1,
                        total_chunks=len(all_functions),
                        total_classes=classes_total_preview,
                    )
                    _insert_repository_function_embedding_item(
                        user_id=user_id,
                        func=normalized_func,
                        vector=vector,
                        embedding_model=embedding_model,
                    )
                    all_functions.append(normalized_func)
                    embedding_map[str(normalized_func.get('chunk_id') or '')] = vector

                normalized = _build_structured_with_treesitter_and_qwen(
                    file_item=file_item,
                    progress_callback=_report_file_progress,
                    function_callback=_on_function_ready,
                )
                file_functions = normalized.get('functions') or []
                file_classes = normalized.get('classes') or []

                if (not file_functions) and file_classes:
                    class_name = _safe_str(file_classes[0].get('qualified_name') or file_classes[0].get('class_name'))
                    detail = f'当前文件仅包含类定义：{class_name}，无需生成函数向量。'
                    update_repository_index_job(
                        job_id,
                        progress_message=_format_repository_progress_message('embedding', f"{filename} - {detail}"),
                        processed_files=idx - 1,
                        total_chunks=len(all_functions),
                        total_classes=len(all_classes),
                    )

                for class_idx, cls in enumerate(file_classes, start=1):
                    cls_name = _safe_str(cls.get('qualified_name') or cls.get('class_name')) or '(anonymous)'
                    update_repository_index_job(
                        job_id,
                        progress_message=_format_repository_progress_message(
                            'persist',
                            f"{filename} - 写入类元数据 {class_idx}/{len(file_classes)}：{cls_name}",
                        ),
                        processed_files=idx - 1,
                        total_chunks=len(all_functions),
                        total_classes=len(all_classes),
                    )
                    _insert_repository_class_metadata_item(user_id=user_id, cls=cls)
                    all_classes.append(cls)

                if _is_repository_index_job_cancel_requested(job_id):
                    raise RepositoryIndexJobCancelled('结构化整理任务已被取消。')
                vectors = _build_cumulative_embeddings(all_functions, embedding_map)
                update_repository_index_job(
                    job_id,
                    progress_message=_format_repository_progress_message('persist', f"{filename} - 正在刷新向量索引（FAISS）"),
                    processed_files=idx - 1,
                    total_chunks=len(all_functions),
                    total_classes=len(all_classes),
                )
                _write_faiss_index(
                    user_id=user_id,
                    chunk_ids=[f['chunk_id'] for f in all_functions],
                    embeddings=vectors,
                    embedding_model=embedding_model,
                )
            except Exception as exc:
                parse_errors.append(f"{filename}: {str(exc)}")
                if _is_repository_index_job_cancel_requested(job_id):
                    raise RepositoryIndexJobCancelled('结构化整理任务已被取消。')
                try:
                    vectors = _build_cumulative_embeddings(all_functions, embedding_map)
                    update_repository_index_job(
                        job_id,
                        progress_message=_format_repository_progress_message(
                            'persist',
                            f"{filename} - 文件处理失败，正在刷新已完成向量索引",
                        ),
                        processed_files=idx - 1,
                        total_chunks=len(all_functions),
                        total_classes=len(all_classes),
                    )
                    _write_faiss_index(
                        user_id=user_id,
                        chunk_ids=[f['chunk_id'] for f in all_functions],
                        embeddings=vectors,
                        embedding_model=embedding_model,
                    )
                except Exception as sync_exc:
                    parse_errors.append(f"{filename}: 刷新 FAISS 失败：{str(sync_exc)}")

            update_repository_index_job(
                job_id,
                processed_files=idx,
                total_chunks=len(all_functions),
                total_classes=len(all_classes),
                progress_message=_format_repository_progress_message(
                    'file_done',
                    (
                        f'已完成文件 {idx}/{total_files}：{filename}；'
                        f'累计函数 {len(all_functions)}，类 {len(all_classes)}'
                    ),
                ),
            )

        if _is_repository_index_job_cancel_requested(job_id):
            raise RepositoryIndexJobCancelled('结构化整理任务已被取消。')
        warn_msg = ''
        if parse_errors:
            warn_msg = '；'.join(parse_errors[:5])
            if len(parse_errors) > 5:
                warn_msg += f"；另有 {len(parse_errors) - 5} 个文件失败"

        if parse_errors:
            update_repository_index_job(
                job_id,
                status='failed',
                processed_files=len(files),
                total_files=len(files),
                total_chunks=len(all_functions),
                total_classes=len(all_classes),
                finished_at=datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                error_message=warn_msg,
                progress_message=_format_repository_progress_message(
                    'failed',
                    f'结构化整理存在失败文件 {len(parse_errors)}/{len(files)}，请查看错误信息。',
                ),
            )
            return {
                'success': False,
                'job_id': job_id,
                'error': f'结构化整理存在失败文件 {len(parse_errors)}/{len(files)}',
                'warnings': parse_errors,
                'partial': True,
                'files': len(files),
                'chunks': len(all_functions),
                'classes': len(all_classes),
                'embedding_model': embedding_model,
            }

        update_repository_index_job(
            job_id,
            status='success',
            processed_files=len(files),
            total_files=len(files),
            total_chunks=len(all_functions),
            total_classes=len(all_classes),
            finished_at=datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
            error_message=warn_msg or None,
            progress_message=_format_repository_progress_message('completed', '结构化整理与向量化已完成。'),
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
            progress_message=_format_repository_progress_message('canceled', str(exc)),
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
                progress_message=_format_repository_progress_message('canceled', '结构化整理任务已被取消。'),
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
            progress_message=_format_repository_progress_message('failed', f'任务失败：{str(exc)}'),
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
