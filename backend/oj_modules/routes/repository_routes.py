#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import hashlib

from flask import Blueprint, jsonify, redirect, render_template, request, url_for

from backend.oj_modules.repository.index import (
    fail_repository_index_job_dispatch,
    get_or_create_active_repository_index_job,
    get_repository_index_job,
    get_latest_active_repository_index_job,
    list_repository_classes,
    request_cancel_repository_index_job,
    search_repository_chunks,
    update_repository_index_job,
)
from backend.oj_modules.repository.settings import (
    DEFAULT_SEARCH_SCORE_THRESHOLD as _DEFAULT_REPOSITORY_SEARCH_SCORE_THRESHOLD,
    DEFAULT_SEARCH_TOP_K as _DEFAULT_REPOSITORY_SEARCH_TOP_K,
)
from backend.oj_modules.repository.tree import (
    RepositoryDomainError,
    UPLOAD_CHUNK_MAX_BYTES,
    append_repository_upload_chunk,
    cancel_repository_upload_session,
    commit_repository_upload_session,
    create_repository_directory as create_repository_directory_service,
    create_repository_upload_session,
    delete_repository_entry,
    finalize_repository_upload_session,
    get_repository_state,
    get_repository_upload_session,
    list_repository_entries,
    list_repository_files,
    move_repository_entry,
    preview_repository_delete,
    read_repository_file,
    save_repository_file as save_repository_file_service,
    upsert_repository_file_by_path,
)


repository_bp = Blueprint('repository', __name__)
_repository_build_index_task = None


def init_repository_index_module(repository_build_index_task):
    global _repository_build_index_task
    _repository_build_index_task = repository_build_index_task


from backend.oj_modules.security.auth import current_user


@repository_bp.route('/code_repository')
def code_repository():
    user = current_user()
    if not user:
        return redirect(url_for('auth.login'))
    return render_template('repository/index.html', user=user)


@repository_bp.route('/api/repository/files', methods=['GET'])
def get_repository_files():
    user = current_user()
    if not user:
        return jsonify(success=False, message="未登录"), 401
    try:
        files = list_repository_files(user['id'])
        for item in files:
            item['filename'] = item['relative_path']
            item['file_size_kb'] = round(item['file_size'] / 1024, 2)
        state = get_repository_state(user['id'])
        return jsonify(success=True, files=files, **state)
    except RepositoryDomainError as e:
        return jsonify(**e.as_payload()), e.status
    except Exception as e:
        return jsonify(success=False, message=f"获取文件列表失败: {str(e)}"), 500


@repository_bp.route('/api/repository/tree', methods=['GET'])
def get_repository_tree():
    user = current_user()
    if not user:
        return jsonify(success=False, message="未登录"), 401
    try:
        return jsonify(success=True, **list_repository_entries(user['id']))
    except RepositoryDomainError as e:
        return jsonify(**e.as_payload()), e.status
    except Exception as e:
        return jsonify(success=False, message=f"获取目录树失败: {str(e)}"), 500


@repository_bp.route('/api/repository/file/<int:file_id>', methods=['GET'])
def get_repository_file(file_id):
    user = current_user()
    if not user:
        return jsonify(success=False, message="未登录"), 401

    try:
        file_data = read_repository_file(user['id'], entry_id=file_id)
        return jsonify(
            success=True,
            **file_data,
            filename=file_data['relative_path'],
        )
    except RepositoryDomainError as e:
        return jsonify(**e.as_payload()), e.status
    except Exception as e:
        return jsonify(success=False, message=f"获取文件失败: {str(e)}"), 500


@repository_bp.route('/api/repository/file', methods=['POST'])
def save_repository_file():
    user = current_user()
    if not user:
        return jsonify(success=False, message="未登录"), 401

    data = request.get_json() or {}
    filename = str(data.get('name') or data.get('filename') or '')
    content = data.get('content', '')
    file_id = data.get('file_id') or data.get('entry_id')
    try:
        if file_id:
            result = save_repository_file_service(
                user['id'],
                entry_id=file_id,
                content=content,
                expected_file_version=data.get('expected_file_version'),
            )
        elif '/' in filename:
            result = upsert_repository_file_by_path(
                user['id'],
                filename,
                content,
                expected_structure_version=data.get('expected_structure_version'),
                overwrite=False,
            )
        else:
            result = save_repository_file_service(
                user['id'],
                parent_id=data.get('parent_id'),
                name=filename,
                content=content,
                expected_structure_version=data.get('expected_structure_version'),
            )
        entry = result['entry']
        return jsonify({
            **result,
            'success': True,
            'message': "文件创建成功" if result.get('created') else "文件更新成功",
            'file_id': result.get('file_id', entry['id']),
            'filename': entry['relative_path'],
        })
    except RepositoryDomainError as e:
        return jsonify(**e.as_payload()), e.status
    except Exception as e:
        return jsonify(success=False, message=f"保存文件失败: {str(e)}"), 500


@repository_bp.route('/api/repository/directory', methods=['POST'])
def create_directory():
    user = current_user()
    if not user:
        return jsonify(success=False, message="未登录"), 401
    data = request.get_json(silent=True) or {}
    try:
        result = create_repository_directory_service(
            user['id'],
            parent_id=data.get('parent_id'),
            name=data.get('name'),
            expected_structure_version=data.get('expected_structure_version'),
        )
        return jsonify(success=True, message="目录创建成功", **result)
    except RepositoryDomainError as e:
        return jsonify(**e.as_payload()), e.status
    except Exception as e:
        return jsonify(success=False, message=f"创建目录失败: {str(e)}"), 500


@repository_bp.route('/api/repository/entry/<int:entry_id>/move', methods=['POST'])
def move_entry(entry_id):
    user = current_user()
    if not user:
        return jsonify(success=False, message="未登录"), 401
    data = request.get_json(silent=True) or {}
    try:
        result = move_repository_entry(
            user['id'],
            entry_id,
            destination_parent_id=data.get('destination_parent_id'),
            new_name=data.get('new_name'),
            expected_structure_version=data.get('expected_structure_version'),
            conflict_policy=data.get('conflict_policy', 'error'),
        )
        return jsonify(success=True, message="移动成功", **result)
    except RepositoryDomainError as e:
        return jsonify(**e.as_payload()), e.status
    except Exception as e:
        return jsonify(success=False, message=f"移动失败: {str(e)}"), 500


@repository_bp.route('/api/repository/entry/<int:entry_id>/delete-preview', methods=['POST'])
def preview_delete_entry(entry_id):
    user = current_user()
    if not user:
        return jsonify(success=False, message="未登录"), 401
    try:
        return jsonify(success=True, **preview_repository_delete(user['id'], entry_id))
    except RepositoryDomainError as e:
        return jsonify(**e.as_payload()), e.status
    except Exception as e:
        return jsonify(success=False, message=f"生成删除预览失败: {str(e)}"), 500


def _delete_entry_response(user, entry_id):
    data = request.get_json(silent=True) or {}
    token = data.get('confirmation_token')
    if not token:
        preview = preview_repository_delete(user['id'], entry_id)
        return jsonify(
            success=False,
            code='confirmation_required',
            message='永久删除前需要确认',
            **preview,
        ), 409
    result = delete_repository_entry(
        user['id'],
        entry_id,
        confirmation_token=token,
    )
    return jsonify(success=True, message="永久删除成功", **result)


@repository_bp.route('/api/repository/entry/<int:entry_id>', methods=['DELETE'])
def delete_entry(entry_id):
    user = current_user()
    if not user:
        return jsonify(success=False, message="未登录"), 401
    try:
        return _delete_entry_response(user, entry_id)
    except RepositoryDomainError as e:
        return jsonify(**e.as_payload()), e.status
    except Exception as e:
        return jsonify(success=False, message=f"删除失败: {str(e)}"), 500
@repository_bp.route('/api/repository/file/<int:file_id>', methods=['DELETE'])
def delete_repository_file(file_id):
    user = current_user()
    if not user:
        return jsonify(success=False, message="未登录"), 401

    try:
        return _delete_entry_response(user, file_id)
    except RepositoryDomainError as e:
        return jsonify(**e.as_payload()), e.status
    except Exception as e:
        return jsonify(success=False, message=f"删除文件失败: {str(e)}"), 500


@repository_bp.route('/api/repository/upload/session', methods=['POST'])
def create_upload_session():
    user = current_user()
    if not user:
        return jsonify(success=False, message="未登录"), 401
    data = request.get_json(silent=True) or {}
    try:
        result = create_repository_upload_session(
            user['id'],
            parent_id=data.get('parent_id'),
            expected_structure_version=data.get('expected_structure_version'),
            files=data.get('files'),
            entries=data.get('entries'),
        )
        return jsonify(success=True, **result), 201
    except RepositoryDomainError as e:
        return jsonify(**e.as_payload()), e.status
    except Exception as e:
        return jsonify(success=False, message=f"创建上传会话失败: {str(e)}"), 500


@repository_bp.route(
    '/api/repository/upload/session/<session_id>/file/<token>/chunk',
    methods=['PUT', 'POST'],
)
def upload_session_chunk(session_id, token):
    user = current_user()
    if not user:
        return jsonify(success=False, message="未登录"), 401
    try:
        raw = request.stream.read(UPLOAD_CHUNK_MAX_BYTES + 1)
        if len(raw) > UPLOAD_CHUNK_MAX_BYTES:
            return jsonify(
                success=False,
                code='chunk_too_large',
                message=f'单个上传分块不能超过 {UPLOAD_CHUNK_MAX_BYTES} 字节',
            ), 413
        result = append_repository_upload_chunk(
            user['id'],
            session_id,
            token,
            offset=request.headers.get('Upload-Offset', request.args.get('offset')),
            total_size=request.headers.get('Upload-Length', request.args.get('total')),
            data=raw,
            chunk_sha256=request.headers.get('Upload-Chunk-SHA256'),
        )
        return jsonify(success=True, **result)
    except RepositoryDomainError as e:
        return jsonify(**e.as_payload()), e.status
    except Exception as e:
        return jsonify(success=False, message=f"上传分块失败: {str(e)}"), 500


@repository_bp.route('/api/repository/upload/session/<session_id>', methods=['GET'])
def upload_session_status(session_id):
    user = current_user()
    if not user:
        return jsonify(success=False, message="未登录"), 401
    try:
        return jsonify(
            success=True,
            **get_repository_upload_session(user['id'], session_id),
        )
    except RepositoryDomainError as e:
        return jsonify(**e.as_payload()), e.status
    except Exception as e:
        return jsonify(success=False, message=f"获取上传状态失败: {str(e)}"), 500


@repository_bp.route(
    '/api/repository/upload/session/<session_id>/finalize',
    methods=['POST'],
)
def finalize_upload_session(session_id):
    user = current_user()
    if not user:
        return jsonify(success=False, message="未登录"), 401
    data = request.get_json(silent=True) or {}
    try:
        return jsonify(
            success=True,
            **finalize_repository_upload_session(
                user['id'],
                session_id,
                encodings=data.get('encodings'),
            ),
        )
    except RepositoryDomainError as e:
        return jsonify(**e.as_payload()), e.status
    except Exception as e:
        return jsonify(success=False, message=f"生成上传预览失败: {str(e)}"), 500


@repository_bp.route(
    '/api/repository/upload/session/<session_id>/commit',
    methods=['POST'],
)
def commit_upload_session(session_id):
    user = current_user()
    if not user:
        return jsonify(success=False, message="未登录"), 401
    data = request.get_json(silent=True) or {}
    try:
        return jsonify(
            success=True,
            message='上传已提交',
            **commit_repository_upload_session(
                user['id'],
                session_id,
                expected_structure_version=data.get('expected_structure_version'),
                resolutions=data.get('resolutions'),
                rename_targets=data.get('rename_targets'),
            ),
        )
    except RepositoryDomainError as e:
        return jsonify(**e.as_payload()), e.status
    except Exception as e:
        return jsonify(success=False, message=f"提交上传失败: {str(e)}"), 500


@repository_bp.route(
    '/api/repository/upload/session/<session_id>',
    methods=['DELETE'],
)
def cancel_upload_session(session_id):
    user = current_user()
    if not user:
        return jsonify(success=False, message="未登录"), 401
    try:
        return jsonify(
            success=True,
            **cancel_repository_upload_session(user['id'], session_id),
        )
    except RepositoryDomainError as e:
        return jsonify(**e.as_payload()), e.status
    except Exception as e:
        return jsonify(success=False, message=f"取消上传失败: {str(e)}"), 500


def _multipart_upload_preview(user):
    uploaded = request.files.getlist('files') or request.files.getlist('file')
    uploaded = [item for item in uploaded if item and item.filename]
    if not uploaded:
        raise RepositoryDomainError("没有选择文件", code="validation_error", status=400)
    relative_paths = request.form.getlist('relative_paths')
    if relative_paths and len(relative_paths) != len(uploaded):
        raise RepositoryDomainError(
            "relative_paths 与 files 数量不一致",
            code="validation_error",
            status=400,
        )
    if not relative_paths:
        relative_paths = [item.filename for item in uploaded]
    manifests = []
    for item, relative_path in zip(uploaded, relative_paths):
        stream = item.stream
        start = stream.tell()
        digest = hashlib.sha256()
        size = 0
        while True:
            chunk = stream.read(UPLOAD_CHUNK_MAX_BYTES)
            if not chunk:
                break
            digest.update(chunk)
            size += len(chunk)
        stream.seek(start)
        manifests.append(
            {
                "relative_path": relative_path,
                "size": size,
                "sha256": digest.hexdigest(),
            }
        )
    created = create_repository_upload_session(
        user['id'],
        parent_id=request.form.get('parent_id') or None,
        expected_structure_version=request.form.get('expected_structure_version'),
        files=manifests,
    )
    try:
        for item, descriptor in zip(uploaded, created['files']):
            offset = 0
            while True:
                chunk = item.stream.read(UPLOAD_CHUNK_MAX_BYTES)
                if not chunk:
                    break
                result = append_repository_upload_chunk(
                    user['id'],
                    created['session_id'],
                    descriptor['token'],
                    offset=offset,
                    total_size=descriptor['raw_size'],
                    data=chunk,
                    chunk_sha256=hashlib.sha256(chunk).hexdigest(),
                )
                offset = result['offset']
        return finalize_repository_upload_session(
            user['id'],
            created['session_id'],
        )
    except Exception:
        try:
            cancel_repository_upload_session(user['id'], created['session_id'])
        except Exception:
            pass
        raise


@repository_bp.route('/api/repository/upload/preview', methods=['POST'])
def upload_repository_preview():
    user = current_user()
    if not user:
        return jsonify(success=False, message="未登录"), 401
    try:
        return jsonify(success=True, **_multipart_upload_preview(user))
    except RepositoryDomainError as e:
        return jsonify(**e.as_payload()), e.status
    except Exception as e:
        return jsonify(success=False, message=f"生成上传预览失败: {str(e)}"), 500


@repository_bp.route('/api/repository/upload', methods=['POST'])
def upload_repository_file():
    """兼容旧单文件客户端；有冲突时仍停在预览，绝不静默覆盖。"""
    user = current_user()
    if not user:
        return jsonify(success=False, message="未登录"), 401
    try:
        preview = _multipart_upload_preview(user)
        conflicts = [item for item in preview['files'] if item.get('status') == 'conflict']
        if not preview.get('ready') or conflicts:
            return jsonify(
                success=False,
                code='upload_preview_required',
                message='上传需要确认编码或冲突处理',
                **preview,
            ), 409
        result = commit_repository_upload_session(
            user['id'],
            preview['session_id'],
            expected_structure_version=preview['structure_version'],
        )
        first = (result.get('committed') or [{}])[0]
        return jsonify(
            success=True,
            message='文件上传成功',
            file_id=first.get('entry_id'),
            **result,
        )
    except RepositoryDomainError as e:
        return jsonify(**e.as_payload()), e.status
    except Exception as e:
        return jsonify(success=False, message=f"上传文件失败: {str(e)}"), 500


@repository_bp.route('/api/repository/index/build', methods=['POST'])
def build_repository_index():
    user = current_user()
    if not user:
        return jsonify(success=False, message="未登录"), 401
    if _repository_build_index_task is None:
        return jsonify(success=False, message="结构化整理任务未初始化"), 500

    created_job_id = None
    try:
        reservation = get_or_create_active_repository_index_job(user['id'])
        if not reservation['created']:
            active_job = get_repository_index_job(
                job_id=reservation['job_id'], user_id=user['id']
            ) or reservation['job']
            return jsonify(
                success=True,
                attached=True,
                message='已连接到正在运行的结构化整理任务',
                job_id=int(active_job['id']),
                job=active_job,
            )

        job_id = int(reservation['job_id'])
        created_job_id = job_id
        repository_state = get_repository_state(user['id'])
        update_repository_index_job(
            job_id,
            base_repository_generation=repository_state['repository_generation'],
        )
        async_result = _repository_build_index_task.delay(user['id'], job_id)
        update_repository_index_job(
            job_id,
            task_id=str(async_result.id),
        )
        return jsonify(
            success=True,
            attached=False,
            message='已开始结构化整理',
            job_id=job_id,
            task_id=async_result.id,
            base_repository_generation=repository_state['repository_generation'],
        )
    except Exception as e:
        if created_job_id is not None:
            try:
                fail_repository_index_job_dispatch(
                    created_job_id,
                    user['id'],
                    f'启动结构化整理失败：{str(e)}',
                )
            except Exception:
                pass
        return jsonify(success=False, message=f"启动结构化整理失败: {str(e)}"), 500


@repository_bp.route('/api/repository/index/rebuild_file', methods=['POST'])
def rebuild_repository_index_for_file():
    user = current_user()
    if not user:
        return jsonify(success=False, message="未登录"), 401
    if _repository_build_index_task is None:
        return jsonify(success=False, message="结构化整理任务未初始化"), 500

    created_job_id = None
    try:
        payload = request.get_json(silent=True) or {}
        file_id = int(payload.get('file_id') or 0)
        if file_id <= 0:
            return jsonify(success=False, message='file_id 非法'), 400

        try:
            target_file = read_repository_file(user['id'], entry_id=file_id)
        except RepositoryDomainError as exc:
            return jsonify(**exc.as_payload()), exc.status

        reservation = get_or_create_active_repository_index_job(user['id'])
        if not reservation['created']:
            active_job = get_repository_index_job(
                job_id=reservation['job_id'], user_id=user['id']
            ) or reservation['job']
            return jsonify(
                success=True,
                attached=True,
                message='已连接到正在运行的结构化整理任务',
                job_id=int(active_job['id']),
                job=active_job,
            )

        job_id = int(reservation['job_id'])
        created_job_id = job_id
        repository_state = get_repository_state(user['id'])
        update_repository_index_job(
            job_id,
            base_repository_generation=repository_state['repository_generation'],
        )
        async_result = _repository_build_index_task.delay(user['id'], job_id, int(file_id))
        update_repository_index_job(
            job_id,
            task_id=str(async_result.id),
        )
        return jsonify(
            success=True,
            attached=False,
            message=f"已开始重建文件索引：{target_file['relative_path']}",
            job_id=job_id,
            task_id=async_result.id,
            file_id=int(file_id),
            filename=target_file['relative_path'],
            base_repository_generation=repository_state['repository_generation'],
        )
    except Exception as e:
        if created_job_id is not None:
            try:
                fail_repository_index_job_dispatch(
                    created_job_id,
                    user['id'],
                    f'启动单文件索引重建失败：{str(e)}',
                )
            except Exception:
                pass
        return jsonify(success=False, message=f"启动单文件索引重建失败: {str(e)}"), 500


@repository_bp.route('/api/repository/index/<int:job_id>/cancel', methods=['POST'])
def cancel_repository_index(job_id):
    user = current_user()
    if not user:
        return jsonify(success=False, message="未登录"), 401
    try:
        row = get_repository_index_job(job_id=job_id, user_id=user['id'])
        if not row:
            return jsonify(success=False, message='任务不存在'), 404
        if row.get('status') in ('success', 'failed', 'canceled'):
            return jsonify(success=True, idempotent=True, job=row)
        cancelled = request_cancel_repository_index_job(
            job_id=job_id,
            user_id=user['id'],
            reason='用户取消结构化整理任务。',
        )
        job = get_repository_index_job(job_id=job_id, user_id=user['id'])
        return jsonify(success=True, job=job)
    except Exception as e:
        return jsonify(success=False, message=f"取消结构化整理失败: {str(e)}"), 500


@repository_bp.route('/api/repository/index/status/<int:job_id>', methods=['GET'])
def get_repository_index_status(job_id):
    user = current_user()
    if not user:
        return jsonify(success=False, message="未登录"), 401
    try:
        row = get_repository_index_job(job_id=job_id, user_id=user['id'])
        if not row:
            return jsonify(success=False, message='任务不存在'), 404
        return jsonify(success=True, job=row)
    except Exception as e:
        return jsonify(success=False, message=f"获取任务状态失败: {str(e)}"), 500


@repository_bp.route('/api/repository/index/status/active', methods=['GET'])
def get_active_repository_index_status():
    user = current_user()
    if not user:
        return jsonify(success=False, message="未登录"), 401
    try:
        row = get_latest_active_repository_index_job(user_id=user['id'])
        if not row:
            return jsonify(success=True, has_active=False, job=None)
        return jsonify(success=True, has_active=True, job=row)
    except Exception as e:
        return jsonify(success=False, message=f"获取活跃任务失败: {str(e)}"), 500


@repository_bp.route('/api/repository/index/search', methods=['POST'])
def search_repository_index():
    user = current_user()
    if not user:
        return jsonify(success=False, message="未登录"), 401

    data = request.get_json() or {}
    query = str(data.get('query') or '').strip()
    if not query:
        return jsonify(success=False, message='query 不能为空'), 400
    top_k = data.get('top_k', _DEFAULT_REPOSITORY_SEARCH_TOP_K)
    score_threshold = data.get('score_threshold', _DEFAULT_REPOSITORY_SEARCH_SCORE_THRESHOLD)

    try:
        result = search_repository_chunks(
            user_id=user['id'],
            query=query,
            top_k=top_k,
            score_threshold=score_threshold,
        )
        return jsonify(success=True, **result)
    except Exception as e:
        return jsonify(success=False, message=f"检索失败: {str(e)}"), 500


@repository_bp.route('/api/repository/index/classes', methods=['GET'])
def get_repository_classes():
    user = current_user()
    if not user:
        return jsonify(success=False, message="未登录"), 401
    limit = request.args.get('limit', 300)
    try:
        classes = list_repository_classes(user_id=user['id'], limit=limit)
        return jsonify(success=True, classes=classes, count=len(classes))
    except Exception as e:
        return jsonify(success=False, message=f"获取类结构失败: {str(e)}"), 500
