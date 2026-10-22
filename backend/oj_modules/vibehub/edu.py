"""VibeHub edu/1：匿名作答、服务端事件、固定版本与成绩快照。"""

from __future__ import annotations

from copy import deepcopy
import json
import re
import secrets

from backend.oj_modules.infrastructure.mysql import get_db_connection, safe_table_name
from backend.oj_modules.vibehub import services, storage
from backend.oj_modules.vibehub.runtime import get_runtime_manager


PROTOCOL = "vibehub-edu/1"
MAX_JSON_BYTES = 2 * 1024 * 1024
MAX_ACTIONS = 200
MAX_INTERNAL_EXECUTIONS = 4
INTERNAL_TIMEOUT_SECONDS = 45
EXECUTION_TIMEOUT_SECONDS = 40
_IDENTIFIER = re.compile(r"^[A-Za-z0-9_-]{8,80}$")
_grade_task = None


def init_grade_task(task):
    global _grade_task
    _grade_task = task


def _dump(value):
    encoded = json.dumps(value, ensure_ascii=False, allow_nan=False, separators=(",", ":"))
    if len(encoded.encode("utf-8")) > MAX_JSON_BYTES:
        raise services.VibeHubError("作答数据超过限制", status_code=413)
    return encoded


def _load(value, default=None):
    return json.loads(value) if isinstance(value, (str, bytes)) else (value if value is not None else default)


def _id(value):
    if not isinstance(value, str) or not _IDENTIFIER.fullmatch(value):
        raise services.VibeHubError("请求编号格式无效")
    return value


def _manifest(value):
    manifest = _load(value, {})
    if manifest.get("kind") != "edu" or manifest.get("education", {}).get("protocol") != PROTOCOL:
        raise ValueError("请选择已发布的 edu 教学作品")
    return manifest


def list_assignable_projects(actor):
    if not services._is_admin(actor):
        raise services.VibeHubPermissionError()
    conn = get_db_connection()
    try:
        with conn.cursor() as cursor:
            cursor.execute("""SELECT p.id,p.slug,v.title,v.id AS version_id,v.manifest_json
                FROM vibehub_projects p JOIN vibehub_versions v ON v.id=p.public_version_id
                WHERE v.review_status='approved' ORDER BY p.id DESC""")
            result = []
            for row in cursor.fetchall():
                try:
                    _manifest(row.pop("manifest_json"))
                except (ValueError, TypeError):
                    continue
                result.append(row)
            return result
    finally:
        conn.close()


def create_assignment(cursor, class_en, homework_id, project_id, actor):
    if not services._is_admin(actor):
        raise ValueError("仅管理员可布置 edu 作业")
    cursor.execute("""SELECT p.id,p.public_version_id,v.manifest_json FROM vibehub_projects p
        JOIN vibehub_versions v ON v.id=p.public_version_id
        WHERE p.id=%s AND v.review_status='approved' FOR UPDATE""", (project_id,))
    project = cursor.fetchone()
    if not project:
        raise ValueError("edu 作品尚未发布")
    _manifest(project["manifest_json"])
    cursor.execute("""INSERT INTO vibehub_edu_assignments
        (class_en,homework_id,project_id,version_id,parameters_json,max_score)
        VALUES (%s,%s,%s,%s,'{}',100)""",
        (class_en, homework_id, project_id, project["public_version_id"]))
    return cursor.lastrowid


def delete_assignment(cursor, assignment_id):
    cursor.execute("UPDATE vibehub_edu_assignments SET deleted_at=NOW() WHERE id=%s", (assignment_id,))


def _assignment(cursor, assignment_id, actor):
    cursor.execute("SELECT * FROM vibehub_edu_assignments WHERE id=%s AND deleted_at IS NULL", (assignment_id,))
    row = cursor.fetchone()
    if not row:
        raise services.VibeHubNotFoundError("作业不存在")
    if not services._is_admin(actor):
        cursor.execute("SELECT 1 FROM user_class_map WHERE user_id=%s AND class_en=%s", (actor["id"], row["class_en"]))
        if not cursor.fetchone():
            raise services.VibeHubPermissionError("你不在该作业的班级中")
    table = safe_table_name(row["class_en"])
    cursor.execute(f"SELECT id FROM `{table}` WHERE id=%s AND vibehub_edu_assignment_id=%s", (row["homework_id"], row["id"]))
    if not cursor.fetchone():
        raise services.VibeHubNotFoundError("作业已被移除")
    return row


def _version(cursor, project_id, version_id):
    cursor.execute("""SELECT v.*,p.slug,p.is_featured FROM vibehub_versions v
        JOIN vibehub_projects p ON p.id=v.project_id WHERE v.id=%s AND p.id=%s""", (version_id, project_id))
    row = cursor.fetchone()
    if not row:
        raise services.VibeHubNotFoundError("作业指定的已发布作品版本不可用")
    row["manifest"] = _manifest(row["manifest_json"])
    return row


def _lease(version):
    """按数据库版本号建立专用镜像别名，不跟随作品 public/latest 切换。"""
    manager = get_runtime_manager()
    # 冒号不属于作者可注册的 slug 字符，避免普通作品占用教学固定版本的镜像别名。
    key = f"edu:{version['project_id']}:v{version['id']}"
    # 同版本的首次固定镜像准备由数据库命名锁串行化。
    conn = get_db_connection()
    lock = f"vibehub:edu-image:{version['id']}"
    try:
        with conn.cursor() as cursor:
            cursor.execute("SELECT GET_LOCK(%s,60) AS acquired", (lock,))
            if int((cursor.fetchone() or {}).get("acquired") or 0) != 1:
                raise services.VibeHubError(
                    "教学作品镜像正在准备，请稍后重试。",
                    status_code=503, code="edu_image_preparing",
                )
            try:
                if manager.capture_image_tag(key, channel="public") is None:
                    reused = manager.pin_existing_image(
                        key, version["slug"], package_digest=version["package_sha256"],
                        featured=bool(version["is_featured"]),
                    )
                    if not reused:
                        app_dir = storage.resolve_snapshot_app(version["slug"], version["version_number"])
                        manager.build_latest_image(key, app_dir, package_digest=version["package_sha256"], featured=bool(version["is_featured"]))
                        manager.promote_latest_to_public(key, package_digest=version["package_sha256"])
            finally:
                cursor.execute("SELECT RELEASE_LOCK(%s)", (lock,))
    finally:
        conn.close()
    return manager.acquire(key, channel="public", featured=bool(version["is_featured"]),
        base_path="/vibehub/runtime", package_digest=version["package_sha256"],
        storage_key=f"project-{version['project_id']}-public")


def _internal(lease, operation, payload):
    if operation not in {"start", "step", "grade"}:
        raise ValueError("未知教育协议操作")
    # 每次续调都重新使用平台原始载荷；作品只能指定 opaque continuation，不能覆盖可信上下文。
    original = deepcopy(payload)
    request = original
    for executed in range(MAX_INTERNAL_EXECUTIONS + 1):
        response = get_runtime_manager().docker.relay_http(lease.container_name, "POST", f"/v1/{operation}",
            {"Content-Type": "application/json"}, _dump(request).encode(), timeout=INTERNAL_TIMEOUT_SECONDS,
            response_max_bytes=MAX_JSON_BYTES, edu=True)
        if response.status != 200:
            if operation in {"start", "step"} and executed == 0 and response.status in {400, 422}:
                raise services.VibeHubError("操作不符合该作品规则", status_code=400)
            raise services.VibeHubError("作品无法处理本次操作", status_code=502, code="edu_protocol_error")
        try:
            if len(response.body) > MAX_JSON_BYTES:
                raise ValueError("响应过大")
            result = json.loads(response.body)
            _dump(result)
        except (TypeError, ValueError) as exc:
            raise services.VibeHubError("作品教育协议响应无效", status_code=502) from exc
        if not isinstance(result, dict):
            raise services.VibeHubError("作品教育协议响应必须为对象", status_code=502)
        if not ({"execute", "continuation"} & result.keys()):
            return result
        if set(result) != {"execute", "continuation"} or not isinstance(result["execute"], dict):
            raise services.VibeHubError("作品执行请求字段无效", status_code=502)
        if executed >= MAX_INTERNAL_EXECUTIONS:
            raise services.VibeHubError("作品执行请求次数超过限制", status_code=502)
        execution_result = _execute_process(lease, original.get("context", {}), result["execute"])
        # execution_result 只来自受控执行接口；浏览器 action 内的同名字段不会提升为可信结果。
        request = {**deepcopy(original), "continuation": result["continuation"],
            "execution_result": execution_result}
        _dump(request)
    raise AssertionError("教育协议执行次数检查失效")


def _execute_process(lease, context, execute):
    """对通用执行施加作答串行与全站并发限制，不解释作品的程序或评分规则。"""
    attempt_id = context.get("attempt_id") if isinstance(context, dict) else None
    if not isinstance(attempt_id, str) or not _IDENTIFIER.fullmatch(attempt_id):
        raise services.VibeHubError("作品执行上下文无效", status_code=502)
    conn = get_db_connection()
    acquired = []
    try:
        with conn.cursor() as cursor:
            owner_lock = f"edu:execute:{attempt_id}"
            cursor.execute("SELECT GET_LOCK(%s,0) AS acquired", (owner_lock,))
            if int((cursor.fetchone() or {}).get("acquired") or 0) != 1:
                raise services.VibeHubError("本次作答正在运行，请等待结果", status_code=429)
            acquired.append(owner_lock)
            for index in range(4):
                slot = f"edu:process-slot:{index}"
                cursor.execute("SELECT GET_LOCK(%s,0) AS acquired", (slot,))
                if int((cursor.fetchone() or {}).get("acquired") or 0) == 1:
                    acquired.append(slot)
                    break
            else:
                raise services.VibeHubError("试运行资源繁忙，请稍后重试", status_code=429)
            result = get_runtime_manager().docker.execute_edu_process(
                lease.container_name, execute, timeout=EXECUTION_TIMEOUT_SECONDS)
            _dump(result)
            return result
    finally:
        try:
            with conn.cursor() as cursor:
                for lock in reversed(acquired):
                    cursor.execute("SELECT RELEASE_LOCK(%s)", (lock,))
        finally:
            conn.close()


def _transition(value):
    if set(value) != {"state", "view"} or not isinstance(value["state"], dict) or not isinstance(value["view"], dict):
        raise services.VibeHubError("作品未返回合法的 state/view", status_code=502)
    return value


def launch(slug, actor, assignment_id=None, channel="public"):
    user_id = services._actor_id(actor)
    conn = get_db_connection()
    try:
        with conn.cursor() as cursor:
            assignment = _assignment(cursor, assignment_id, actor) if assignment_id is not None else None
            if assignment:
                version = _version(cursor, assignment["project_id"], assignment["version_id"])
                if version["slug"] != slug:
                    raise services.VibeHubPermissionError("作品与作业不匹配")
            else:
                package = services.resolve_project_package(slug, audience=channel, actor=actor)
                version = _version(cursor, package["project_id"], package["version_id"])
            cursor.execute("""SELECT * FROM vibehub_edu_attempts WHERE user_id=%s
                AND assignment_id <=> %s AND version_id=%s AND status='active' ORDER BY created_at DESC LIMIT 1""",
                (user_id, assignment_id, version["id"]))
            attempt = cursor.fetchone()
        conn.rollback()
    finally:
        conn.close()
    lease = _lease(version)
    try:
        if attempt is None:
            attempt_id = "att_" + secrets.token_urlsafe(20)
            seed = secrets.token_urlsafe(24)
            parameters = _load(assignment["parameters_json"], {}) if assignment else {}
            context = {"attempt_id": attempt_id, "assignment_id": assignment_id,
                "project_version_id": int(version["id"]), "rubric_version": 1,
                "challenge_seed": seed, "parameters": parameters}
            initial = _transition(_internal(lease, "start", {"context": context}))
            conn = get_db_connection()
            try:
                with conn.cursor() as cursor:
                    cursor.execute("""INSERT INTO vibehub_edu_attempts
                        (id,assignment_id,project_id,version_id,user_id,context_json,state_json,view_json,status)
                        VALUES (%s,%s,%s,%s,%s,%s,%s,%s,'active')""", (attempt_id, assignment_id,
                        version["project_id"], version["id"], user_id, _dump(context), _dump(initial["state"]), _dump(initial["view"])))
                conn.commit()
            finally:
                conn.close()
            attempt = {"id": attempt_id, "seq": 0}
        get_runtime_manager().bind_edu_attempt(lease.token, attempt["id"])
        return {"attempt_id": attempt["id"], "seq": int(attempt["seq"]), "lease_token": lease.token,
            "proxy_url": lease.proxy_base_path + "/", "heartbeat_url": f"/vibehub/runtime/{lease.token}/heartbeat",
            "release_url": f"/vibehub/runtime/{lease.token}/release", "expires_at": lease.expires_at}
    except Exception:
        get_runtime_manager().release(lease.token)
        raise


def _get_attempt(cursor, attempt_id, actor=None, *, for_update=False):
    suffix = " FOR UPDATE" if for_update else ""
    cursor.execute("SELECT * FROM vibehub_edu_attempts WHERE id=%s" + suffix, (attempt_id,))
    row = cursor.fetchone()
    if not row:
        raise services.VibeHubNotFoundError("作答不存在")
    if actor is not None and int(row["user_id"]) != services._actor_id(actor):
        raise services.VibeHubPermissionError("无权访问他人的作答")
    if row["assignment_id"]:
        if actor is None:
            cursor.execute("SELECT id,is_admin FROM users WHERE id=%s", (row["user_id"],))
            actor = cursor.fetchone()
            if not actor:
                raise services.VibeHubPermissionError("作答所属用户不存在")
        _assignment(cursor, row["assignment_id"], actor)
    return row


def attempt_state(attempt_id, actor=None):
    conn = get_db_connection()
    try:
        with conn.cursor() as cursor:
            row = _get_attempt(cursor, attempt_id, actor)
            return {"attempt_id": row["id"], "assignment_id": row["assignment_id"], "seq": int(row["seq"]), "status": row["status"], "view": _load(row["view_json"])}
    finally:
        conn.close()


def apply_action(attempt_id, payload, actor=None):
    if not isinstance(payload, dict) or set(payload) != {"command_id", "expected_seq", "action"}:
        raise services.VibeHubError("操作请求字段无效")
    command_id = _id(payload["command_id"])
    action = payload["action"]
    if not isinstance(action, dict) or not isinstance(action.get("type"), str):
        raise services.VibeHubError("操作格式无效")
    if type(payload["expected_seq"]) is not int:
        raise services.VibeHubError("操作序号无效")
    action_json = _dump(action)
    conn = get_db_connection()
    try:
        with conn.cursor() as cursor:
            row = _get_attempt(cursor, attempt_id, actor)
            cursor.execute("SELECT * FROM vibehub_edu_commands WHERE attempt_id=%s AND command_id=%s", (attempt_id, command_id))
            previous = cursor.fetchone()
            if previous:
                if _load(previous["action_json"]) != action or int(previous["seq"]) != payload["expected_seq"] + 1:
                    raise services.VibeHubError("请求编号已用于不同操作", status_code=409)
                return _load(previous["response_json"])
            if row["status"] != "active" or int(row["seq"]) != payload["expected_seq"]:
                raise services.VibeHubError("作答状态已变化，请刷新后重试", status_code=409)
            if int(row["seq"]) >= MAX_ACTIONS:
                raise services.VibeHubError("本次作答操作次数已达上限")
            version = _version(cursor, row["project_id"], row["version_id"])
        conn.rollback()
    finally:
        conn.close()
    lease = _lease(version)
    try:
        context = _load(row["context_json"])
        transition = _transition(_internal(lease, "step", {"context": context, "state": _load(row["state_json"]), "action": action, "seq": int(row["seq"]) + 1}))
    finally:
        get_runtime_manager().release(lease.token)
    result = {"attempt_id": attempt_id, "seq": int(row["seq"]) + 1, "status": "active", "view": transition["view"]}
    conn = get_db_connection()
    try:
        with conn.cursor() as cursor:
            cursor.execute("""UPDATE vibehub_edu_attempts SET seq=seq+1,state_json=%s,view_json=%s
                WHERE id=%s AND seq=%s AND status='active'""", (_dump(transition["state"]), _dump(transition["view"]), attempt_id, row["seq"]))
            if cursor.rowcount != 1:
                conn.rollback()
                cursor.execute("SELECT action_json,response_json,seq FROM vibehub_edu_commands WHERE attempt_id=%s AND command_id=%s", (attempt_id, command_id))
                previous = cursor.fetchone()
                if previous and _load(previous["action_json"]) == action and int(previous["seq"]) == payload["expected_seq"] + 1:
                    return _load(previous["response_json"])
                raise services.VibeHubError("操作并发冲突，请刷新后重试", status_code=409)
            cursor.execute("""INSERT INTO vibehub_edu_commands(attempt_id,command_id,seq,action_json,response_json)
                VALUES (%s,%s,%s,%s,%s)""", (attempt_id, command_id, result["seq"], action_json, _dump(result)))
        conn.commit()
        return result
    finally:
        conn.close()


def submit(attempt_id, payload, actor=None):
    if not isinstance(payload, dict) or set(payload) != {"request_id", "expected_seq"}:
        raise services.VibeHubError("提交请求字段无效")
    request_id = _id(payload["request_id"])
    if type(payload["expected_seq"]) is not int:
        raise services.VibeHubError("提交序号无效")
    conn = get_db_connection()
    try:
        with conn.cursor() as cursor:
            row = _get_attempt(cursor, attempt_id, actor, for_update=True)
            cursor.execute("SELECT * FROM vibehub_edu_submissions WHERE attempt_id=%s", (attempt_id,))
            previous = cursor.fetchone()
            if previous:
                if int(previous["final_seq"]) != payload["expected_seq"]:
                    raise services.VibeHubError("本次作答已提交", status_code=409)
                submission_id = previous["id"]
            else:
                cursor.execute("UPDATE vibehub_edu_attempts SET status='submitted' WHERE id=%s AND status='active' AND seq=%s", (attempt_id, payload["expected_seq"]))
                if cursor.rowcount != 1:
                    raise services.VibeHubError("作答状态已变化", status_code=409)
                cursor.execute("SELECT seq,action_json FROM vibehub_edu_commands WHERE attempt_id=%s ORDER BY seq", (attempt_id,))
                actions = [{"seq": int(event["seq"]), "action": _load(event["action_json"])} for event in cursor.fetchall()]
                if not actions:
                    raise services.VibeHubError("请先完成至少一次操作")
                snapshot = {"context": _load(row["context_json"]), "actions": actions}
                cursor.execute("""INSERT INTO vibehub_edu_submissions
                    (attempt_id,assignment_id,project_id,version_id,user_id,request_id,final_seq,status,snapshot_json)
                    VALUES (%s,%s,%s,%s,%s,%s,%s,'submitted',%s)""", (attempt_id, row["assignment_id"], row["project_id"], row["version_id"], row["user_id"], request_id, row["seq"], _dump(snapshot)))
                submission_id = cursor.lastrowid
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()
    if _grade_task is None:
        raise services.VibeHubError("评分服务未就绪，请重试提交", status_code=503)
    _grade_task.apply_async(args=[int(submission_id)], queue="celery")
    return {"submission_id": int(submission_id), "status": "grading"}


def dispatch_pending_grades():
    """补投已冻结但未成功派发的提交，不修改运行锁或已开始的评分。"""
    if _grade_task is None:
        return 0
    conn = get_db_connection()
    try:
        with conn.cursor() as cursor:
            cursor.execute("""SELECT id FROM vibehub_edu_submissions WHERE
                (status='submitted' AND created_at < DATE_SUB(NOW(), INTERVAL 60 SECOND))
                OR (status='grading' AND created_at < DATE_SUB(NOW(), INTERVAL 5 MINUTE))
                ORDER BY id LIMIT 50""")
            ids = [int(row["id"]) for row in cursor.fetchall()]
    finally:
        conn.close()
    for submission_id in ids:
        _grade_task.apply_async(args=[submission_id], queue="celery")
    return len(ids)


def submission_result(submission_id=None, *, attempt_id=None, actor=None):
    conn = get_db_connection()
    try:
        with conn.cursor() as cursor:
            if attempt_id is not None:
                _get_attempt(cursor, attempt_id, actor)
                cursor.execute("SELECT * FROM vibehub_edu_submissions WHERE attempt_id=%s", (attempt_id,))
            else:
                cursor.execute("SELECT * FROM vibehub_edu_submissions WHERE id=%s", (submission_id,))
            row = cursor.fetchone()
            if not row:
                return {"status": "active", "submission_id": None}
            if actor is not None and int(row["user_id"]) != services._actor_id(actor) and not services._is_admin(actor):
                raise services.VibeHubPermissionError()
            return {"submission_id": int(row["id"]), "attempt_id": row["attempt_id"], "status": row["status"],
                "score": float(row["score"]) if row["score"] is not None else None,
                "result": _load(row["result_json"], None), "created_at": row["created_at"]}
    finally:
        conn.close()


def grade_submission(submission_id):
    conn = get_db_connection()
    lock = f"vibehub:edu-grade:{int(submission_id)}"
    try:
        with conn.cursor() as cursor:
            cursor.execute("SELECT GET_LOCK(%s,0) AS acquired", (lock,))
            if int((cursor.fetchone() or {}).get("acquired") or 0) != 1:
                return
            try:
                cursor.execute("SELECT * FROM vibehub_edu_submissions WHERE id=%s", (submission_id,))
                row = cursor.fetchone()
                if not row or row["status"] == "graded":
                    return
                version = _version(cursor, row["project_id"], row["version_id"])
                snapshot = _load(row["snapshot_json"])
                cursor.execute("UPDATE vibehub_edu_submissions SET status='grading' WHERE id=%s", (submission_id,))
                conn.commit()
                lease = _lease(version)
                try:
                    result = _internal(lease, "grade", {"context": snapshot["context"], "actions": snapshot["actions"]})
                finally:
                    get_runtime_manager().release(lease.token)
                score_bp = result.get("score_bp")
                if type(score_bp) is not int or not 0 <= score_bp <= 10000 or result.get("verdict") not in {"passed", "failed"}:
                    raise services.VibeHubError("作品评分响应无效", status_code=502)
                cursor.execute("""UPDATE vibehub_edu_submissions SET status='graded',score_bp=%s,
                    score=%s,result_json=%s,graded_at=NOW() WHERE id=%s""", (score_bp, score_bp / 100, _dump(result), submission_id))
                cursor.execute("UPDATE vibehub_edu_attempts SET status='graded' WHERE id=%s", (row["attempt_id"],))
                conn.commit()
                from backend.oj_modules.problems.catalog import invalidate_problem_list_cache_for_user
                invalidate_problem_list_cache_for_user(user_id=int(row["user_id"]))
            except Exception:
                conn.rollback()
                cursor.execute("UPDATE vibehub_edu_submissions SET status='error',result_json=%s WHERE id=%s AND status<>'graded'",
                    (_dump({"feedback": "评分服务暂时不可用，可重试评分。"}), submission_id))
                conn.commit()
                raise
            finally:
                cursor.execute("SELECT RELEASE_LOCK(%s)", (lock,))
    finally:
        conn.close()
