"""在原有构建事务外提供 NDJSON 响应，断连不重复提交或中断事务。"""
from __future__ import annotations

from collections import deque
import json
import threading
import time

from flask import Response, copy_current_request_context, current_app, stream_with_context
from werkzeug.exceptions import HTTPException

from backend.oj_modules.vibehub import build_progress, services


def submission_stream(operation):
    pending = deque(maxlen=256)
    condition = threading.Condition()
    finished = threading.Event()
    started = time.monotonic()

    def publish(event):
        with condition:
            pending.append(event)
            condition.notify()

    @copy_current_request_context
    def run():
        try:
            with build_progress.capture(publish):
                project = operation()
            publish({"event": "result", "success": True, "project": project})
        except services.VibeHubError as exc:
            publish({"event": "error", "success": False, "message": str(exc), "code": exc.code, "http_status": exc.status_code})
        except HTTPException as exc:
            publish({"event": "error", "success": False, "message": "请求数据无效或超过上传上限", "http_status": exc.code})
        except Exception as exc:
            current_app.logger.exception("VibeHub 流式提交失败", extra={"event_fields": {"error_type": type(exc).__name__}})
            publish({"event": "error", "success": False, "message": "作品提交失败，请查看作品最新版本后再重试。", "http_status": 500})
        finally:
            finished.set()
            with condition:
                condition.notify()

    @stream_with_context
    def generate():
        # 线程只服务于当前同步 HTTP 请求。上下文退出前等待事务和文件清理，
        # 防止断连时关闭仍在解析/构建使用的上传流；并发仍受原有持久变更槽约束。
        worker = threading.Thread(target=run, name="vibehub-build-stream", daemon=True)
        worker.start()
        try:
            yield json.dumps({"event": "progress", "phase": "accepted", "message": "请求已接收，正在准备构建。"}, ensure_ascii=False) + "\n"
            while True:
                with condition:
                    if not pending and not finished.is_set():
                        condition.wait(timeout=5)
                    events = list(pending)
                    pending.clear()
                for event in events:
                    yield json.dumps(event, ensure_ascii=False) + "\n"
                if finished.is_set() and not pending:
                    break
                if not events:
                    yield json.dumps({"event": "heartbeat", "elapsed_seconds": int(time.monotonic() - started)}) + "\n"
        finally:
            worker.join()

    return Response(generate(), mimetype="application/x-ndjson", headers={
        "Cache-Control": "no-store", "X-Accel-Buffering": "no", "X-Content-Type-Options": "nosniff",
    })
