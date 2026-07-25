import io

from flask import Flask
import pytest

from oj_modules.routes import repository_routes


@pytest.mark.parametrize(
    ("created", "expected_message"),
    [
        (True, "文件创建成功"),
        (False, "文件更新成功"),
    ],
)
def test_save_repository_file_serializes_service_file_id_once(
    monkeypatch,
    created,
    expected_message,
):
    app = Flask(__name__)
    service_result = {
        "created": created,
        "changed": True,
        "file_id": 41,
        "entry": {
            "id": 41,
            "relative_path": "src/main.cpp",
            "file_version": 1,
        },
        "structure_version": 7,
    }
    monkeypatch.setattr(
        repository_routes,
        "current_user",
        lambda: {"id": 9},
    )
    monkeypatch.setattr(
        repository_routes,
        "upsert_repository_file_by_path",
        lambda *_args, **_kwargs: service_result,
    )

    with app.test_request_context(
        "/api/repository/file",
        method="POST",
        json={
            "filename": "src/main.cpp",
            "content": "int main() { return 0; }\n",
            "expected_structure_version": 6,
        },
    ):
        response = repository_routes.save_repository_file()

    assert response.status_code == 200
    assert response.get_json() == {
        **service_result,
        "success": True,
        "message": expected_message,
        "file_id": 41,
        "filename": "src/main.cpp",
    }


def test_multipart_upload_uses_the_exact_raw_size_and_rewinds_the_stream(
    monkeypatch,
):
    app = Flask(__name__)
    payload = b'#include "A/B.h"\nint main() { return 0; }\n'
    captured = {
        "chunks": [],
    }

    def fake_create(
        user_id,
        *,
        parent_id,
        expected_structure_version,
        files,
    ):
        captured["create"] = {
            "user_id": user_id,
            "parent_id": parent_id,
            "expected_structure_version": expected_structure_version,
            "files": files,
        }
        return {
            "session_id": "upload-session",
            "files": [
                {
                    "token": "file-token",
                    "raw_size": files[0]["size"],
                }
            ],
        }

    def fake_append(
        user_id,
        session_id,
        token,
        *,
        offset,
        total_size,
        data,
        chunk_sha256,
    ):
        captured["chunks"].append(
            {
                "user_id": user_id,
                "session_id": session_id,
                "token": token,
                "offset": offset,
                "total_size": total_size,
                "data": data,
                "chunk_sha256": chunk_sha256,
            }
        )
        return {"offset": offset + len(data)}

    monkeypatch.setattr(
        repository_routes,
        "create_repository_upload_session",
        fake_create,
    )
    monkeypatch.setattr(
        repository_routes,
        "append_repository_upload_chunk",
        fake_append,
    )
    monkeypatch.setattr(
        repository_routes,
        "finalize_repository_upload_session",
        lambda user_id, session_id: {
            "user_id": user_id,
            "session_id": session_id,
            "ready": True,
        },
    )

    with app.test_request_context(
        "/api/repository/upload/preview",
        method="POST",
        data={
            "files": (io.BytesIO(payload), "main.cpp"),
            "relative_paths": "src/main.cpp",
            "parent_id": "17",
            "expected_structure_version": "23",
        },
        content_type="multipart/form-data",
    ):
        result = repository_routes._multipart_upload_preview({"id": 7})

    manifest = captured["create"]["files"][0]
    assert manifest["relative_path"] == "src/main.cpp"
    assert manifest["size"] == len(payload)
    assert captured["create"]["parent_id"] == "17"
    assert captured["create"]["expected_structure_version"] == "23"
    assert b"".join(item["data"] for item in captured["chunks"]) == payload
    assert [item["offset"] for item in captured["chunks"]] == [0]
    assert {
        item["total_size"]
        for item in captured["chunks"]
    } == {len(payload)}
    assert result == {
        "user_id": 7,
        "session_id": "upload-session",
        "ready": True,
    }
