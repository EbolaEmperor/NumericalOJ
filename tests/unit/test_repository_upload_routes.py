import io

from flask import Flask

from oj_modules.routes import repository_routes


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
