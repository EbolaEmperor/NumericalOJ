# -*- coding: utf-8 -*-

import zipfile

from oj_modules.routes import homework_routes


def _item(username, code, problem_id=1, submission_id=1):
    return {
        "user_id": submission_id,
        "username": username,
        "submission_id": submission_id,
        "problem_id": problem_id,
        "problem_title": f"题目 {problem_id}",
        "raw_code": code,
        "compare_code": code,
    }


def _fingerprint(label, content):
    return f"{label}:{homework_routes.hashlib.sha256(content).hexdigest()}"


def test_byte_plagiarism_requires_exact_raw_code():
    data = [
        _item("u1", "x = 1;\n", submission_id=1),
        _item("u2", "x = 1;\n", submission_id=2),
        _item("u3", "x=1;\n", submission_id=3),
    ]

    components = homework_routes._build_plagiarism_components(data, mode="byte", threshold=1)
    records = homework_routes._build_plagiarism_record_rows(
        components,
        "Ctest",
        "测试班级",
        "byte-identical",
    )

    assert [[item["username"] for item in comp] for comp in components] == [["u1", "u2"]]
    assert {record["username"] for record in records} == {"u1", "u2"}
    assert records[0]["comparison_rule"] == "byte-identical"


def test_byte_plagiarism_groups_by_raw_code_hash(monkeypatch):
    seen_hash_inputs = []
    real_sha256 = homework_routes.hashlib.sha256

    def recording_sha256(data):
        seen_hash_inputs.append(data)
        return real_sha256(data)

    def fail_similarity(_code1, _code2):
        raise AssertionError("byte-identical mode should not use similarity comparison")

    monkeypatch.setattr(homework_routes.hashlib, "sha256", recording_sha256)
    monkeypatch.setattr(homework_routes, "calculate_code_similarity", fail_similarity)

    data = [
        _item("u1", "x = 1;\n", submission_id=1),
        _item("u2", "x = 1;\n", submission_id=2),
        _item("u3", "", submission_id=3),
        _item("u4", "", submission_id=4),
    ]

    components = homework_routes._build_plagiarism_components(data, mode="byte", threshold=1)

    assert [[item["username"] for item in comp] for comp in components] == [["u1", "u2"]]
    assert seen_hash_inputs == [b"x = 1;\n", b"x = 1;\n"]


def test_threshold_plagiarism_uses_dsu_transitive_merge(monkeypatch):
    data = [
        _item("u1", "A", submission_id=1),
        _item("u2", "B", submission_id=2),
        _item("u3", "C", submission_id=3),
    ]
    scores = {
        frozenset(("A", "B")): 0.95,
        frozenset(("B", "C")): 0.95,
        frozenset(("A", "C")): 0.10,
    }

    def fake_similarity(code1, code2):
        return scores[frozenset((code1, code2))]

    monkeypatch.setattr(homework_routes, "calculate_code_similarity", fake_similarity)

    components = homework_routes._build_plagiarism_components(data, mode="threshold", threshold=0.9)
    records = homework_routes._build_plagiarism_record_rows(components, "Ctest", "测试班级", "0.90")

    assert len(components) == 1
    assert {item["username"] for item in components[0]} == {"u1", "u2", "u3"}
    assert len(records) == 3
    assert next(record for record in records if record["username"] == "u1")["matched_usernames"] == ["u2", "u3"]


def test_promptly_plagiarism_compares_prompt_text():
    data = [
        {
            **_item("u1", "use monotonic queue", submission_id=1),
            "compare_kind": "prompt",
            "material_label": "Prompt",
        },
        {
            **_item("u2", "use monotonic queue", submission_id=2),
            "raw_code": "use monotonic queue",
            "compare_code": "use monotonic queue",
            "compare_kind": "prompt",
            "material_label": "Prompt",
        },
    ]

    components = homework_routes._build_plagiarism_components(data, mode="byte", threshold=1)

    assert [[item["username"] for item in comp] for comp in components] == [["u1", "u2"]]


def test_tex_similarity_pairs_same_filename_only():
    data = [
        {
            **_item("u1", "", submission_id=1),
            "compare_kind": "tex_files",
            "compare_files": {
                "main.tex": r"\begin{document}A\end{document}",
                "appendix.tex": "unique left",
            },
        },
        {
            **_item("u2", "", submission_id=2),
            "compare_kind": "tex_files",
            "compare_files": {
                "main.tex": r"\begin{document}A\end{document}",
                "other.tex": "unique right",
            },
        },
    ]

    components = homework_routes._build_plagiarism_components(data, mode="threshold", threshold=0.99)

    assert [[item["username"] for item in comp] for comp in components] == [["u1", "u2"]]


def test_byte_plagiarism_supports_multiple_fingerprints_for_elo():
    shared_answer = _fingerprint("answer-zip", b"same-answer")
    data = [
        {
            **_item("u1", "", problem_id=-7, submission_id=10),
            "target_kind": "ranking",
            "target_key": "ranking:7",
            "byte_fingerprints": [shared_answer, _fingerprint("code-zip", b"code-a")],
        },
        {
            **_item("u2", "", problem_id=-7, submission_id=11),
            "target_kind": "ranking",
            "target_key": "ranking:7",
            "byte_fingerprints": [shared_answer, _fingerprint("code-zip", b"code-b")],
        },
        {
            **_item("u3", "", problem_id=-7, submission_id=12),
            "target_kind": "ranking",
            "target_key": "ranking:7",
            "byte_fingerprints": [_fingerprint("answer-zip", b"other-answer")],
        },
    ]

    components = homework_routes._build_plagiarism_components(data, mode="byte", threshold=1)

    assert [[item["username"] for item in comp] for comp in components] == [["u1", "u2"]]


def test_agent_judge_zip_content_fingerprint_ignores_entry_order(tmp_path):
    zip_a = tmp_path / "a.zip"
    zip_b = tmp_path / "b.zip"

    with zipfile.ZipFile(zip_a, "w") as zf:
        zf.writestr("main.py", "print(1)\n")
        zf.writestr("lib/helper.py", "x = 1\n")
    with zipfile.ZipFile(zip_b, "w") as zf:
        zf.writestr("lib/helper.py", "x = 1\n")
        zf.writestr("main.py", "print(1)\n")

    assert homework_routes._zip_content_sha256_fingerprint(str(zip_a), label="agent-files")
    assert (
        homework_routes._zip_content_sha256_fingerprint(str(zip_a), label="agent-files")
        == homework_routes._zip_content_sha256_fingerprint(str(zip_b), label="agent-files")
    )
