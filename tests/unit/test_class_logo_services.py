from oj_modules import class_logo_services


class _Cursor:
    def __init__(self, rows):
        self.rows = rows
        self.executions = []
        self.rowcount = 0

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_value, traceback):
        return False

    def execute(self, sql, params=None):
        normalized = " ".join(sql.split())
        self.executions.append((normalized, params))
        self.rowcount = 1 if normalized.startswith("UPDATE class_table") else 0

    def fetchall(self):
        return self.rows


class _Connection:
    def __init__(self, cursor):
        self.cursor_instance = cursor
        self.committed = False
        self.rolled_back = False
        self.closed = False

    def cursor(self):
        return self.cursor_instance

    def commit(self):
        self.committed = True

    def rollback(self):
        self.rolled_back = True

    def close(self):
        self.closed = True


def test_generated_seed_is_valid_128_bit_hex():
    seed = class_logo_services.generate_class_logo_seed()

    assert len(seed) == 32
    assert class_logo_services.is_valid_class_logo_seed(seed)


def test_logo_presentation_is_stable_symmetric_and_matches_reference_algorithm():
    seed = "00112233445566778899aabbccddeeff"

    first = class_logo_services.class_logo_presentation(seed)
    second = class_logo_services.class_logo_presentation(seed)

    assert first == second
    cells = set(first["cells"])
    assert cells == {
        (1, 0), (2, 0), (3, 0),
        (2, 1),
        (0, 2), (4, 2),
        (0, 3), (1, 3), (3, 3), (4, 3),
        (1, 4), (2, 4), (3, 4),
    }
    assert all(
        (class_logo_services.IDENTICON_GRID_SIZE - 1 - column, row) in cells
        for column, row in cells
    )


def test_missing_seed_has_stable_read_only_fallback_and_is_not_exposed():
    rows = [{
        "class_en": "C2026",
        "class_cn": "超长班级名称",
        "logo_seed": None,
        "is_primary": 1,
    }]

    first = class_logo_services.attach_class_logos(rows)
    second = class_logo_services.attach_class_logos(rows)

    assert first == second
    assert "logo_seed" not in first[0]
    assert first[0]["logo"]["cells"]
    assert "logo" not in rows[0]


def test_backfill_only_updates_missing_rows_and_commits(monkeypatch):
    cursor = _Cursor([{"class_en": "C1"}, {"class_en": "C2"}])
    connection = _Connection(cursor)
    seeds = iter((
        "11111111111111111111111111111111",
        "22222222222222222222222222222222",
    ))
    monkeypatch.setattr(
        class_logo_services,
        "get_db_connection",
        lambda: connection,
    )
    monkeypatch.setattr(
        class_logo_services,
        "generate_class_logo_seed",
        lambda: next(seeds),
    )

    assert class_logo_services.backfill_missing_class_logo_seeds() == 2
    updates = [
        params
        for sql, params in cursor.executions
        if sql.startswith("UPDATE class_table")
    ]
    assert updates == [
        ("11111111111111111111111111111111", "C1"),
        ("22222222222222222222222222222222", "C2"),
    ]
    assert connection.committed is True
    assert connection.rolled_back is False
    assert connection.closed is True


def test_admin_class_creation_persists_generated_logo_seed(monkeypatch):
    from flask import Flask

    from oj_modules.routes import admin_user_routes

    cursor = _Cursor([])
    connection = _Connection(cursor)
    seed = "abcdefabcdefabcdefabcdefabcdefab"
    monkeypatch.setattr(
        admin_user_routes,
        "current_user",
        lambda: {"id": 1, "is_admin": 1},
    )
    monkeypatch.setattr(admin_user_routes, "is_admin", lambda _user: True)
    monkeypatch.setattr(admin_user_routes, "get_class_by_en", lambda _value: None)
    monkeypatch.setattr(admin_user_routes, "get_class_by_cn", lambda _value: None)
    monkeypatch.setattr(
        admin_user_routes,
        "generate_class_logo_seed",
        lambda: seed,
    )
    monkeypatch.setattr(
        admin_user_routes,
        "get_db_connection",
        lambda: connection,
    )
    app = Flask(__name__)
    app.secret_key = "test"

    with app.test_request_context(
        "/admin/add_class_ajax",
        method="POST",
        data={"class_en": "long_name", "class_cn": "很长的班级名称"},
    ):
        response = admin_user_routes.add_class_ajax()

    insert_params = next(
        params
        for sql, params in cursor.executions
        if sql.startswith("INSERT INTO class_table")
    )
    assert insert_params == (
        "Clong_name",
        "很长的班级名称",
        seed,
    )
    assert response.get_json()["success"] is True
