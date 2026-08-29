from oj_modules import db_services
from oj_modules.site_config import services


class _MailCursor:
    def __init__(self, row):
        self.row = row

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_value, traceback):
        return None

    def execute(self, sql):
        assert "site_mail_settings" in sql

    def fetchone(self):
        return dict(self.row) if self.row else None


class _MailConnection:
    def __init__(self, row):
        self.row = row
        self.closed = False

    def cursor(self):
        return _MailCursor(self.row)

    def close(self):
        self.closed = True


def test_class_adjust_flag_cache_reuses_loader_and_can_be_invalidated(monkeypatch):
    calls = []
    monkeypatch.setattr(db_services, "_class_adjust_cache", None)
    monkeypatch.setattr(
        db_services,
        "get_setting",
        lambda key, default=None: calls.append((key, default)) or "1",
    )

    assert db_services.is_class_adjust_enabled() is True
    assert db_services.is_class_adjust_enabled() is True
    assert len(calls) == 1

    db_services._invalidate_class_adjust_cache()
    assert db_services.is_class_adjust_enabled() is True
    assert len(calls) == 2


def test_mail_settings_cache_reuses_raw_row_without_leaking_secret(monkeypatch):
    row = {
        "id": 1,
        "smtp_server": "smtp.example.test",
        "smtp_port": 465,
        "smtp_username": "mailer@example.test",
        "smtp_password": "mail-secret",
    }
    connections = []

    def connect():
        connection = _MailConnection(row)
        connections.append(connection)
        return connection

    monkeypatch.setattr(services, "_mail_settings_cache", None)
    monkeypatch.setattr(services, "get_db_connection", connect)

    public = services.get_mail_settings()
    internal = services.get_mail_settings(include_secret=True)

    assert len(connections) == 1
    assert connections[0].closed is True
    assert public["smtp_password"] == ""
    assert public["smtp_password_configured"] is True
    assert internal["smtp_password"] == "mail-secret"

    services._invalidate_mail_settings_cache()
    services.get_mail_settings()
    assert len(connections) == 2
