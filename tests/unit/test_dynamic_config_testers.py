# -*- coding: utf-8 -*-

from oj_modules.site_config import testers


def test_mail_tester_sends_message_to_current_admin(monkeypatch):
    events = []

    class FakeSMTP:
        def __init__(self, server, port, timeout):
            events.append(("connect", server, port, timeout))

        def __enter__(self):
            return self

        def __exit__(self, *_args):
            return None

        def login(self, username, password):
            events.append(("login", username, password))

        def send_message(self, message):
            events.append(("send", message["To"], message["Subject"]))

    monkeypatch.setattr(testers.smtplib, "SMTP_SSL", FakeSMTP)

    result = testers.test_mail_settings({
        "smtp_server": "smtp.example.test",
        "smtp_port": 465,
        "smtp_username": "mailer@example.test",
        "smtp_password": "secret",
        "recipient_email": "admin@example.test",
    })

    assert result["passed"] is True
    assert events[-1] == (
        "send",
        "admin@example.test",
        "NumericalOJ 邮件配置测试",
    )


def test_web_search_tester_only_initializes_mcp(monkeypatch):
    calls = []

    class Response:
        status_code = 200
        text = '{"jsonrpc":"2.0","id":1,"result":{}}'

        def json(self):
            return {"jsonrpc": "2.0", "id": 1, "result": {}}

    class Client:
        def __init__(self, **kwargs):
            calls.append(("client", kwargs))

        def __enter__(self):
            return self

        def __exit__(self, *_args):
            return None

        def post(self, url, **kwargs):
            calls.append(("post", url, kwargs))
            return Response()

    monkeypatch.setattr(testers.httpx, "Client", Client)

    result = testers.test_web_search_settings({
        "base_url": "https://search.example.test/mcp",
        "authorization": "Bearer secret",
    })

    assert result["passed"] is True
    _, _url, kwargs = calls[-1]
    assert kwargs["json"]["method"] == "initialize"
    assert "tools/call" not in str(kwargs["json"])
