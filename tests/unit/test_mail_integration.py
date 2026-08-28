from email import policy
from email.parser import Parser

import pytest

from oj_modules.integrations import mail


def test_plain_text_mail_uses_dynamic_smtp_settings(monkeypatch):
    calls = []

    class FakeSMTP:
        def __init__(self, host, port, timeout):
            calls.append(('connect', host, port, timeout))

        def __enter__(self):
            return self

        def __exit__(self, *_args):
            return None

        def login(self, username, password):
            calls.append(('login', username, password))

        def sendmail(self, sender, recipients, raw_message):
            calls.append(('sendmail', sender, recipients, raw_message))

    monkeypatch.setattr(mail.smtplib, 'SMTP_SSL', FakeSMTP)
    mail.send_plain_text_email(
        settings={
            'smtp_server': 'smtp.example.test',
            'smtp_port': 465,
            'smtp_username': 'mailer@example.test',
            'smtp_password': 'secret',
        },
        recipient='alice@example.com',
        subject='密码已重置',
        body='新密码：SafePass2026Abcd',
    )

    assert calls[:2] == [
        ('connect', 'smtp.example.test', 465, 20.0),
        ('login', 'mailer@example.test', 'secret'),
    ]
    _, sender, recipients, raw_message = calls[2]
    parsed = Parser(policy=policy.default).parsestr(raw_message)
    assert sender == 'mailer@example.test'
    assert recipients == ['alice@example.com']
    assert parsed['To'] == 'alice@example.com'
    assert parsed['Subject'] == '密码已重置'
    assert parsed.get_content().strip() == '新密码：SafePass2026Abcd'


def test_plain_text_mail_rejects_incomplete_settings():
    with pytest.raises(mail.MailDeliveryError, match='配置不完整'):
        mail.send_plain_text_email(
            settings={'smtp_server': 'smtp.example.test'},
            recipient='alice@example.com',
            subject='subject',
            body='body',
        )
