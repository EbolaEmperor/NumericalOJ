"""基于全站动态 SMTP 配置的邮件发送原语。"""

import logging
import smtplib
from email.mime.text import MIMEText


logger = logging.getLogger(__name__)


class MailDeliveryError(RuntimeError):
    """邮件无法投递。异常消息只包含可公开给管理员的原因。"""


def send_plain_text_email(*, settings, recipient, subject, body, timeout_seconds=20):
    """使用已解析的动态配置发送纯文本邮件。

    调用方负责读取动态配置，便于在需要数据库事务的流程中避免嵌套读取。
    """
    if not settings:
        raise MailDeliveryError("站点尚未配置邮件服务")

    required = ("smtp_server", "smtp_port", "smtp_username", "smtp_password")
    if any(not settings.get(field) for field in required):
        raise MailDeliveryError("邮件服务配置不完整")

    message = MIMEText(str(body), "plain", "utf-8")
    message["Subject"] = str(subject)
    message["From"] = str(settings["smtp_username"])
    message["To"] = str(recipient)

    try:
        with smtplib.SMTP_SSL(
            settings["smtp_server"],
            int(settings["smtp_port"]),
            timeout=float(timeout_seconds),
        ) as server:
            server.login(settings["smtp_username"], settings["smtp_password"])
            server.sendmail(
                settings["smtp_username"],
                [recipient],
                message.as_string(),
            )
    except Exception as exc:
        logger.exception("邮件发送失败")
        raise MailDeliveryError("邮件发送失败，请检查邮件服务配置后重试") from exc


__all__ = ["MailDeliveryError", "send_plain_text_email"]
