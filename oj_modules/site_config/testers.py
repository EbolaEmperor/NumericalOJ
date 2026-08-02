#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""站点动态配置的真实、最小、无外部写入测试适配器。"""

from __future__ import annotations

import smtplib
import time
from email.message import EmailMessage

import httpx


def test_llm_endpoint(candidate, *, timeout_seconds=30):
    from oj_modules.ai.endpoints import test_endpoint_candidate

    return test_endpoint_candidate(candidate, timeout=timeout_seconds)


def test_mail_settings(candidate, *, timeout_seconds=20):
    started = time.monotonic()
    try:
        with smtplib.SMTP_SSL(
            candidate["smtp_server"],
            int(candidate["smtp_port"]),
            timeout=float(timeout_seconds),
        ) as server:
            server.login(candidate["smtp_username"], candidate["smtp_password"])
            message = EmailMessage()
            message["Subject"] = "NumericalOJ 邮件配置测试"
            message["From"] = candidate["smtp_username"]
            message["To"] = candidate["recipient_email"]
            message.set_content(
                "这是一封由 NumericalOJ 站点配置页发送的测试邮件。"
                "若您收到此邮件，说明当前 SMTP 配置可用。"
            )
            server.send_message(message)
    except Exception:
        return {
            "passed": False,
            "message": "无法使用当前配置登录 SMTP 服务器。",
            "latency_ms": max(0, int((time.monotonic() - started) * 1000)),
        }
    return {
        "passed": True,
        "message": "测试邮件已发送到当前管理员邮箱。",
        "latency_ms": max(0, int((time.monotonic() - started) * 1000)),
    }


def _mcp_response_has_error(response):
    try:
        payload = response.json()
    except Exception:
        text = str(getattr(response, "text", "") or "").lower()
        return '"error"' in text and '"result"' not in text
    return isinstance(payload, dict) and bool(payload.get("error"))


def test_web_search_settings(candidate, *, timeout_seconds=20):
    """用 MCP initialize 探测 URL 和 Authorization，不调用搜索工具。"""
    started = time.monotonic()
    headers = {
        "Authorization": candidate["authorization"],
        "Content-Type": "application/json",
        "Accept": "application/json, text/event-stream",
    }
    payload = {
        "jsonrpc": "2.0",
        "id": 1,
        "method": "initialize",
        "params": {
            "protocolVersion": "2024-11-05",
            "capabilities": {},
            "clientInfo": {"name": "numericaloj-config-probe", "version": "1.0.0"},
        },
    }
    try:
        with httpx.Client(
            timeout=float(timeout_seconds),
            follow_redirects=False,
        ) as client:
            response = client.post(candidate["base_url"], headers=headers, json=payload)
        if int(response.status_code) < 200 or int(response.status_code) >= 300:
            raise RuntimeError("MCP HTTP 状态异常")
        if _mcp_response_has_error(response):
            raise RuntimeError("MCP 返回协议错误")
    except Exception:
        return {
            "passed": False,
            "message": "无法使用当前配置初始化 WebSearch MCP。",
            "latency_ms": max(0, int((time.monotonic() - started) * 1000)),
        }
    return {
        "passed": True,
        "message": "WebSearch MCP 连接测试成功。",
        "latency_ms": max(0, int((time.monotonic() - started) * 1000)),
    }


__all__ = [
    "test_llm_endpoint",
    "test_mail_settings",
    "test_web_search_settings",
]
