#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""无需认证的进程存活与依赖就绪探针。"""

from flask import Blueprint, jsonify


def create_health_blueprint(redis_client, db_connection_factory):
    """创建健康检查 Blueprint，并通过参数注入外部依赖以便独立测试。"""
    blueprint = Blueprint('health', __name__)

    @blueprint.get('/health/live')
    def live():
        return jsonify(status='ok')

    @blueprint.get('/health/ready')
    def ready():
        checks = {'mysql': False, 'redis': False}

        try:
            checks['redis'] = bool(redis_client.ping())
        except Exception:
            pass

        connection = None
        try:
            connection = db_connection_factory()
            with connection.cursor() as cursor:
                cursor.execute('SELECT 1')
                cursor.fetchone()
            checks['mysql'] = True
        except Exception:
            pass
        finally:
            if connection is not None:
                try:
                    connection.close()
                except Exception:
                    checks['mysql'] = False

        is_ready = all(checks.values())
        return jsonify(status='ok' if is_ready else 'unavailable', checks=checks), (200 if is_ready else 503)

    return blueprint
