"""AI Vote 复制来源的只读查询，保留原始配置供严格校验。"""

from backend.oj_modules.infrastructure.mysql import get_db_connection


def list_written_vote_copy_sources():
    """只读取复制所需字段；损坏的显式配置不能降级为空配置。"""

    connection = get_db_connection()
    try:
        with connection.cursor() as cursor:
            cursor.execute(
                "SELECT id,title,type,written_grading_mode,written_vote_config,"
                "llm_endpoint_bindings FROM problems "
                "WHERE type=2 AND COALESCE(written_grading_mode,1) IN (1,2,3) "
                "ORDER BY id ASC"
            )
            return cursor.fetchall()
    finally:
        connection.close()


__all__ = ["list_written_vote_copy_sources"]
