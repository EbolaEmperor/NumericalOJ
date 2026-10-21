"""教学作品作业的只读成绩聚合。"""

from backend.oj_modules.infrastructure.mysql import safe_table_name


def edu_completion_counts(cursor, class_en):
    table_name = safe_table_name(class_en)
    cursor.execute(
        f"""
        SELECT h.id AS homework_id, COUNT(DISTINCT u.id) AS completed_count
        FROM `{table_name}` h
        JOIN user_class_map m ON m.class_en = %s
        JOIN users u ON u.id = m.user_id
        JOIN vibehub_edu_submissions es
          ON es.user_id = u.id AND es.assignment_id = h.vibehub_edu_assignment_id
         AND es.created_at <= COALESCE(h.ddl, es.created_at)
        WHERE h.vibehub_edu_assignment_id IS NOT NULL
          AND u.is_admin = 0 AND es.status = 'graded' AND es.score_bp >= 10000
        GROUP BY h.id
        """,
        (class_en,),
    )
    return {
        int(row['homework_id']): int(row.get('completed_count') or 0)
        for row in cursor.fetchall() or []
    }
