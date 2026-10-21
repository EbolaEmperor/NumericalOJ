"""教学审计记录引用的版本必须保留物理快照。"""

# 仅供内部固定别名 v 的版本查询使用；软删除作业也保留历史证据。
EDU_VERSION_REFERENCED_SQL = """(
    EXISTS (SELECT 1 FROM vibehub_edu_assignments ea WHERE ea.version_id=v.id)
    OR EXISTS (SELECT 1 FROM vibehub_edu_attempts et WHERE et.version_id=v.id)
    OR EXISTS (SELECT 1 FROM vibehub_edu_submissions es WHERE es.version_id=v.id)
)"""
