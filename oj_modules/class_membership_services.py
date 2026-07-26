#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""班级成员关系的事务边界。

``user_class_map`` 是用户班级关系的唯一事实源；每一条关系地位等价。
关系写入与 ``class_table.class_cnt`` 必须在同一个事务内变化。路由只负责
权限、输入与响应，不应分别提交这些表的写入。
"""

from contextlib import contextmanager

from oj_modules.db_services import get_db_connection


class MembershipNotFoundError(LookupError):
    """目标用户、班级或成员关系不存在。"""


class LastMembershipError(ValueError):
    """自助退出会让普通用户失去最后一个班级。"""


class MembershipConsistencyError(RuntimeError):
    """成员关系与班级人数计数不一致。"""


@contextmanager
def _transaction():
    conn = get_db_connection()
    try:
        with conn.cursor() as cursor:
            yield cursor
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


def _lock_user(cursor, user_id):
    cursor.execute(
        "SELECT id, is_admin FROM users WHERE id=%s FOR UPDATE",
        (user_id,),
    )
    return cursor.fetchone()


def _lock_required_user(cursor, user_id):
    user = _lock_user(cursor, user_id)
    if not user:
        raise MembershipNotFoundError("用户不存在")
    return user


def _raise_class_count_failure(
        cursor,
        class_en,
        *,
        missing_is_consistency=False,
):
    cursor.execute(
        "SELECT class_cnt FROM class_table WHERE class_en=%s FOR UPDATE",
        (class_en,),
    )
    row = cursor.fetchone()
    if not row:
        if missing_is_consistency:
            raise MembershipConsistencyError(
                f"班级 {class_en} 的成员关系缺少对应班级"
            )
        raise MembershipNotFoundError("班级不存在")
    raise MembershipConsistencyError(
        f"班级 {class_en} 的人数计数与成员关系不一致"
    )


def _decrement_class_count(cursor, class_en):
    cursor.execute(
        "UPDATE class_table "
        "SET class_cnt = class_cnt - 1 "
        "WHERE class_en=%s AND class_cnt > 0",
        (class_en,),
    )
    if cursor.rowcount != 1:
        _raise_class_count_failure(
            cursor,
            class_en,
            missing_is_consistency=True,
        )


def _increment_class_count(cursor, class_en):
    cursor.execute(
        "UPDATE class_table SET class_cnt = class_cnt + 1 WHERE class_en=%s",
        (class_en,),
    )
    if cursor.rowcount != 1:
        _raise_class_count_failure(cursor, class_en)


def add_class_membership(user_id, class_en):
    """添加班级关系，返回是否实际新增。

    重复添加是幂等操作，不会重复增加 ``class_cnt``。
    """
    with _transaction() as cursor:
        _lock_required_user(cursor, user_id)
        cursor.execute(
            """
            SELECT 1
            FROM user_class_map
            WHERE user_id=%s AND class_en=%s
            FOR UPDATE
            """,
            (user_id, class_en),
        )
        added = not cursor.fetchone()
        if added:
            cursor.execute(
                """
                INSERT INTO user_class_map (user_id, class_en)
                VALUES (%s, %s)
                """,
                (user_id, class_en),
            )
            _increment_class_count(cursor, class_en)
        return added


def _remove_class_membership(
        user_id,
        class_en,
        *,
        missing_ok,
):
    with _transaction() as cursor:
        user = _lock_user(cursor, user_id)
        if not user:
            if missing_ok:
                return False
            raise MembershipNotFoundError("用户不存在")

        cursor.execute(
            """
            SELECT 1
            FROM user_class_map
            WHERE user_id=%s AND class_en=%s
            FOR UPDATE
            """,
            (user_id, class_en),
        )
        membership = cursor.fetchone()
        if not membership:
            if missing_ok:
                return False
            raise MembershipNotFoundError("班级成员关系不存在")

        # 角色与成员关系在同一事务、同一 users 行锁下判定，避免权限变更
        # 与最后一条成员关系删除之间出现 TOCTOU 窗口。
        if int(user.get("is_admin") or 0) != 1:
            # 所有成员写操作都先锁同一 users 行，因此这次计数与随后的 DELETE
            # 在服务边界内不会和该用户的 join/leave 并发交错。
            cursor.execute(
                "SELECT COUNT(*) AS membership_count "
                "FROM user_class_map WHERE user_id=%s",
                (user_id,),
            )
            count_row = cursor.fetchone() or {}
            if int(count_row.get("membership_count") or 0) <= 1:
                raise LastMembershipError("至少需要保留一个班级")

        cursor.execute(
            "DELETE FROM user_class_map WHERE user_id=%s AND class_en=%s",
            (user_id, class_en),
        )
        if cursor.rowcount != 1:
            raise MembershipNotFoundError("班级成员关系不存在")
        _decrement_class_count(cursor, class_en)
        return True


def remove_class_membership(user_id, class_en):
    """移除班级关系，返回是否实际删除。

    普通用户必须保留至少一条关系，管理员允许没有具体班级；角色判断与删除
    在同一事务内完成。缺失用户或关系作为幂等无变化返回 ``False``。
    """
    return _remove_class_membership(
        user_id,
        class_en,
        missing_ok=True,
    )


def leave_class_membership(user_id, class_en):
    """用户退出班级。

    普通用户拒绝退出最后一个班级；管理员允许没有具体班级归属。角色判断
    与删除在同一事务内完成。
    """
    return _remove_class_membership(
        user_id,
        class_en,
        missing_ok=False,
    )
