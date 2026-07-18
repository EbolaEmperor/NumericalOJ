#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""班级成员关系的事务用例。

``users`` 的主班级快照、``user_class_map`` 的成员关系与
``class_table.class_cnt`` 必须在同一个事务内变化。路由只负责权限、输入与响应，
不应分别提交这些表的写入。
"""

from contextlib import contextmanager

from oj_modules.db_services import get_db_connection


class MembershipNotFoundError(LookupError):
    """目标用户或成员关系不存在。"""


class PrimaryMembershipError(ValueError):
    """试图直接移除主班级成员关系。"""


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
    cursor.execute("SELECT id FROM users WHERE id=%s FOR UPDATE", (user_id,))
    return bool(cursor.fetchone())


def _lock_required_user(cursor, user_id):
    if not _lock_user(cursor, user_id):
        raise MembershipNotFoundError("用户不存在")


def _decrement_class_count(cursor, class_en):
    cursor.execute(
        "UPDATE class_table "
        "SET class_cnt = class_cnt - 1 "
        "WHERE class_en=%s AND class_cnt > 0",
        (class_en,),
    )
    if cursor.rowcount != 1:
        raise MembershipNotFoundError("班级不存在或班级人数计数异常")


def _increment_class_count(cursor, class_en):
    cursor.execute(
        "UPDATE class_table SET class_cnt = class_cnt + 1 WHERE class_en=%s",
        (class_en,),
    )
    if cursor.rowcount != 1:
        raise MembershipNotFoundError("班级不存在")


def add_class_membership(user_id, class_en):
    """添加附加班级，返回是否实际新增。

    重复添加是幂等操作，且不会改写已有关系的 ``is_primary``。
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
                INSERT INTO user_class_map (user_id, class_en, is_primary)
                VALUES (%s, %s, 0)
                """,
                (user_id, class_en),
            )
            _increment_class_count(cursor, class_en)
        return added


def remove_secondary_membership(user_id, class_en):
    """移除附加班级，返回是否实际删除；主班级必须走主班级变更流程。"""
    with _transaction() as cursor:
        removed = False
        if _lock_user(cursor, user_id):
            cursor.execute(
                """
                SELECT is_primary
                FROM user_class_map
                WHERE user_id=%s AND class_en=%s
                FOR UPDATE
                """,
                (user_id, class_en),
            )
            membership = cursor.fetchone()
            if membership and membership['is_primary'] == 1:
                raise PrimaryMembershipError("不能移除主班级")

            if membership:
                cursor.execute(
                    "DELETE FROM user_class_map WHERE user_id=%s AND class_en=%s",
                    (user_id, class_en),
                )
                removed = cursor.rowcount == 1
                if removed:
                    _decrement_class_count(cursor, class_en)
        return removed


def leave_class_membership(
        user_id,
        class_en,
        *,
        replacement_class_en=None,
        replacement_class_cn=None,
):
    """退出班级；退出主班级时同时切换主班级快照与映射。"""
    with _transaction() as cursor:
        _lock_required_user(cursor, user_id)
        cursor.execute(
            """
            SELECT is_primary
            FROM user_class_map
            WHERE user_id=%s AND class_en=%s
            FOR UPDATE
            """,
            (user_id, class_en),
        )
        membership = cursor.fetchone()
        if not membership:
            raise MembershipNotFoundError("班级成员关系不存在")

        if membership['is_primary'] == 1:
            if not replacement_class_en or replacement_class_cn is None:
                raise PrimaryMembershipError("退出主班级前必须指定新的主班级")
            if replacement_class_en == class_en:
                raise PrimaryMembershipError("新的主班级不能是正在退出的班级")
            cursor.execute(
                """
                SELECT class_en
                FROM user_class_map
                WHERE user_id=%s AND class_en=%s
                FOR UPDATE
                """,
                (user_id, replacement_class_en),
            )
            if not cursor.fetchone():
                raise MembershipNotFoundError("新的主班级成员关系不存在")

            cursor.execute(
                "UPDATE users SET class=%s, class_cn=%s WHERE id=%s",
                (replacement_class_en, replacement_class_cn, user_id),
            )
            cursor.execute(
                "UPDATE user_class_map SET is_primary=0 WHERE user_id=%s",
                (user_id,),
            )
            cursor.execute(
                """
                UPDATE user_class_map
                SET is_primary=1
                WHERE user_id=%s AND class_en=%s
                """,
                (user_id, replacement_class_en),
            )

        cursor.execute(
            "DELETE FROM user_class_map WHERE user_id=%s AND class_en=%s",
            (user_id, class_en),
        )
        if cursor.rowcount != 1:
            raise MembershipNotFoundError("班级成员关系不存在")
        _decrement_class_count(cursor, class_en)


def set_primary_membership(
        user_id,
        class_en,
        class_cn,
        is_admin,
        *,
        create_if_missing=False,
):
    """把成员关系设为主班级，并同步 ``users`` 快照。

    普通用户只能把已有的附加班级设为主班级；管理员编辑用户时可以通过
    ``create_if_missing`` 原子地补建目标关系。主班级切换不会删除原班级关系，
    因而只有实际补建关系时才增加 ``class_cnt``，不能按主班级快照的变化增减
    人数。

    返回目标成员关系是否由本次事务创建。
    """
    with _transaction() as cursor:
        _lock_required_user(cursor, user_id)
        cursor.execute(
            """
            SELECT class_en
            FROM user_class_map
            WHERE user_id=%s AND class_en=%s
            FOR UPDATE
            """,
            (user_id, class_en),
        )
        membership_added = not cursor.fetchone()
        if membership_added:
            if not create_if_missing:
                raise MembershipNotFoundError("目标班级成员关系不存在")
            cursor.execute(
                """
                INSERT INTO user_class_map (user_id, class_en, is_primary)
                VALUES (%s, %s, 0)
                """,
                (user_id, class_en),
            )
            _increment_class_count(cursor, class_en)

        cursor.execute(
            "UPDATE users SET class=%s, class_cn=%s, is_admin=%s WHERE id=%s",
            (class_en, class_cn, is_admin, user_id),
        )
        cursor.execute(
            "UPDATE user_class_map SET is_primary=0 WHERE user_id=%s",
            (user_id,),
        )
        cursor.execute(
            """
            UPDATE user_class_map
            SET is_primary=1
            WHERE user_id=%s AND class_en=%s
            """,
            (user_id, class_en),
        )
        if cursor.rowcount != 1:
            raise MembershipNotFoundError("目标班级成员关系不存在")
        return membership_added
