from oj_modules.classroom.logos import (
    backfill_missing_class_logo_seeds,
    is_valid_class_logo_seed,
)
from oj_modules.infrastructure.mysql import get_db_connection


def _class_logo_seeds():
    conn = get_db_connection()
    try:
        with conn.cursor() as cursor:
            cursor.execute(
                "SELECT class_en, logo_seed FROM class_table ORDER BY class_en"
            )
            return {
                row["class_en"]: row.get("logo_seed")
                for row in cursor.fetchall() or []
            }
    finally:
        conn.close()


def test_class_logo_backfill_is_complete_idempotent_and_preserves_existing_seed():
    preserved_seed = "0123456789abcdef0123456789abcdef"
    conn = get_db_connection()
    try:
        with conn.cursor() as cursor:
            cursor.execute("UPDATE class_table SET logo_seed=NULL")
            cursor.execute(
                "UPDATE class_table SET logo_seed=%s WHERE class_en='Cclass1'",
                (preserved_seed,),
            )
        conn.commit()
    finally:
        conn.close()

    first_count = backfill_missing_class_logo_seeds()
    first = _class_logo_seeds()
    second_count = backfill_missing_class_logo_seeds()
    second = _class_logo_seeds()

    assert first_count == len(first) - 1
    assert first["Cclass1"] == preserved_seed
    assert all(is_valid_class_logo_seed(seed) for seed in first.values())
    assert second_count == 0
    assert second == first
