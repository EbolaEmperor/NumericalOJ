-- 为已上线的数据库补加性能索引（幂等：已存在则跳过）。
-- 用法：mysql -u root -p myojdb < fix-tools/add_perf_indexes.sql
--
-- 对应 myojdb.sql 中新增的索引：
--   submissions(problem_id, id)            —— 按题检索/重判，避免全表扫
--   submissions(status, problem_type, id)  —— 待批改书面作业（status='Pending' AND problem_type=2）
--   forum_replies(created_at)              —— 论坛按天统计的范围查询
--   forum_threads(created_at)

DELIMITER //
DROP PROCEDURE IF EXISTS _add_index_if_absent //
CREATE PROCEDURE _add_index_if_absent(IN tbl VARCHAR(64), IN idx VARCHAR(64), IN cols VARCHAR(255))
BEGIN
  IF NOT EXISTS (
    SELECT 1 FROM information_schema.statistics
    WHERE table_schema = DATABASE() AND table_name = tbl AND index_name = idx
  ) THEN
    SET @s = CONCAT('ALTER TABLE `', tbl, '` ADD INDEX `', idx, '` (', cols, ')');
    PREPARE st FROM @s; EXECUTE st; DEALLOCATE PREPARE st;
  END IF;
END //
DELIMITER ;

CALL _add_index_if_absent('submissions', 'idx_submissions_problem_id', 'problem_id, id');
CALL _add_index_if_absent('submissions', 'idx_submissions_status_type', 'status, problem_type, id');
CALL _add_index_if_absent('forum_replies', 'idx_forum_replies_created', 'created_at');
CALL _add_index_if_absent('forum_threads', 'idx_forum_threads_created', 'created_at');

DROP PROCEDURE IF EXISTS _add_index_if_absent;

-- 口令哈希从无盐 sha256(64位) 迁到带盐慢哈希(werkzeug，~100+ 字符)：列必须加宽，
-- 否则注册/改密/登录重哈希会因 "Data too long for column 'password_hash'" 失败。
-- MODIFY 幂等（重复执行无副作用）。
ALTER TABLE users MODIFY COLUMN password_hash VARCHAR(255) NOT NULL;
