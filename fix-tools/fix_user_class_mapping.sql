-- 数据修复 SQL 脚本
-- 用于修复 user_class_map 表中缺失的记录

-- 开始事务（安全起见）
START TRANSACTION;

-- 为所有在 users 表中有班级信息但在 user_class_map 中缺失记录的用户
-- 创建主班级映射记录
INSERT INTO user_class_map (user_id, class_en, is_primary)
SELECT 
    u.id,
    u.class,
    1 as is_primary
FROM users u
LEFT JOIN user_class_map m ON u.id = m.user_id AND u.class = m.class_en
INNER JOIN class_table c ON u.class = c.class_en  -- 确保班级存在
WHERE u.class IS NOT NULL 
  AND u.class != '' 
  AND u.class != 'Cadmin'
  AND m.user_id IS NULL;

-- 显示修复结果统计
SELECT 
    '修复后统计' as 信息,
    '总用户数（有班级）' as 类型,
    COUNT(*) as 数量
FROM users 
WHERE class IS NOT NULL 
  AND class != '' 
  AND class != 'Cadmin'
UNION ALL
SELECT 
    '修复后统计' as 信息,
    'user_class_map记录数' as 类型,
    COUNT(*) as 数量
FROM user_class_map
UNION ALL
SELECT 
    '修复后统计' as 信息,
    '主班级记录数' as 类型,
    COUNT(*) as 数量
FROM user_class_map 
WHERE is_primary = 1;

-- 提交事务
-- 注意：如果您想先检查结果，可以使用 ROLLBACK; 来回滚
-- 如果确认无误，请手动执行 COMMIT; 来提交更改
-- COMMIT;
