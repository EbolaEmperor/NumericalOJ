-- 数据一致性检查 SQL 脚本
-- 用于检查 user_class_map 表记录比 users 表少的问题

-- 1. 统计 users 表中的用户数（排除管理员和无班级信息的用户）
SELECT 'users表中有班级信息的用户数' as 检查项, COUNT(*) as 数量
FROM users 
WHERE class IS NOT NULL 
  AND class != '' 
  AND class != 'Cadmin';

-- 2. 统计 user_class_map 表中的记录数
SELECT 'user_class_map表中的记录数' as 检查项, COUNT(*) as 数量
FROM user_class_map;

-- 3. 统计主班级记录数
SELECT 'user_class_map表中主班级记录数' as 检查项, COUNT(*) as 数量
FROM user_class_map 
WHERE is_primary = 1;

-- 4. 查找缺失映射的用户（在 users 表中有班级信息，但在 user_class_map 中没有对应记录）
SELECT 
    '缺失映射的用户' as 检查项,
    u.id as 用户ID,
    u.username as 用户名,
    u.class as 班级代码,
    u.class_cn as 班级名称,
    u.email as 邮箱
FROM users u
LEFT JOIN user_class_map m ON u.id = m.user_id AND u.class = m.class_en
WHERE u.class IS NOT NULL 
  AND u.class != '' 
  AND u.class != 'Cadmin'
  AND m.user_id IS NULL
ORDER BY u.id;

-- 5. 查找班级不存在的用户（用户的班级在 class_table 中不存在）
SELECT 
    '班级不存在的用户' as 检查项,
    u.id as 用户ID,
    u.username as 用户名,
    u.class as 班级代码,
    '该班级在class_table中不存在' as 问题描述
FROM users u
LEFT JOIN class_table c ON u.class = c.class_en
WHERE u.class IS NOT NULL 
  AND u.class != '' 
  AND u.class != 'Cadmin'
  AND c.class_en IS NULL
ORDER BY u.id;

-- 6. 检查重复的主班级记录（一个用户不应该有多个主班级）
SELECT 
    '有多个主班级的用户' as 检查项,
    user_id as 用户ID,
    COUNT(*) as 主班级数量,
    GROUP_CONCAT(class_en) as 班级列表
FROM user_class_map 
WHERE is_primary = 1
GROUP BY user_id
HAVING COUNT(*) > 1;

-- 7. 生成修复 SQL（为缺失映射的用户添加主班级记录）
-- 注意：这个查询生成修复用的 INSERT 语句，但不会执行
SELECT CONCAT(
    'INSERT INTO user_class_map (user_id, class_en, is_primary) VALUES (',
    u.id, ', ''', u.class, ''', 1);'
) as 修复SQL语句
FROM users u
LEFT JOIN user_class_map m ON u.id = m.user_id AND u.class = m.class_en
LEFT JOIN class_table c ON u.class = c.class_en  -- 确保班级存在
WHERE u.class IS NOT NULL 
  AND u.class != '' 
  AND u.class != 'Cadmin'
  AND m.user_id IS NULL
  AND c.class_en IS NOT NULL  -- 只为有效班级生成修复语句
ORDER BY u.id;
