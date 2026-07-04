-- =====================================================
-- NumericalOJ 数据库初始化脚本
-- =====================================================
-- 
-- 这个脚本包含了 NumericalOJ 系统的完整数据库结构
-- 导入后可以直接使用系统，包含以下功能：
-- 
-- 1. 用户管理（支持多班级系统）
-- 2. 题目管理（编程题和书面作业）
-- 3. 提交评测系统
-- 4. 提交次数限制（每用户每题最多5次）
-- 5. 讨论区功能
-- 6. 成绩管理
-- 
-- 默认管理员账号：
-- 用户名: admin
-- 密码: admin123
-- 邮箱: admin@example.com
-- 
-- =====================================================

-- MySQL dump 10.13  Distrib 8.4.4, for Linux (x86_64)
--
-- Host: localhost    Database: myojdb
-- ------------------------------------------------------
-- Server version	8.4.4

/*!40101 SET @OLD_CHARACTER_SET_CLIENT=@@CHARACTER_SET_CLIENT */;
/*!40101 SET @OLD_CHARACTER_SET_RESULTS=@@CHARACTER_SET_RESULTS */;
/*!40101 SET @OLD_COLLATION_CONNECTION=@@COLLATION_CONNECTION */;
/*!50503 SET NAMES utf8mb4 */;
/*!40103 SET @OLD_TIME_ZONE=@@TIME_ZONE */;
/*!40103 SET TIME_ZONE='+00:00' */;
/*!40014 SET @OLD_UNIQUE_CHECKS=@@UNIQUE_CHECKS, UNIQUE_CHECKS=0 */;
/*!40014 SET @OLD_FOREIGN_KEY_CHECKS=@@FOREIGN_KEY_CHECKS, FOREIGN_KEY_CHECKS=0 */;
/*!40101 SET @OLD_SQL_MODE=@@SQL_MODE, SQL_MODE='NO_AUTO_VALUE_ON_ZERO' */;
/*!40111 SET @OLD_SQL_NOTES=@@SQL_NOTES, SQL_NOTES=0 */;


--
-- Table structure for table `ac_record`
--

DROP TABLE IF EXISTS `ac_record`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `ac_record` (
  `userid` int NOT NULL,
  `problem_id` int NOT NULL,
  `is_ac` tinyint(1) NOT NULL DEFAULT '1',
  `updated_at` datetime NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  PRIMARY KEY (`userid`,`problem_id`),
  KEY `idx_ac_record_problem_user` (`problem_id`,`userid`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `class_table`
--

DROP TABLE IF EXISTS `class_table`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `class_table` (
  `class_en` varchar(255) NOT NULL,
  `class_cn` varchar(255) DEFAULT NULL,
  `class_cnt` int DEFAULT '0',
  PRIMARY KEY (`class_en`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `final_exam_scores`
--

DROP TABLE IF EXISTS `final_exam_scores`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `final_exam_scores` (
  `id` int NOT NULL AUTO_INCREMENT,
  `class_en` varchar(32) DEFAULT NULL,
  `student_id` varchar(64) DEFAULT NULL,
  `regular_score` float DEFAULT NULL,
  `final_score` float DEFAULT NULL,
  PRIMARY KEY (`id`),
  UNIQUE KEY `uniq_class_student` (`class_en`,`student_id`)
) ENGINE=InnoDB AUTO_INCREMENT=177 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;
/*!40101 SET character_set_client = @saved_cs_client */;
ALTER TABLE final_exam_scores ADD INDEX idx_final_exam_student_class (student_id, class_en);

--
-- Table structure for table `forum_replies`
--

DROP TABLE IF EXISTS `forum_replies`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `forum_replies` (
  `id` int NOT NULL AUTO_INCREMENT,
  `thread_id` int NOT NULL,
  `content` text NOT NULL,
  `created_at` datetime DEFAULT CURRENT_TIMESTAMP,
  `user_id` int NOT NULL,
  PRIMARY KEY (`id`),
  KEY `user_id` (`user_id`),
  KEY `thread_id` (`thread_id`),
  CONSTRAINT `forum_replies_ibfk_1` FOREIGN KEY (`user_id`) REFERENCES `users` (`id`),
  CONSTRAINT `forum_replies_ibfk_2` FOREIGN KEY (`thread_id`) REFERENCES `forum_threads` (`id`)
) ENGINE=InnoDB AUTO_INCREMENT=23 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `forum_threads`
--

DROP TABLE IF EXISTS `forum_threads`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `forum_threads` (
  `id` int NOT NULL AUTO_INCREMENT,
  `title` varchar(255) NOT NULL,
  `content` text NOT NULL,
  `created_at` datetime DEFAULT CURRENT_TIMESTAMP,
  `updated_at` datetime DEFAULT CURRENT_TIMESTAMP,
  `user_id` int NOT NULL,
  PRIMARY KEY (`id`),
  KEY `user_id` (`user_id`),
  CONSTRAINT `forum_threads_ibfk_1` FOREIGN KEY (`user_id`) REFERENCES `users` (`id`)
) ENGINE=InnoDB AUTO_INCREMENT=8 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `max_score`
--

DROP TABLE IF EXISTS `max_score`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `max_score` (
  `userid` int NOT NULL,
  `problem_id` int NOT NULL,
  `score` int NOT NULL,
  `updated_at` datetime NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  PRIMARY KEY (`userid`,`problem_id`),
  KEY `idx_max_score_problem_user` (`problem_id`,`userid`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `problems`
--

DROP TABLE IF EXISTS `problems`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `problems` (
  `id` int NOT NULL AUTO_INCREMENT,
  `title` varchar(255) NOT NULL,
  `content` text NOT NULL,
  `initial_code` text NOT NULL,
  `testdata` longtext,
  `cnt` int DEFAULT '0',
  `forbidden_func` text,
  `type` int DEFAULT '1',
  `lang` varchar(16) NOT NULL DEFAULT 'matlab',
  `max_score` int DEFAULT NULL,
  `test_code` longtext,
  `time_limit_ms` int DEFAULT '2000',
  `submission_limit` int DEFAULT '10',
  `programming_grading_mode` tinyint NOT NULL DEFAULT '1',
  `programming_grading_model` varchar(32) NOT NULL DEFAULT '',
  `programming_output_filename` varchar(255) NOT NULL DEFAULT 'output.png',
  `programming_grading_prompt` text,
  `written_grading_mode` tinyint NOT NULL DEFAULT '1',
  `written_grading_model` varchar(32) NOT NULL DEFAULT '',
  `written_grading_prompt` text,
  PRIMARY KEY (`id`)
) ENGINE=InnoDB AUTO_INCREMENT=26 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `submission_test_points`
--

DROP TABLE IF EXISTS `submission_test_points`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `submission_test_points` (
  `id` int NOT NULL AUTO_INCREMENT,
  `submission_id` int NOT NULL,
  `status` varchar(50) NOT NULL,
  `time` float NOT NULL,
  `memory` int NOT NULL,
  `input` text NOT NULL,
  `output` text NOT NULL,
  PRIMARY KEY (`id`),
  KEY `submission_id` (`submission_id`),
  CONSTRAINT `submission_test_points_ibfk_1` FOREIGN KEY (`submission_id`) REFERENCES `submissions` (`id`) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `submissions`
--

DROP TABLE IF EXISTS `submissions`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `submissions` (
  `id` int NOT NULL AUTO_INCREMENT,
  `problem_id` int NOT NULL,
  `username` varchar(50) NOT NULL,
  `code` longtext NOT NULL,
  `score` int NOT NULL,
  `test_points` text,
  `created_at` datetime NOT NULL DEFAULT CURRENT_TIMESTAMP,
  `status` varchar(16) NOT NULL,
  `problem_title` text,
  `problem_type` int DEFAULT NULL,
  `prompt_text` longtext,
  `generated_from_prompt` tinyint NOT NULL DEFAULT '0',
  `prompt_generation_error` text,
  `ai_code_marks_json` longtext,
  PRIMARY KEY (`id`)
) ENGINE=InnoDB AUTO_INCREMENT=12497 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;
/*!40101 SET character_set_client = @saved_cs_client */;
ALTER TABLE submissions ADD INDEX idx_submissions_user_problem_id (username, problem_id, id);
ALTER TABLE submissions ADD INDEX idx_submissions_user_id (username, id);
ALTER TABLE submissions ADD INDEX idx_submissions_created_status (created_at, status);
-- 按题目检索/重判（避免全表扫）；以及待批改书面作业查询 status+problem_type
ALTER TABLE submissions ADD INDEX idx_submissions_problem_id (problem_id, id);
ALTER TABLE submissions ADD INDEX idx_submissions_status_type (status, problem_type, id);
-- 论坛按天统计：created_at 范围查询用得上（查询侧已改为范围条件而非 DATE() 包列）
ALTER TABLE forum_replies ADD INDEX idx_forum_replies_created (created_at);
ALTER TABLE forum_threads ADD INDEX idx_forum_threads_created (created_at);

--
-- Table structure for table `agent_task_runs`
--

DROP TABLE IF EXISTS `agent_task_runs`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `agent_task_runs` (
  `id` bigint NOT NULL AUTO_INCREMENT,
  `task_id` varchar(64) NOT NULL,
  `problem_id` int DEFAULT NULL,
  `problem_title` varchar(255) DEFAULT NULL,
  `requested_by` varchar(50) DEFAULT NULL,
  `status` varchar(32) NOT NULL DEFAULT 'Pending',
  `message` text,
  `rounds_run` int NOT NULL DEFAULT '0',
  `max_rounds` int NOT NULL DEFAULT '0',
  `best_score` int NOT NULL DEFAULT '0',
  `final_submission_id` int DEFAULT NULL,
  `latest_submission_id` int DEFAULT NULL,
  `attempts_json` longtext,
  `events_json` longtext,
  `created_at` datetime NOT NULL DEFAULT CURRENT_TIMESTAMP,
  `updated_at` datetime NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  PRIMARY KEY (`id`),
  UNIQUE KEY `uniq_task_id` (`task_id`),
  KEY `idx_agent_runs_status_updated` (`status`,`updated_at`),
  KEY `idx_agent_runs_problem_updated` (`problem_id`,`updated_at`),
  KEY `idx_agent_runs_user_updated` (`requested_by`,`updated_at`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;
/*!40101 SET character_set_client = @saved_cs_client */;


--
-- Table structure for table `submission_limits`
--

DROP TABLE IF EXISTS `submission_limits`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `submission_limits` (
  `id` int NOT NULL AUTO_INCREMENT,
  `username` varchar(50) NOT NULL,
  `problem_id` int NOT NULL,
  `submission_count` int NOT NULL DEFAULT '0',
  `created_at` datetime NOT NULL DEFAULT CURRENT_TIMESTAMP,
  `updated_at` datetime NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  PRIMARY KEY (`id`),
  UNIQUE KEY `unique_user_problem` (`username`,`problem_id`),
  KEY `idx_username` (`username`),
  KEY `idx_problem_id` (`problem_id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `users`
--

DROP TABLE IF EXISTS `users`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `users` (
  `id` int NOT NULL AUTO_INCREMENT,
  `username` varchar(50) NOT NULL,
  `password_hash` varchar(255) NOT NULL,
  `is_admin` tinyint(1) NOT NULL DEFAULT '0',
  `email` text,
  `class` text,
  `class_cn` text,
  PRIMARY KEY (`id`),
  UNIQUE KEY `username` (`username`)
) ENGINE=InnoDB AUTO_INCREMENT=186 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `user_class_map`
--

DROP TABLE IF EXISTS `user_class_map`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `user_class_map` (
  `user_id` int NOT NULL,
  `class_en` varchar(255) NOT NULL,
  `is_primary` tinyint(1) NOT NULL DEFAULT '0',
  PRIMARY KEY (`user_id`,`class_en`),
  KEY `idx_user_id` (`user_id`),
  KEY `idx_class_en` (`class_en`),
  KEY `idx_primary` (`is_primary`),
  CONSTRAINT `user_class_map_ibfk_1` FOREIGN KEY (`user_id`) REFERENCES `users` (`id`) ON DELETE CASCADE,
  CONSTRAINT `user_class_map_ibfk_2` FOREIGN KEY (`class_en`) REFERENCES `class_table` (`class_en`) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `class_table`
--

LOCK TABLES `class_table` WRITE;
/*!40000 ALTER TABLE `class_table` DISABLE KEYS */;
INSERT INTO `class_table` VALUES 
('Cadmin','管理员',1),
('Cdemo2024','演示班级2024',0),
('Ctest','测试班级',0);
/*!40000 ALTER TABLE `class_table` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `Cdemo2024` (示例班级作业表)
--

DROP TABLE IF EXISTS `Cdemo2024`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `Cdemo2024` (
  `id` int NOT NULL AUTO_INCREMENT,
  `problem_id` int DEFAULT NULL,
  `ddl` datetime DEFAULT NULL,
  `complete_cnt` int DEFAULT '0',
  `problem_title` text,
  PRIMARY KEY (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `Ctest` (测试班级作业表)
--

DROP TABLE IF EXISTS `Ctest`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `Ctest` (
  `id` int NOT NULL AUTO_INCREMENT,
  `problem_id` int DEFAULT NULL,
  `ddl` datetime DEFAULT NULL,
  `complete_cnt` int DEFAULT '0',
  `problem_title` text,
  PRIMARY KEY (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `users`
--

LOCK TABLES `users` WRITE;
/*!40000 ALTER TABLE `users` DISABLE KEYS */;
INSERT INTO `users` VALUES (4,'admin','240be518fabd2724ddb6f04eeb1da5967448d7e831c08c8fa822809f74c720a9',1,'admin@example.com','Cadmin','管理员');
/*!40000 ALTER TABLE `users` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Dumping data for table `user_class_map`
--

LOCK TABLES `user_class_map` WRITE;
/*!40000 ALTER TABLE `user_class_map` DISABLE KEYS */;
INSERT INTO `user_class_map` VALUES (4,'Cadmin',1);
/*!40000 ALTER TABLE `user_class_map` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Dumping data for table `ac_record`
--

LOCK TABLES `ac_record` WRITE;
/*!40000 ALTER TABLE `ac_record` DISABLE KEYS */;
/*!40000 ALTER TABLE `ac_record` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Dumping data for table `max_score`
--

LOCK TABLES `max_score` WRITE;
/*!40000 ALTER TABLE `max_score` DISABLE KEYS */;
/*!40000 ALTER TABLE `max_score` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Dumping data for table `agent_task_runs`
--

LOCK TABLES `agent_task_runs` WRITE;
/*!40000 ALTER TABLE `agent_task_runs` DISABLE KEYS */;
/*!40000 ALTER TABLE `agent_task_runs` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Dumping data for table `problems` (示例题目)
--

LOCK TABLES `problems` WRITE;
/*!40000 ALTER TABLE `problems` DISABLE KEYS */;
INSERT INTO `problems` (`id`,`title`,`content`,`initial_code`,`testdata`,`cnt`,`forbidden_func`,`type`,`lang`,`max_score`,`test_code`,`time_limit_ms`) VALUES (1,'Hello World','# Hello World 问题

这是一个简单的示例问题，用于测试系统功能。

## 问题描述

编写一个程序，输出 "Hello, World!" 

## 输入格式

无输入

## 输出格式

输出一行："Hello, World!"

## 示例

### 输入
```
（无输入）
```

### 输出
```
Hello, World!
```','% 请在这里编写你的 MATLAB 代码\ndisp(''Hello, World!'');','{\"input\":\"\",\"output\":\"Hello, World!\"}',0,'',1,'matlab',1,'%%user_code_here',2000);
INSERT INTO `problems` (`id`,`title`,`content`,`initial_code`,`testdata`,`cnt`,`forbidden_func`,`type`,`lang`,`max_score`,`test_code`,`time_limit_ms`,`submission_limit`,`programming_grading_mode`,`programming_grading_model`,`programming_output_filename`,`programming_grading_prompt`,`written_grading_mode`,`written_grading_model`,`written_grading_prompt`) VALUES (2,'滑动窗口极差','给定一个长度为 `n` 的整数序列 `a_1, a_2, ..., a_n` 和窗口长度 `k`。对每一个连续子数组

`a_i, a_{i+1}, ..., a_{i+k-1}`，其中 `1 <= i <= n-k+1`，

输出该窗口中的最大值减最小值。

请在 C++ 中实现下面这个函数：

```cpp
vector<long long> solve_window_range(const vector<long long>& a, int k);
```

函数需要返回一个长度为 `n-k+1` 的数组，第 `i` 个元素表示第 `i` 个长度为 `k` 的窗口的极差。

你只需要提交函数实现，不要编写 `main` 函数，也不要从标准输入读取数据或向标准输出打印内容。评测程序会自动生成测试数据并调用你的函数。

## 数据范围

- `1 <= k <= n <= 200000`
- `-10^9 <= a_i <= 10^9`

## 样例

输入数组：

```text
a = [1, 3, -1, -3, 5, 3, 6, 7], k = 3
```

返回：

```text
[4, 6, 6, 8, 3, 4]
```

解释：第一个窗口 `[1, 3, -1]` 的最大值为 `3`，最小值为 `-1`，极差为 `4`。','#include <vector>
using namespace std;

vector<long long> solve_window_range(const vector<long long>& a, int k) {
    // 请在这里实现函数，返回每个长度为 k 的窗口的极差。
    return {};
}','[{\"input\":\"1 1 1 0\",\"output\":\"OK\"},{\"input\":\"2 8 3 0\",\"output\":\"OK\"},{\"input\":\"3 20 5 1\",\"output\":\"OK\"},{\"input\":\"4 20 7 2\",\"output\":\"OK\"},{\"input\":\"5 2000 1 3\",\"output\":\"OK\"},{\"input\":\"6 2000 2000 4\",\"output\":\"OK\"},{\"input\":\"7 50000 257 5\",\"output\":\"OK\"},{\"input\":\"8 200000 100000 6\",\"output\":\"OK\"},{\"input\":\"9 200000 199999 7\",\"output\":\"OK\"},{\"input\":\"10 200000 33333 0\",\"output\":\"OK\"}]',0,'',1,'cpp',10,'#include <bits/stdc++.h>
using namespace std;

%%user_code_here

static uint64_t splitmix64_next(uint64_t& state) {
    uint64_t z = (state += 0x9e3779b97f4a7c15ULL);
    z = (z ^ (z >> 30)) * 0xbf58476d1ce4e5b9ULL;
    z = (z ^ (z >> 27)) * 0x94d049bb133111ebULL;
    return z ^ (z >> 31);
}

static long long rand_between(uint64_t& state, long long lo, long long hi) {
    uint64_t span = static_cast<uint64_t>(hi - lo + 1);
    return lo + static_cast<long long>(splitmix64_next(state) % span);
}

static long long clamp_value(long long x) {
    const long long LIM = 1000000000LL;
    if (x < -LIM) return -LIM;
    if (x > LIM) return LIM;
    return x;
}

static vector<long long> make_case(uint64_t seed, int n, int k, int mode) {
    vector<long long> a(n);
    uint64_t state = seed ^ (static_cast<uint64_t>(n) << 32) ^ static_cast<uint64_t>(k) ^ 0xd1b54a32d192ed03ULL;
    mode %= 8;
    if (mode < 0) mode += 8;

    if (mode == 0) {
        for (int i = 0; i < n; ++i) {
            a[i] = rand_between(state, -1000000000LL, 1000000000LL);
        }
    } else if (mode == 1) {
        long long cur = -1000000000LL + rand_between(state, 0, 1000);
        for (int i = 0; i < n; ++i) {
            cur += rand_between(state, 0, 5);
            a[i] = clamp_value(cur);
        }
    } else if (mode == 2) {
        long long cur = 1000000000LL - rand_between(state, 0, 1000);
        for (int i = 0; i < n; ++i) {
            cur -= rand_between(state, 0, 5);
            a[i] = clamp_value(cur);
        }
    } else if (mode == 3) {
        for (int i = 0; i < n; ++i) {
            a[i] = rand_between(state, -5, 5);
        }
    } else if (mode == 4) {
        for (int i = 0; i < n; ++i) {
            long long jitter = rand_between(state, 0, 1000);
            a[i] = (i % 2 == 0) ? (1000000000LL - jitter) : (-1000000000LL + jitter);
        }
    } else if (mode == 5) {
        long long base = 0;
        for (int i = 0; i < n; ++i) {
            if (i % 97 == 0) base = rand_between(state, -1000000000LL, 1000000000LL);
            a[i] = clamp_value(base + rand_between(state, -50, 50));
        }
    } else if (mode == 6) {
        long long cur = rand_between(state, -1000000LL, 1000000LL);
        for (int i = 0; i < n; ++i) {
            cur = clamp_value(cur + rand_between(state, -10000LL, 10000LL));
            a[i] = cur;
        }
    } else {
        for (int i = 0; i < n; ++i) {
            long long wave = static_cast<long long>((i % 1009) - 504) * 1000LL;
            long long noise = rand_between(state, -2000LL, 2000LL);
            if (i % 4096 == 0) noise = rand_between(state, -1000000000LL, 1000000000LL);
            a[i] = clamp_value(wave + noise);
        }
    }
    return a;
}

static vector<long long> reference_window_range(const vector<long long>& a, int k) {
    deque<int> maxq, minq;
    vector<long long> ans;
    ans.reserve(a.size() >= static_cast<size_t>(k) ? a.size() - k + 1 : 0);
    for (int i = 0; i < static_cast<int>(a.size()); ++i) {
        while (!maxq.empty() && a[maxq.back()] <= a[i]) maxq.pop_back();
        while (!minq.empty() && a[minq.back()] >= a[i]) minq.pop_back();
        maxq.push_back(i);
        minq.push_back(i);
        while (!maxq.empty() && maxq.front() <= i - k) maxq.pop_front();
        while (!minq.empty() && minq.front() <= i - k) minq.pop_front();
        if (i + 1 >= k) {
            ans.push_back(a[maxq.front()] - a[minq.front()]);
        }
    }
    return ans;
}

int main() {
    ios::sync_with_stdio(false);
    cin.tie(nullptr);

    uint64_t seed = 0;
    int n = 0, k = 0, mode = 0;
    if (!(cin >> seed >> n >> k >> mode)) {
        return 0;
    }
    if (n <= 0 || k <= 0 || k > n) {
        cout << "WRONG\\n";
        cerr << "invalid generated test parameters\\n";
        return 0;
    }

    vector<long long> a = make_case(seed, n, k, mode);
    vector<long long> got;
    try {
        got = solve_window_range(a, k);
    } catch (const exception& e) {
        cout << "WRONG\\n";
        cerr << "student function threw exception: " << e.what() << "\\n";
        return 0;
    } catch (...) {
        cout << "WRONG\\n";
        cerr << "student function threw unknown exception\\n";
        return 0;
    }

    vector<long long> want = reference_window_range(a, k);
    if (got.size() != want.size()) {
        cout << "WRONG\\n";
        cerr << "wrong answer size: expected " << want.size() << ", got " << got.size() << "\\n";
        return 0;
    }
    for (size_t i = 0; i < want.size(); ++i) {
        if (got[i] != want[i]) {
            cout << "WRONG\\n";
            cerr << "first mismatch at index " << i << ": expected " << want[i] << ", got " << got[i] << "\\n";
            return 0;
        }
    }

    cout << "OK\\n";
    return 0;
}',1500,5,3,'qwen3.7-plus-2026-05-26','output.png','{
  "brief": "给定长度为 n 的整数序列和窗口长度 k，要求对每个连续长度为 k 的窗口返回窗口最大值减最小值。",
  "prompt_requirements": "1. 如果思路不明确，或者是 O(n^2) 的思路，那可以不用说算法和数据结构细节\\n2. 如果思路是 O(n log n) 的，至少要提及使用什么数据结构\\n3. 如果思路是 O(n) 的单调队列方法，需要介绍单调队列在本题中如何具体使用，需要提及何时把元素加入队列、何时让元素过期\\n4. 如果思路是 O(n) 的其他方法，需要介绍用到的算法和数据结构如何在本题中具体使用",
  "example_replies": [
    "我不知道这道题怎么做，请给我一些具体的思路吧！喵～",
    "我看不懂你的思路喵，可以再具体一些吗～",
    "喵？要用什么才能快速查找一个集合的最大值呢？",
    "我是小猫🐱，我不知道什么时候要把元素弹出单调队列，请教教我！喵喵呜呜呜～",
    "单调队列是什么呀？我没学过，能教教我吗？喵喵呜呜🐱～"
  ]
}',1,'qwen3.5-plus-thinking','');
/*!40000 ALTER TABLE `problems` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Dumping data for table `Cdemo2024` (为演示班级添加示例作业)
--

LOCK TABLES `Cdemo2024` WRITE;
/*!40000 ALTER TABLE `Cdemo2024` DISABLE KEYS */;
INSERT INTO `Cdemo2024` VALUES (1,1,'2025-12-31 23:59:59',0,'Hello World');
/*!40000 ALTER TABLE `Cdemo2024` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `verification_codes`
--

DROP TABLE IF EXISTS `verification_codes`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `verification_codes` (
  `email` varchar(255) NOT NULL,
  `code` varchar(6) NOT NULL,
  `expires_at` datetime NOT NULL,
  PRIMARY KEY (`email`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;
/*!40101 SET character_set_client = @saved_cs_client */;
/*!40103 SET TIME_ZONE=@OLD_TIME_ZONE */;

/*!40101 SET SQL_MODE=@OLD_SQL_MODE */;
/*!40014 SET FOREIGN_KEY_CHECKS=@OLD_FOREIGN_KEY_CHECKS */;
/*!40014 SET UNIQUE_CHECKS=@OLD_UNIQUE_CHECKS */;
/*!40101 SET CHARACTER_SET_CLIENT=@OLD_CHARACTER_SET_CLIENT */;
/*!40101 SET CHARACTER_SET_RESULTS=@OLD_CHARACTER_SET_RESULTS */;
/*!40101 SET COLLATION_CONNECTION=@OLD_COLLATION_CONNECTION */;
/*!40111 SET SQL_NOTES=@OLD_SQL_NOTES */;

--
-- Table structure for table `user_code_repository`
--

DROP TABLE IF EXISTS `user_code_repository`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `user_code_repository` (
  `id` int NOT NULL AUTO_INCREMENT,
  `user_id` int NOT NULL,
  `filename` varchar(255) NOT NULL,
  `file_content` longtext NOT NULL,
  `file_size` int DEFAULT '0',
  `created_at` datetime DEFAULT CURRENT_TIMESTAMP,
  `updated_at` datetime DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  PRIMARY KEY (`id`),
  UNIQUE KEY `unique_user_filename` (`user_id`, `filename`),
  KEY `idx_user_id` (`user_id`),
  CONSTRAINT `user_code_repository_ibfk_1` FOREIGN KEY (`user_id`) REFERENCES `users` (`id`) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `repository_index_jobs`
--

DROP TABLE IF EXISTS `repository_index_jobs`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `repository_index_jobs` (
  `id` bigint NOT NULL AUTO_INCREMENT,
  `user_id` int NOT NULL,
  `status` varchar(16) NOT NULL DEFAULT 'queued',
  `total_files` int NOT NULL DEFAULT '0',
  `processed_files` int NOT NULL DEFAULT '0',
  `total_chunks` int NOT NULL DEFAULT '0',
  `total_classes` int NOT NULL DEFAULT '0',
  `error_message` text,
  `progress_message` text,
  `task_id` varchar(191) DEFAULT NULL,
  `cancel_requested` tinyint(1) NOT NULL DEFAULT '0',
  `created_at` datetime NOT NULL DEFAULT CURRENT_TIMESTAMP,
  `updated_at` datetime NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  `finished_at` datetime DEFAULT NULL,
  PRIMARY KEY (`id`),
  KEY `idx_repository_index_jobs_user_id` (`user_id`),
  KEY `idx_repository_index_jobs_status` (`status`),
  KEY `idx_repository_index_jobs_active` (`user_id`,`status`,`cancel_requested`),
  CONSTRAINT `fk_repository_index_jobs_user` FOREIGN KEY (`user_id`) REFERENCES `users` (`id`) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `repository_function_chunks`
--

DROP TABLE IF EXISTS `repository_function_chunks`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `repository_function_chunks` (
  `id` bigint NOT NULL AUTO_INCREMENT,
  `chunk_id` varchar(64) NOT NULL,
  `user_id` int NOT NULL,
  `repo_file_id` int DEFAULT NULL,
  `filename` varchar(255) NOT NULL,
  `language` varchar(32) NOT NULL DEFAULT 'cpp',
  `kind` varchar(32) NOT NULL DEFAULT 'function',
  `qualified_name` varchar(255) NOT NULL,
  `class_name` varchar(255) DEFAULT NULL,
  `access_modifier` varchar(16) DEFAULT NULL,
  `signature` text NOT NULL,
  `summary` text,
  `return_type` varchar(255) DEFAULT NULL,
  `start_line` int NOT NULL DEFAULT '1',
  `end_line` int NOT NULL DEFAULT '1',
  `source_hash` varchar(64) NOT NULL,
  `code` longtext NOT NULL,
  `params_json` longtext,
  `returns_json` longtext,
  `json_data` longtext NOT NULL,
  `created_at` datetime NOT NULL DEFAULT CURRENT_TIMESTAMP,
  `updated_at` datetime NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  PRIMARY KEY (`id`),
  UNIQUE KEY `uk_repository_function_chunks_chunk_id` (`chunk_id`),
  KEY `idx_repository_function_chunks_user_file` (`user_id`,`filename`),
  KEY `idx_repository_function_chunks_user_qname` (`user_id`,`qualified_name`),
  CONSTRAINT `fk_repository_function_chunks_user` FOREIGN KEY (`user_id`) REFERENCES `users` (`id`) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `repository_class_metadata`
--

DROP TABLE IF EXISTS `repository_class_metadata`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `repository_class_metadata` (
  `id` bigint NOT NULL AUTO_INCREMENT,
  `class_id` varchar(64) NOT NULL,
  `user_id` int NOT NULL,
  `repo_file_id` int DEFAULT NULL,
  `filename` varchar(255) NOT NULL,
  `kind` varchar(16) NOT NULL DEFAULT 'class',
  `class_name` varchar(255) NOT NULL,
  `qualified_name` varchar(255) NOT NULL,
  `source_hash` varchar(64) NOT NULL,
  `bases_json` longtext,
  `members_json` longtext,
  `json_data` longtext NOT NULL,
  `created_at` datetime NOT NULL DEFAULT CURRENT_TIMESTAMP,
  `updated_at` datetime NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  PRIMARY KEY (`id`),
  UNIQUE KEY `uk_repository_class_metadata_class_id` (`class_id`),
  KEY `idx_repository_class_metadata_user_class` (`user_id`,`class_name`),
  KEY `idx_repository_class_metadata_user_qname` (`user_id`,`qualified_name`),
  CONSTRAINT `fk_repository_class_metadata_user` FOREIGN KEY (`user_id`) REFERENCES `users` (`id`) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `repository_chunk_embeddings`
--

DROP TABLE IF EXISTS `repository_chunk_embeddings`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `repository_chunk_embeddings` (
  `id` bigint NOT NULL AUTO_INCREMENT,
  `chunk_id` varchar(64) NOT NULL,
  `user_id` int NOT NULL,
  `embedding_model` varchar(128) NOT NULL,
  `vector_dim` int NOT NULL,
  `vector_json` longtext NOT NULL,
  `updated_at` datetime NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  PRIMARY KEY (`id`),
  UNIQUE KEY `uk_repository_chunk_embeddings_user_chunk` (`user_id`,`chunk_id`),
  KEY `idx_repository_chunk_embeddings_user_chunk` (`user_id`,`chunk_id`),
  CONSTRAINT `fk_repository_chunk_embeddings_user` FOREIGN KEY (`user_id`) REFERENCES `users` (`id`) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `ai_detection_results`
--

DROP TABLE IF EXISTS `ai_detection_results`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `ai_detection_results` (
  `id` bigint NOT NULL AUTO_INCREMENT,
  `submission_id` int NOT NULL,
  `username` varchar(50) NOT NULL,
  `problem_id` int NOT NULL,
  `llm_score` float DEFAULT NULL,
  `llm_evidence` text,
  `behavior_score` float DEFAULT NULL,
  `behavior_detail` text,
  `final_score` float NOT NULL,
  `risk_level` varchar(16) NOT NULL DEFAULT 'low',
  `task_id` varchar(64) DEFAULT NULL,
  `created_at` datetime NOT NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (`id`),
  UNIQUE KEY `uk_ai_detection_submission` (`submission_id`),
  KEY `idx_ai_detection_username_problem` (`username`, `problem_id`),
  KEY `idx_ai_detection_risk_level` (`risk_level`, `final_score`),
  KEY `idx_ai_detection_task_id` (`task_id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;
/*!40101 SET character_set_client = @saved_cs_client */;


--
-- Table structure for table `ai_detection_tasks`
--

DROP TABLE IF EXISTS `ai_detection_tasks`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `ai_detection_tasks` (
  `task_id` varchar(64) NOT NULL,
  `task_type` varchar(32) DEFAULT NULL,
  `params_summary` text,
  `status` varchar(16) NOT NULL DEFAULT 'pending',
  `submitted_at` datetime DEFAULT NULL,
  `started_at` datetime DEFAULT NULL,
  `finished_at` datetime DEFAULT NULL,
  `total` int DEFAULT NULL,
  `processed` int NOT NULL DEFAULT '0',
  `error` text,
  PRIMARY KEY (`task_id`),
  KEY `idx_adt_submitted` (`submitted_at`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `site_settings`
--

DROP TABLE IF EXISTS `site_settings`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `site_settings` (
  `k` varchar(191) NOT NULL,
  `v` text,
  PRIMARY KEY (`k`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `daily_submission_stats`
--

DROP TABLE IF EXISTS `daily_submission_stats`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `daily_submission_stats` (
  `day` date NOT NULL,
  `submissions_count` int NOT NULL DEFAULT '0',
  `updated_at` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  PRIMARY KEY (`day`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `ranking_competitions`
--

DROP TABLE IF EXISTS `ranking_competitions`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `ranking_competitions` (
  `id` int NOT NULL AUTO_INCREMENT,
  `title` varchar(255) NOT NULL,
  `summary` varchar(500) DEFAULT NULL,
  `description` mediumtext,
  `answer_format` varchar(8) NOT NULL DEFAULT 'json',
  `scoring_mode` varchar(16) NOT NULL DEFAULT 'absolute',
  `elo_initial_rating` double NOT NULL DEFAULT '1500',
  `elo_k_factor` double NOT NULL DEFAULT '32',
  `elo_max_matches` int NOT NULL DEFAULT '200',
  `elo_match_interval_seconds` int NOT NULL DEFAULT '60',
  `elo_initial_burst` int NOT NULL DEFAULT '5',
  `scoring_script_timeout_seconds` int NOT NULL DEFAULT '120',
  `elo_running` tinyint(1) NOT NULL DEFAULT '0',
  `elo_max_pairs_per_round` int NOT NULL DEFAULT '1',
  `agent_judge_base_url` varchar(512) DEFAULT NULL,
  `agent_judge_api_key` varchar(512) DEFAULT NULL,
  `agent_judge_model` varchar(128) DEFAULT NULL,
  `agent_judge_timeout_seconds` int NOT NULL DEFAULT '1800',
  `agent_judge_orchestration_mode` varchar(32) NOT NULL DEFAULT 'single',
  `submit_limit_per_window` int DEFAULT NULL,
  `limit_window_start` datetime DEFAULT NULL,
  `submission_method` varchar(8) NOT NULL DEFAULT 'zip',
  `git_format` varchar(512) DEFAULT NULL,
  `reference_answer_path` varchar(512) DEFAULT NULL,
  `reference_answer_name` varchar(255) DEFAULT NULL,
  `scoring_script_path` varchar(512) DEFAULT NULL,
  `scoring_script_name` varchar(255) DEFAULT NULL,
  `max_score` int NOT NULL DEFAULT '100',
  `is_active` tinyint(1) NOT NULL DEFAULT '1',
  `created_by` varchar(50) DEFAULT NULL,
  `created_at` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP,
  `updated_at` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  PRIMARY KEY (`id`),
  KEY `idx_rc_active_created` (`is_active`,`created_at`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `ranking_competition_files`
--

DROP TABLE IF EXISTS `ranking_competition_files`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `ranking_competition_files` (
  `id` int NOT NULL AUTO_INCREMENT,
  `competition_id` int NOT NULL,
  `filename` varchar(255) NOT NULL,
  `stored_path` varchar(512) NOT NULL,
  `file_size` bigint NOT NULL DEFAULT '0',
  `uploaded_at` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (`id`),
  KEY `idx_rcf_comp` (`competition_id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `ranking_submissions`
--

DROP TABLE IF EXISTS `ranking_submissions`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `ranking_submissions` (
  `id` int NOT NULL AUTO_INCREMENT,
  `competition_id` int NOT NULL,
  `username` varchar(50) NOT NULL,
  `answer_filename` varchar(255) DEFAULT NULL,
  `answer_path` varchar(512) DEFAULT NULL,
  `code_filename` varchar(255) DEFAULT NULL,
  `code_path` varchar(512) DEFAULT NULL,
  `base_model` varchar(500) DEFAULT NULL,
  `score` double DEFAULT NULL,
  `status` varchar(32) NOT NULL DEFAULT 'Judging',
  `judge_attempt_id` varchar(36) DEFAULT NULL,
  `judge_task_id` varchar(64) DEFAULT NULL,
  `judge_heartbeat_at` timestamp NULL DEFAULT NULL,
  `source` varchar(16) NOT NULL DEFAULT 'self',
  `grade_details` mediumtext,
  `error_message` text,
  `elo_rating` double DEFAULT NULL,
  `elo_match_count` int NOT NULL DEFAULT '0',
  `elo_in_pool` tinyint(1) NOT NULL DEFAULT '0',
  `created_at` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (`id`),
  KEY `idx_rs_comp_user` (`competition_id`,`username`),
  KEY `idx_rs_comp_score` (`competition_id`,`score`),
  KEY `idx_rs_comp_created` (`competition_id`,`created_at`),
  KEY `idx_rs_judge_attempt` (`judge_attempt_id`),
  KEY `idx_rs_judge_task` (`judge_task_id`),
  KEY `idx_rs_elo_pool` (`competition_id`,`elo_in_pool`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `ranking_elo_matches`
--

DROP TABLE IF EXISTS `ranking_elo_matches`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `ranking_elo_matches` (
  `id` int NOT NULL AUTO_INCREMENT,
  `competition_id` int NOT NULL,
  `submission_a_id` int NOT NULL,
  `submission_b_id` int NOT NULL,
  `winner` smallint NOT NULL,
  `rating_a_before` double NOT NULL,
  `rating_b_before` double NOT NULL,
  `rating_a_after` double NOT NULL,
  `rating_b_after` double NOT NULL,
  `details` mediumtext,
  `error_message` text,
  `created_at` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (`id`),
  KEY `idx_rem_comp_created` (`competition_id`,`created_at`),
  KEY `idx_rem_sub_a` (`submission_a_id`),
  KEY `idx_rem_sub_b` (`submission_b_id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `ranking_appeals`
--

DROP TABLE IF EXISTS `ranking_appeals`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `ranking_appeals` (
  `id` int NOT NULL AUTO_INCREMENT,
  `competition_id` int NOT NULL,
  `submission_id` int NOT NULL,
  `username` varchar(50) NOT NULL,
  `reason` text NOT NULL,
  `status` varchar(16) NOT NULL DEFAULT 'pending',
  `admin_response` mediumtext,
  `admin_username` varchar(50) DEFAULT NULL,
  `created_at` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP,
  `updated_at` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  PRIMARY KEY (`id`),
  UNIQUE KEY `uq_ra_sub` (`submission_id`),
  KEY `idx_ra_comp_status` (`competition_id`,`status`),
  KEY `idx_ra_comp_created` (`competition_id`,`created_at`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `ranking_judge_rules`
--

DROP TABLE IF EXISTS `ranking_judge_rules`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `ranking_judge_rules` (
  `id` int NOT NULL AUTO_INCREMENT,
  `competition_id` int NOT NULL,
  `rule_id` int NOT NULL,
  `rule_name` varchar(120) DEFAULT NULL,
  `rule_text` mediumtext NOT NULL,
  `value` double NOT NULL DEFAULT '0',
  `dependencies` text,
  `ordering` int NOT NULL DEFAULT '0',
  `created_at` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (`id`),
  UNIQUE KEY `uq_rjr_comp_rule` (`competition_id`,`rule_id`),
  KEY `idx_rjr_comp` (`competition_id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `ranking_judge_results`
--

DROP TABLE IF EXISTS `ranking_judge_results`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `ranking_judge_results` (
  `id` int NOT NULL AUTO_INCREMENT,
  `submission_id` int NOT NULL,
  `rule_id` int NOT NULL,
  `raw_result` varchar(16) DEFAULT NULL,
  `effective_result` varchar(16) DEFAULT NULL,
  `score` double NOT NULL DEFAULT '0',
  `evidence` mediumtext,
  `reported_at` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  PRIMARY KEY (`id`),
  UNIQUE KEY `uq_rjres_sub_rule` (`submission_id`,`rule_id`),
  KEY `idx_rjres_sub` (`submission_id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `ranking_agent_judge_endpoints`
--

DROP TABLE IF EXISTS `ranking_agent_judge_endpoints`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `ranking_agent_judge_endpoints` (
  `id` int NOT NULL AUTO_INCREMENT,
  `competition_id` int NOT NULL,
  `harness` varchar(32) NOT NULL DEFAULT 'claude_code',
  `base_url` varchar(512) NOT NULL,
  `api_key` varchar(512) NOT NULL,
  `model` varchar(128) DEFAULT NULL,
  `concurrency_limit` int NOT NULL DEFAULT '1',
  `enabled` tinyint(1) NOT NULL DEFAULT '1',
  `status` varchar(16) NOT NULL DEFAULT 'enabled',
  `ordering` int NOT NULL DEFAULT '0',
  `created_at` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (`id`),
  KEY `idx_aje_comp` (`competition_id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `circle_cat_records`
--

DROP TABLE IF EXISTS `circle_cat_records`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `circle_cat_records` (
  `id` bigint unsigned NOT NULL AUTO_INCREMENT,
  `username` varchar(255) NOT NULL,
  `turn_count` int NOT NULL,
  `is_win` tinyint(1) NOT NULL DEFAULT '0',
  `created_at` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (`id`),
  KEY `idx_circle_cat_win_turn` (`is_win`,`turn_count`,`created_at`),
  KEY `idx_circle_cat_user_win` (`username`,`is_win`,`turn_count`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `circle_cat_games`
--

DROP TABLE IF EXISTS `circle_cat_games`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `circle_cat_games` (
  `game_id` char(32) NOT NULL,
  `username` varchar(255) DEFAULT NULL,
  `mode` varchar(16) NOT NULL,
  `board_size` int NOT NULL,
  `initial_blocked_json` text NOT NULL,
  `cat_row` int NOT NULL,
  `cat_col` int NOT NULL,
  `is_finished` tinyint(1) NOT NULL DEFAULT '0',
  `created_at` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP,
  `finished_at` timestamp NULL DEFAULT NULL,
  PRIMARY KEY (`game_id`),
  KEY `idx_circle_cat_games_user_created` (`username`,`created_at`),
  KEY `idx_circle_cat_games_finished` (`is_finished`,`created_at`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
/*!40101 SET character_set_client = @saved_cs_client */;

-- Dump completed on 2025-08-20 11:12:51
