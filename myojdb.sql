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
  `test_code` text,
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
  `code` text NOT NULL,
  `score` int NOT NULL,
  `test_points` text,
  `created_at` datetime NOT NULL DEFAULT CURRENT_TIMESTAMP,
  `status` varchar(16) NOT NULL,
  `problem_title` text,
  `problem_type` int DEFAULT NULL,
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

-- Dump completed on 2025-08-20 11:12:51
