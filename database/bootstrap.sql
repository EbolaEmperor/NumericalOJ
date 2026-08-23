-- =====================================================
-- NumericalOJ 数据库 bootstrap（结构基线 + 开发/首次安装种子）
-- =====================================================
-- 
-- 这个脚本包含 NumericalOJ 的完整数据库结构和首次安装种子；生产增量同步器
-- scripts/init_db_schema.py 只解析其中的 CREATE/ALTER 定义，不执行 INSERT。
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
  `logo_seed` char(32) DEFAULT NULL,
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
-- Table structure for table `forum_anonymous_identities`
--

DROP TABLE IF EXISTS `forum_anonymous_identities`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `forum_anonymous_identities` (
  `id` bigint NOT NULL AUTO_INCREMENT,
  `user_id` int NOT NULL,
  `display_name` varchar(10) CHARACTER SET utf8mb4 COLLATE utf8mb4_bin NOT NULL,
  `normalized_name` varchar(10) CHARACTER SET utf8mb4 COLLATE utf8mb4_bin NOT NULL,
  `created_at` datetime NOT NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (`id`),
  UNIQUE KEY `uq_forum_anonymous_normalized_name` (`normalized_name`),
  UNIQUE KEY `uq_forum_anonymous_identity_owner` (`user_id`,`id`),
  KEY `idx_forum_anonymous_user_created` (`user_id`,`created_at`,`id`),
  CONSTRAINT `fk_forum_anonymous_user` FOREIGN KEY (`user_id`) REFERENCES `users` (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `forum_identity_operation_receipts`
--

DROP TABLE IF EXISTS `forum_identity_operation_receipts`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `forum_identity_operation_receipts` (
  `id` bigint NOT NULL AUTO_INCREMENT,
  `user_id` int NOT NULL,
  `client_request_id` varchar(64) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
  `display_name` varchar(10) CHARACTER SET utf8mb4 COLLATE utf8mb4_bin NOT NULL,
  `normalized_name` varchar(10) CHARACTER SET utf8mb4 COLLATE utf8mb4_bin NOT NULL,
  `requested_enable` tinyint(1) DEFAULT NULL,
  `anonymous_identity_id` bigint NOT NULL,
  `result_use_anonymous` tinyint(1) NOT NULL,
  `created_at` datetime NOT NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (`id`),
  UNIQUE KEY `uq_forum_identity_operation_request` (`user_id`,`client_request_id`),
  KEY `idx_forum_identity_operation_identity` (`anonymous_identity_id`),
  KEY `idx_forum_identity_operation_owner` (`user_id`,`anonymous_identity_id`),
  CONSTRAINT `fk_forum_identity_operation_user` FOREIGN KEY (`user_id`) REFERENCES `users` (`id`),
  CONSTRAINT `fk_forum_identity_operation_identity` FOREIGN KEY (`anonymous_identity_id`) REFERENCES `forum_anonymous_identities` (`id`),
  CONSTRAINT `fk_forum_identity_operation_owner` FOREIGN KEY (`user_id`,`anonymous_identity_id`) REFERENCES `forum_anonymous_identities` (`user_id`,`id`) ON DELETE RESTRICT ON UPDATE RESTRICT
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `forum_user_identity_settings`
--

DROP TABLE IF EXISTS `forum_user_identity_settings`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `forum_user_identity_settings` (
  `user_id` int NOT NULL,
  `use_anonymous` tinyint(1) NOT NULL DEFAULT '0',
  `current_anonymous_identity_id` bigint DEFAULT NULL,
  `identity_changed_at` datetime DEFAULT NULL,
  `updated_at` datetime NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  PRIMARY KEY (`user_id`),
  KEY `idx_forum_identity_current` (`current_anonymous_identity_id`),
  KEY `idx_forum_settings_identity_owner` (`user_id`,`current_anonymous_identity_id`),
  CONSTRAINT `fk_forum_identity_settings_user` FOREIGN KEY (`user_id`) REFERENCES `users` (`id`),
  CONSTRAINT `fk_forum_identity_settings_current` FOREIGN KEY (`current_anonymous_identity_id`) REFERENCES `forum_anonymous_identities` (`id`),
  CONSTRAINT `fk_forum_settings_identity_owner` FOREIGN KEY (`user_id`,`current_anonymous_identity_id`) REFERENCES `forum_anonymous_identities` (`user_id`,`id`) ON DELETE RESTRICT ON UPDATE RESTRICT
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `forum_replies`
--

DROP TABLE IF EXISTS `forum_replies`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `forum_replies` (
  `id` int NOT NULL AUTO_INCREMENT,
  `thread_id` int NOT NULL,
  `content` mediumtext NOT NULL,
  `created_at` datetime DEFAULT CURRENT_TIMESTAMP,
  `updated_at` datetime DEFAULT NULL,
  `user_id` int NOT NULL,
  `anonymous_identity_id` bigint DEFAULT NULL,
  `client_request_id` varchar(64) CHARACTER SET ascii COLLATE ascii_bin DEFAULT NULL,
  `edit_version` int NOT NULL DEFAULT '1',
  PRIMARY KEY (`id`),
  KEY `user_id` (`user_id`),
  KEY `thread_id` (`thread_id`),
  KEY `idx_forum_replies_identity` (`anonymous_identity_id`),
  KEY `idx_forum_replies_identity_owner` (`user_id`,`anonymous_identity_id`),
  KEY `idx_forum_replies_thread_created` (`thread_id`,`created_at`,`id`),
  KEY `idx_forum_replies_user_thread` (`user_id`,`thread_id`),
  UNIQUE KEY `uq_forum_replies_user_request` (`user_id`,`client_request_id`),
  CONSTRAINT `forum_replies_ibfk_1` FOREIGN KEY (`user_id`) REFERENCES `users` (`id`),
  CONSTRAINT `forum_replies_ibfk_2` FOREIGN KEY (`thread_id`) REFERENCES `forum_threads` (`id`),
  CONSTRAINT `fk_forum_replies_identity_owner` FOREIGN KEY (`user_id`,`anonymous_identity_id`) REFERENCES `forum_anonymous_identities` (`user_id`,`id`) ON DELETE RESTRICT ON UPDATE RESTRICT
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
  `content` mediumtext NOT NULL,
  `created_at` datetime DEFAULT CURRENT_TIMESTAMP,
  `updated_at` datetime DEFAULT CURRENT_TIMESTAMP,
  `user_id` int NOT NULL,
  `anonymous_identity_id` bigint DEFAULT NULL,
  `client_request_id` varchar(64) CHARACTER SET ascii COLLATE ascii_bin DEFAULT NULL,
  `edit_version` int NOT NULL DEFAULT '1',
  PRIMARY KEY (`id`),
  KEY `user_id` (`user_id`),
  KEY `idx_forum_threads_identity` (`anonymous_identity_id`),
  KEY `idx_forum_threads_identity_owner` (`user_id`,`anonymous_identity_id`),
  KEY `idx_forum_threads_user_created` (`user_id`,`created_at`,`id`),
  UNIQUE KEY `uq_forum_threads_user_request` (`user_id`,`client_request_id`),
  CONSTRAINT `forum_threads_ibfk_1` FOREIGN KEY (`user_id`) REFERENCES `users` (`id`),
  CONSTRAINT `fk_forum_threads_identity_owner` FOREIGN KEY (`user_id`,`anonymous_identity_id`) REFERENCES `forum_anonymous_identities` (`user_id`,`id`) ON DELETE RESTRICT ON UPDATE RESTRICT
) ENGINE=InnoDB AUTO_INCREMENT=8 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `forum_thread_revisions`
--

DROP TABLE IF EXISTS `forum_thread_revisions`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `forum_thread_revisions` (
  `id` bigint NOT NULL AUTO_INCREMENT,
  `thread_id` int NOT NULL,
  `editor_user_id` int NOT NULL,
  `title` varchar(255) NOT NULL,
  `content` mediumtext NOT NULL,
  `source_version` int NOT NULL,
  `created_at` datetime NOT NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (`id`),
  UNIQUE KEY `uq_forum_thread_revision_version` (`thread_id`,`source_version`),
  KEY `idx_forum_thread_revisions_editor` (`editor_user_id`),
  CONSTRAINT `fk_forum_thread_revisions_thread` FOREIGN KEY (`thread_id`) REFERENCES `forum_threads` (`id`) ON DELETE CASCADE,
  CONSTRAINT `fk_forum_thread_revisions_editor` FOREIGN KEY (`editor_user_id`) REFERENCES `users` (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `forum_reply_revisions`
--

DROP TABLE IF EXISTS `forum_reply_revisions`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `forum_reply_revisions` (
  `id` bigint NOT NULL AUTO_INCREMENT,
  `reply_id` int NOT NULL,
  `editor_user_id` int NOT NULL,
  `content` mediumtext NOT NULL,
  `source_version` int NOT NULL,
  `created_at` datetime NOT NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (`id`),
  UNIQUE KEY `uq_forum_reply_revision_version` (`reply_id`,`source_version`),
  KEY `idx_forum_reply_revisions_editor` (`editor_user_id`),
  CONSTRAINT `fk_forum_reply_revisions_reply` FOREIGN KEY (`reply_id`) REFERENCES `forum_replies` (`id`) ON DELETE CASCADE,
  CONSTRAINT `fk_forum_reply_revisions_editor` FOREIGN KEY (`editor_user_id`) REFERENCES `users` (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `forum_edit_operation_receipts`
--

DROP TABLE IF EXISTS `forum_edit_operation_receipts`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `forum_edit_operation_receipts` (
  `id` bigint NOT NULL AUTO_INCREMENT,
  `user_id` int NOT NULL,
  `operation_kind` varchar(16) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
  `client_request_id` varchar(64) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
  `target_id` bigint NOT NULL,
  `request_fingerprint` char(64) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
  `result_version` int DEFAULT NULL,
  `result_updated_at` datetime DEFAULT NULL,
  `result_changed` tinyint(1) DEFAULT NULL,
  `created_at` datetime NOT NULL DEFAULT CURRENT_TIMESTAMP,
  `completed_at` datetime DEFAULT NULL,
  PRIMARY KEY (`id`),
  UNIQUE KEY `uq_forum_edit_operation_request` (`user_id`,`operation_kind`,`client_request_id`),
  KEY `idx_forum_edit_operation_target` (`operation_kind`,`target_id`),
  CONSTRAINT `fk_forum_edit_operation_user` FOREIGN KEY (`user_id`) REFERENCES `users` (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `forum_create_operation_receipts`
--

DROP TABLE IF EXISTS `forum_create_operation_receipts`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `forum_create_operation_receipts` (
  `id` bigint NOT NULL AUTO_INCREMENT,
  `user_id` int NOT NULL,
  `operation_kind` varchar(16) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
  `client_request_id` varchar(64) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
  `request_fingerprint` char(64) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
  `result_id` bigint DEFAULT NULL,
  `result_created_at` datetime DEFAULT NULL,
  `created_at` datetime NOT NULL DEFAULT CURRENT_TIMESTAMP,
  `completed_at` datetime DEFAULT NULL,
  PRIMARY KEY (`id`),
  UNIQUE KEY `uq_forum_create_operation_request` (`user_id`,`operation_kind`,`client_request_id`),
  CONSTRAINT `fk_forum_create_operation_user` FOREIGN KEY (`user_id`) REFERENCES `users` (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;
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
  `output_image_filename` varchar(255) NOT NULL DEFAULT 'output.png',
  `programming_grading_prompt` text,
  `written_grading_mode` tinyint NOT NULL DEFAULT '1',
  `written_grading_model` varchar(32) NOT NULL DEFAULT '',
  `written_grading_prompt` text,
  `llm_endpoint_bindings` json DEFAULT NULL,
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

--
-- Table structure for immutable Lean 4 problem workspaces
--

DROP TABLE IF EXISTS `lean_problem_revisions`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `lean_problem_revisions` (
  `id` bigint unsigned NOT NULL AUTO_INCREMENT,
  `problem_id` int NOT NULL,
  `revision_number` int unsigned NOT NULL,
  `schema_version` int unsigned NOT NULL DEFAULT '1',
  `default_file` varchar(512) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
  `manifest_json` json NOT NULL,
  `package_sha256` char(64) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
  `file_count` int unsigned NOT NULL,
  `total_size` bigint unsigned NOT NULL,
  `created_by_user_id` int DEFAULT NULL,
  `created_at` datetime NOT NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (`id`),
  UNIQUE KEY `uniq_lean_problem_revision_number` (`problem_id`,`revision_number`),
  KEY `idx_lean_problem_revision_hash` (`problem_id`,`package_sha256`),
  KEY `idx_lean_problem_revision_current` (`problem_id`,`id`),
  KEY `idx_lean_problem_revision_creator` (`created_by_user_id`,`created_at`),
  CONSTRAINT `lean_problem_revision_problem_fk` FOREIGN KEY (`problem_id`) REFERENCES `problems` (`id`) ON DELETE CASCADE,
  CONSTRAINT `lean_problem_revision_creator_fk` FOREIGN KEY (`created_by_user_id`) REFERENCES `users` (`id`) ON DELETE SET NULL,
  CONSTRAINT `lean_problem_revision_number_chk` CHECK ((`revision_number` > 0)),
  CONSTRAINT `lean_problem_revision_file_count_chk` CHECK ((`file_count` > 0))
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

DROP TABLE IF EXISTS `lean_problem_revision_files`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `lean_problem_revision_files` (
  `revision_id` bigint unsigned NOT NULL,
  `relative_path` varchar(512) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
  `access_mode` varchar(16) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
  `order_index` int unsigned NOT NULL,
  `content` longtext CHARACTER SET utf8mb4 COLLATE utf8mb4_bin NOT NULL,
  `content_sha256` char(64) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
  `size_bytes` int unsigned NOT NULL,
  PRIMARY KEY (`revision_id`,`relative_path`),
  UNIQUE KEY `uniq_lean_problem_revision_file_order` (`revision_id`,`order_index`),
  CONSTRAINT `lean_problem_revision_file_revision_fk` FOREIGN KEY (`revision_id`) REFERENCES `lean_problem_revisions` (`id`) ON DELETE CASCADE,
  CONSTRAINT `lean_problem_revision_file_mode_chk` CHECK ((`access_mode` in (_utf8mb4'readonly',_utf8mb4'writable')))
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

DROP TABLE IF EXISTS `lean_submission_workspaces`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `lean_submission_workspaces` (
  `submission_id` int NOT NULL,
  `problem_revision_id` bigint unsigned NOT NULL,
  `source_sha256` char(64) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
  `file_count` int unsigned NOT NULL,
  `total_size` bigint unsigned NOT NULL,
  `created_at` datetime NOT NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (`submission_id`),
  KEY `idx_lean_submission_workspace_revision` (`problem_revision_id`,`submission_id`),
  CONSTRAINT `lean_submission_workspace_submission_fk` FOREIGN KEY (`submission_id`) REFERENCES `submissions` (`id`) ON DELETE CASCADE,
  CONSTRAINT `lean_submission_workspace_revision_fk` FOREIGN KEY (`problem_revision_id`) REFERENCES `lean_problem_revisions` (`id`) ON DELETE RESTRICT,
  CONSTRAINT `lean_submission_workspace_file_count_chk` CHECK ((`file_count` > 0))
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

DROP TABLE IF EXISTS `lean_submission_files`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `lean_submission_files` (
  `submission_id` int NOT NULL,
  `relative_path` varchar(512) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
  `content` longtext CHARACTER SET utf8mb4 COLLATE utf8mb4_bin NOT NULL,
  `content_sha256` char(64) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
  `size_bytes` int unsigned NOT NULL,
  PRIMARY KEY (`submission_id`,`relative_path`),
  CONSTRAINT `lean_submission_file_workspace_fk` FOREIGN KEY (`submission_id`) REFERENCES `lean_submission_workspaces` (`submission_id`) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;
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
-- Table structure for table `plagiarism_records`
--

DROP TABLE IF EXISTS `plagiarism_records`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `plagiarism_records` (
  `id` bigint NOT NULL AUTO_INCREMENT,
  `user_id` int NOT NULL,
  `username` varchar(50) NOT NULL,
  `class_en` varchar(255) NOT NULL,
  `class_cn` varchar(255) DEFAULT NULL,
  `problem_id` int NOT NULL,
  `problem_title` varchar(255) DEFAULT NULL,
  `submission_id` int NOT NULL,
  `comparison_rule` varchar(64) NOT NULL,
  `matched_usernames` text NOT NULL,
  `created_at` datetime NOT NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (`id`),
  UNIQUE KEY `uniq_plagiarism_record` (`class_en`,`problem_id`,`username`,`submission_id`,`comparison_rule`),
  KEY `idx_plagiarism_username` (`username`),
  KEY `idx_plagiarism_class` (`class_en`),
  KEY `idx_plagiarism_class_problem` (`class_en`,`problem_id`),
  KEY `idx_plagiarism_user_problem` (`username`,`problem_id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

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
  `harness` varchar(32) DEFAULT NULL,
  `endpoint_id` bigint DEFAULT NULL,
  `endpoint_model` varchar(255) DEFAULT NULL,
  `context_window_tokens` int DEFAULT NULL,
  `max_output_tokens` int DEFAULT NULL,
  `status` varchar(32) NOT NULL DEFAULT 'Pending',
  `message` text,
  `best_score` int NOT NULL DEFAULT '0',
  `final_submission_id` int DEFAULT NULL,
  `latest_submission_id` int DEFAULT NULL,
  `attempts_json` longtext,
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
-- Table structure for table `agent_trace_sync_state`
--

DROP TABLE IF EXISTS `agent_trace_sync_state`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `agent_trace_sync_state` (
  `task_id` varchar(64) NOT NULL,
  `schema_version` smallint NOT NULL DEFAULT '2',
  `last_event_order` bigint unsigned NOT NULL DEFAULT '0',
  `next_item_index` int unsigned NOT NULL DEFAULT '1',
  `active_block_id` varchar(80) DEFAULT NULL,
  `active_item_index` int unsigned DEFAULT NULL,
  `token_usage_json` longtext,
  `migration_completed` tinyint(1) NOT NULL DEFAULT '0',
  `created_at` datetime NOT NULL DEFAULT CURRENT_TIMESTAMP,
  `updated_at` datetime NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  PRIMARY KEY (`task_id`),
  CONSTRAINT `chk_agent_trace_schema_version` CHECK (`schema_version` = 2),
  CONSTRAINT `chk_agent_trace_next_item` CHECK (`next_item_index` > 0),
  CONSTRAINT `chk_agent_trace_migration_completed` CHECK (`migration_completed` IN (0,1))
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `agent_trace_migrations`
--

DROP TABLE IF EXISTS `agent_trace_migrations`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `agent_trace_migrations` (
  `migration_key` varchar(64) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
  `summary_json` longtext NOT NULL,
  `completed_at` datetime NOT NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (`migration_key`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `agent_trace_events`
--

DROP TABLE IF EXISTS `agent_trace_events`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `agent_trace_events` (
  `id` bigint NOT NULL AUTO_INCREMENT,
  `task_id` varchar(64) NOT NULL,
  `event_id` varchar(80) NOT NULL,
  `event_order` bigint unsigned NOT NULL,
  `item_index` int unsigned NOT NULL,
  `block_id` varchar(80) DEFAULT NULL,
  `kind` varchar(16) NOT NULL,
  `title` varchar(255) DEFAULT NULL,
  `text` longtext,
  `meta` varchar(255) DEFAULT NULL,
  `format` varchar(16) NOT NULL DEFAULT 'text',
  `is_error` tinyint(1) NOT NULL DEFAULT '0',
  `message_id` varchar(64) DEFAULT NULL,
  `created_at` datetime NOT NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (`id`),
  UNIQUE KEY `uniq_agent_trace_event` (`task_id`,`event_id`),
  UNIQUE KEY `uniq_agent_trace_order` (`task_id`,`event_order`),
  KEY `idx_agent_trace_timeline` (`task_id`,`item_index`,`event_order`),
  KEY `idx_agent_trace_block` (`task_id`,`block_id`,`event_order`),
  KEY `idx_agent_trace_assistant` (`task_id`,`kind`,`event_order`),
  CONSTRAINT `chk_agent_trace_item_index` CHECK (`item_index` > 0),
  CONSTRAINT `chk_agent_trace_kind` CHECK (`kind` IN ('assistant','user','thinking','reasoning','tool','tool_call','tool_result','tool-result','subagent')),
  CONSTRAINT `chk_agent_trace_format` CHECK (`format` IN ('text','json')),
  CONSTRAINT `chk_agent_trace_is_error` CHECK (`is_error` IN (0,1))
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `agent_sessions`
--

DROP TABLE IF EXISTS `agent_sessions`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `agent_sessions` (
  `id` bigint NOT NULL AUTO_INCREMENT,
  `session_id` varchar(64) NOT NULL,
  `current_task_id` varchar(64) NOT NULL,
  `title` varchar(64) DEFAULT NULL,
  `task_kind` varchar(32) NOT NULL DEFAULT 'custom',
  `problem_id` int DEFAULT NULL,
  `problem_title` varchar(255) DEFAULT NULL,
  `requested_by` varchar(50) NOT NULL,
  `access_role` varchar(16) NOT NULL DEFAULT 'user',
  `harness` varchar(32) NOT NULL,
  `reasoning_effort` varchar(16) NOT NULL DEFAULT 'default',
  `endpoint_source` varchar(16) NOT NULL DEFAULT 'global',
  `endpoint_id` bigint NOT NULL,
  `endpoint_revision` bigint NOT NULL DEFAULT '1',
  `endpoint_model` varchar(255) NOT NULL,
  `native_session_id` varchar(128) DEFAULT NULL,
  `status` varchar(32) NOT NULL DEFAULT 'Pending',
  `message` text,
  `turn_count` int NOT NULL DEFAULT '1',
  `queue_paused` tinyint(1) NOT NULL DEFAULT '0',
  `queue_pause_reason` text,
  `fresh_native_session_pending` tinyint(1) NOT NULL DEFAULT '0',
  `created_at` datetime NOT NULL DEFAULT CURRENT_TIMESTAMP,
  `updated_at` datetime NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  PRIMARY KEY (`id`),
  UNIQUE KEY `uniq_agent_session_id` (`session_id`),
  UNIQUE KEY `uniq_agent_session_current_task` (`current_task_id`),
  KEY `idx_agent_sessions_status_updated` (`status`,`updated_at`),
  KEY `idx_agent_sessions_user_updated` (`requested_by`,`updated_at`),
  CONSTRAINT `chk_agent_sessions_access_role` CHECK (`access_role` IN ('user','admin')),
  CONSTRAINT `chk_agent_sessions_reasoning_effort` CHECK (`reasoning_effort` IN ('default','off','minimal','low','medium','high','xhigh','max')),
  CONSTRAINT `chk_agent_sessions_endpoint_source` CHECK (`endpoint_source` IN ('global','user')),
  CONSTRAINT `chk_agent_sessions_endpoint_revision` CHECK (`endpoint_revision` > 0),
  CONSTRAINT `chk_agent_sessions_turn_count` CHECK (`turn_count` > 0),
  CONSTRAINT `chk_agent_sessions_queue_paused` CHECK (`queue_paused` IN (0,1)),
  CONSTRAINT `chk_agent_sessions_fresh_native_pending` CHECK (`fresh_native_session_pending` IN (0,1))
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `agent_session_turns`
--

DROP TABLE IF EXISTS `agent_session_turns`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `agent_session_turns` (
  `id` bigint NOT NULL AUTO_INCREMENT,
  `session_id` varchar(64) NOT NULL,
  `task_id` varchar(64) NOT NULL,
  `turn_index` int NOT NULL,
  `user_message` longtext NOT NULL,
  `attachments_json` longtext,
  `base_runtime_checkpoint_id` varchar(64) DEFAULT NULL,
  `base_native_session_id` varchar(128) DEFAULT NULL,
  `retry_of_task_id` varchar(64) DEFAULT NULL,
  `superseded_by_task_id` varchar(64) DEFAULT NULL,
  `superseded_at` datetime DEFAULT NULL,
  `status` varchar(32) NOT NULL DEFAULT 'Pending',
  `conclusion` longtext,
  `created_at` datetime NOT NULL DEFAULT CURRENT_TIMESTAMP,
  `updated_at` datetime NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  PRIMARY KEY (`id`),
  UNIQUE KEY `uniq_agent_turn_task` (`task_id`),
  UNIQUE KEY `uniq_agent_session_turn` (`session_id`,`turn_index`),
  KEY `idx_agent_turns_session_created` (`session_id`,`created_at`),
  KEY `idx_agent_turns_session_visible` (`session_id`,`superseded_at`,`turn_index`),
  KEY `idx_agent_turns_retry_of` (`retry_of_task_id`),
  KEY `idx_agent_turns_superseded_by` (`superseded_by_task_id`),
  CONSTRAINT `fk_agent_turns_session` FOREIGN KEY (`session_id`) REFERENCES `agent_sessions` (`session_id`) ON DELETE CASCADE,
  CONSTRAINT `chk_agent_turn_index` CHECK (`turn_index` > 0)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `agent_session_messages`
--

DROP TABLE IF EXISTS `agent_session_messages`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `agent_session_messages` (
  `id` bigint NOT NULL AUTO_INCREMENT,
  `message_id` varchar(64) NOT NULL,
  `session_id` varchar(64) NOT NULL,
  `created_by` varchar(50) NOT NULL,
  `user_message` longtext NOT NULL,
  `attachments_json` longtext,
  `dispatch_payload_json` longtext,
  `delivery_mode` varchar(16) NOT NULL,
  `status` varchar(16) NOT NULL DEFAULT 'queued',
  `target_task_id` varchar(64) DEFAULT NULL,
  `final_task_id` varchar(64) DEFAULT NULL,
  `queue_position` bigint NOT NULL,
  `dispatch_attempt_id` varchar(64) DEFAULT NULL,
  `dispatch_attempted_at` datetime DEFAULT NULL,
  `broker_enqueued_at` datetime DEFAULT NULL,
  `error_message` text,
  `delivered_at` datetime DEFAULT NULL,
  `created_at` datetime NOT NULL DEFAULT CURRENT_TIMESTAMP,
  `updated_at` datetime NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  PRIMARY KEY (`id`),
  UNIQUE KEY `uniq_agent_message_id` (`message_id`),
  UNIQUE KEY `uniq_agent_message_final_task` (`final_task_id`),
  KEY `idx_agent_messages_session_queue` (`session_id`,`delivery_mode`,`status`,`queue_position`,`id`),
  KEY `idx_agent_messages_delivery_status` (`delivery_mode`,`status`,`session_id`,`final_task_id`),
  KEY `idx_agent_messages_dispatch_recovery` (`delivery_mode`,`status`,`broker_enqueued_at`,`dispatch_attempted_at`,`session_id`),
  KEY `idx_agent_messages_target_status` (`target_task_id`,`status`,`queue_position`),
  CONSTRAINT `fk_agent_messages_session` FOREIGN KEY (`session_id`) REFERENCES `agent_sessions` (`session_id`) ON DELETE CASCADE,
  CONSTRAINT `chk_agent_messages_delivery_mode` CHECK (`delivery_mode` IN ('turn','queue','steer')),
  CONSTRAINT `chk_agent_messages_status` CHECK (`status` IN ('queued','dispatching','sent','canceled','failed','unknown')),
  CONSTRAINT `chk_agent_messages_queue_position` CHECK (`queue_position` > 0)
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
  PRIMARY KEY (`id`),
  UNIQUE KEY `username` (`username`)
) ENGINE=InnoDB AUTO_INCREMENT=186 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `agent_launch_preferences`
--

DROP TABLE IF EXISTS `agent_launch_preferences`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `agent_launch_preferences` (
  `user_id` int NOT NULL,
  `harness` varchar(32) NOT NULL,
  `endpoint_source` varchar(16) NOT NULL DEFAULT 'global',
  `endpoint_id` bigint NOT NULL,
  `created_at` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP,
  `updated_at` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  PRIMARY KEY (`user_id`),
  KEY `idx_agent_launch_preferences_endpoint` (`endpoint_id`),
  CONSTRAINT `fk_agent_launch_preferences_user` FOREIGN KEY (`user_id`) REFERENCES `users` (`id`) ON DELETE CASCADE,
  CONSTRAINT `chk_agent_launch_preferences_endpoint_source` CHECK (`endpoint_source` IN ('global','user')),
  CONSTRAINT `chk_agent_launch_preferences_harness` CHECK (`harness` IN ('claude_code','codex','opencode','pi'))
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `agent_user_endpoints`
--

DROP TABLE IF EXISTS `agent_user_endpoints`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `agent_user_endpoints` (
  `id` bigint NOT NULL AUTO_INCREMENT,
  `user_id` int NOT NULL,
  `name` varchar(255) NOT NULL,
  `protocol` varchar(16) NOT NULL,
  `category` varchar(16) NOT NULL DEFAULT 'text',
  `base_url` varchar(1024) NOT NULL,
  `api_key` text NOT NULL,
  `model` varchar(255) NOT NULL,
  `context_window_tokens` int NOT NULL DEFAULT '384000',
  `max_output_tokens` int NOT NULL DEFAULT '32000',
  `thinking_enabled` tinyint(1) NOT NULL DEFAULT '0',
  `thinking_format` varchar(32) NOT NULL DEFAULT 'none',
  `test_status` varchar(16) NOT NULL DEFAULT 'untested',
  `test_message` text,
  `test_latency_ms` int DEFAULT NULL,
  `tested_at` datetime DEFAULT NULL,
  `revision` bigint NOT NULL DEFAULT '1',
  `created_at` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP,
  `updated_at` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  PRIMARY KEY (`id`),
  KEY `idx_agent_user_endpoints_user_model` (`user_id`,`model`,`id`),
  CONSTRAINT `fk_agent_user_endpoints_user` FOREIGN KEY (`user_id`) REFERENCES `users` (`id`) ON DELETE CASCADE,
  CONSTRAINT `chk_agent_user_endpoints_revision` CHECK (`revision` > 0)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;
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
  PRIMARY KEY (`user_id`,`class_en`),
  KEY `idx_user_id` (`user_id`),
  KEY `idx_class_en` (`class_en`),
  CONSTRAINT `user_class_map_ibfk_1` FOREIGN KEY (`user_id`) REFERENCES `users` (`id`) ON DELETE CASCADE,
  CONSTRAINT `user_class_map_ibfk_2` FOREIGN KEY (`class_en`) REFERENCES `class_table` (`class_en`) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `class_table`
--

LOCK TABLES `class_table` WRITE;
/*!40000 ALTER TABLE `class_table` DISABLE KEYS */;
INSERT INTO `class_table` (`class_en`, `class_cn`, `class_cnt`, `logo_seed`) VALUES
('Cdemo2024','演示班级2024',0,NULL),
('Ctest','测试班级',0,NULL);
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
INSERT INTO `users` (`id`, `username`, `password_hash`, `is_admin`, `email`) VALUES
(4,'admin','240be518fabd2724ddb6f04eeb1da5967448d7e831c08c8fa822809f74c720a9',1,'admin@example.com');
/*!40000 ALTER TABLE `users` ENABLE KEYS */;
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
INSERT INTO `problems` (`id`,`title`,`content`,`initial_code`,`testdata`,`cnt`,`forbidden_func`,`type`,`lang`,`max_score`,`test_code`,`time_limit_ms`,`submission_limit`,`programming_grading_mode`,`programming_grading_model`,`output_image_filename`,`programming_grading_prompt`,`written_grading_mode`,`written_grading_model`,`written_grading_prompt`) VALUES (2,'滑动窗口极差','给定一个长度为 `n` 的整数序列 `a_1, a_2, ..., a_n` 和窗口长度 `k`。对每一个连续子数组

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
-- Table structure for table `repository_states`
--

DROP TABLE IF EXISTS `repository_states`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `repository_states` (
  `user_id` int NOT NULL,
  `storage_key` char(32) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
  `structure_version` bigint unsigned NOT NULL DEFAULT '1',
  `repository_generation` bigint unsigned NOT NULL DEFAULT '1',
  `active_index_generation` bigint unsigned DEFAULT NULL,
  `index_status` varchar(16) CHARACTER SET ascii COLLATE ascii_bin NOT NULL DEFAULT 'stale',
  `entry_count` int unsigned NOT NULL DEFAULT '0',
  `total_size` bigint unsigned NOT NULL DEFAULT '0',
  `created_at` datetime NOT NULL DEFAULT CURRENT_TIMESTAMP,
  `updated_at` datetime NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  PRIMARY KEY (`user_id`),
  UNIQUE KEY `uq_repository_states_storage_key` (`storage_key`),
  CONSTRAINT `fk_repository_states_user` FOREIGN KEY (`user_id`) REFERENCES `users` (`id`) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `repository_entries`
--

DROP TABLE IF EXISTS `repository_entries`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `repository_entries` (
  `id` bigint unsigned NOT NULL AUTO_INCREMENT,
  `user_id` int NOT NULL,
  `parent_id` bigint unsigned DEFAULT NULL,
  `parent_scope` bigint unsigned NOT NULL,
  `name` varchar(255) CHARACTER SET utf8mb4 COLLATE utf8mb4_bin NOT NULL,
  `relative_path` varchar(1024) CHARACTER SET utf8mb4 COLLATE utf8mb4_bin NOT NULL,
  `path_hash` binary(32) NOT NULL,
  `entry_type` varchar(16) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
  `file_size` bigint unsigned NOT NULL DEFAULT '0',
  `file_version` bigint unsigned NOT NULL DEFAULT '0',
  `content_sha256` char(64) CHARACTER SET ascii COLLATE ascii_bin DEFAULT NULL,
  `created_at` datetime NOT NULL DEFAULT CURRENT_TIMESTAMP,
  `updated_at` datetime NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  PRIMARY KEY (`id`),
  UNIQUE KEY `uq_repository_entries_owner_id` (`user_id`,`id`),
  UNIQUE KEY `uq_repository_entries_sibling_name` (`user_id`,`parent_scope`,`name`),
  UNIQUE KEY `uq_repository_entries_path_hash` (`user_id`,`path_hash`),
  KEY `idx_repository_entries_parent` (`user_id`,`parent_id`,`entry_type`,`name`),
  CONSTRAINT `fk_repository_entries_user` FOREIGN KEY (`user_id`) REFERENCES `users` (`id`) ON DELETE CASCADE,
  CONSTRAINT `fk_repository_entries_parent_owner` FOREIGN KEY (`user_id`,`parent_id`) REFERENCES `repository_entries` (`user_id`,`id`) ON DELETE CASCADE,
  CONSTRAINT `chk_repository_entries_parent_scope` CHECK (`parent_scope` = ifnull(`parent_id`,0)),
  CONSTRAINT `chk_repository_entries_type` CHECK (`entry_type` IN ('file','directory')),
  CONSTRAINT `chk_repository_entries_file_shape` CHECK (
    (`entry_type` = 'directory' AND `file_size` = 0 AND `file_version` = 0 AND `content_sha256` IS NULL)
    OR
    (`entry_type` = 'file' AND `file_version` >= 1 AND `content_sha256` IS NOT NULL)
  )
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `repository_upload_sessions`
--

DROP TABLE IF EXISTS `repository_upload_sessions`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `repository_upload_sessions` (
  `id` char(32) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
  `user_id` int NOT NULL,
  `parent_id` bigint unsigned DEFAULT NULL,
  `base_structure_version` bigint unsigned NOT NULL,
  `status` varchar(16) CHARACTER SET ascii COLLATE ascii_bin NOT NULL DEFAULT 'preview',
  `manifest_json` longtext NOT NULL,
  `entry_count` int unsigned NOT NULL DEFAULT '0',
  `total_size` bigint unsigned NOT NULL DEFAULT '0',
  `expires_at` datetime NOT NULL,
  `created_at` datetime NOT NULL DEFAULT CURRENT_TIMESTAMP,
  `updated_at` datetime NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  PRIMARY KEY (`id`),
  KEY `idx_repository_upload_sessions_user_status` (`user_id`,`status`,`expires_at`),
  CONSTRAINT `fk_repository_upload_sessions_user` FOREIGN KEY (`user_id`) REFERENCES `users` (`id`) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `repository_delete_confirmations`
--

DROP TABLE IF EXISTS `repository_delete_confirmations`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `repository_delete_confirmations` (
  `id` char(32) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
  `user_id` int NOT NULL,
  `entry_id` bigint unsigned NOT NULL,
  `structure_version` bigint unsigned NOT NULL,
  `manifest_sha256` char(64) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
  `file_count` int unsigned NOT NULL DEFAULT '0',
  `directory_count` int unsigned NOT NULL DEFAULT '0',
  `total_size` bigint unsigned NOT NULL DEFAULT '0',
  `status` varchar(16) CHARACTER SET ascii COLLATE ascii_bin NOT NULL DEFAULT 'pending',
  `result_json` longtext,
  `expires_at` datetime NOT NULL,
  `created_at` datetime NOT NULL DEFAULT CURRENT_TIMESTAMP,
  `committed_at` datetime DEFAULT NULL,
  PRIMARY KEY (`id`),
  KEY `idx_repository_delete_confirmations_user` (`user_id`,`status`,`expires_at`),
  CONSTRAINT `fk_repository_delete_confirmations_user` FOREIGN KEY (`user_id`) REFERENCES `users` (`id`) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `repository_fs_journal`
--

DROP TABLE IF EXISTS `repository_fs_journal`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `repository_fs_journal` (
  `operation_id` char(32) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
  `user_id` int NOT NULL,
  `operation_type` varchar(32) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
  `status` varchar(16) CHARACTER SET ascii COLLATE ascii_bin NOT NULL DEFAULT 'prepared',
  `structure_version_before` bigint unsigned NOT NULL,
  `structure_version_after` bigint unsigned DEFAULT NULL,
  `payload_json` longtext NOT NULL,
  `error_message` text,
  `created_at` datetime NOT NULL DEFAULT CURRENT_TIMESTAMP,
  `updated_at` datetime NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  PRIMARY KEY (`operation_id`),
  KEY `idx_repository_fs_journal_user_status` (`user_id`,`status`,`created_at`),
  CONSTRAINT `fk_repository_fs_journal_user` FOREIGN KEY (`user_id`) REFERENCES `users` (`id`) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `submission_repository_snapshots`
--

DROP TABLE IF EXISTS `submission_repository_snapshots`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `submission_repository_snapshots` (
  `submission_id` int NOT NULL,
  `user_id` int NOT NULL,
  `snapshot_key` char(32) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
  `relative_root` varchar(255) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
  `repository_generation` bigint unsigned NOT NULL,
  `manifest_sha256` char(64) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
  `entry_count` int unsigned NOT NULL DEFAULT '0',
  `total_size` bigint unsigned NOT NULL DEFAULT '0',
  `created_at` datetime NOT NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (`submission_id`),
  UNIQUE KEY `uq_submission_repository_snapshots_key` (`snapshot_key`),
  KEY `idx_submission_repository_snapshots_user` (`user_id`,`created_at`),
  CONSTRAINT `fk_submission_repository_snapshots_submission` FOREIGN KEY (`submission_id`) REFERENCES `submissions` (`id`) ON DELETE CASCADE,
  CONSTRAINT `fk_submission_repository_snapshots_user` FOREIGN KEY (`user_id`) REFERENCES `users` (`id`) ON DELETE CASCADE
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
  `base_repository_generation` bigint unsigned NOT NULL DEFAULT '0',
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
  `index_generation` bigint unsigned NOT NULL DEFAULT '0',
  `repo_file_id` bigint unsigned DEFAULT NULL,
  `filename` varchar(1024) CHARACTER SET utf8mb4 COLLATE utf8mb4_0900_as_cs NOT NULL,
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
  `embedding_input_hash` char(64) CHARACTER SET ascii COLLATE ascii_bin NOT NULL DEFAULT '',
  `parser_version` varchar(64) CHARACTER SET ascii COLLATE ascii_bin NOT NULL DEFAULT '',
  `structured_model` varchar(191) NOT NULL DEFAULT '',
  `code` longtext NOT NULL,
  `params_json` longtext,
  `returns_json` longtext,
  `json_data` longtext NOT NULL,
  `created_at` datetime NOT NULL DEFAULT CURRENT_TIMESTAMP,
  `updated_at` datetime NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  PRIMARY KEY (`id`),
  UNIQUE KEY `uk_repository_function_chunks_generation_chunk` (`user_id`,`index_generation`,`chunk_id`),
  KEY `idx_repository_function_chunks_user_file` (`user_id`,`repo_file_id`),
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
  `index_generation` bigint unsigned NOT NULL DEFAULT '0',
  `repo_file_id` bigint unsigned DEFAULT NULL,
  `filename` varchar(1024) CHARACTER SET utf8mb4 COLLATE utf8mb4_0900_as_cs NOT NULL,
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
  UNIQUE KEY `uk_repository_class_metadata_generation_class` (`user_id`,`index_generation`,`class_id`),
  KEY `idx_repository_class_metadata_user_file` (`user_id`,`repo_file_id`),
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
  `index_generation` bigint unsigned NOT NULL DEFAULT '0',
  `embedding_model` varchar(128) NOT NULL,
  `vector_dim` int NOT NULL,
  `vector_json` longtext NOT NULL,
  `updated_at` datetime NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  PRIMARY KEY (`id`),
  UNIQUE KEY `uk_repository_chunk_embeddings_generation_chunk` (`user_id`,`index_generation`,`chunk_id`),
  KEY `idx_repository_chunk_embeddings_user_chunk` (`user_id`,`index_generation`,`chunk_id`),
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
  `agent_judge_timeout_seconds` int NOT NULL DEFAULT '1800',
  `reverse_judge_finalize_timeout_seconds` int NOT NULL DEFAULT '180',
  `reverse_quality_gate_enabled` tinyint(1) NOT NULL DEFAULT '0',
  `reverse_quality_gate_prompt` mediumtext,
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
  `agent_endpoint_id` int DEFAULT NULL,
  `agent_endpoint_harness` varchar(32) DEFAULT NULL,
  `agent_endpoint_model` varchar(128) DEFAULT NULL,
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
  KEY `idx_rs_created_source` (`created_at`,`source`),
  KEY `idx_rs_judge_attempt` (`judge_attempt_id`),
  KEY `idx_rs_judge_task` (`judge_task_id`),
  KEY `idx_rs_agent_endpoint` (`agent_endpoint_id`),
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
-- Table structure for table `ranking_reverse_judge_steps`
--

DROP TABLE IF EXISTS `ranking_reverse_judge_steps`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `ranking_reverse_judge_steps` (
  `id` int NOT NULL AUTO_INCREMENT,
  `submission_id` int NOT NULL,
  `step_key` varchar(32) NOT NULL,
  `step_order` int NOT NULL DEFAULT '0',
  `title` varchar(64) NOT NULL,
  `status` varchar(32) NOT NULL DEFAULT 'pending',
  `max_score` double DEFAULT NULL,
  `score` double DEFAULT NULL,
  `result_json` mediumtext,
  `stdout` mediumtext,
  `stderr` mediumtext,
  `error_message` text,
  `trace_dir` varchar(512) DEFAULT NULL,
  `started_at` timestamp NULL DEFAULT NULL,
  `finished_at` timestamp NULL DEFAULT NULL,
  `updated_at` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  PRIMARY KEY (`id`),
  UNIQUE KEY `uq_rrjs_sub_step` (`submission_id`,`step_key`),
  KEY `idx_rrjs_sub` (`submission_id`)
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
  `pool_kind` varchar(32) NOT NULL DEFAULT 'primary',
  `harness` varchar(32) NOT NULL DEFAULT 'claude_code',
  `protocol` varchar(16) DEFAULT NULL,
  `base_url` varchar(512) NOT NULL,
  `api_key` varchar(512) NOT NULL,
  `model` varchar(128) DEFAULT NULL,
  `context_window_tokens` int NOT NULL DEFAULT '1000000',
  `max_output_tokens` int NOT NULL DEFAULT '384000',
  `thinking_compatibility` tinyint(1) NOT NULL DEFAULT '1',
  `thinking_format` varchar(32) DEFAULT NULL,
  `concurrency_limit` int NOT NULL DEFAULT '1',
  `enabled` tinyint(1) NOT NULL DEFAULT '1',
  `status` varchar(16) NOT NULL DEFAULT 'enabled',
  `ordering` int NOT NULL DEFAULT '0',
  `created_at` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (`id`),
  KEY `idx_aje_comp` (`competition_id`),
  KEY `idx_aje_comp_pool` (`competition_id`,`pool_kind`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `llm_endpoints`
--

DROP TABLE IF EXISTS `llm_endpoints`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `llm_endpoints` (
  `id` bigint NOT NULL AUTO_INCREMENT,
  `protocol` varchar(16) NOT NULL,
  `category` varchar(16) NOT NULL,
  `base_url` varchar(1024) NOT NULL,
  `api_key` text NOT NULL,
  `model` varchar(255) NOT NULL,
  `context_window_tokens` int NOT NULL DEFAULT '384000',
  `max_output_tokens` int NOT NULL DEFAULT '32000',
  `thinking_enabled` tinyint(1) NOT NULL DEFAULT '0',
  `thinking_format` varchar(32) NOT NULL DEFAULT 'none',
  `input_price_per_million` decimal(20,8) NOT NULL,
  `cached_input_price_per_million` decimal(20,8) NOT NULL,
  `output_price_per_million` decimal(20,8) NOT NULL,
  `peak_pricing_enabled` tinyint(1) NOT NULL DEFAULT '0',
  `peak_time_ranges` varchar(1024) NOT NULL DEFAULT '',
  `peak_input_price_per_million` decimal(20,8) DEFAULT NULL,
  `peak_cached_input_price_per_million` decimal(20,8) DEFAULT NULL,
  `peak_output_price_per_million` decimal(20,8) DEFAULT NULL,
  `test_status` varchar(16) NOT NULL DEFAULT 'untested',
  `test_message` text,
  `test_latency_ms` int DEFAULT NULL,
  `tested_at` datetime DEFAULT NULL,
  `tested_by_user_id` int DEFAULT NULL,
  `is_locked` tinyint(1) NOT NULL DEFAULT '0',
  `lock_reason` varchar(1000) DEFAULT NULL,
  `locked_by_user_id` int DEFAULT NULL,
  `locked_at` datetime DEFAULT NULL,
  `revision` bigint NOT NULL DEFAULT '1',
  `created_by_user_id` int NOT NULL,
  `updated_by_user_id` int NOT NULL,
  `created_at` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP,
  `updated_at` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  PRIMARY KEY (`id`),
  KEY `idx_llm_endpoint_model` (`model`),
  KEY `idx_llm_endpoint_category` (`category`),
  KEY `idx_llm_endpoint_test_status` (`test_status`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `agent_quota_accounts`
--

DROP TABLE IF EXISTS `agent_quota_accounts`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `agent_quota_accounts` (
  `user_id` int NOT NULL,
  `granted_amount` decimal(30,14) NOT NULL DEFAULT '0',
  `used_amount` decimal(30,14) NOT NULL DEFAULT '0',
  `updated_by_user_id` int DEFAULT NULL,
  `adjustment_note` text,
  `created_at` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP,
  `updated_at` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  PRIMARY KEY (`user_id`),
  KEY `idx_agent_quota_accounts_updated_by` (`updated_by_user_id`),
  CONSTRAINT `fk_agent_quota_accounts_user` FOREIGN KEY (`user_id`) REFERENCES `users` (`id`) ON DELETE CASCADE,
  CONSTRAINT `fk_agent_quota_accounts_updated_by` FOREIGN KEY (`updated_by_user_id`) REFERENCES `users` (`id`) ON DELETE SET NULL,
  CONSTRAINT `chk_agent_quota_accounts_granted` CHECK (`granted_amount` >= 0),
  CONSTRAINT `chk_agent_quota_accounts_used` CHECK (`used_amount` >= 0)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `agent_quota_requests`
--

DROP TABLE IF EXISTS `agent_quota_requests`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `agent_quota_requests` (
  `id` bigint NOT NULL AUTO_INCREMENT,
  `user_id` int NOT NULL,
  `requested_amount` decimal(30,14) DEFAULT NULL,
  `approved_amount` decimal(30,14) DEFAULT NULL,
  `reason` text NOT NULL,
  `status` varchar(16) NOT NULL DEFAULT 'pending',
  `review_note` text,
  `reviewed_by_user_id` int DEFAULT NULL,
  `reviewed_at` datetime DEFAULT NULL,
  `created_at` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP,
  `updated_at` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  PRIMARY KEY (`id`),
  KEY `idx_agent_quota_requests_user_created` (`user_id`,`created_at`),
  KEY `idx_agent_quota_requests_status_created` (`status`,`created_at`),
  KEY `idx_agent_quota_requests_reviewer` (`reviewed_by_user_id`),
  CONSTRAINT `fk_agent_quota_requests_user` FOREIGN KEY (`user_id`) REFERENCES `users` (`id`) ON DELETE CASCADE,
  CONSTRAINT `fk_agent_quota_requests_reviewer` FOREIGN KEY (`reviewed_by_user_id`) REFERENCES `users` (`id`) ON DELETE SET NULL,
  CONSTRAINT `chk_agent_quota_requests_requested` CHECK (`requested_amount` > 0),
  CONSTRAINT `chk_agent_quota_requests_approved` CHECK (`approved_amount` IS NULL OR `approved_amount` > 0),
  CONSTRAINT `chk_agent_quota_requests_status` CHECK (`status` IN ('pending','approved','rejected'))
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `agent_quota_grants`
--

DROP TABLE IF EXISTS `agent_quota_grants`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `agent_quota_grants` (
  `id` bigint NOT NULL AUTO_INCREMENT,
  `user_id` int NOT NULL,
  `amount` decimal(30,14) NOT NULL,
  `kind` varchar(32) NOT NULL,
  `batch_id` char(32) DEFAULT NULL,
  `request_id` bigint DEFAULT NULL,
  `granted_by_user_id` int DEFAULT NULL,
  `note` text,
  `created_at` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (`id`),
  KEY `idx_agent_quota_grants_user_created` (`user_id`,`created_at`),
  KEY `idx_agent_quota_grants_batch` (`batch_id`),
  KEY `idx_agent_quota_grants_request` (`request_id`),
  KEY `idx_agent_quota_grants_granted_by` (`granted_by_user_id`),
  CONSTRAINT `fk_agent_quota_grants_user` FOREIGN KEY (`user_id`) REFERENCES `users` (`id`) ON DELETE CASCADE,
  CONSTRAINT `fk_agent_quota_grants_request` FOREIGN KEY (`request_id`) REFERENCES `agent_quota_requests` (`id`) ON DELETE SET NULL,
  CONSTRAINT `fk_agent_quota_grants_granted_by` FOREIGN KEY (`granted_by_user_id`) REFERENCES `users` (`id`) ON DELETE SET NULL,
  CONSTRAINT `chk_agent_quota_grants_amount` CHECK (`amount` <> 0),
  CONSTRAINT `chk_agent_quota_grants_kind` CHECK (`kind` IN ('request_approval','manual_adjustment','class_batch'))
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `agent_usage_ledger`
--

DROP TABLE IF EXISTS `agent_usage_ledger`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `agent_usage_ledger` (
  `id` bigint NOT NULL AUTO_INCREMENT,
  `user_id` int DEFAULT NULL,
  `session_id` varchar(64) NOT NULL,
  `task_id` varchar(64) NOT NULL,
  `source` varchar(32) NOT NULL,
  `usage_event_id` varchar(191) NOT NULL,
  `endpoint_id` bigint DEFAULT NULL,
  `endpoint_revision` bigint NOT NULL,
  `endpoint_model` varchar(255) NOT NULL,
  `input_uncached_tokens` bigint unsigned NOT NULL DEFAULT '0',
  `input_cached_tokens` bigint unsigned NOT NULL DEFAULT '0',
  `input_cache_write_tokens` bigint unsigned NOT NULL DEFAULT '0',
  `output_tokens` bigint unsigned NOT NULL DEFAULT '0',
  `reasoning_output_tokens` bigint unsigned NOT NULL DEFAULT '0',
  `input_price_per_million` decimal(30,14) NOT NULL,
  `cached_input_price_per_million` decimal(30,14) NOT NULL,
  `output_price_per_million` decimal(30,14) NOT NULL,
  `charged_amount` decimal(30,14) NOT NULL,
  `remaining_after` decimal(30,14) NOT NULL,
  `cached_fallback_request_count` bigint unsigned NOT NULL DEFAULT '0',
  `cached_fallback_input_tokens` bigint unsigned NOT NULL DEFAULT '0',
  `created_at` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (`id`),
  UNIQUE KEY `uniq_agent_usage_event` (`task_id`,`source`,`usage_event_id`),
  KEY `idx_agent_usage_user_created` (`user_id`,`created_at`),
  KEY `idx_agent_usage_session_created` (`session_id`,`created_at`),
  KEY `idx_agent_usage_endpoint` (`endpoint_id`),
  CONSTRAINT `fk_agent_usage_user` FOREIGN KEY (`user_id`) REFERENCES `users` (`id`) ON DELETE SET NULL,
  CONSTRAINT `fk_agent_usage_task` FOREIGN KEY (`task_id`) REFERENCES `agent_session_turns` (`task_id`) ON DELETE RESTRICT,
  CONSTRAINT `fk_agent_usage_endpoint` FOREIGN KEY (`endpoint_id`) REFERENCES `llm_endpoints` (`id`) ON DELETE SET NULL,
  CONSTRAINT `chk_agent_usage_endpoint_revision` CHECK (`endpoint_revision` > 0),
  CONSTRAINT `chk_agent_usage_prices` CHECK (`input_price_per_million` >= 0 AND `cached_input_price_per_million` >= 0 AND `output_price_per_million` >= 0),
  CONSTRAINT `chk_agent_usage_charge` CHECK (`charged_amount` >= 0)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `llm_feature_bindings`
--

DROP TABLE IF EXISTS `llm_feature_bindings`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `llm_feature_bindings` (
  `feature_key` varchar(64) NOT NULL,
  `endpoint_id` bigint DEFAULT NULL,
  `is_locked` tinyint(1) NOT NULL DEFAULT '0',
  `lock_reason` varchar(1000) DEFAULT NULL,
  `locked_by_user_id` int DEFAULT NULL,
  `locked_at` datetime DEFAULT NULL,
  `revision` bigint NOT NULL DEFAULT '1',
  `updated_by_user_id` int NOT NULL,
  `updated_at` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  PRIMARY KEY (`feature_key`),
  KEY `idx_llm_binding_endpoint` (`endpoint_id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `dynamic_config_test_grants`
--

DROP TABLE IF EXISTS `dynamic_config_test_grants`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `dynamic_config_test_grants` (
  `id` bigint NOT NULL AUTO_INCREMENT,
  `token_hash` char(64) NOT NULL,
  `config_kind` varchar(32) NOT NULL,
  `target_id` bigint DEFAULT NULL,
  `base_revision` bigint NOT NULL DEFAULT '0',
  `payload_fingerprint` char(64) NOT NULL,
  `status` varchar(16) NOT NULL,
  `test_message` text,
  `test_latency_ms` int DEFAULT NULL,
  `created_by_user_id` int NOT NULL,
  `created_at` datetime NOT NULL,
  `expires_at` datetime NOT NULL,
  `consumed_at` datetime DEFAULT NULL,
  PRIMARY KEY (`id`),
  UNIQUE KEY `uq_dynamic_config_test_token` (`token_hash`),
  KEY `idx_dynamic_config_test_lookup` (`config_kind`,`target_id`,`created_by_user_id`),
  KEY `idx_dynamic_config_test_expiry` (`expires_at`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `site_mail_settings`
--

DROP TABLE IF EXISTS `site_mail_settings`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `site_mail_settings` (
  `id` tinyint NOT NULL DEFAULT '1',
  `smtp_server` varchar(512) NOT NULL,
  `smtp_port` int NOT NULL,
  `smtp_username` varchar(512) NOT NULL,
  `smtp_password` text NOT NULL,
  `test_status` varchar(16) NOT NULL DEFAULT 'untested',
  `test_message` text,
  `test_latency_ms` int DEFAULT NULL,
  `tested_at` datetime DEFAULT NULL,
  `tested_by_user_id` int DEFAULT NULL,
  `revision` bigint NOT NULL DEFAULT '1',
  `updated_by_user_id` int NOT NULL,
  `updated_at` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  PRIMARY KEY (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `site_web_search_settings`
--

DROP TABLE IF EXISTS `site_web_search_settings`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `site_web_search_settings` (
  `id` tinyint NOT NULL DEFAULT '1',
  `base_url` varchar(1024) NOT NULL,
  `authorization` text NOT NULL,
  `test_status` varchar(16) NOT NULL DEFAULT 'untested',
  `test_message` text,
  `test_latency_ms` int DEFAULT NULL,
  `tested_at` datetime DEFAULT NULL,
  `tested_by_user_id` int DEFAULT NULL,
  `revision` bigint NOT NULL DEFAULT '1',
  `updated_by_user_id` int NOT NULL,
  `updated_at` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  PRIMARY KEY (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `vibehub_projects`
--

DROP TABLE IF EXISTS `vibehub_projects`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `vibehub_projects` (
  `id` bigint unsigned NOT NULL AUTO_INCREMENT,
  `slug` varchar(63) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
  `owner_id` int NOT NULL,
  `latest_version_id` bigint unsigned DEFAULT NULL,
  `public_version_id` bigint unsigned DEFAULT NULL,
  `review_version_id` bigint unsigned DEFAULT NULL,
  `last_reviewed_version_id` bigint unsigned DEFAULT NULL,
  `featured_status` varchar(16) CHARACTER SET ascii COLLATE ascii_bin NOT NULL DEFAULT 'none',
  `is_featured` tinyint(1) NOT NULL DEFAULT '0',
  `featured_requested_at` datetime DEFAULT NULL,
  `featured_reviewed_at` datetime DEFAULT NULL,
  `featured_reviewed_by_user_id` int DEFAULT NULL,
  `featured_review_note` text,
  `created_at` datetime NOT NULL DEFAULT CURRENT_TIMESTAMP,
  `updated_at` datetime NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  PRIMARY KEY (`id`),
  UNIQUE KEY `uq_vibehub_projects_slug` (`slug`),
  KEY `idx_vibehub_projects_owner_updated` (`owner_id`,`updated_at`),
  KEY `idx_vibehub_projects_public_featured` (`public_version_id`,`is_featured`,`updated_at`),
  KEY `idx_vibehub_projects_review` (`review_version_id`),
  KEY `idx_vibehub_projects_last_reviewed` (`last_reviewed_version_id`),
  KEY `idx_vibehub_projects_featured_review` (`featured_status`,`featured_requested_at`),
  CONSTRAINT `fk_vibehub_projects_owner` FOREIGN KEY (`owner_id`) REFERENCES `users` (`id`) ON DELETE CASCADE,
  CONSTRAINT `fk_vibehub_projects_featured_reviewer` FOREIGN KEY (`featured_reviewed_by_user_id`) REFERENCES `users` (`id`) ON DELETE SET NULL,
  CONSTRAINT `chk_vibehub_projects_featured_status` CHECK (`featured_status` IN ('none','pending','approved','rejected'))
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `vibehub_versions`
--

DROP TABLE IF EXISTS `vibehub_versions`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `vibehub_versions` (
  `id` bigint unsigned NOT NULL AUTO_INCREMENT,
  `project_id` bigint unsigned NOT NULL,
  `version_number` int unsigned NOT NULL,
  `created_by_user_id` int NOT NULL,
  `title` varchar(120) NOT NULL,
  `summary` varchar(500) NOT NULL DEFAULT '',
  `description` mediumtext,
  `tags_json` text NOT NULL,
  `cover_image` varchar(512) CHARACTER SET utf8mb4 COLLATE utf8mb4_bin DEFAULT NULL,
  `package_sha256` char(64) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
  `package_size` bigint unsigned NOT NULL,
  `manifest_json` text NOT NULL,
  `review_status` varchar(16) CHARACTER SET ascii COLLATE ascii_bin NOT NULL DEFAULT 'draft',
  `review_requested_at` datetime DEFAULT NULL,
  `reviewed_at` datetime DEFAULT NULL,
  `reviewed_by_user_id` int DEFAULT NULL,
  `review_note` text,
  `created_at` datetime NOT NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (`id`),
  UNIQUE KEY `uq_vibehub_versions_project_number` (`project_id`,`version_number`),
  KEY `idx_vibehub_versions_review` (`review_status`,`review_requested_at`),
  KEY `idx_vibehub_versions_creator` (`created_by_user_id`,`created_at`),
  CONSTRAINT `fk_vibehub_versions_project` FOREIGN KEY (`project_id`) REFERENCES `vibehub_projects` (`id`) ON DELETE CASCADE,
  CONSTRAINT `fk_vibehub_versions_creator` FOREIGN KEY (`created_by_user_id`) REFERENCES `users` (`id`) ON DELETE RESTRICT,
  CONSTRAINT `fk_vibehub_versions_reviewer` FOREIGN KEY (`reviewed_by_user_id`) REFERENCES `users` (`id`) ON DELETE SET NULL,
  CONSTRAINT `chk_vibehub_versions_number` CHECK (`version_number` > 0),
  CONSTRAINT `chk_vibehub_versions_review_status` CHECK (`review_status` IN ('draft','pending','approved','rejected'))
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

-- Dump completed on 2025-08-20 11:12:51
