-- MySQL dump 10.13  Distrib 5.5.54, for debian-linux-gnu (x86_64)
--
-- Host: localhost    Database: cloudphish
-- ------------------------------------------------------
-- Server version	5.5.54-0ubuntu0.14.04.1

/*!40101 SET @OLD_CHARACTER_SET_CLIENT=@@CHARACTER_SET_CLIENT */;
/*!40101 SET @OLD_CHARACTER_SET_RESULTS=@@CHARACTER_SET_RESULTS */;
/*!40101 SET @OLD_COLLATION_CONNECTION=@@COLLATION_CONNECTION */;
/*!40101 SET NAMES utf8 */;
/*!40103 SET @OLD_TIME_ZONE=@@TIME_ZONE */;
/*!40103 SET TIME_ZONE='+00:00' */;
/*!40014 SET @OLD_UNIQUE_CHECKS=@@UNIQUE_CHECKS, UNIQUE_CHECKS=0 */;
/*!40014 SET @OLD_FOREIGN_KEY_CHECKS=@@FOREIGN_KEY_CHECKS, FOREIGN_KEY_CHECKS=0 */;
/*!40101 SET @OLD_SQL_MODE=@@SQL_MODE, SQL_MODE='NO_AUTO_VALUE_ON_ZERO' */;
/*!40111 SET @OLD_SQL_NOTES=@@SQL_NOTES, SQL_NOTES=0 */;

--
-- Table structure for table `analysis_results`
--

DROP TABLE IF EXISTS `analysis_results`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `analysis_results` (
  `sha256_url` binary(32) NOT NULL,
  `http_result_code` int(11) DEFAULT NULL,
  `http_message` varchar(256) DEFAULT NULL,
  `sha256_content` binary(32) DEFAULT NULL,
  `status` enum('NEW','ANALYZING','ANALYZED') NOT NULL DEFAULT 'NEW',
  `result` enum('UNKNOWN','ERROR','CLEAR','ALERT','PASS') NOT NULL DEFAULT 'UNKNOWN',
  `insert_date` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (`sha256_url`),
  KEY `insert_date_index` (`insert_date`),
  KEY `sha256_content_index` (`sha256_content`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `content_metadata`
--

DROP TABLE IF EXISTS `content_metadata`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `content_metadata` (
  `sha256_content` binary(32) NOT NULL,
  `location` varchar(255) DEFAULT NULL,
  `name` varbinary(4096) NOT NULL,
  PRIMARY KEY (`sha256_content`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `workload`
--

DROP TABLE IF EXISTS `workload`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `workload` (
  `sha256_url` binary(32) NOT NULL,
  `url` varchar(4096) NOT NULL,
  `node` varchar(128) DEFAULT NULL,
  `reprocess` tinyint(4) NOT NULL DEFAULT '0',
  `insert_date` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP,
  `alertable` tinyint(4) NOT NULL DEFAULT '0',
  `details` longblob,
  PRIMARY KEY (`sha256_url`),
  KEY `index_node` (`node`),
  CONSTRAINT `fk_workload_1` FOREIGN KEY (`sha256_url`) REFERENCES `analysis_results` (`sha256_url`) ON DELETE CASCADE ON UPDATE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8;
/*!40101 SET character_set_client = @saved_cs_client */;
/*!40103 SET TIME_ZONE=@OLD_TIME_ZONE */;

/*!40101 SET SQL_MODE=@OLD_SQL_MODE */;
/*!40014 SET FOREIGN_KEY_CHECKS=@OLD_FOREIGN_KEY_CHECKS */;
/*!40014 SET UNIQUE_CHECKS=@OLD_UNIQUE_CHECKS */;
/*!40101 SET CHARACTER_SET_CLIENT=@OLD_CHARACTER_SET_CLIENT */;
/*!40101 SET CHARACTER_SET_RESULTS=@OLD_CHARACTER_SET_RESULTS */;
/*!40101 SET COLLATION_CONNECTION=@OLD_COLLATION_CONNECTION */;
/*!40111 SET SQL_NOTES=@OLD_SQL_NOTES */;

-- Dump completed on 2018-08-22 16:13:07
