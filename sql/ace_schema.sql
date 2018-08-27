-- MySQL dump 10.13  Distrib 5.5.53, for debian-linux-gnu (x86_64)
--
-- Host: localhost    Database: saq-production
-- ------------------------------------------------------
-- Server version	5.5.53-0ubuntu0.14.04.1

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
-- Table structure for table `alerts`
--

DROP TABLE IF EXISTS `alerts`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `alerts` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `uuid` char(36) NOT NULL,
  `insert_date` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP,
  `storage_dir` varchar(512) NOT NULL,
  `tool` varchar(256) NOT NULL,
  `tool_instance` varchar(1024) NOT NULL,
  `alert_type` varchar(64) NOT NULL,
  `description` varchar(1024) CHARACTER SET utf8 DEFAULT NULL,
  `priority` int(11) NOT NULL DEFAULT '0',
  `disposition` enum('FALSE_POSITIVE','IGNORE','UNKNOWN','REVIEWED','GRAYWARE','POLICY_VIOLATION','RECONNAISSANCE','WEAPONIZATION','DELIVERY','EXPLOITATION','INSTALLATION','COMMAND_AND_CONTROL','EXFIL','DAMAGE') DEFAULT NULL,
  `disposition_user_id` int(11) DEFAULT NULL,
  `disposition_time` timestamp NULL DEFAULT NULL,
  `owner_id` int(11) DEFAULT NULL,
  `owner_time` timestamp NULL DEFAULT NULL,
  `archived` tinyint(1) NOT NULL DEFAULT '0',
  `removal_user_id` int(11) DEFAULT NULL,
  `removal_time` timestamp NULL DEFAULT NULL,
  `lock_owner` varchar(256) DEFAULT NULL,
  `lock_id` varchar(36) DEFAULT NULL,
  `lock_transaction_id` varchar(36) DEFAULT NULL,
  `lock_time` datetime DEFAULT NULL,
  `company_id` int(11) DEFAULT NULL,
  `location` varchar(253) NOT NULL,
  `detection_count` int(11) DEFAULT '0',
  PRIMARY KEY (`id`),
  UNIQUE KEY `uuid` (`uuid`),
  KEY `insert_date` (`insert_date`),
  KEY `disposition_user_id` (`disposition_user_id`),
  KEY `owner_id` (`owner_id`),
  KEY `fk_removal_user_id` (`removal_user_id`),
  KEY `idx_company_id` (`company_id`),
  KEY `idx_location` (`location`),
  KEY `idx_disposition` (`disposition`),
  KEY `idx_alert_type` (`alert_type`),
  CONSTRAINT `fk_company` FOREIGN KEY (`company_id`) REFERENCES `company` (`id`) ON DELETE CASCADE ON UPDATE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=latin1;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `campaign`
--

DROP TABLE IF EXISTS `campaign`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `campaign` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `name` varchar(128) NOT NULL,
  PRIMARY KEY (`name`),
  KEY `id` (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=latin1;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `comments`
--

DROP TABLE IF EXISTS `comments`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `comments` (
  `comment_id` int(11) NOT NULL AUTO_INCREMENT,
  `insert_date` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP,
  `user_id` int(11) NOT NULL,
  `uuid` varchar(36) NOT NULL,
  `comment` text NOT NULL,
  PRIMARY KEY (`comment_id`),
  KEY `insert_date` (`insert_date`),
  KEY `user_id` (`user_id`),
  KEY `uuid` (`uuid`)
) ENGINE=InnoDB DEFAULT CHARSET=latin1;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `company`
--

DROP TABLE IF EXISTS `company`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `company` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `name` varchar(128) NOT NULL,
  PRIMARY KEY (`name`),
  KEY `id` (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=latin1;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `company_mapping`
--

DROP TABLE IF EXISTS `company_mapping`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `company_mapping` (
  `event_id` int(11) NOT NULL,
  `company_id` int(11) NOT NULL,
  PRIMARY KEY (`event_id`,`company_id`),
  KEY `company_mapping_ibfk_2` (`company_id`),
  CONSTRAINT `company_mapping_ibfk_1` FOREIGN KEY (`event_id`) REFERENCES `events` (`id`) ON DELETE CASCADE ON UPDATE CASCADE,
  CONSTRAINT `company_mapping_ibfk_2` FOREIGN KEY (`company_id`) REFERENCES `company` (`id`) ON DELETE CASCADE ON UPDATE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=latin1;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `delayed_analysis`
--

DROP TABLE IF EXISTS `delayed_analysis`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `delayed_analysis` (
  `alert_id` int(11) NOT NULL,
  `observable_id` char(36) NOT NULL,
  `analysis_module` varchar(512) NOT NULL,
  PRIMARY KEY (`alert_id`,`observable_id`,`analysis_module`),
  CONSTRAINT `fk_alert_id` FOREIGN KEY (`alert_id`) REFERENCES `alerts` (`id`) ON DELETE CASCADE ON UPDATE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=latin1;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `event_mapping`
--

DROP TABLE IF EXISTS `event_mapping`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `event_mapping` (
  `event_id` int(11) NOT NULL,
  `alert_id` int(11) NOT NULL,
  PRIMARY KEY (`event_id`,`alert_id`),
  KEY `event_mapping_ibfk_2` (`alert_id`),
  CONSTRAINT `event_mapping_ibfk_1` FOREIGN KEY (`event_id`) REFERENCES `events` (`id`) ON DELETE CASCADE ON UPDATE CASCADE,
  CONSTRAINT `event_mapping_ibfk_2` FOREIGN KEY (`alert_id`) REFERENCES `alerts` (`id`) ON DELETE CASCADE ON UPDATE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=latin1;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `events`
--

DROP TABLE IF EXISTS `events`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `events` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `creation_date` date NOT NULL,
  `name` varchar(128) NOT NULL,
  `type` enum('phish','recon','host compromise','credential compromise','web browsing') NOT NULL,
  `vector` enum('corporate email','webmail','usb','website','unknown') NOT NULL,
  `prevention_tool` enum('response team','ips','fw','proxy','antivirus','email filter','application whitelisting','user') NOT NULL,
  `remediation` enum('not remediated','cleaned with antivirus','cleaned manually','reimaged','credentials reset','removed from mailbox','NA') NOT NULL,
  `status` enum('OPEN','CLOSED','IGNORE') NOT NULL,
  `comment` text,
  `campaign_id` int(11) NOT NULL,
  PRIMARY KEY (`id`),
  UNIQUE KEY `creation_date` (`creation_date`,`name`)
) ENGINE=InnoDB DEFAULT CHARSET=latin1;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `malware`
--

DROP TABLE IF EXISTS `malware`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `malware` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `name` varchar(128) NOT NULL,
  PRIMARY KEY (`name`),
  KEY `id` (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=latin1;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `malware_mapping`
--

DROP TABLE IF EXISTS `malware_mapping`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `malware_mapping` (
  `event_id` int(11) NOT NULL,
  `malware_id` int(11) NOT NULL,
  PRIMARY KEY (`event_id`,`malware_id`),
  KEY `malware_mapping_ibfk_2` (`malware_id`),
  CONSTRAINT `malware_mapping_ibfk_1` FOREIGN KEY (`event_id`) REFERENCES `events` (`id`) ON DELETE CASCADE ON UPDATE CASCADE,
  CONSTRAINT `malware_mapping_ibfk_2` FOREIGN KEY (`malware_id`) REFERENCES `malware` (`id`) ON DELETE CASCADE ON UPDATE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=latin1;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `malware_threat_mapping`
--

DROP TABLE IF EXISTS `malware_threat_mapping`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `malware_threat_mapping` (
  `malware_id` int(11) NOT NULL,
  `type` enum('UNKNOWN','KEYLOGGER','INFOSTEALER','DOWNLOADER','BOTNET','RAT','RANSOMWARE','ROOTKIT','CLICK_FRAUD') NOT NULL,
  PRIMARY KEY (`malware_id`,`type`),
  CONSTRAINT `malware_threat_mapping_ibfk_1` FOREIGN KEY (`malware_id`) REFERENCES `malware` (`id`) ON DELETE CASCADE ON UPDATE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=latin1;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `observable_mapping`
--

DROP TABLE IF EXISTS `observable_mapping`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `observable_mapping` (
  `observable_id` int(11) NOT NULL,
  `alert_id` int(11) NOT NULL,
  PRIMARY KEY (`observable_id`,`alert_id`),
  KEY `observable_mapping_ibfk_2` (`alert_id`),
  CONSTRAINT `fk_observable_mapping_1` FOREIGN KEY (`observable_id`) REFERENCES `observables` (`id`) ON DELETE CASCADE ON UPDATE CASCADE,
  CONSTRAINT `fk_observable_mapping_2` FOREIGN KEY (`alert_id`) REFERENCES `alerts` (`id`) ON DELETE CASCADE ON UPDATE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=latin1;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `observables`
--

DROP TABLE IF EXISTS `observables`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `observables` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `type` varchar(64) NOT NULL,
  `value` varbinary(1024) NOT NULL,
  PRIMARY KEY (`id`),
  UNIQUE KEY `index_type_value` (`type`,`value`(255))
) ENGINE=InnoDB DEFAULT CHARSET=latin1;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `pp_alert_mapping`
--

DROP TABLE IF EXISTS `pp_alert_mapping`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `pp_alert_mapping` (
  `profile_point_id` int(11) NOT NULL,
  `alert_id` int(11) NOT NULL,
  PRIMARY KEY (`profile_point_id`,`alert_id`),
  KEY `fk_pp_alert_mapping_2_idx` (`alert_id`),
  CONSTRAINT `fk_pp_alert_mapping_1` FOREIGN KEY (`profile_point_id`) REFERENCES `profile_points` (`id`) ON DELETE CASCADE ON UPDATE CASCADE,
  CONSTRAINT `fk_pp_alert_mapping_2` FOREIGN KEY (`alert_id`) REFERENCES `alerts` (`id`) ON DELETE CASCADE ON UPDATE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=latin1;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `pp_tag_mapping`
--

DROP TABLE IF EXISTS `pp_tag_mapping`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `pp_tag_mapping` (
  `profile_point_id` int(11) NOT NULL,
  `tag_id` int(11) NOT NULL,
  PRIMARY KEY (`profile_point_id`,`tag_id`),
  KEY `fk_pp_tag_mapping_2_idx` (`tag_id`),
  CONSTRAINT `fk_pp_tag_mapping_1` FOREIGN KEY (`profile_point_id`) REFERENCES `profile_points` (`id`) ON DELETE CASCADE ON UPDATE CASCADE,
  CONSTRAINT `fk_pp_tag_mapping_2` FOREIGN KEY (`tag_id`) REFERENCES `tags` (`id`) ON DELETE CASCADE ON UPDATE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=latin1;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `profile_points`
--

DROP TABLE IF EXISTS `profile_points`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `profile_points` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `crits_id` char(24) DEFAULT NULL,
  `description` varchar(4096) NOT NULL,
  PRIMARY KEY (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=latin1;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `remediation`
--

DROP TABLE IF EXISTS `remediation`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `remediation` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `type` enum('email') NOT NULL,
  `action` enum('remove','restore') NOT NULL DEFAULT 'remove' COMMENT 'The action that was taken, either the time was removed or it was restored.',
  `insert_date` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP COMMENT 'The time the action occured.',
  `user_id` int(11) NOT NULL COMMENT 'The user who performed the action.',
  `key` varchar(256) NOT NULL COMMENT 'The key to look up the item.  In the case of emails this is the message_id and the recipient email address.',
  `result` text COMMENT 'The result of the action.  This is free form data for the analyst to see, usually includes error codes and messages.',
  `comment` text COMMENT 'Optional comment, additional free form data.',
  `successful` tinyint(4) DEFAULT '0' COMMENT '1 - remediation worked, 0 - remediation didn’t work',
  PRIMARY KEY (`id`),
  KEY `i_key` (`key`),
  KEY `fk_user_id_idx` (`user_id`),
  CONSTRAINT `fk_user_id` FOREIGN KEY (`user_id`) REFERENCES `users` (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=latin1;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `tag_mapping`
--

DROP TABLE IF EXISTS `tag_mapping`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `tag_mapping` (
  `tag_id` int(11) NOT NULL,
  `alert_id` int(11) NOT NULL,
  PRIMARY KEY (`tag_id`,`alert_id`),
  KEY `tag_mapping_ibfk_2` (`alert_id`),
  CONSTRAINT `fk_tag_mapping_1` FOREIGN KEY (`tag_id`) REFERENCES `tags` (`id`) ON DELETE CASCADE ON UPDATE CASCADE,
  CONSTRAINT `fk_tag_mapping_2` FOREIGN KEY (`alert_id`) REFERENCES `alerts` (`id`) ON DELETE CASCADE ON UPDATE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=latin1;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `tags`
--

DROP TABLE IF EXISTS `tags`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `tags` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `name` varchar(256) NOT NULL,
  PRIMARY KEY (`id`),
  UNIQUE KEY `name` (`name`)
) ENGINE=InnoDB DEFAULT CHARSET=latin1;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `users`
--

DROP TABLE IF EXISTS `users`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `users` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `username` varchar(64) NOT NULL,
  `password_hash` char(128) DEFAULT NULL,
  `email` varchar(64) NOT NULL,
  `omniscience` int(11) NOT NULL DEFAULT '0',
  PRIMARY KEY (`id`),
  UNIQUE KEY `username` (`username`,`email`)
) ENGINE=InnoDB DEFAULT CHARSET=latin1;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `workload`
--

DROP TABLE IF EXISTS `workload`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `workload` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `alert_id` int(11) NOT NULL,
  `node` varchar(256) DEFAULT NULL COMMENT 'the node that has claimed this work item',
  PRIMARY KEY (`id`),
  KEY `alert_id` (`alert_id`)
) ENGINE=InnoDB DEFAULT CHARSET=latin1 COMMENT='the list of alerts that need to be analyzed';
/*!40101 SET character_set_client = @saved_cs_client */;
/*!40103 SET TIME_ZONE=@OLD_TIME_ZONE */;

/*!40101 SET SQL_MODE=@OLD_SQL_MODE */;
/*!40014 SET FOREIGN_KEY_CHECKS=@OLD_FOREIGN_KEY_CHECKS */;
/*!40014 SET UNIQUE_CHECKS=@OLD_UNIQUE_CHECKS */;
/*!40101 SET CHARACTER_SET_CLIENT=@OLD_CHARACTER_SET_CLIENT */;
/*!40101 SET CHARACTER_SET_RESULTS=@OLD_CHARACTER_SET_RESULTS */;
/*!40101 SET COLLATION_CONNECTION=@OLD_COLLATION_CONNECTION */;
/*!40111 SET SQL_NOTES=@OLD_SQL_NOTES */;

-- Dump completed on 2018-08-20 14:47:26
