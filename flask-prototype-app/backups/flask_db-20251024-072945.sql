-- MySQL dump 10.13  Distrib 5.7.44, for Linux (x86_64)
--
-- Host: db    Database: flask_db
-- ------------------------------------------------------
-- Server version	5.7.44-log

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
SET @MYSQLDUMP_TEMP_LOG_BIN = @@SESSION.SQL_LOG_BIN;
SET @@SESSION.SQL_LOG_BIN= 0;

--
-- Current Database: `flask_db`
--

CREATE DATABASE /*!32312 IF NOT EXISTS*/ `flask_db` /*!40100 DEFAULT CHARACTER SET latin1 */;

USE `flask_db`;

--
-- Table structure for table `candidate`
--

DROP TABLE IF EXISTS `candidate`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `candidate` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `name` varchar(120) NOT NULL,
  `party` varchar(120) NOT NULL,
  `order` int(11) DEFAULT NULL,
  PRIMARY KEY (`id`)
) ENGINE=InnoDB AUTO_INCREMENT=2 DEFAULT CHARSET=latin1;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `candidate`
--

LOCK TABLES `candidate` WRITE;
/*!40000 ALTER TABLE `candidate` DISABLE KEYS */;
INSERT INTO `candidate` VALUES (1,'SEKIRO','ELECTRONIC ARTS',1);
/*!40000 ALTER TABLE `candidate` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `role`
--

DROP TABLE IF EXISTS `role`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `role` (
  `name` varchar(32) NOT NULL,
  `description` varchar(200) DEFAULT NULL,
  PRIMARY KEY (`name`)
) ENGINE=InnoDB DEFAULT CHARSET=latin1;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `role`
--

LOCK TABLES `role` WRITE;
/*!40000 ALTER TABLE `role` DISABLE KEYS */;
INSERT INTO `role` VALUES ('admin','System admin: manage candidates and system areas'),('clerk','Polling clerk: verify enrollment, assist voters'),('voter','Regular voter with minimal privileges');
/*!40000 ALTER TABLE `role` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `user_account`
--

DROP TABLE IF EXISTS `user_account`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `user_account` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `username` varchar(120) NOT NULL,
  `password_hash` varchar(255) NOT NULL,
  `mfa_secret` varchar(32) DEFAULT NULL,
  `mfa_enabled` tinyint(1) DEFAULT NULL,
  `voter_id` int(11) DEFAULT NULL,
  `role` varchar(32) NOT NULL,
  PRIMARY KEY (`id`),
  UNIQUE KEY `username` (`username`),
  KEY `voter_id` (`voter_id`),
  KEY `role` (`role`),
  CONSTRAINT `user_account_ibfk_1` FOREIGN KEY (`voter_id`) REFERENCES `voter` (`id`),
  CONSTRAINT `user_account_ibfk_2` FOREIGN KEY (`role`) REFERENCES `role` (`name`)
) ENGINE=InnoDB AUTO_INCREMENT=5 DEFAULT CHARSET=latin1;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `user_account`
--

LOCK TABLES `user_account` WRITE;
/*!40000 ALTER TABLE `user_account` DISABLE KEYS */;
INSERT INTO `user_account` VALUES (1,'admin','pbkdf2:sha256:260000$MDGXOI2OKYdbGUYj$36c2f60ee2ee016ef82460edf7231475c76dfd0d74bc83748213bda36051cdc7',NULL,0,NULL,'admin'),(2,'clerk','pbkdf2:sha256:260000$ZNMNAlf8hOEC6vqS$29588d319dc21e1fb73acae6cae41caf61f28d6ef43b95a33a296324aa1f785c',NULL,0,NULL,'clerk'),(3,'voter','pbkdf2:sha256:260000$UAoi1owvzCNFkTTP$1dde9e9b96b156a5cf041fd3eddd97e3d33d5c6c1f9d020b9ad2be594c201f66','EEU37R6FPGV4BSC4DYYOEPUY6RHHVWD5',0,NULL,'voter'),(4,'sam','pbkdf2:sha256:260000$QjrVSmzgkUKwFTUd$e43469635f01fb4e6856d49f3f15939b08cfe1d4c8dafa88ce3f6d58ea4a1b21','CE2H6NX4BFO6OCPUBZ3G7FI5BJSG7HGL',1,NULL,'voter');
/*!40000 ALTER TABLE `user_account` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `vote`
--

DROP TABLE IF EXISTS `vote`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `vote` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `voter_id` int(11) NOT NULL,
  `house_preferences` varchar(200) DEFAULT NULL,
  `senate_above` varchar(200) DEFAULT NULL,
  `senate_below` varchar(200) DEFAULT NULL,
  `source` varchar(50) DEFAULT NULL,
  PRIMARY KEY (`id`),
  KEY `voter_id` (`voter_id`),
  CONSTRAINT `vote_ibfk_1` FOREIGN KEY (`voter_id`) REFERENCES `voter` (`id`)
) ENGINE=InnoDB AUTO_INCREMENT=3 DEFAULT CHARSET=latin1;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `vote`
--

LOCK TABLES `vote` WRITE;
/*!40000 ALTER TABLE `vote` DISABLE KEYS */;
INSERT INTO `vote` VALUES (1,1,'1','','','electronic'),(2,2,'yMjZnUbETpZX61YKpADtqXRiKt2T547FoD5M5kI=','Pgc_FJEbhodZZhKFcywpjS76L1_rUID-shPIoC8=','U22SAO55IpMy_gQtLlVf2h_AKgkbpA0GjDPnOH4=','electronic');
/*!40000 ALTER TABLE `vote` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `vote_receipt`
--

DROP TABLE IF EXISTS `vote_receipt`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `vote_receipt` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `vote_id` int(11) NOT NULL,
  `receipt` varchar(64) NOT NULL,
  PRIMARY KEY (`id`),
  UNIQUE KEY `receipt` (`receipt`),
  KEY `vote_id` (`vote_id`),
  CONSTRAINT `vote_receipt_ibfk_1` FOREIGN KEY (`vote_id`) REFERENCES `vote` (`id`)
) ENGINE=InnoDB AUTO_INCREMENT=3 DEFAULT CHARSET=latin1;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `vote_receipt`
--

LOCK TABLES `vote_receipt` WRITE;
/*!40000 ALTER TABLE `vote_receipt` DISABLE KEYS */;
INSERT INTO `vote_receipt` VALUES (1,1,'1e808fbbd44e488d99fdaf89ae9b0b02'),(2,2,'4278fe83ca974d57bd17152bb7577c0e');
/*!40000 ALTER TABLE `vote_receipt` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `voter`
--

DROP TABLE IF EXISTS `voter`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `voter` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `name` varchar(120) NOT NULL,
  `address` varchar(200) NOT NULL,
  `enrolled` tinyint(1) DEFAULT NULL,
  PRIMARY KEY (`id`)
) ENGINE=InnoDB AUTO_INCREMENT=4 DEFAULT CHARSET=latin1;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `voter`
--

LOCK TABLES `voter` WRITE;
/*!40000 ALTER TABLE `voter` DISABLE KEYS */;
INSERT INTO `voter` VALUES (1,'ROCK','1234 STANFORD',1),(2,'james bond ','123 james',1),(3,'jack','sparrow',1);
/*!40000 ALTER TABLE `voter` ENABLE KEYS */;
UNLOCK TABLES;

--
-- GTID state at the end of the backup 
--

SET @@GLOBAL.GTID_PURGED='74e378dc-acd6-11f0-8545-7efaa0983e45:1-2';
/*!40103 SET TIME_ZONE=@OLD_TIME_ZONE */;

/*!40101 SET SQL_MODE=@OLD_SQL_MODE */;
/*!40014 SET FOREIGN_KEY_CHECKS=@OLD_FOREIGN_KEY_CHECKS */;
/*!40014 SET UNIQUE_CHECKS=@OLD_UNIQUE_CHECKS */;
/*!40101 SET CHARACTER_SET_CLIENT=@OLD_CHARACTER_SET_CLIENT */;
/*!40101 SET CHARACTER_SET_RESULTS=@OLD_CHARACTER_SET_RESULTS */;
/*!40101 SET COLLATION_CONNECTION=@OLD_COLLATION_CONNECTION */;
/*!40111 SET SQL_NOTES=@OLD_SQL_NOTES */;

-- Dump completed on 2025-10-24  7:29:45
