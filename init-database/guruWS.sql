-- phpMyAdmin SQL Dump
-- version 4.4.13.1deb1
-- http://www.phpmyadmin.net
--
-- Client :  localhost
-- Généré le :  Lun 14 Mars 2016 à 05:30
-- Version du serveur :  5.6.27-0ubuntu1
-- Version de PHP :  5.6.11-1ubuntu3.1
 
SET SQL_MODE = "NO_AUTO_VALUE_ON_ZERO";
SET time_zone = "+00:00";
 
 
/*!40101 SET @OLD_CHARACTER_SET_CLIENT=@@CHARACTER_SET_CLIENT */;
/*!40101 SET @OLD_CHARACTER_SET_RESULTS=@@CHARACTER_SET_RESULTS */;
/*!40101 SET @OLD_COLLATION_CONNECTION=@@COLLATION_CONNECTION */;
/*!40101 SET NAMES utf8mb4 */;
 
--
-- Base de données :  `guruWS`
--
 
-- --------------------------------------------------------
 
--
-- Structure de la table `projectInfo`
--
 
CREATE TABLE IF NOT EXISTS `projectInfo` (
  `projectID` varchar(128) NOT NULL,
  `shareID` varchar(128) NOT NULL,
  `projectName` varchar(128) NOT NULL,
  `sha1Hash` varchar(128) NOT NULL,
  `scanTime` varchar(128) NOT NULL
) ENGINE=InnoDB DEFAULT CHARSET=latin1;
 
-- --------------------------------------------------------
 
--
-- Structure de la table `scanProgress`
--
 
CREATE TABLE IF NOT EXISTS `scanProgress` (
  `projectID` varchar(128) NOT NULL,
  `vulStatus` int(11) NOT NULL,
  `sigStatus` int(11) NOT NULL
) ENGINE=InnoDB DEFAULT CHARSET=latin1;
 
-- --------------------------------------------------------
 
--
-- Structure de la table `vulResult`
--
 
CREATE TABLE IF NOT EXISTS `vulResult` (
  `projectID` varchar(128) NOT NULL,
  `fileName` varchar(128) NOT NULL,
  `description` varchar(2048) NOT NULL,
  `flowpath` varchar(2048) NOT NULL,
  `dependencies` varchar(2048) NOT NULL
) ENGINE=InnoDB DEFAULT CHARSET=latin1;
 
/*!40101 SET CHARACTER_SET_CLIENT=@OLD_CHARACTER_SET_CLIENT */;
/*!40101 SET CHARACTER_SET_RESULTS=@OLD_CHARACTER_SET_RESULTS */;
/*!40101 SET COLLATION_CONNECTION=@OLD_COLLATION_CONNECTION */;
