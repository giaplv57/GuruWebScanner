-- phpMyAdmin SQL Dump
-- version 4.0.10deb1
-- http://www.phpmyadmin.net
--
-- Host: localhost
-- Generation Time: May 08, 2016 at 01:31 AM
-- Server version: 5.5.43-0ubuntu0.14.04.1
-- PHP Version: 5.5.9-1ubuntu4.11

SET SQL_MODE = "NO_AUTO_VALUE_ON_ZERO";
SET time_zone = "+00:00";


/*!40101 SET @OLD_CHARACTER_SET_CLIENT=@@CHARACTER_SET_CLIENT */;
/*!40101 SET @OLD_CHARACTER_SET_RESULTS=@@CHARACTER_SET_RESULTS */;
/*!40101 SET @OLD_COLLATION_CONNECTION=@@COLLATION_CONNECTION */;
/*!40101 SET NAMES utf8 */;

--
-- Database: `guruWS`
--

-- --------------------------------------------------------

--
-- Table structure for table `malResult`
--

CREATE TABLE IF NOT EXISTS `malResult` (
  `projectID` varchar(128) NOT NULL,
  `result` longtext NOT NULL
) ENGINE=InnoDB DEFAULT CHARSET=latin1;

-- --------------------------------------------------------

--
-- Table structure for table `projectInfo`
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
-- Table structure for table `scanProgress`
--

CREATE TABLE IF NOT EXISTS `scanProgress` (
  `projectID` varchar(128) NOT NULL,
  `vulStatus` int(11) NOT NULL,
  `sigStatus` int(11) NOT NULL
) ENGINE=InnoDB DEFAULT CHARSET=latin1;

-- --------------------------------------------------------

--
-- Table structure for table `vulResult`
--

CREATE TABLE IF NOT EXISTS `vulResult` (
  `projectID` varchar(128) NOT NULL,
  `fileName` varchar(128) NOT NULL,
  `description` varchar(2048) NOT NULL,
  `flowpath` varchar(2048) NOT NULL,
  `dependencies` varchar(2048) NOT NULL
) ENGINE=InnoDB DEFAULT CHARSET=latin1;

-- --------------------------------------------------------

--
-- Table structure for table `webChecker`
--

CREATE TABLE IF NOT EXISTS `webChecker` (
  `id` INT(6) AUTO_INCREMENT PRIMARY KEY,
  `uwebsite` varchar(128) NOT NULL,
  `uemail` varchar(128) NOT NULL,
  `uname` varchar(128) NOT NULL,
  `ulang` varchar(128) NOT NULL,
  `ustatus` varchar(128) NOT NULL,
  `utime` INT(6)  
) ENGINE=InnoDB DEFAULT CHARSET=latin1;

/*!40101 SET CHARACTER_SET_CLIENT=@OLD_CHARACTER_SET_CLIENT */;
/*!40101 SET CHARACTER_SET_RESULTS=@OLD_CHARACTER_SET_RESULTS */;
/*!40101 SET COLLATION_CONNECTION=@OLD_COLLATION_CONNECTION */;
