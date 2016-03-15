-- phpMyAdmin SQL Dump
-- version 4.0.10deb1
-- http://www.phpmyadmin.net
--
-- Host: localhost
-- Generation Time: Mar 14, 2016 at 11:14 PM
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

--
-- Dumping data for table `vulResult`
--

INSERT INTO `vulResult` (`projectID`, `fileName`, `description`, `flowpath`, `dependencies`) VALUES
('07d6dcda036cd93a13228a6b7bbe7be64f6f32ca', '/grandprix(tainted)/upload.php', 'XSS VULNERABILITY FOUND AT echo IN FILE /grandprix(tainted)/upload.php LINE 27', '/grandprix(tainted)/upload.php:27:echo (&#039;&lt;div class=&quot;alert alert-danger col-md-6 col-md-offset-3&quot; role=&quot;alert&quot;&gt;<br />\r\n							  	&lt;center&gt;<br />\r\n								  	&lt;strong&gt;Error!&lt;/strong&gt;<br />\r\n								  	&#039; . $FileName) . &#039; already exists!.<br />\r\n							  	&lt;/center&gt;<br />\r\n							  &lt;/div&gt;&#039;<br />\n/grandprix(tainted)/upload.php:17:$FileName = (unicode_str_filter($_POST[&#039;filename&#039;]) . &#039;.&#039;) . $Extension<br />\n', '/grandprix(tainted)/upload.php:3:if (((!empty($_FILES) &amp; isset($_POST[&#039;filetype&#039;])) &amp; isset($_POST[&#039;filename&#039;])) &amp; isset($_SESSION[&#039;username&#039;]))<br />\n/grandprix(tainted)/upload.php:7:else<br />\n/grandprix(tainted)/upload.php:22:if ($_FILES[&#039;file&#039;][&#039;size&#039;] &lt; 2097152 &amp;&amp; !in_array($Extension, $BlackListExts))<br />\n/grandprix(tainted)/upload.php:25:else<br />\n/grandprix(tainted)/upload.php:26:if (file_exists($Location))<br />\n'),
('07d6dcda036cd93a13228a6b7bbe7be64f6f32ca', '/grandprix(tainted)/upload.php', '-+-SQL VULNERABILITY FOUND AT mysqli_query (DEBUG A3) IN FILE /grandprix(tainted)/upload.php LINE 34', '/grandprix(tainted)/upload.php:34:mysqli_query($con, &quot;INSERT INTO files (uid, filetype, filename, filesize, location) VALUES ({$UserId}, {$FileType}, &#039;{$FileName}&#039;, &#039;{$FileSize}&#039;, &#039;{$Location}&#039;)&quot;)<br />\n/grandprix(tainted)/upload.php:18:$FileType = $_POST[&#039;filetype&#039;]<br />\n/grandprix(tainted)/upload.php:17:$FileName = (unicode_str_filter($_POST[&#039;filename&#039;]) . &#039;.&#039;) . $Extension<br />\n/grandprix(tainted)/upload.php:20:$Location = &#039;files/&#039; . $FileName<br />\n', '/grandprix(tainted)/upload.php:3:if (((!empty($_FILES) &amp; isset($_POST[&#039;filetype&#039;])) &amp; isset($_POST[&#039;filename&#039;])) &amp; isset($_SESSION[&#039;username&#039;]))<br />\n/grandprix(tainted)/upload.php:7:else<br />\n/grandprix(tainted)/upload.php:22:if ($_FILES[&#039;file&#039;][&#039;size&#039;] &lt; 2097152 &amp;&amp; !in_array($Extension, $BlackListExts))<br />\n/grandprix(tainted)/upload.php:25:else<br />\n/grandprix(tainted)/upload.php:33:else<br />\n'),
('07d6dcda036cd93a13228a6b7bbe7be64f6f32ca', '/grandprix(tainted)/register.php', 'XSS VULNERABILITY FOUND AT echo IN FILE /grandprix(tainted)/register.php LINE 29', '/grandprix(tainted)/register.php:29:echo (((&#039;&lt;div class=&quot;alert alert-success col-md-8 col-md-offset-2&quot; role=&quot;alert&quot;&gt;<br />\r\n					  	&lt;center&gt;<br />\r\n					  		&lt;strong&gt;Success!&lt;/strong&gt;<br />\r\n					  	 	 Your username is: &#039;&#039; . $username) . &#039;&#039;, your password is: &#039;&#039;) . $password) . &#039;&#039;<br />\r\n					  	 	 &lt;br&gt;<br />\r\n					  	 	 You can login to enjoy our service now!!!<br />\r\n					  	&lt;/center&gt;<br />\r\n					  &lt;/div&gt;&#039;<br />\n/grandprix(tainted)/register.php:22:$username = filter($username)<br />\n/grandprix(tainted)/register.php:21:$username = unicode_str_filter($_POST[&#039;username&#039;])<br />\n/grandprix(tainted)/validate.php:27:return $str<br />\n/grandprix(tainted)/validate.php:25:$str = preg_replace(&quot;/({$uni})/i&quot;, $nonUnicode, $str)<br />\n/grandprix(tainted)/validate.php:5:return $src<br />\n/grandprix(tainted)/validate.php:4:$src = addslashes($src)<br />\n/grandprix(tainted)/validate.php:3:$src = stripslashes($src)<br />\n/grandprix(tainted)/register.php:29:echo (((&#039;&lt;div class=&quot;alert alert-success col-md-8 col-md-offset-2&quot; role=&quot;alert&quot;&gt;<br />\r\n					  	&lt;center&gt;<br />\r\n					  		&lt;strong&gt;Success!&lt;/strong&gt;<br />\r\n					  	 	 Your username is: &#039;&#039; . $username) . &#039;&#039;, your password is: &#039;&#039;) . $password) . &#039;&#039;<br />\r\n					  	 	 &lt;br&gt;<br />\r\n					  	 	 You can login to enjoy our service now!!!<br />\r\n					  	&lt;/center&gt;<br />\r\n					  &lt;/div&gt;&#039;<br />\n/grandprix(tainted)/register.php:22:$username = filter($username)<br />\n/grandprix(tainted)/register.php:21:$username = unicode_str_filter($_POST[&#039;username&#039;])<br />\n/grandprix(tainted)/validate.php:27:return $str<br />\n/grandprix(tainted)/validate.php:25:$str = preg_replace(&quot;/({$uni})/i&quot;, $nonUnicode, $str)<br />\n/grandprix(tainted)/validate.php:5:return $src<br />\n/grandprix(tainted)/validate.php:4:$src = addslashes($src)<br />\n/grandprix(tainte', '/grandprix(tainted)/register.php:19:if (isset($_POST[&#039;username&#039;]))<br />\n/grandprix(tainted)/register.php:23:if ($username !== &#039;&#039;)<br />\n/grandprix(tainted)/register.php:27:if (mysqli_num_rows($check) == 0)<br />\n/grandprix(tainted)/register.php:19:if (isset($_POST[&#039;username&#039;]))<br />\n/grandprix(tainted)/register.php:23:if ($username !== &#039;&#039;)<br />\n/grandprix(tainted)/register.php:27:if (mysqli_num_rows($check) == 0)<br />\n');

/*!40101 SET CHARACTER_SET_CLIENT=@OLD_CHARACTER_SET_CLIENT */;
/*!40101 SET CHARACTER_SET_RESULTS=@OLD_CHARACTER_SET_RESULTS */;
/*!40101 SET COLLATION_CONNECTION=@OLD_COLLATION_CONNECTION */;
