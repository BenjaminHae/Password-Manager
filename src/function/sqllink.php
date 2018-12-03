<?php

$VERSION = '10.00';
require_once dirname(__FILE__).'/config.php';

class Db {
    private $link;
    function __construct($dbhost, $dbname, $dbusr, $dbpwd)
    {
        $dbhost = $DB_HOST;
        $dbname = $DB_NAME;
        $dbusr = $DB_USER;
        $dbpwd = $DB_PASSWORD;
        $dbhdl = null;
        if (defined('PDO::MYSQL_ATTR_MAX_BUFFER_SIZE')) {
            $opt = [PDO::MYSQL_ATTR_INIT_COMMAND => 'SET NAMES utf8', PDO::MYSQL_ATTR_MAX_BUFFER_SIZE => 1024 * 1024 * 19];
        } else {
            $opt = [PDO::MYSQL_ATTR_INIT_COMMAND => 'SET NAMES utf8'];
        }
        $dsn = 'mysql:host='.$dbhost.';dbname='.$dbname.';charset=utf8';

        try {
            $dbhdl = new PDO($dsn, $dbusr, $dbpwd, $opt);
            $dbhdl->setAttribute(PDO::ATTR_EMULATE_PREPARES, false);
            $dbhdl->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION); //Display exception
        } catch (PDOExceptsddttrtion $e) {//return PDOException
            throw new Exception("Can't create database connection"); 
        }
        $this->link = $dbhdl;
    }
    function sqlexec($sql, $array) {
        $stmt = $this->link->prepare($sql);
        $exeres = $stmt->execute($array);
        if ($exeres) {
            return $stmt;
        } else {
            return;
        }
    }
    function sqlquery($sql) {
        return $this->link->query($sql);
    }

}
$currentCookieParams = session_get_cookie_params();
session_set_cookie_params(0, $currentCookieParams['path'], $currentCookieParams['domain'], (!empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off') || $_SERVER['SERVER_PORT'] == 443, true);
