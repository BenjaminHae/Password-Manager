<?php
require_once dirname(__FILE__).'/sqllink.php';

class PluginException extends Exception { }

class User {
    private $db;
    private $id;
    private $data;
    private $authenticated = FALSE;
    function __construct($db, $id) {
        $this->db = $db;
        $this->id = $id;
    }
    static function fromUsername($db, $username) {
        $sql = 'SELECT `id` FROM `pwdusrrecord` WHERE `username` = ?';
        $res = $db->sqlexec($sql, [$username]);
        $record = $res->fetch(PDO::FETCH_ASSOC);
        if (!$record) {
            throw new Exception('loginFailed');
        }
        return new User($db, $record["id"]);
    }
    static function logon($db, $session, $username, $password) {
        $user = User::fromUsername($db, $username);
        try {
            $user->checkBanned();
            $user->checkPassword($password);
            
            // login is ok for now
            // now ask plugins if everything is alright
            // if a plugin returns Null login goes on
            // if a plugin returns a value, additional authentication is needed (p.e. 2FA)
            // if a plugin throws an exception: authentication failed
            $plugin_results = call_plugins("loginCredentialCheckSuccess", $user);
            foreach ($plugin_results as $plugin_result) {
                if ($plugin_result !== Null) {
                    // throw specialiced Exception that signals a plugin error that requires additional authentication
                    throw new PluginException($plugin_result);
                }
            }
        }
        catch (PluginException $pluginEx) {
            $session->persist($pluginEx->getMessage());
            $user->logAccess(2); // additional authentication needed
            throw $pluginEx;
        }
        catch (Exception $e) {
            $user->logAccess(0); // authentication failed
            $user->doIPBan();
            $session->invalidate();
            throw $e;
        }

        $user->logAccess(1); // authentication successfull
        $session->persist($user, "loggedIn");
        return $user;
    }

    function checkBanned() {
        global $ACCOUNT_BAN_TIME, $BLOCK_ACCOUNT_TRY;
        $sql = 'SELECT count(*) as `m` FROM `history` WHERE `userid` = ? AND outcome = 0 AND UNIX_TIMESTAMP( NOW( ) ) - UNIX_TIMESTAMP(`time`) < ?';
        $res = $this->db->sqlexec($sql, [(int) $this->id, $ACCOUNT_BAN_TIME]);
        $count = $res->fetch(PDO::FETCH_ASSOC);
        if ((int) $count['m'] >= $BLOCK_ACCOUNT_TRY) {
            throw new Exception("blockAccount");
        }
    }
    function checkPassword($password) {
        global $PBKDF2_ITERATIONS;
        if (strcmp((string) $this->data()['password'], (string) hash_pbkdf2('sha256', $pw, (string) $this->data()['salt'], $PBKDF2_ITERATIONS)) != 0) {
            throw new Exception('loginFailed');
        }
    }
    function logAccess($result) {
        function getUserIP() {
            if (isset($_SERVER['HTTP_X_FORWARDED_FOR']) && $_SERVER['HTTP_X_FORWARDED_FOR']) {
                return $_SERVER['HTTP_X_FORWARDED_FOR'];
            }

            return $_SERVER['REMOTE_ADDR'];
        }
        global $_SERVER;
        $ip = getUserIP();
        $r = $this->db->sqlquery('SELECT max(`id`) AS `m` FROM `history`')->fetch(PDO::FETCH_ASSOC);
        $i = (!$r) ? 0 : ((int) $r['m']) + 1;
        $sql = 'INSERT INTO `history` VALUES (?,?,?,?,?,CURRENT_TIMESTAMP)';
        $this->db->sqlexec($sql, [$i, $this->id, $ip, $_SERVER['HTTP_USER_AGENT'], (int)$result]);
    }
    function doIPBan() {
        $sql = 'SELECT count(*) as `m` FROM `history` WHERE `ip` = ? AND outcome = 0 AND UNIX_TIMESTAMP( NOW( ) ) - UNIX_TIMESTAMP(`time`) < ?';
        $res = $this->db->sqlexec($sql, [$ip, $BLOCK_IP_TIME]);
        $count = $res->fetch(PDO::FETCH_ASSOC);
        if ((int) $count['m'] >= $BLOCK_IP_TRY) {
            $sql = 'INSERT INTO `blockip` VALUES (?, CURRENT_TIMESTAMP)';
            $res = $this->db->sqlexec($sql, [$ip]);
        }
    }
    function data($forceReload = FALSE) {
        if ($forceReload || !$this->data) {
            $sql = 'SELECT * FROM `pwdusrrecord` WHERE `id` = ?';
            $res = $this->db->sqlexec($sql, [$usr]);
            $record = $res->fetch(PDO::FETCH_ASSOC);
            if (!$record) {
                throw new Exception("can't access user");
            }
            $this->data = $record;
        }
        return $this->data;
    }
    function getAccounts() {
        $res = $this->db->sqlexec('SELECT * FROM `password` WHERE `userid` = ?', [$id]);
        $accounts = [];
        while ($i = $res->fetch(PDO::FETCH_ASSOC)) {
            $accounts[] = ['index' => $i['index'], 'name' => $i['name'], 'additional' => $i['other'], 'kss' => $i['pwd']];
        }
        return $accounts;
    }
    function getFiles() {
        $res = $this->db->sqlexec('SELECT `index`,`fname`,`key` FROM `files` WHERE `userid` = ?', [$id]);
        $fdata = [];
        while ($i = $res->fetch(PDO::FETCH_ASSOC)) {
            $fdata[] = ['index' => $i['index'], 'fname' => $i['fname'], 'fkey' => $i['key']];
        }
        return $fdata;
    }
    //Todo: move to log
    function getLastLogins() {
        $sql = 'SELECT `id`, UNIX_TIMESTAMP(`time`) AS `time` FROM `history` WHERE `userid` = ? AND `outcome` = 1 ORDER BY `id` DESC LIMIT 1 OFFSET 1';
        $res = $this->db->sqlexec($sql, [$id]);
        $data = $res->fetch(PDO::FETCH_ASSOC);
        $loginID = $data['id'];
        $loginInformation = ['lastLogin' => $data['time']];

        $sql = 'SELECT COUNT(*) AS `failedLogins` FROM `history` WHERE `userid` = ? AND `outcome` = 0 AND `id` > ?';
        $res = $this->db->sqlexec($sql, [$id, $loginID]);
        $data = $res->fetch(PDO::FETCH_ASSOC);
        $loginInformation['failedCount'] = (int) $data['failedLogins'];
        return $loginInformation;
    }
}
class Session {
    private user;
    private authenticated = FALSE;
    private db;
    function __construct($db) {
        $this->db = $db;
    }
    function authenticate($refreshTimeout = TRUE, $allowUnauthenticated = FALSE) {
        global $_SESSION;
        global $SERVER_TIMEOUT, $SERVER_SOFT_TIMEOUT, $HOSTDOMAIN;
        session_start();
        try {
            if (!isset($_SESSION['authenticated']) || $_SESSION['authenticated'] !== TRUE) {
                throw new Exception('sessionInvalid');
            }
            if (isset($_SERVER['HTTP_REFERER']) && ($_SERVER['HTTP_REFERER'] != '') && (strpos(strtolower($_SERVER['HTTP_REFERER']), strtolower($HOSTDOMAIN)) !== 0)) {
                throw new Exception('refererInvalid');
            }
            if (($_SERVER['REQUEST_METHOD'] === 'POST') && ($_POST['session_token'] !== $_SESSION['session_token'])) {
                throw new Exception('csrf');
            }
            if (!isset($_SESSION['create_time']) || $_SESSION['create_time'] + $SERVER_TIMEOUT < time()) {
                throw new Exception('timeout');
            }
            if ($_SESSION['refresh_time'] + $SERVER_SOFT_TIMEOUT < time()) {
                throw new Exception('timeout');
            }
            if (!$this->db) {
                throw new Exception("link");
            }
            $id = $_SESSION['id'];
            if (!is_int($id)) {
                throw new Exception("id");
            }
            $this->authenticated = $_SESSION['authenticated'] === "loggedIn";
            $this->checkAuthenticated($allowUnauthenticated);
            $this->user = new User($this->db, $id);
            if ($refreshTimeout) {
                $_SESSION['refresh_time'] = time();
            }
        } catch (Exception $e) {
            $this->invalidate();
            throw $e;
        }
        return $this->user;
    }
    function persist($user, $authenticated, $time = 0) {
        global $_SESSION;
        if ($time === 0) {
            $time = time();
        }
        $_SESSION['id'] = $this->user;
        $_SESSION['authenticated'] = $authenticated;
        $_SESSION['create_time'] = $time;
        $_SESSION['refresh_time'] = $time;
    }
    function invalidate() {
        foreach ($_SESSION as $key => $value) {
            unset($_SESSION[$key]);
        }
        session_regenerate_id(TRUE); //as suggested by owasp, change sessionId when changing context
        session_destroy();
        if ($this->user) {
            unset($this->user);
        }
    }
    function checkAuthenticated($ignoreAuthentication = FALSE) {
        if (!$ignoreAuthentication && !$this->authenticated) {
            throw new Exception("unauthenticated");
        }
    }
    function user($unauthenticated = FALSE) {
        $this->checkAuthenticated($unauthenticated);
        return $this->user;
    }
}
?>
