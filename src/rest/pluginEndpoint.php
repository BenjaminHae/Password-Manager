<?php

require_once dirname(__FILE__).'/../function/sqllink.php';
require_once dirname(__FILE__).'/../function/ajax.php';
require_once dirname(__FILE__).'/../function/plugins.php';

$link = sqllink();

// plugin should call ajaxSuccess
call_plugins($_POST["plugin"] + "_HTTP_" + $_POST["method"], $_POST["data"]);

ajaxError("noPluginFound");
