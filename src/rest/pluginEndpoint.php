<?php

require_once dirname(__FILE__).'/../function/sqllink.php';
require_once dirname(__FILE__).'/../function/ajax.php';
require_once dirname(__FILE__).'/../function/plugins.php';

$link = sqllink();

// plugin should call ajaxSuccess
call_plugins($_GET["plugin"]+"_HTTP_"+$_GET["method"]);

ajaxError("noPluginFound");
