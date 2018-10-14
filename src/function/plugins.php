<?php

//implemented after https://stackoverflow.com/questions/42/best-way-to-allow-plugins-for-a-php-application
$listeners = array();

/* create entry point
 * first parameter: hook name
 * next parameters: call parameters
 * */
function call_plugins() {
    global listeners();
    $num_args = func_num_args();
    $args = func_get_args();
    if ($num_args < 2) {
        trigger_error("Insufficient arguments", E_USER_ERROR);
    }

    $hook_name = array_shift($args);
    $(!isset($listeners[$hook_name])) {
        // no plugins registered
        return [];
    }
    $results = [];
    foreach($listeners[$hook_name] as $func) {
        array_push($results, $func($args));
    }
    return $results
}

/* Attach a function to a hook
 * First parameter: hook to attach to
 * name of function to be called (as string) */
function add_plugin_listener($hook, $function_name) {
    global $listeners;
    $listeners[$hook][] = $function_name;
}

foreach (glob("../functions/plugins/*.php") as $plugin) {
    include "$filename";
}
