<?php

//implemented after https://stackoverflow.com/questions/42/best-way-to-allow-plugins-for-a-php-application
$listeners = array();

/* create entry point
 * first parameter: hook name
 * second parameters: call parameters
 * third parameter: whether results are changes of the input and should be forwarded through the plugins
 * */
function call_plugins($hook_name, $args, $hook_forward_results = false) {
    global $listeners;

    $(!isset($listeners[$hook_name])) {
        // no plugins registered
        if ($hook_forward_results) {
            return $args;
        }
        else {
            return [];
        }
    }
    $results = [];
    foreach($listeners[$hook_name] as $func) {
        $parameters = $args;
        if ($hook_forward_results) {
            $parameters = end($results);
        }
        array_push($results, $func($parameters));
    }
    if ($hook_forward_results) {
        if (count($results) > 0) {
            return end($results);
        }
        else {
            return $args;
        }
    }
    else {
        return $results;
    }
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
