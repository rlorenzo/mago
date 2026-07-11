<?php

class My_Plugin {
    public function register($args, $name = 'post') {
        if (!isset($args['label'])) {
            $args['label'] = ucfirst($name);
        }

        foreach ($args as $key => $value) {
            update_option("my_plugin_{$key}", $value);
        }

        $callback = function ($x) use ($args) {
            return empty($x) ? $args : $this->handle($x, $args);
        };

        return apply_filters('my_plugin_args', $args, $name);
    }

    private function handle($x, $args) {
        return $x . ' ' . $args['label'];
    }
}

function my_plugin_init() {
    do_action('my_plugin_loaded');
}
