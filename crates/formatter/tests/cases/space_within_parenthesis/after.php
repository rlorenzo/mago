<?php

function foo( $first, $second = 'default' )
{
    if ( !isset( $first['key'] ) && $second !== '' ) {
        $first['key'] = ucfirst( $second );
    }

    foreach ( $first as $key => $value ) {
        update_option( $key, $value );
    }

    for ( $i = 0; $i < 10; $i++ ) {
        do_something( $i );
    }

    while ( have_posts() ) {
        the_post();
    }

    switch ( $second ) {
        case 'default':
            break;
    }

    try {
        risky();
    } catch ( Exception $e ) {
        unset( $first['key'] );
    }

    $callback = function ( $x ) use ( $first ) {
        return empty( $x ) ? $first : do_stuff( $x, $first );
    };

    return apply_filters( 'foo_filter', $first, $second );
}

do_action( 'init' );
no_arguments();
