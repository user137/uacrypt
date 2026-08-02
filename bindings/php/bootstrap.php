<?php

declare(strict_types=1);

/**
 * PHPUnit bootstrap - the compiled `dstu_core_php` extension itself must already be loaded by the
 * PHP CLI SAPI before this file runs (extensions load at startup, via `-d extension=...` or
 * `php.ini`, never at runtime - `cargo xtask php`/`bindings-php.yml` both pass `-d extension=...`
 * pointing at the freshly built binary). This file only pulls in the pure-PHP wrapper layer
 * (step 3) that isn't part of the compiled extension itself.
 */

if (!extension_loaded('dstu_core_php')) {
    fwrite(STDERR, "dstu_core_php extension is not loaded - pass -d extension=<path to the built .dll/.so>\n");
    exit(1);
}

require __DIR__ . '/lib/DstuCoreSecretStream.php';
