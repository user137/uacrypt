<?php

declare(strict_types=1);

use PHPUnit\Framework\TestCase;

/**
 * T-219: concurrency contract for this binding, decided and recorded rather than assumed - and
 * decided differently from the other 7 bindings, for a real reason specific to PHP.
 *
 * Every other binding in this batch (.NET/Java/Go/C++/Python/Node.js/Ruby) has a real in-process
 * threading primitive (SafeHandle-guarded threads, goroutines, std::thread, Python's GIL-serialized
 * Threads, worker_threads, Ruby's GVL-serialized Threads) that a caller could plausibly use to
 * share one of this library's wrapper objects across. PHP does not, in the configuration this
 * binding is actually built and shipped against: `docs/bindings-strategy.md`'s own toolchain notes
 * (and this project's `.claude.local.md`) record every PHP install used for `bindings/php` - dev
 * machine and CI alike - as an NTS (non-thread-safe) build. On an NTS build, `ext-pthreads` cannot
 * even be compiled (it hard-requires ZTS), and the modern `parallel` extension has the same ZTS
 * requirement - so there is no `Thread`-like class, no shared-memory-across-threads mechanism, and
 * no way to even attempt calling this extension's functions from two threads at once. Each PHP
 * process (one per CLI invocation, or one per PHP-FPM worker in a real deployment) is a fully
 * separate OS process with its own copy of the extension's state - trivially safe, with nothing
 * for this binding to do or guard against, since nothing is ever shared.
 *
 * This test exists so that premise is verified on every CI run, not just asserted once in a
 * comment and left to rot: if a future PHP build this project switches to is ever ZTS instead, the
 * assertions below fail, and this binding's concurrency story needs re-deciding (most likely
 * following the Ruby/Python precedent - the underlying Rust types have no shared mutable state
 * across independent calls, and the PHP wrapper's stateful `SecretStreamPushState`/`PullState`
 * would need the same "one stream per thread, not shared" documentation those bindings already
 * carry).
 */
final class ThreadSafetyTest extends TestCase
{
    public function testRuntimeHasNoThreadSharingMechanism(): void
    {
        $this->assertFalse(
            \defined('PHP_ZTS') && \PHP_ZTS,
            'this binding assumes an NTS PHP build (see class doc) - a ZTS build changes the ' .
            'concurrency question this test exists to answer, and needs its own decision'
        );
        $this->assertFalse(
            \class_exists('Thread', false),
            'no ext-pthreads Thread class should be loadable on an NTS build'
        );
        $this->assertFalse(
            \class_exists('parallel\\Runtime', false),
            'no ext-parallel Runtime class should be loadable on an NTS build'
        );
    }
}
