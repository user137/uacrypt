<?php

declare(strict_types=1);

use PHPUnit\Framework\TestCase;

/**
 * T-213: FFI memory-leak smoke test. Loops crypto_secretstream push/pull (the most stateful,
 * longest-lived native object this binding wraps - DstuCoreSecretStreamPushState/PullState) and
 * crypto_box seal/open (a keyed one-shot primitive) N=1000+ times with normal cleanup, then
 * asserts memory_get_usage(false) growth stays far below what a real leak of that many iterations
 * would show.
 *
 * IMPORTANT: this uses memory_get_usage(false) ("real" usage), not memory_get_usage(true) (total
 * memory allocated from the OS by the Zend Memory Manager's arena). Measured empirically before
 * writing this assertion: a negative control holding 2000 handles alive showed memory_get_usage(true)
 * flat at 0 growth - the arena is blind to this leak class entirely, since PHP's memory manager
 * doesn't shrink/regrow the arena per small allocation - while memory_get_usage(false) showed the
 * expected ~429KB growth for the same held objects. Using (true) here would have been a green test
 * that measures nothing.
 *
 * Same reasoning as bindings/python/tests/test_memory_leak.py (T-213) for *why* a leak would show up
 * at all: these wrapper objects are direct ext-php-rs handles around a Rust struct with no separate
 * C ABI free() call, so once the PHP wrapper is garbage-collected/refcounted to zero, Rust's own
 * Drop is guaranteed to run correctly - "the wrapper object never gets collected" (a held reference,
 * D-118's cleanup-hook pitfall) is the leak risk this test targets. PHP has no generational GC to
 * force explicitly the way Ruby/.NET/Java do - refcounting reclaims these objects immediately once
 * unset, and gc_collect_cycles() only matters for reference cycles, which none of these objects form.
 */
final class MemoryLeakTest extends TestCase
{
    public function testSecretstreamAndBoxLoopDoesNotLeak(): void
    {
        $n = 1000;
        // Measured normal-case growth is 0 bytes; a deliberate leak of all 2000 handles measures
        // ~429KB. This threshold sits with wide margin below that leak signal.
        $maxAcceptableGrowthBytes = $n * 100;

        $key = dstu_core_secretstream_keygen();
        $boxSecret = dstu_core_box_keygen();
        $boxPublic = dstu_core_box_public_key($boxSecret);

        gc_collect_cycles();
        $before = memory_get_usage(false);

        for ($i = 0; $i < $n; $i++) {
            $push = new DstuCoreSecretStreamPushState($key);
            $header = $push->header();
            [$ciphertext, $authTag] = $push->push(DSTU_CORE_SECRETSTREAM_TAG_MESSAGE, 'leak-check chunk');
            $pull = new DstuCoreSecretStreamPullState($key, $header);
            $pull->pull(DSTU_CORE_SECRETSTREAM_TAG_MESSAGE, $ciphertext, $authTag);
            unset($push, $pull, $header, $ciphertext, $authTag);

            $sealed = dstu_core_box_seal($boxPublic, 'leak-check message');
            $opened = dstu_core_box_open($boxSecret, $sealed);
            $this->assertSame('leak-check message', $opened);
            unset($sealed, $opened);
        }

        gc_collect_cycles();
        $after = memory_get_usage(false);
        $growth = $after - $before;
        $this->assertLessThan(
            $maxAcceptableGrowthBytes,
            $growth,
            "memory_get_usage(false) grew by {$growth} bytes over {$n} iterations "
            . "(threshold {$maxAcceptableGrowthBytes}) - possible native handle leak",
        );
    }
}
