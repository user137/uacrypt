<?php

declare(strict_types=1);

use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

/**
 * Streaming crypto_box/crypto_box384/crypto_box512 (T-265 format v3, T-269, T-297):
 * DstuCoreSecretStreamWriter::forBox/forBox384/forBox512 and the matching readers over the core's seal_stream/open_stream. Happy path: the
 * shared v3 vectors (one-shot open and the streaming reader), a round trip across record
 * boundaries, one-shot/streaming byte equivalence. Security: tampering, a wrong key, trailing
 * data. Misuse: wrong-length keys, a cut prefix, the 0.4-0.6 format. Error path: a writer whose
 * caller failed before close() leaves no Final record (D-118). Mirrors
 * bindings/python/tests/test_box_stream.py.
 */
final class BoxStreamTest extends TestCase
{
    /** @return array<string, array{int}> */
    public static function curves(): array
    {
        return ['box256' => [256], 'box384' => [384], 'box512' => [512]];
    }

    private static function vectors(string $name): array
    {
        $path = dirname(__DIR__, 3) . "/crates/dstu-core/tests/vectors/box/{$name}";

        return json_decode(file_get_contents($path), true, flags: JSON_THROW_ON_ERROR);
    }

    private static function pattern(int $n): string
    {
        $out = '';
        for ($i = 0; $i < $n; $i++) {
            $out .= chr(($i * 31 + 7) % 256);
        }

        return $out;
    }

    /** @return resource */
    private static function memoryStream(string $initial = ''): mixed
    {
        $s = fopen('php://memory', 'w+b');
        fwrite($s, $initial);
        rewind($s);

        return $s;
    }

    private static function oneShotOpen(int $curve, string $secret, string $sealed): string
    {
        return match ($curve) {
            256 => dstu_core_box_open($secret, $sealed),
            384 => dstu_core_box384_open($secret, $sealed),
            default => dstu_core_box512_open($secret, $sealed),
        };
    }

    private static function streamOpen(int $curve, string $secret, string $sealed): string
    {
        $in = self::memoryStream($sealed);
        $reader = match ($curve) {
            256 => DstuCoreSecretStreamReader::forBox($secret, $in),
            384 => DstuCoreSecretStreamReader::forBox384($secret, $in),
            default => DstuCoreSecretStreamReader::forBox512($secret, $in),
        };

        return $reader->readAll();
    }

    private static function keypair(int $curve): array
    {
        $secret = match ($curve) {
            256 => dstu_core_box_keygen(),
            384 => dstu_core_box384_keygen(),
            default => dstu_core_box512_keygen(),
        };
        $public = match ($curve) {
            256 => dstu_core_box_public_key($secret),
            384 => dstu_core_box384_public_key($secret),
            default => dstu_core_box512_public_key($secret),
        };

        return [$secret, $public];
    }

    private static function streamSeal(int $curve, string $public, string $message): string
    {
        $out = self::memoryStream();
        $writer = match ($curve) {
            256 => DstuCoreSecretStreamWriter::forBox($public, $out),
            384 => DstuCoreSecretStreamWriter::forBox384($public, $out),
            default => DstuCoreSecretStreamWriter::forBox512($public, $out),
        };
        $writer->write(substr($message, 0, 7));
        $writer->write(substr($message, 7));
        $writer->close();
        rewind($out);

        return stream_get_contents($out);
    }

    #[DataProvider('curves')]
    public function testSharedV3VectorsGiveTheirExpectedOutcome(int $curve): void
    {
        $vectors = self::vectors('v3.json');
        $secret = hex2bin($vectors["box{$curve}_secret_key_hex"]);
        $seen = 0;
        foreach ($vectors['cases'] as $case) {
            if ($case['curve'] !== $curve) {
                continue;
            }
            $sealed = hex2bin($case['sealed_hex']);
            if ($case['expect'] === 'ok') {
                $expected = self::pattern($case['plaintext_len']);
                $this->assertSame($expected, self::oneShotOpen($curve, $secret, $sealed), $case['name']);
                $this->assertSame($expected, self::streamOpen($curve, $secret, $sealed), $case['name']);
            } else {
                $opens = [
                    'one-shot' => fn () => self::oneShotOpen($curve, $secret, $sealed),
                    'streaming' => fn () => self::streamOpen($curve, $secret, $sealed),
                ];
                foreach ($opens as $name => $open) {
                    try {
                        $open();
                        $this->fail("{$case['name']}: {$name} open accepted it");
                    } catch (DstuCoreException) {
                        $this->addToAssertionCount(1);
                    }
                }
            }
            $seen++;
        }
        $this->assertGreaterThan(0, $seen);
    }

    #[DataProvider('curves')]
    public function testTheZeroSixFormatIsRefusedAsUnsupported(int $curve): void
    {
        $vectors = self::vectors('legacy_v2.json');
        if ($curve === 384) {
            // 0.4-0.6 had no l(p)=384 (T-297): a version-2 byte stands in for such a file.
            [$secret] = self::keypair($curve);
            $vectors = ['cases' => [['curve' => 384, 'sealed_hex' => bin2hex("\x02" . str_repeat("\x00", 240))]]];
        } else {
            $secret = hex2bin($vectors["box{$curve}_secret_key_hex"]);
        }
        foreach ($vectors['cases'] as $case) {
            if ($case['curve'] !== $curve) {
                continue;
            }
            $sealed = hex2bin($case['sealed_hex']);
            $opens = [
                'one-shot' => fn () => self::oneShotOpen($curve, $secret, $sealed),
                'streaming' => fn () => self::streamOpen($curve, $secret, $sealed),
            ];
            foreach ($opens as $name => $open) {
                try {
                    $open();
                    $this->fail("{$name} open accepted a v2 blob");
                } catch (DstuCoreException $e) {
                    $this->assertStringContainsString('version', $e->getMessage());
                }
            }
        }
    }

    #[DataProvider('curves')]
    public function testStreamRoundTripReadsBackStreamingAndOneShot(int $curve): void
    {
        [$secret, $public] = self::keypair($curve);
        foreach ([0, 1, 8 * 1024, 8 * 1024 + 1, 3 * 8 * 1024 + 5] as $size) {
            $message = self::pattern($size);
            $sealed = self::streamSeal($curve, $public, $message);
            $this->assertSame($message, self::streamOpen($curve, $secret, $sealed));
            $this->assertSame($message, self::oneShotOpen($curve, $secret, $sealed));
        }
    }

    #[DataProvider('curves')]
    public function testTamperingAWrongKeyAndTrailingDataFailClosed(int $curve): void
    {
        [$secret, $public] = self::keypair($curve);
        $sealed = self::streamSeal($curve, $public, self::pattern(100));
        [$other] = self::keypair($curve);
        $bad = [$sealed . "\x00"];
        foreach ([1, intdiv(strlen($sealed), 2), strlen($sealed) - 1] as $index) {
            $flipped = $sealed;
            $flipped[$index] = chr(ord($flipped[$index]) ^ 0x01);
            $bad[] = $flipped;
        }
        foreach ($bad as $i => $input) {
            try {
                self::streamOpen($curve, $secret, $input);
                $this->fail("case {$i} accepted");
            } catch (DstuCoreException) {
                $this->addToAssertionCount(1);
            }
        }
        $this->expectException(DstuCoreException::class);
        self::streamOpen($curve, $other, $sealed);
    }

    #[DataProvider('curves')]
    public function testACutPrefixIsRefused(int $curve): void
    {
        [$secret, $public] = self::keypair($curve);
        $sealed = self::streamSeal($curve, $public, self::pattern(10));
        foreach ([0, 1, 50] as $cut) {
            try {
                self::streamOpen($curve, $secret, substr($sealed, 0, $cut));
                $this->fail("a {$cut}-byte input was accepted");
            } catch (DstuCoreException $e) {
                $this->assertStringContainsString('too short', $e->getMessage());
            }
        }
    }

    #[DataProvider('curves')]
    public function testAWrongLengthPublicKeyIsRefused(int $curve): void
    {
        $this->expectException(\ValueError::class);
        if ($curve === 256) {
            DstuCoreSecretStreamWriter::forBox("\x01\x01\x01", self::memoryStream());
        } elseif ($curve === 384) {
            DstuCoreSecretStreamWriter::forBox384("\x01\x01\x01", self::memoryStream());
        } else {
            DstuCoreSecretStreamWriter::forBox512("\x01\x01\x01", self::memoryStream());
        }
    }

    #[DataProvider('curves')]
    public function testAWrongLengthSecretKeyIsRefused(int $curve): void
    {
        $this->expectException(\ValueError::class);
        $in = self::memoryStream(str_repeat("\x03", 400));
        if ($curve === 256) {
            DstuCoreSecretStreamReader::forBox("\x01\x01\x01", $in);
        } elseif ($curve === 384) {
            DstuCoreSecretStreamReader::forBox384("\x01\x01\x01", $in);
        } else {
            DstuCoreSecretStreamReader::forBox512("\x01\x01\x01", $in);
        }
    }

    #[DataProvider('curves')]
    public function testAnUnclosedWriterLeavesNoFinalRecord(int $curve): void
    {
        [$secret, $public] = self::keypair($curve);
        $out = self::memoryStream();
        $writer = match ($curve) {
            256 => DstuCoreSecretStreamWriter::forBox($public, $out),
            384 => DstuCoreSecretStreamWriter::forBox384($public, $out),
            default => DstuCoreSecretStreamWriter::forBox512($public, $out),
        };
        $writer->write(self::pattern(3 * 8 * 1024));
        // No close(): the caller's own work failed (D-118), so no Final record is written.
        rewind($out);
        $this->expectException(DstuCoreException::class);
        self::streamOpen($curve, $secret, stream_get_contents($out));
    }
}
