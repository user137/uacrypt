<?php

declare(strict_types=1);

use PHPUnit\Framework\TestCase;

/**
 * Passphrase files (D-219, moved into the core by T-269/D-240): DstuCoreSecretStreamWriter/Reader
 * ::forPassphrase, the same bytes `uacrypt encrypt --passphrase-file` writes. Argon2 is 256 MiB,
 * t=3 per run, so only the shared-vector test and the uacrypt interop run it; every header refusal
 * stops before Argon2. Mirrors bindings/python/tests/test_passphrase_file.py.
 */
final class PassphraseFileTest extends TestCase
{
    private static function cases(bool $argon2): array
    {
        $path = dirname(__DIR__, 3) . '/crates/dstu-core/tests/vectors/pwhash/passphrase_file.json';
        $cases = json_decode(file_get_contents($path), true, flags: JSON_THROW_ON_ERROR)['cases'];

        return array_values(array_filter($cases, fn ($c) => $c['argon2'] === $argon2));
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

    private static function open(string $passphrase, string $data): string
    {
        return DstuCoreSecretStreamReader::forPassphrase($passphrase, self::memoryStream($data))->readAll();
    }

    public function testHeaderVectorsAreRefusedBeforeArgon2(): void
    {
        $messages = [
            'not_passphrase_file' => 'not a passphrase file',
            'unsupported_format' => 'unsupported passphrase file format',
            'unsupported_params' => 'unsupported Argon2 parameters',
            'truncated' => 'too short',
        ];
        $refused = self::cases(false);
        $this->assertCount(6, $refused);
        foreach ($refused as $case) {
            try {
                self::open(hex2bin($case['passphrase_hex']), hex2bin($case['sealed_hex']));
                $this->fail("{$case['name']} was accepted");
            } catch (DstuCoreException $e) {
                $this->assertStringContainsString($messages[$case['expect']], $e->getMessage(), $case['name']);
            }
        }
    }

    public function testFilesWrittenByUacrypt060GiveTheirExpectedOutcome(): void
    {
        $argon2 = self::cases(true);
        $this->assertCount(4, $argon2);
        foreach ($argon2 as $case) {
            $passphrase = hex2bin($case['passphrase_hex']);
            $sealed = hex2bin($case['sealed_hex']);
            if ($case['expect'] === 'ok') {
                $this->assertSame(self::pattern($case['plaintext_len']), self::open($passphrase, $sealed), $case['name']);
            } else {
                try {
                    self::open($passphrase, $sealed);
                    $this->fail("{$case['name']} was accepted");
                } catch (DstuCoreException) {
                    $this->addToAssertionCount(1);
                }
            }
        }
    }

    public function testAnEmptyPassphraseIsRefusedWhenWriting(): void
    {
        $this->expectException(DstuCoreException::class);
        $this->expectExceptionMessage('empty');
        DstuCoreSecretStreamWriter::forPassphrase('', self::memoryStream());
    }

    public function testAnEmptyPassphraseIsRefusedWhenReading(): void
    {
        $this->expectException(DstuCoreException::class);
        $this->expectExceptionMessage('empty');
        self::open('', hex2bin(self::cases(true)[0]['sealed_hex']));
    }

    public function testAKeyEncryptedStreamIsNotAPassphraseFile(): void
    {
        $out = self::memoryStream();
        DstuCoreSecretStreamWriter::withStream(dstu_core_secretstream_keygen(), $out, fn ($w) => $w->write('x'));
        rewind($out);
        $this->expectException(DstuCoreException::class);
        $this->expectExceptionMessage('not a passphrase file');
        self::open('pw', stream_get_contents($out));
    }

    public function testInteroperatesWithUacryptInBothDirections(): void
    {
        $repoRoot = dirname(__DIR__, 3);
        $uacrypt = null;
        foreach (['release', 'debug'] as $profile) {
            foreach (['uacrypt.exe', 'uacrypt'] as $name) {
                if ($uacrypt === null && is_file("{$repoRoot}/target/{$profile}/{$name}")) {
                    $uacrypt = "{$repoRoot}/target/{$profile}/{$name}";
                }
            }
        }
        if ($uacrypt === null) {
            $this->markTestSkipped('uacrypt binary not built (cargo build -p uacrypt --release)');
        }

        $dir = sys_get_temp_dir() . '/dstu_core_php_pf_' . bin2hex(random_bytes(8));
        mkdir($dir);
        try {
            $message = self::pattern(8 * 1024 + 9);
            $passphrase = 'спільний пароль';
            file_put_contents("{$dir}/pw.txt", $passphrase);

            $out = fopen("{$dir}/ours.uac", 'wb');
            $writer = DstuCoreSecretStreamWriter::forPassphrase($passphrase, $out);
            $writer->write($message);
            $writer->close();
            fclose($out);
            $cmd = [$uacrypt, 'decrypt', '--passphrase-file', "{$dir}/pw.txt", '--in', "{$dir}/ours.uac", '--out', "{$dir}/ours.back"];
            exec(implode(' ', array_map('escapeshellarg', $cmd)), $output, $code);
            $this->assertSame(0, $code);
            $this->assertSame($message, file_get_contents("{$dir}/ours.back"));

            file_put_contents("{$dir}/plain.bin", $message);
            $cmd = [$uacrypt, 'encrypt', '--passphrase-file', "{$dir}/pw.txt", '--in', "{$dir}/plain.bin", '--out', "{$dir}/theirs.uac"];
            exec(implode(' ', array_map('escapeshellarg', $cmd)), $output, $code);
            $this->assertSame(0, $code);
            $this->assertSame($message, self::open($passphrase, file_get_contents("{$dir}/theirs.uac")));
        } finally {
            array_map('unlink', glob("{$dir}/*"));
            rmdir($dir);
        }
    }
}
