# frozen_string_literal: true

require "stringio"
require "tempfile"

# crypto_secretstream - both the low-level SecretStreamPushState/PullState (step 2) and the
# idiomatic SecretStreamWriter/SecretStreamReader pipeline (step 3, D-118). Three categories per
# D-64/D-65: correctness (round trip across chunk-boundary sizes, plus real byte-for-byte interop
# with `uacrypt encrypt`/`decrypt`'s own wire format), rejection (tamper, oversized chunk, trailing
# data), misuse (wrong-length key, write-after-close).
RSpec.describe "DstuCore secretstream" do
  repo_root = File.expand_path("../../..", __dir__)
  uacrypt_candidates = [
    File.join(repo_root, "target", "release", "uacrypt.exe"),
    File.join(repo_root, "target", "debug", "uacrypt.exe"),
    File.join(repo_root, "target", "release", "uacrypt"),
    File.join(repo_root, "target", "debug", "uacrypt")
  ]
  uacrypt = uacrypt_candidates.find { |path| File.file?(path) }

  [0, 1, 100, 8 * 1024, (8 * 1024) + 1, 8 * 1024 * 3, (8 * 1024 * 3) + 777].each do |size|
    it "round-trips a #{size}-byte message across chunk boundaries" do
      key = DstuCore.secretstream_keygen
      plaintext = Random.bytes(size)

      out = StringIO.new
      DstuCore::SecretStreamWriter.open(key, out) do |w|
        step = 777
        (0...plaintext.bytesize).step(step) { |i| w.write(plaintext.byteslice(i, step)) }
      end

      out.rewind
      result = DstuCore::SecretStreamReader.open(key, out, &:read_all)
      expect(result).to eq(plaintext)
    end
  end

  it "interoperates with the real uacrypt CLI in both directions", if: uacrypt do
    key = DstuCore.secretstream_keygen
    plaintext = Random.bytes((8 * 1024 * 2) + 555)

    Tempfile.create("key") do |key_file|
      key_file.binmode
      key_file.write(key)
      key_file.close

      Tempfile.create("plain") do |plain_file|
        plain_file.binmode
        plain_file.write(plaintext)
        plain_file.close

        Tempfile.create("rb_encrypted") do |rb_encrypted|
          rb_encrypted.close
          File.open(rb_encrypted.path, "wb") do |f|
            DstuCore::SecretStreamWriter.open(key, f) { |w| w.write(plaintext) }
          end

          Tempfile.create("uacrypt_decrypted") do |uacrypt_decrypted|
            uacrypt_decrypted.close
            system(uacrypt, "decrypt", "--key", key_file.path, "--in", rb_encrypted.path,
                   "--out", uacrypt_decrypted.path, exception: true)
            expect(File.binread(uacrypt_decrypted.path)).to eq(plaintext)
          end
        end

        Tempfile.create("uacrypt_encrypted") do |uacrypt_encrypted|
          uacrypt_encrypted.close
          system(uacrypt, "encrypt", "--key", key_file.path, "--in", plain_file.path,
                 "--out", uacrypt_encrypted.path, exception: true)
          File.open(uacrypt_encrypted.path, "rb") do |f|
            result = DstuCore::SecretStreamReader.open(key, f, &:read_all)
            expect(result).to eq(plaintext)
          end
        end
      end
    end
  end

  # `skip` (rather than silently omitting the example) keeps this visible in RSpec's own summary
  # line ("N pending") rather than a quietly smaller example count - `cargo xtask ruby`/CI always
  # build `uacrypt --release` from the repo root before this suite runs (step 5), so in the
  # pipeline that actually matters this never skips; a bare local `bundle exec rspec` without that
  # build step is the only case where it does, and RSpec's own output makes that visible.
  it "documents the uacrypt-missing case explicitly", if: uacrypt.nil? do
    skip "uacrypt binary not built (cargo build -p uacrypt --release)"
  end

  it "rejects a tampered chunk" do
    key = DstuCore.secretstream_keygen
    out = StringIO.new
    DstuCore::SecretStreamWriter.open(key, out) { |w| w.write("secret message") }
    data = out.string.dup
    data[-1] = (data[-1].ord ^ 1).chr
    expect do
      DstuCore::SecretStreamReader.open(key, StringIO.new(data), &:read_all)
    end.to raise_error(DstuCore::Error)
  end

  it "rejects a truncated stream" do
    key = DstuCore.secretstream_keygen
    out = StringIO.new
    DstuCore::SecretStreamWriter.open(key, out) { |w| w.write("x" * 20_000) }
    truncated = out.string[0, 100]
    expect do
      DstuCore::SecretStreamReader.open(key, StringIO.new(truncated), &:read_all)
    end.to raise_error(DstuCore::Error)
  end

  it "rejects an oversized declared chunk length" do
    key = DstuCore.secretstream_keygen
    push = DstuCore::SecretStreamPushState.new(key)
    malicious = push.header + [DstuCore::SECRETSTREAM_TAG_FINAL].pack("C") + [0xFFFFFFFF].pack("V")
    expect do
      DstuCore::SecretStreamReader.open(key, StringIO.new(malicious), &:read_all)
    end.to raise_error(DstuCore::Error, /too large/)
  end

  it "rejects trailing data after Final" do
    key = DstuCore.secretstream_keygen
    out = StringIO.new
    DstuCore::SecretStreamWriter.open(key, out) { |w| w.write("msg") }
    data = "#{out.string}unexpected trailing bytes"
    expect do
      DstuCore::SecretStreamReader.open(key, StringIO.new(data), &:read_all)
    end.to raise_error(DstuCore::Error, /trailing/)
  end

  it "leaves the stream unfinalized when the block raises mid-write" do
    key = DstuCore.secretstream_keygen
    out = StringIO.new
    expect do
      DstuCore::SecretStreamWriter.open(key, out) do |w|
        w.write("chunk one")
        raise "simulated failure mid-stream"
      end
    end.to raise_error(RuntimeError, "simulated failure mid-stream")

    out.rewind
    expect do
      DstuCore::SecretStreamReader.open(key, out, &:read_all)
    end.to raise_error(DstuCore::Error)
  end

  it "rejects a wrong-length key" do
    expect { DstuCore::SecretStreamPushState.new("too short") }.to raise_error(ArgumentError)
  end

  it "rejects write after close" do
    key = DstuCore.secretstream_keygen
    out = StringIO.new
    writer = DstuCore::SecretStreamWriter.new(key, out)
    writer.write("data")
    writer.close
    expect { writer.write("more data") }.to raise_error(IOError)
  end
end
