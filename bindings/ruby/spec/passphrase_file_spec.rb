# frozen_string_literal: true

require "json"
require "stringio"
require "tmpdir"

# Passphrase files (D-219, moved into the core by T-269/D-240): PassphraseWriter/PassphraseReader,
# the same bytes `uacrypt encrypt --passphrase-file` writes. Argon2 is 256 MiB, t=3 per run, so
# only the shared-vector spec and the uacrypt interop run it; every header refusal stops before
# Argon2. Mirrors bindings/python/tests/test_passphrase_file.py.
RSpec.describe "DstuCore passphrase files" do
  repo_root = File.expand_path("../../..", __dir__)
  vectors = File.join(repo_root, "crates", "dstu-core", "tests", "vectors", "pwhash", "passphrase_file.json")
  uacrypt = [
    File.join(repo_root, "target", "release", "uacrypt.exe"),
    File.join(repo_root, "target", "debug", "uacrypt.exe"),
    File.join(repo_root, "target", "release", "uacrypt"),
    File.join(repo_root, "target", "debug", "uacrypt")
  ].find { |path| File.file?(path) }
  cases = ->(argon2) { JSON.parse(File.read(vectors, encoding: "UTF-8"))["cases"].select { |c| c["argon2"] == argon2 } }
  pattern = ->(n) { Array.new(n) { |i| ((i * 31) + 7) % 256 }.pack("C*") }
  hex = ->(s) { [s].pack("H*") }
  open_file = ->(passphrase, data) { DstuCore::PassphraseReader.open(passphrase, StringIO.new(data), &:read_all) }

  it "refuses the header vectors before Argon2" do
    messages = {
      "not_passphrase_file" => /not a passphrase file/,
      "unsupported_format" => /unsupported passphrase file format/,
      "unsupported_params" => /unsupported Argon2 parameters/,
      "truncated" => /too short/
    }
    refused = cases.call(false)
    expect(refused.size).to eq(6)
    refused.each do |c|
      expect { open_file.call(hex.call(c["passphrase_hex"]), hex.call(c["sealed_hex"])) }
        .to raise_error(DstuCore::Error, messages.fetch(c["expect"]))
    end
  end

  it "opens the files uacrypt 0.6.0 wrote, and refuses a wrong passphrase or a flipped bit" do
    argon2 = cases.call(true)
    expect(argon2.size).to eq(4)
    argon2.each do |c|
      run = -> { open_file.call(hex.call(c["passphrase_hex"]), hex.call(c["sealed_hex"])) }
      if c["expect"] == "ok"
        expect(run.call).to eq(pattern.call(c["plaintext_len"]))
      else
        expect { run.call }.to raise_error(DstuCore::Error)
      end
    end
  end

  it "refuses an empty passphrase on both sides" do
    expect { DstuCore::PassphraseWriter.new("", StringIO.new) }.to raise_error(DstuCore::Error, /empty/)
    sealed = hex.call(cases.call(true).first["sealed_hex"])
    expect { open_file.call("", sealed) }.to raise_error(DstuCore::Error, /empty/)
  end

  it "says a key-encrypted stream is not a passphrase file" do
    out = StringIO.new
    DstuCore::SecretStreamWriter.open(DstuCore.secretstream_keygen, out) { |w| w.write("x") }
    expect { open_file.call("pw", out.string) }.to raise_error(DstuCore::Error, /not a passphrase file/)
  end

  it "interoperates with uacrypt in both directions", if: uacrypt do
    Dir.mktmpdir do |dir|
      message = pattern.call((8 * 1024) + 9)
      passphrase = "спільний пароль".b
      pw_file = File.join(dir, "pw.txt")
      File.binwrite(pw_file, passphrase)

      ours = File.join(dir, "ours.uac")
      File.open(ours, "wb") { |f| DstuCore::PassphraseWriter.open(passphrase, f) { |w| w.write(message) } }
      back = File.join(dir, "ours.back")
      expect(system(uacrypt, "decrypt", "--passphrase-file", pw_file, "--in", ours, "--out", back)).to be(true)
      expect(File.binread(back)).to eq(message)

      plain = File.join(dir, "plain.bin")
      File.binwrite(plain, message)
      theirs = File.join(dir, "theirs.uac")
      expect(system(uacrypt, "encrypt", "--passphrase-file", pw_file, "--in", plain, "--out", theirs)).to be(true)
      expect(File.open(theirs, "rb") { |f| DstuCore::PassphraseReader.open(passphrase, f, &:read_all) }).to eq(message)
    end
  end
end
