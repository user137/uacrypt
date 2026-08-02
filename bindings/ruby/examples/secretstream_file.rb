# frozen_string_literal: true

# crypto_secretstream: encrypt/decrypt a file incrementally, chunk by chunk, via the idiomatic
# SecretStreamWriter/SecretStreamReader wrapper (docs/DECISIONS.md D-118). The wire format matches
# `uacrypt encrypt`/`decrypt` exactly - a file this writes is decryptable by the `uacrypt` CLI and
# vice versa.
#
# Run: ruby examples/secretstream_file.rb

$LOAD_PATH.unshift(File.expand_path("../lib", __dir__))
require "dstu_core"
require "tmpdir"

key = DstuCore.secretstream_keygen
plaintext = ("a message spread across more than one 8 KiB chunk\n" * 1000)

Dir.mktmpdir do |tmp|
  encrypted_path = File.join(tmp, "message.enc")
  decrypted_path = File.join(tmp, "message.dec")

  File.open(encrypted_path, "wb") do |f|
    DstuCore::SecretStreamWriter.open(key, f) { |w| w.write(plaintext) }
  end

  recovered = File.open(encrypted_path, "rb") do |f|
    DstuCore::SecretStreamReader.open(key, f, &:read_all)
  end

  raise "round trip failed" unless recovered == plaintext

  puts "#{plaintext.bytesize} bytes -> #{File.size(encrypted_path)} bytes on disk, round-tripped OK"
  File.binwrite(decrypted_path, recovered)
end
