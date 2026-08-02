# frozen_string_literal: true

# crypto_secretbox: seal/open a single message with a symmetric key.
#
# Run: ruby examples/secretbox.rb

$LOAD_PATH.unshift(File.expand_path("../lib", __dir__))
require "dstu_core"

key = DstuCore.secretbox_keygen
sealed = DstuCore.secretbox_seal(key, "a message worth protecting")
plaintext = DstuCore.secretbox_open(key, sealed)
raise "round trip failed" unless plaintext == "a message worth protecting"

puts "sealed #{plaintext.bytesize} bytes -> #{sealed.bytesize} bytes, round-tripped OK"

tampered = sealed.dup
tampered[-1] = (tampered[-1].ord ^ 1).chr
begin
  DstuCore.secretbox_open(key, tampered)
rescue DstuCore::Error
  puts "tampered ciphertext correctly rejected"
end
