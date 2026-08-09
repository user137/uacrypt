# frozen_string_literal: true

# crypto_box512 (l(p)=512 sibling of crypto_box, T-193/T-204): generate a keypair, seal a message
# to the public key, open it with the secret key.
#
# Run: ruby examples/box512.rb

$LOAD_PATH.unshift(File.expand_path("../lib", __dir__))
require "dstu_core"

secret_key = DstuCore.box512_keygen
public_key = DstuCore.box512_public_key(secret_key) # safe to share/publish

message = "a message for the public key's holder only"
sealed = DstuCore.box512_seal(public_key, message)
opened = DstuCore.box512_open(secret_key, sealed)
raise "round trip failed" unless opened == message

puts "sealed #{message.bytesize} bytes -> #{sealed.bytesize} bytes, round-tripped OK"

tampered = sealed.dup
tampered[-1] = (tampered[-1].ord ^ 1).chr
begin
  DstuCore.box512_open(secret_key, tampered)
rescue DstuCore::Error
  puts "tampered ciphertext correctly rejected"
end
