# frozen_string_literal: true

# crypto_sign (DSTU 4145): generate a signing keypair, sign a message, verify it.
#
# Run: ruby examples/sign.rb

$LOAD_PATH.unshift(File.expand_path("../lib", __dir__))
require "dstu_core"

signing_key = DstuCore.sign_keygen
verifying_key = DstuCore.sign_verifying_key(signing_key)

message = "a message whose origin and integrity matter"
signature = DstuCore.sign_message(signing_key, message)
raise "verification failed" unless DstuCore.sign_verify(verifying_key, message, signature)

puts "signed and verified a #{message.bytesize}-byte message"

unless DstuCore.sign_verify(verifying_key, "a different message", signature)
  puts "signature over a different message correctly rejected"
end
