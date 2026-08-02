# frozen_string_literal: true

# The remaining crypto_* modules, each small enough to share one file:
#
# - crypto_auth (Kupyna-KMAC): keyed message authentication.
# - crypto_kdf: deterministic subkey derivation from a master key.
# - crypto_generichash (Kupyna-256/512): one-shot and streaming hashing.
# - crypto_stream (Strumok-256): unauthenticated keystream cipher - no integrity, wrong
#   key/tampered ciphertext silently decrypts to different, wrong plaintext instead of raising.
# - randombytes: CSPRNG-backed random bytes.
#
# Run: ruby examples/misc.rb

$LOAD_PATH.unshift(File.expand_path("../lib", __dir__))
require "dstu_core"

def auth_example
  key = DstuCore.auth_keygen
  message = "a message both parties want to confirm is unmodified"
  tag = DstuCore.auth(key, message)
  DstuCore.auth_verify(key, message, tag)
  puts "auth: tag verified"
end

def kdf_example
  master_key = DstuCore.kdf_keygen
  subkey_a = DstuCore.kdf_derive_subkey(master_key, 0, "encrypt_")
  subkey_b = DstuCore.kdf_derive_subkey(master_key, 1, "encrypt_")
  raise "subkeys should differ" if subkey_a == subkey_b

  puts "kdf: subkey 0 and subkey 1 differ, as expected"
end

def generichash_example
  one_shot = DstuCore.kupyna256("hello world")
  hasher = DstuCore::Kupyna256Hasher.new
  hasher.update("hello ")
  hasher.update("world")
  raise "streaming mismatch" unless hasher.finalize == one_shot

  puts "generichash: kupyna256('hello world') = #{one_shot.unpack1('H*')}"
end

def stream_example
  key = DstuCore.stream_keygen
  sealed = DstuCore.stream_encrypt(key, "a message")
  raise "round trip failed" unless DstuCore.stream_decrypt(key, sealed) == "a message"

  puts "stream: round-tripped (note: unauthenticated, no tamper detection)"
end

def randombytes_example
  a = DstuCore.randombytes_buf(16)
  b = DstuCore.randombytes_buf(16)
  raise "draws should differ" if a == b

  puts "randombytes: two independent 16-byte draws, e.g. #{a.unpack1('H*')}"
end

auth_example
kdf_example
generichash_example
stream_example
randombytes_example
