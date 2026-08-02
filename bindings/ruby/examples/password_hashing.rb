# frozen_string_literal: true

# crypto_pwhash (Argon2id): hash and verify a password.
#
# DstuCore::PWHASH_INTERACTIVE is used here so the example runs fast - PWHASH_MODERATE (the
# default strength most applications should use) and PWHASH_SENSITIVE both take real seconds by
# design.
#
# Run: ruby examples/password_hashing.rb

$LOAD_PATH.unshift(File.expand_path("../lib", __dir__))
require "dstu_core"

password = "correct horse battery staple"
stored = DstuCore.pwhash_hash_password(password, DstuCore::PWHASH_INTERACTIVE)
puts "stored hash: #{stored}"

raise "correct password rejected" unless DstuCore.pwhash_verify_password(password, stored)

puts "correct password accepted"

raise "wrong password accepted" if DstuCore.pwhash_verify_password("wrong guess", stored)

puts "wrong password correctly rejected"
