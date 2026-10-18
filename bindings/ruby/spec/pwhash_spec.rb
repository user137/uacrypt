# frozen_string_literal: true

require "json"

# crypto_pwhash (Argon2id, the one deliberately non-DSTU component, D-49/D-50). Correctness: round
# trip. Rejection: wrong password, malformed hash string. Misuse: invalid strength value.
# PWHASH_INTERACTIVE is used throughout (not the default PWHASH_MODERATE) so this file's own specs
# stay fast - Strength::Sensitive alone takes real seconds, per the Rust crate's own test comments.
RSpec.describe "DstuCore pwhash" do
  it "round-trips hash_password/verify_password" do
    stored = DstuCore.pwhash_hash_password("correct horse battery staple", DstuCore::PWHASH_INTERACTIVE)
    expect(DstuCore.pwhash_verify_password("correct horse battery staple", stored)).to be(true)
  end

  it "rejects the wrong password" do
    stored = DstuCore.pwhash_hash_password("correct horse battery staple", DstuCore::PWHASH_INTERACTIVE)
    expect(DstuCore.pwhash_verify_password("wrong guess", stored)).to be(false)
  end

  it "rejects a malformed hash string" do
    expect(DstuCore.pwhash_verify_password("anything", "not a real PHC string")).to be(false)
  end

  it "rejects an invalid strength value" do
    expect { DstuCore.pwhash_hash_password("password", 255) }.to raise_error(ArgumentError)
  end

  # T-272/D-222: a crafted hash string returns false instead of aborting the interpreter.
  vectors = File.expand_path("../../../crates/dstu-core/tests/vectors/pwhash/verify.json", __dir__)
  JSON.parse(File.read(vectors, encoding: "UTF-8"))["cases"].each do |c|
    it "shared verify vector: #{c['name']}" do
      expect(DstuCore.pwhash_verify_password(c["password"], c["hash"])).to be(c["expect"] == "accept")
      expect(DstuCore.pwhash_verify_password("#{c['password']}x", c["hash"])).to be(false)
    end
  end

  # T-269: pwhash_derive_key equals libsodium crypto_pwhash (the vectors' oracle, D-219).
  derive_vectors = File.expand_path("../../../crates/dstu-core/tests/vectors/pwhash/derive_key.json", __dir__)

  it "derives the libsodium crypto_pwhash keys" do
    cases = JSON.parse(File.read(derive_vectors, encoding: "UTF-8"))["cases"]
    expect(cases.size).to eq(3)
    cases.each do |c|
      key = DstuCore.pwhash_derive_key([c["password_hex"]].pack("H*"), [c["salt_hex"]].pack("H*"), DstuCore::PWHASH_MODERATE)
      expect(key.unpack1("H*")).to eq(c["key_hex"])
    end
  end

  it "refuses a wrong-length salt and an unknown strength" do
    expect { DstuCore.pwhash_derive_key("pw", "\x00".b * 15, DstuCore::PWHASH_MODERATE) }.to raise_error(ArgumentError, /salt/)
    expect { DstuCore.pwhash_derive_key("pw", "\x00".b * 16, 255) }.to raise_error(ArgumentError, /strength/)
  end
end
