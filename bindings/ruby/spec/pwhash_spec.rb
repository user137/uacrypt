# frozen_string_literal: true

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
end
