# frozen_string_literal: true

require "json"

# crypto_generichash (Kupyna-256/512) - three categories per D-64/D-65: correctness against a real
# official Kupyna-256 vector (loaded directly from the same JSON the Rust crate's own tests and
# self_test use - crates/dstu-core/tests/vectors/kupyna/kupyna-256.json, not just round-trip
# self-consistency) plus one-shot/streaming agreement, misuse (calling #finalize twice - there is
# no rejection category, a hash has no key/tag to tamper with).
RSpec.describe "DstuCore generichash" do
  vector_path = File.expand_path("../../../crates/dstu-core/tests/vectors/kupyna/kupyna-256.json", __dir__)

  it "matches the official Kupyna-256 vector" do
    vectors = JSON.parse(File.read(vector_path))
    the_case = vectors["cases"][0]
    message = [the_case["message_hex"]].pack("H*")
    expected = [the_case["hash_hex"]].pack("H*")
    expect(DstuCore.kupyna256(message)).to eq(expected)
  end

  it "matches one-shot with a streaming Kupyna256Hasher" do
    whole = DstuCore.kupyna256("hello world")
    hasher = DstuCore::Kupyna256Hasher.new
    hasher.update("hello ")
    hasher.update("world")
    expect(hasher.finalize).to eq(whole)
  end

  it "matches one-shot with a streaming Kupyna512Hasher" do
    whole = DstuCore.kupyna512("hello world")
    hasher = DstuCore::Kupyna512Hasher.new
    hasher.update("hello ")
    hasher.update("world")
    expect(hasher.finalize).to eq(whole)
  end

  it "rejects calling finalize twice" do
    hasher = DstuCore::Kupyna256Hasher.new
    hasher.update("data")
    hasher.finalize
    expect { hasher.finalize }.to raise_error(ArgumentError)
  end

  it "rejects update after finalize" do
    hasher = DstuCore::Kupyna256Hasher.new
    hasher.finalize
    expect { hasher.update("more data") }.to raise_error(ArgumentError)
  end
end
