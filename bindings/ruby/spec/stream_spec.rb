# frozen_string_literal: true

# crypto_stream (Strumok-256 keystream) - **no authentication** (see dstu_core::crypto_stream's
# own module doc): no rejection category, since there is no tag to tamper with -
# DstuCore.stream_decrypt never fails on tampered input, it silently returns different, wrong
# plaintext instead. Correctness: round trip. Misuse: wrong-length key, truncated input.
RSpec.describe "DstuCore stream" do
  it "round-trips encrypt/decrypt" do
    key = DstuCore.stream_keygen
    sealed = DstuCore.stream_encrypt(key, "message")
    expect(DstuCore.stream_decrypt(key, sealed)).to eq("message")
  end

  it "does not detect tampering but produces wrong plaintext" do
    # Documents the no-integrity property explicitly, per this project's own precedent
    # (hazmat::kalyna_xts's tampered_ciphertext_does_not_error_but_produces_garbage) - a
    # deliberate design property, not a missing rejection test.
    key = DstuCore.stream_keygen
    sealed = DstuCore.stream_encrypt(key, "message").dup
    sealed[-1] = (sealed[-1].ord ^ 1).chr
    garbage = DstuCore.stream_decrypt(key, sealed)
    expect(garbage).not_to eq("message")
  end

  it "rejects a wrong-length key" do
    expect { DstuCore.stream_encrypt("too short", "message") }.to raise_error(ArgumentError)
  end

  it "rejects truncated sealed input" do
    key = DstuCore.stream_keygen
    expect { DstuCore.stream_decrypt(key, "short") }.to raise_error(DstuCore::Error)
  end
end
