# frozen_string_literal: true

# crypto_sign (DSTU 4145) - the official Annex B.1 verify vector is already covered by
# DstuCore.self_test (selftest_spec.rb); this file covers what that single vector doesn't reach:
# correctness (round trip, determinism of the nonce derivation), rejection (wrong message/wrong
# key), misuse (invalid signing key - zero/out-of-range, wrong-length verifying key/signature).
RSpec.describe "DstuCore sign" do
  it "round-trips sign/verify" do
    signing_key = DstuCore.sign_keygen
    verifying_key = DstuCore.sign_verifying_key(signing_key)
    message = "a message whose origin and integrity matter"
    signature = DstuCore.sign_message(signing_key, message)
    expect(DstuCore.sign_verify(verifying_key, message, signature)).to be(true)
  end

  it "is deterministic" do
    # D-46: the ephemeral nonce is derived deterministically, not from an RNG - the same
    # (key, message) pair always produces the same signature.
    signing_key = DstuCore.sign_keygen
    message = "same message every time"
    expect(DstuCore.sign_message(signing_key, message)).to eq(DstuCore.sign_message(signing_key, message))
  end

  it "rejects the wrong message" do
    signing_key = DstuCore.sign_keygen
    verifying_key = DstuCore.sign_verifying_key(signing_key)
    signature = DstuCore.sign_message(signing_key, "original message")
    expect(DstuCore.sign_verify(verifying_key, "a different message", signature)).to be(false)
  end

  it "rejects the wrong key" do
    signing_key = DstuCore.sign_keygen
    other_verifying_key = DstuCore.sign_verifying_key(DstuCore.sign_keygen)
    message = "message"
    signature = DstuCore.sign_message(signing_key, message)
    expect(DstuCore.sign_verify(other_verifying_key, message, signature)).to be(false)
  end

  it "rejects an all-zero signing key" do
    expect { DstuCore.sign_verifying_key("\x00" * 21) }.to raise_error(ArgumentError)
  end

  it "rejects a wrong-length signing key" do
    expect { DstuCore.sign_message("too short", "message") }.to raise_error(ArgumentError)
  end

  it "rejects a wrong-length verifying key" do
    expect { DstuCore.sign_verify("too short", "message", "\x00" * 42) }.to raise_error(ArgumentError)
  end

  it "rejects a wrong-length signature" do
    signing_key = DstuCore.sign_keygen
    verifying_key = DstuCore.sign_verifying_key(signing_key)
    expect { DstuCore.sign_verify(verifying_key, "message", "too short") }.to raise_error(ArgumentError)
  end
end
