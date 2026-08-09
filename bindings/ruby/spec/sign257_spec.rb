# frozen_string_literal: true

# crypto_sign257 (DSTU 4145 m=257) - m=257 sibling of crypto_sign (T-199/T-204). Correctness
# (round trip, determinism of the nonce derivation), rejection (wrong message/wrong key), misuse
# (invalid signing key - zero/out-of-range, wrong-length verifying key/signature).
RSpec.describe "DstuCore sign257" do
  it "round-trips sign/verify" do
    signing_key = DstuCore.sign257_keygen
    verifying_key = DstuCore.sign257_verifying_key(signing_key)
    message = "a message whose origin and integrity matter"
    signature = DstuCore.sign257_message(signing_key, message)
    expect(DstuCore.sign257_verify(verifying_key, message, signature)).to be(true)
  end

  it "is deterministic" do
    signing_key = DstuCore.sign257_keygen
    message = "same message every time"
    expect(DstuCore.sign257_message(signing_key, message)).to eq(DstuCore.sign257_message(signing_key, message))
  end

  it "rejects the wrong message" do
    signing_key = DstuCore.sign257_keygen
    verifying_key = DstuCore.sign257_verifying_key(signing_key)
    signature = DstuCore.sign257_message(signing_key, "original message")
    expect(DstuCore.sign257_verify(verifying_key, "a different message", signature)).to be(false)
  end

  it "rejects the wrong key" do
    signing_key = DstuCore.sign257_keygen
    other_verifying_key = DstuCore.sign257_verifying_key(DstuCore.sign257_keygen)
    message = "message"
    signature = DstuCore.sign257_message(signing_key, message)
    expect(DstuCore.sign257_verify(other_verifying_key, message, signature)).to be(false)
  end

  it "rejects an all-zero signing key" do
    expect { DstuCore.sign257_verifying_key("\x00" * 33) }.to raise_error(ArgumentError)
  end

  it "rejects a wrong-length signing key" do
    expect { DstuCore.sign257_message("too short", "message") }.to raise_error(ArgumentError)
  end

  it "rejects a wrong-length verifying key" do
    expect { DstuCore.sign257_verify("too short", "message", "\x00" * 66) }.to raise_error(ArgumentError)
  end

  it "rejects a wrong-length signature" do
    signing_key = DstuCore.sign257_keygen
    verifying_key = DstuCore.sign257_verifying_key(signing_key)
    expect { DstuCore.sign257_verify(verifying_key, "message", "too short") }.to raise_error(ArgumentError)
  end
end
