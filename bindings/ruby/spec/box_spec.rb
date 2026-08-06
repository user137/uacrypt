# frozen_string_literal: true

# crypto_box - no official vector exists for this composite construction (same posture as
# crypto_secretbox, D-51/D-169's own "Provenance" section) - correctness (round trip, including a
# message larger than the 25-byte KEM payload), rejection (tampered wire segments, wrong key),
# misuse (wrong-length/invalid key encodings, truncated input).
RSpec.describe "DstuCore box" do
  it "round-trips seal/open" do
    secret_key = DstuCore.box_keygen
    public_key = DstuCore.box_public_key(secret_key)
    message = "a message for the public key's holder only"
    sealed = DstuCore.box_seal(public_key, message)
    expect(DstuCore.box_open(secret_key, sealed)).to eq(message)
  end

  it "handles an empty message" do
    secret_key = DstuCore.box_keygen
    public_key = DstuCore.box_public_key(secret_key)
    sealed = DstuCore.box_seal(public_key, "")
    expect(DstuCore.box_open(secret_key, sealed)).to eq("")
  end

  it "handles a message larger than the KEM payload" do
    secret_key = DstuCore.box_keygen
    public_key = DstuCore.box_public_key(secret_key)
    message = "x" * 10_000
    sealed = DstuCore.box_seal(public_key, message)
    expect(DstuCore.box_open(secret_key, sealed)).to eq(message)
  end

  it "uses different ephemeral material for two seals" do
    secret_key = DstuCore.box_keygen
    public_key = DstuCore.box_public_key(secret_key)
    message = "same message twice"
    expect(DstuCore.box_seal(public_key, message)).not_to eq(DstuCore.box_seal(public_key, message))
  end

  it "rejects a tampered KEM prefix" do
    secret_key = DstuCore.box_keygen
    public_key = DstuCore.box_public_key(secret_key)
    sealed = DstuCore.box_seal(public_key, "message").dup
    sealed[0] = (sealed[0].ord ^ 1).chr
    expect { DstuCore.box_open(secret_key, sealed) }.to raise_error(DstuCore::Error)
  end

  it "rejects tampered ciphertext" do
    secret_key = DstuCore.box_keygen
    public_key = DstuCore.box_public_key(secret_key)
    sealed = DstuCore.box_seal(public_key, "message").dup
    sealed[-1] = (sealed[-1].ord ^ 1).chr
    expect { DstuCore.box_open(secret_key, sealed) }.to raise_error(DstuCore::Error)
  end

  it "rejects the wrong secret key" do
    secret_key = DstuCore.box_keygen
    public_key = DstuCore.box_public_key(secret_key)
    other_secret_key = DstuCore.box_keygen
    sealed = DstuCore.box_seal(public_key, "message")
    expect { DstuCore.box_open(other_secret_key, sealed) }.to raise_error(DstuCore::Error)
  end

  it "rejects a wrong-length secret key" do
    expect { DstuCore.box_public_key("too short") }.to raise_error(ArgumentError)
  end

  it "rejects a zero secret key" do
    expect { DstuCore.box_public_key("\x00" * 32) }.to raise_error(ArgumentError)
  end

  it "rejects a wrong-length public key" do
    expect { DstuCore.box_seal("too short", "message") }.to raise_error(ArgumentError)
  end

  it "rejects a degenerate public key x = 0" do
    expect { DstuCore.box_seal("\x00" * 32, "message") }.to raise_error(ArgumentError)
  end

  it "rejects truncated sealed input" do
    secret_key = DstuCore.box_keygen
    expect { DstuCore.box_open(secret_key, "short") }.to raise_error(DstuCore::Error)
  end
end
