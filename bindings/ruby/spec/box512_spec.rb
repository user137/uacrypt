# frozen_string_literal: true

# crypto_box512 - l(p)=512 sibling of crypto_box (T-193/T-204). No official vector exists for this
# composite construction (same posture as crypto_box) - correctness (round trip), rejection
# (tampered wire segments, wrong key), misuse (wrong-length/invalid key encodings, truncated
# input).
RSpec.describe "DstuCore box512" do
  it "round-trips seal/open" do
    secret_key = DstuCore.box512_keygen
    public_key = DstuCore.box512_public_key(secret_key)
    message = "a message for the public key's holder only"
    sealed = DstuCore.box512_seal(public_key, message)
    expect(DstuCore.box512_open(secret_key, sealed)).to eq(message)
  end

  it "handles an empty message" do
    secret_key = DstuCore.box512_keygen
    public_key = DstuCore.box512_public_key(secret_key)
    sealed = DstuCore.box512_seal(public_key, "")
    expect(DstuCore.box512_open(secret_key, sealed)).to eq("")
  end

  it "uses different ephemeral material for two seals" do
    secret_key = DstuCore.box512_keygen
    public_key = DstuCore.box512_public_key(secret_key)
    message = "same message twice"
    expect(DstuCore.box512_seal(public_key, message)).not_to eq(DstuCore.box512_seal(public_key, message))
  end

  it "rejects tampered ciphertext" do
    secret_key = DstuCore.box512_keygen
    public_key = DstuCore.box512_public_key(secret_key)
    sealed = DstuCore.box512_seal(public_key, "message").dup
    sealed[-1] = (sealed[-1].ord ^ 1).chr
    expect { DstuCore.box512_open(secret_key, sealed) }.to raise_error(DstuCore::Error)
  end

  it "rejects the wrong secret key" do
    secret_key = DstuCore.box512_keygen
    public_key = DstuCore.box512_public_key(secret_key)
    other_secret_key = DstuCore.box512_keygen
    sealed = DstuCore.box512_seal(public_key, "message")
    expect { DstuCore.box512_open(other_secret_key, sealed) }.to raise_error(DstuCore::Error)
  end

  it "rejects a wrong-length secret key" do
    expect { DstuCore.box512_public_key("too short") }.to raise_error(ArgumentError)
  end

  it "rejects a zero secret key" do
    expect { DstuCore.box512_public_key("\x00" * 64) }.to raise_error(ArgumentError)
  end

  it "rejects a wrong-length public key" do
    expect { DstuCore.box512_seal("too short", "message") }.to raise_error(ArgumentError)
  end

  it "rejects a degenerate public key x = 0" do
    expect { DstuCore.box512_seal("\x00" * 64, "message") }.to raise_error(ArgumentError)
  end

  it "rejects truncated sealed input" do
    secret_key = DstuCore.box512_keygen
    expect { DstuCore.box512_open(secret_key, "short") }.to raise_error(DstuCore::Error)
  end
end
