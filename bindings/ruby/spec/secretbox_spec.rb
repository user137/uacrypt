# frozen_string_literal: true

# crypto_secretbox - three test categories per D-64/D-65: correctness (round trip - no official
# vector exists for this construction, same posture as the Rust crate's own tests, D-51),
# rejection (tamper/wrong key), misuse (wrong-length key, truncated input).
RSpec.describe "DstuCore secretbox" do
  it "round-trips seal/open" do
    key = DstuCore.secretbox_keygen
    sealed = DstuCore.secretbox_seal(key, "a message worth protecting")
    expect(DstuCore.secretbox_open(key, sealed)).to eq("a message worth protecting")
  end

  it "handles an empty message" do
    key = DstuCore.secretbox_keygen
    sealed = DstuCore.secretbox_seal(key, "")
    expect(DstuCore.secretbox_open(key, sealed)).to eq("")
  end

  it "rejects tampered ciphertext" do
    key = DstuCore.secretbox_keygen
    sealed = DstuCore.secretbox_seal(key, "message").dup
    sealed[-1] = (sealed[-1].ord ^ 1).chr
    expect { DstuCore.secretbox_open(key, sealed) }.to raise_error(DstuCore::Error)
  end

  it "rejects a tampered nonce" do
    key = DstuCore.secretbox_keygen
    sealed = DstuCore.secretbox_seal(key, "message").dup
    sealed[0] = (sealed[0].ord ^ 1).chr
    expect { DstuCore.secretbox_open(key, sealed) }.to raise_error(DstuCore::Error)
  end

  it "rejects the wrong key" do
    key = DstuCore.secretbox_keygen
    other_key = DstuCore.secretbox_keygen
    sealed = DstuCore.secretbox_seal(key, "message")
    expect { DstuCore.secretbox_open(other_key, sealed) }.to raise_error(DstuCore::Error)
  end

  it "rejects a wrong-length key" do
    expect { DstuCore.secretbox_seal("too short", "message") }.to raise_error(ArgumentError)
  end

  it "rejects truncated sealed input" do
    key = DstuCore.secretbox_keygen
    expect { DstuCore.secretbox_open(key, "short") }.to raise_error(DstuCore::Error)
  end
end
