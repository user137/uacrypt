# frozen_string_literal: true

# crypto_kdf - no official vector exists for this construction (D-45: no DSTU KDF standard or
# reference implementation exists at all). Correctness here means determinism/distinctness,
# matching the Rust crate's own property-test posture. Misuse: wrong-length master key/context
# (infallible otherwise, D-66 - no rejection category, there is no tag to tamper with).
RSpec.describe "DstuCore kdf" do
  it "derives a deterministic subkey" do
    master_key = DstuCore.kdf_keygen
    a = DstuCore.kdf_derive_subkey(master_key, 0, "encrypt_")
    b = DstuCore.kdf_derive_subkey(master_key, 0, "encrypt_")
    expect(a).to eq(b)
  end

  it "gives a different subkey for a different subkey_id" do
    master_key = DstuCore.kdf_keygen
    a = DstuCore.kdf_derive_subkey(master_key, 0, "context1")
    b = DstuCore.kdf_derive_subkey(master_key, 1, "context1")
    expect(a).not_to eq(b)
  end

  it "gives a different subkey for a different context" do
    master_key = DstuCore.kdf_keygen
    a = DstuCore.kdf_derive_subkey(master_key, 0, "context1")
    b = DstuCore.kdf_derive_subkey(master_key, 0, "context2")
    expect(a).not_to eq(b)
  end

  it "rejects a wrong-length master key" do
    expect { DstuCore.kdf_derive_subkey("too short", 0, "context1") }.to raise_error(ArgumentError)
  end

  it "rejects a wrong-length context" do
    master_key = DstuCore.kdf_keygen
    expect { DstuCore.kdf_derive_subkey(master_key, 0, "short") }.to raise_error(ArgumentError)
  end

  it "rejects a negative subkey_id" do
    master_key = DstuCore.kdf_keygen
    expect { DstuCore.kdf_derive_subkey(master_key, -1, "context1") }.to raise_error(ArgumentError)
  end
end
