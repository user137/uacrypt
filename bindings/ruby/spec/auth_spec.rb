# frozen_string_literal: true

# crypto_auth - three categories per D-64/D-65: correctness (round trip), rejection (tampered
# message, wrong key), misuse (wrong-length key/tag - foreclosed at the Rust layer by fixed-size
# arrays, D-66, so `auth` itself is infallible; only the Ruby-boundary length checks are testable
# here).
RSpec.describe "DstuCore auth" do
  it "round-trips auth/auth_verify" do
    key = DstuCore.auth_keygen
    message = "a message both parties want to confirm is unmodified"
    tag = DstuCore.auth(key, message)
    expect { DstuCore.auth_verify(key, message, tag) }.not_to raise_error
  end

  it "rejects a tampered message" do
    key = DstuCore.auth_keygen
    tag = DstuCore.auth(key, "original message")
    expect { DstuCore.auth_verify(key, "a different message", tag) }.to raise_error(DstuCore::Error)
  end

  it "rejects the wrong key" do
    key = DstuCore.auth_keygen
    other_key = DstuCore.auth_keygen
    tag = DstuCore.auth(key, "message")
    expect { DstuCore.auth_verify(other_key, "message", tag) }.to raise_error(DstuCore::Error)
  end

  it "rejects a wrong-length key" do
    expect { DstuCore.auth("too short", "message") }.to raise_error(ArgumentError)
  end

  it "rejects a wrong-length tag" do
    key = DstuCore.auth_keygen
    expect { DstuCore.auth_verify(key, "message", "too short") }.to raise_error(ArgumentError)
  end
end
