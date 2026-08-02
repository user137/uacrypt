# frozen_string_literal: true

# randombytes - no rejection/misuse category (a single `size` parameter, no key/tag to tamper with
# or malform). Correctness: returns the requested length, and two calls are not identical.
RSpec.describe "DstuCore randombytes" do
  it "returns the requested length" do
    expect(DstuCore.randombytes_buf(32).bytesize).to eq(32)
  end

  it "returns empty for a zero length" do
    expect(DstuCore.randombytes_buf(0)).to eq("")
  end

  it "does not return the same bytes twice" do
    expect(DstuCore.randombytes_buf(32)).not_to eq(DstuCore.randombytes_buf(32))
  end
end
