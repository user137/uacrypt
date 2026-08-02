# frozen_string_literal: true

# Correctness gate: `DstuCore.self_test` re-verifies one official vector per primitive (Kalyna,
# Kupyna, Strumok, DSTU 4145) against this exact compiled extension - docs/TASKS.md T-161. Every
# other spec file in this suite adds its own correctness/rejection/misuse coverage on top of this
# baseline (D-64/D-65).
RSpec.describe "DstuCore.self_test" do
  it "passes" do
    expect { DstuCore.self_test }.not_to raise_error
  end
end
