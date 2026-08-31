# frozen_string_literal: true

# T-213: FFI memory-leak smoke test. Loops crypto_secretstream push/pull (the most stateful,
# longest-lived native object this binding wraps - SecretStreamPushState/PullState) and crypto_box
# seal/open (a keyed one-shot primitive) N=1000+ times with normal cleanup, then asserts
# GC.stat[:heap_live_slots] growth stays far below what a real leak of that many iterations would
# show.
#
# Same reasoning as bindings/python/tests/test_memory_leak.py (T-213): these wrapper objects are
# direct magnus handles (Rust structs behind #[wrap]) with no separate C ABI free() call, so once
# the Ruby wrapper is garbage-collected, Rust's own Drop is guaranteed to run correctly - "the
# wrapper object never gets collected" (a held reference, D-118's cleanup-hook pitfall) is the leak
# risk this test targets, and a live-slot-count measurement genuinely observes it.
RSpec.describe "DstuCore memory leak (T-213)" do
  it "does not leak native handles over a secretstream + box loop" do
    n = 1000
    # Measured normal-case growth is ~22 slots for n=1000; a deliberate leak of all 2000 handles
    # (push+pull per iteration) measures ~2023 slots. This threshold sits with wide margin on both
    # sides of that gap, not tucked right against the leak signal.
    max_acceptable_slot_growth = n

    key = DstuCore.secretstream_keygen
    box_secret = DstuCore.box_keygen
    box_public = DstuCore.box_public_key(box_secret)

    GC.start
    before = GC.stat[:heap_live_slots]

    n.times do
      push = DstuCore::SecretStreamPushState.new(key)
      header = push.header
      ciphertext, auth_tag = push.push(DstuCore::SECRETSTREAM_TAG_MESSAGE, "leak-check chunk")
      pull = DstuCore::SecretStreamPullState.new(key, header)
      pull.pull(DstuCore::SECRETSTREAM_TAG_MESSAGE, ciphertext, auth_tag)

      sealed = DstuCore.box_seal(box_public, "leak-check message")
      opened = DstuCore.box_open(box_secret, sealed)
      expect(opened).to eq("leak-check message")
    end

    GC.start
    after = GC.stat[:heap_live_slots]
    growth = after - before
    expect(growth).to be < max_acceptable_slot_growth,
                      "heap_live_slots grew by #{growth} over #{n} iterations " \
                      "(threshold #{max_acceptable_slot_growth}) - possible native handle leak"
  end
end
