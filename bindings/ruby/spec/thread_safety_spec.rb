# frozen_string_literal: true

# T-219: concurrency contract for this binding's own wrapper types, decided and recorded rather
# than assumed.
#
# - DstuCore.sign_keygen/sign_verifying_key/sign_message/sign_verify are plain functions over
#   immutable Ruby String keys - no native object holds state across calls, so nothing to race on
#   regardless of the GVL. Verified below with real concurrent Ruby Threads calling
#   sign_verify/sign_message on the SAME key.
# - SecretStreamPushState/PullState DO hold native state (an interior RefCell the Rust side
#   borrow_muts on every push/pull) that advances with every call. The GVL means two Ruby Threads
#   can never literally race a single native call - but nothing stops two threads from
#   interleaving separate calls on the SAME session in an unpredictable order, which would be
#   logically wrong for a stream even though it can't corrupt memory. This binding adds no lock of
#   its own - the supported concurrency model is one stream (one Push/PullState pair) per thread,
#   verified below with each thread driving its own independent stream concurrently rather than
#   racing a shared one.
RSpec.describe "DstuCore thread safety (T-219)" do
  it "allows concurrent verify on a shared key" do
    signing_key = DstuCore.sign_keygen
    verifying_key = DstuCore.sign_verifying_key(signing_key)
    message = "shared-key concurrent verify"
    signature = DstuCore.sign_message(signing_key, message)

    errors = Queue.new
    threads = Array.new(16) do
      Thread.new do
        200.times do
          errors << "Verify returned false on a valid signature" unless DstuCore.sign_verify(verifying_key, message, signature)
        end
      rescue StandardError => e
        errors << e
      end
    end
    threads.each(&:join)

    expect(errors).to be_empty
  end

  it "allows concurrent sign on a shared key" do
    signing_key = DstuCore.sign_keygen
    verifying_key = DstuCore.sign_verifying_key(signing_key)
    message = "shared-key concurrent sign"

    errors = Queue.new
    threads = Array.new(16) do
      Thread.new do
        50.times do
          sig = DstuCore.sign_message(signing_key, message)
          errors << "a concurrently-produced signature failed to verify" unless DstuCore.sign_verify(verifying_key, message, sig)
        end
      rescue StandardError => e
        errors << e
      end
    end
    threads.each(&:join)

    expect(errors).to be_empty
  end

  it "allows independent secretstream loops on separate threads" do
    errors = Queue.new
    threads = Array.new(8) do |thread_index|
      Thread.new do
        key = DstuCore.secretstream_keygen
        chunks = Array.new(20) { |i| "thread #{thread_index} chunk #{i}" }

        push = DstuCore::SecretStreamPushState.new(key)
        header = push.header
        pushed = chunks.map { |chunk| push.push(DstuCore::SECRETSTREAM_TAG_MESSAGE, chunk) }

        pull = DstuCore::SecretStreamPullState.new(key, header)
        chunks.each_with_index do |chunk, i|
          ciphertext, auth_tag = pushed[i]
          _tag, plaintext = pull.pull(DstuCore::SECRETSTREAM_TAG_MESSAGE, ciphertext, auth_tag)
          errors << "thread #{thread_index}: round trip mismatch at chunk #{i}" unless plaintext == chunk
        end
      rescue StandardError => e
        errors << e
      end
    end
    threads.each(&:join)

    expect(errors).to be_empty
  end
end
