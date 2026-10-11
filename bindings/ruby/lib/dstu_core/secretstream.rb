# frozen_string_literal: true

# `crypto_secretstream` idiomatic wrapper (docs/DECISIONS.md D-118, docs/bindings-strategy.md
# T-160 step 3) - hides chunk/tag/header bookkeeping behind `write`/`each`. The framing itself
# (record layout, length rules, Final, trailing data) is dstu-core's stream-file codec, exposed as
# SecretStreamFileEncryptor/SecretStreamFileDecryptor (T-284); this file does only I/O. Modeled on
# stdlib's own
# Zlib::GzipWriter/Zlib::GzipReader - the same "wraps an IO, transforms chunks transparently"
# shape, the closest Ruby-native precedent for this problem (matching Python's file-like object,
# Node's stream.Transform).
#
# **Wire format matches `uacrypt encrypt`/`decrypt` exactly**
# (crates/uacrypt/src/lib.rs's `run_secretstream_encrypt`/`run_secretstream_decrypt`, D-68):
# `version (1) || header (32 bytes)` followed by one record per chunk, `tag_byte (1) ||
# chunk_len_u32_le (4) || ciphertext (chunk_len) || auth_tag (16)`. Every record but the Final one is
# exactly 8 KiB (`SECRETSTREAM_CHUNK_BYTES`, part of the format since D-208, not an independent
# choice) - a file `SecretStreamWriter` writes is decryptable by `uacrypt decrypt` and vice versa.
# The shared vectors in crates/dstu-core/tests/vectors/secretstream-file/ pin this.
#
# **Every `String` this wrapper touches is binary (`ASCII-8BIT`/`BINARY`)**, both what it writes
# to `out`/`inp` and what `#read_all`/`#each` yield - matching every underlying `crypto_*` wrapper
# function (`RString::to_bytes`, D-134). A caller passing UTF-8 text must `.b`/
# `force_encoding("BINARY")` before comparing against the decrypted result, or the comparison sees
# differing encodings and fails even when the bytes match (`"привіт".b == "привіт"` is `false` in
# Ruby) - this is a caller-side encoding-compare gotcha, not a bug in this wrapper.
module DstuCore
  # dstu-core's crypto_secretstream::CHUNK_BYTES and wire constants (D-208); the codec enforces
  # them, these stay as public constants.
  SECRETSTREAM_CHUNK_BYTES = 8 * 1024
  SECRETSTREAM_AUTH_TAG_BYTES = 16
  # Matches dstu-core's crypto_secretstream::FORMAT_VERSION (D-208); the shared vectors pin it.
  SECRETSTREAM_FORMAT_VERSION = 2

  # Write-only wrapper: buffers input and pushes each full 8 KiB chunk to `out` as it fills, hiding
  # the header/tag/framing bookkeeping entirely.
  #
  #   File.open("out.bin", "wb") do |f|
  #     DstuCore::SecretStreamWriter.open(key, f) { |w| w.write("a whole file, incrementally") }
  #   end
  class SecretStreamWriter
    def initialize(key, out)
      @out = out
      @out.binmode if @out.respond_to?(:binmode)
      @enc = SecretStreamFileEncryptor.new(key)
      @out.write(@enc.prefix)
      @buf = +""
      @closed = false
    end

    # Block form: yields a writer, then closes it - **only on the success path**. The D-118
    # pitfall this deliberately avoids: Ruby's own "always runs, even on error" cleanup idiom
    # (`ensure`, the shape `File.open`/`Zlib::GzipWriter.wrap` both use) would finalize (emit the
    # `Final` chunk) even when the block raised partway through, producing a stream that looks
    # complete but silently drops data - violates D-65's "no partial output treated as valid on
    # failure." If a truncated-but-decryptable prefix is genuinely wanted, call `close` explicitly
    # inside a `rescue` clause instead.
    def self.open(key, out)
      writer = new(key, out)
      yield writer
      writer.close
      writer
    end

    def closed?
      @closed
    end

    # Buffers `data`, sealing every full 8 KiB chunk that is certain not to be the last one. The
    # trailing partial (or exactly-8-KiB) chunk is held back until `close`, since only `close`
    # knows no more data is coming - an exact multiple of 8 KiB must end in a full Final record
    # (D-208). Full chunks are cut from `data` by offset, so one large write costs linear time
    # (T-276).
    def write(data)
      raise IOError, "closed stream" if @closed

      data = data.b
      pos = top_up_buffer(data)
      while data.bytesize - pos > SECRETSTREAM_CHUNK_BYTES
        @out.write(@enc.seal_chunk(data.byteslice(pos, SECRETSTREAM_CHUNK_BYTES)))
        pos += SECRETSTREAM_CHUNK_BYTES
      end
      @buf << data.byteslice(pos..)
      data.bytesize
    end

    alias << write

    # Flushes any buffered bytes as the stream's Final chunk. Idempotent - safe to call more than
    # once, matching normal Ruby `IO#close` semantics.
    def close
      return if @closed

      @out.write(@enc.seal_final(@buf))
      @buf = +""
      @closed = true
    end

    private

    # Adds `data` to the held-back chunk if it all fits; otherwise tops that chunk up to a full one
    # and seals it, since more data follows. Returns how many bytes of `data` it consumed.
    def top_up_buffer(data)
      return 0 if @buf.empty?

      if @buf.bytesize + data.bytesize <= SECRETSTREAM_CHUNK_BYTES
        @buf << data
        return data.bytesize
      end
      taken = SECRETSTREAM_CHUNK_BYTES - @buf.bytesize
      @buf << data.byteslice(0, taken)
      @out.write(@enc.seal_chunk(@buf))
      @buf = +""
      taken
    end
  end

  # Read-only, chunk-iterating wrapper: reads and decrypts one chunk from `inp` at a time.
  # `include Enumerable` gives `to_a`/`map`/etc. for free; `read_all` joins every plaintext chunk
  # into one `String`, bounded only by available memory (the same caveat `crypto_secretbox`
  # already carries). Raises `DstuCore::Error` on authentication failure or truncation - a
  # dropped/tampered/reordered chunk, or a stream that ends before a Final chunk, both fail closed
  # rather than yielding wrong plaintext.
  #
  #   File.open("out.bin", "rb") do |f|
  #     plaintext = DstuCore::SecretStreamReader.open(key, f, &:read_all)
  #   end
  class SecretStreamReader
    include Enumerable

    def initialize(key, inp)
      @inp = inp
      @inp.binmode if @inp.respond_to?(:binmode)
      @dec = SecretStreamFileDecryptor.new(key)
      @done = false
      # The version byte and header, read now so a wrong version fails at construction.
      2.times { step }
    end

    def self.open(key, inp)
      reader = new(key, inp)
      yield reader
    end

    def each
      return enum_for(:each) unless block_given?

      until @done
        plaintext = step
        yield plaintext unless plaintext.empty?
      end
    end

    def read_all
      each.to_a.join
    end

    # No-op - present for symmetry with SecretStreamWriter and Ruby's own IO-like `close` idiom.
    def close; end

    private

    # Feeds the codec one `next_len` read: the plaintext that read released (possibly empty), or
    # at end of input the Final chunk's (after which the stream is done).
    def step
      want = @dec.next_len
      data = read_up_to(want)
      if data.bytesize < want
        @done = true
        return @dec.finish
      end
      @dec.feed(data)
    end

    # Reads until `size` bytes arrived or `inp` ended; a short result means end of input.
    def read_up_to(size)
      pieces = []
      remaining = size
      while remaining.positive?
        piece = @inp.read(remaining)
        break unless piece

        pieces << piece
        remaining -= piece.bytesize
      end
      pieces.join.b
    end
  end
end
