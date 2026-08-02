# frozen_string_literal: true

# `crypto_secretstream` idiomatic wrapper (docs/DECISIONS.md D-118, docs/bindings-strategy.md
# T-160 step 3) - hides chunk/tag/header bookkeeping behind `write`/`each`, built in pure Ruby on
# top of the low-level SecretStreamPushState/SecretStreamPullState the compiled extension already
# exposes (step 2), rather than new Rust glue. Modeled on stdlib's own
# Zlib::GzipWriter/Zlib::GzipReader - the same "wraps an IO, transforms chunks transparently"
# shape, the closest Ruby-native precedent for this problem (matching Python's file-like object,
# Node's stream.Transform).
#
# **Wire format matches `uacrypt encrypt`/`decrypt` exactly**
# (crates/uacrypt/src/lib.rs's `run_secretstream_encrypt`/`run_secretstream_decrypt`, D-68):
# `header (32 bytes)` followed by one record per chunk, `tag_byte (1) || chunk_len_u32_le (4) ||
# ciphertext (chunk_len) || auth_tag (16)`, chunks capped at 8 KiB (matching
# `SECRETSTREAM_CHUNK_BYTES`, not an independent choice) - a file `SecretStreamWriter` writes is
# decryptable by `uacrypt decrypt` and vice versa.
#
# **Every `String` this wrapper touches is binary (`ASCII-8BIT`/`BINARY`)**, both what it writes
# to `out`/`inp` and what `#read_all`/`#each` yield - matching every underlying `crypto_*` wrapper
# function (`RString::to_bytes`, D-134). A caller passing UTF-8 text must `.b`/
# `force_encoding("BINARY")` before comparing against the decrypted result, or the comparison sees
# differing encodings and fails even when the bytes match (`"привіт".b == "привіт"` is `false` in
# Ruby) - this is a caller-side encoding-compare gotcha, not a bug in this wrapper.
module DstuCore
  # Matches crates/uacrypt/src/lib.rs's SECRETSTREAM_CHUNK_BYTES exactly - required for
  # wire-format interop with `uacrypt encrypt`/`decrypt`, not an independent choice.
  SECRETSTREAM_CHUNK_BYTES = 8 * 1024
  SECRETSTREAM_AUTH_TAG_BYTES = 16

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
      @push = SecretStreamPushState.new(key)
      @out.write(@push.header)
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

    # Buffers `data`, pushing any now-complete 8 KiB chunks immediately. The trailing partial (or
    # exactly-8-KiB) chunk is always held back until `close`, since only `close` knows no more
    # data is coming - the same one-chunk-ahead reasoning `uacrypt encrypt` itself uses to tag the
    # true last chunk `Final`, not an extra empty one after it.
    def write(data)
      raise IOError, "closed stream" if @closed

      @buf << data.b
      while @buf.bytesize > SECRETSTREAM_CHUNK_BYTES
        push_chunk(SECRETSTREAM_TAG_MESSAGE, @buf.byteslice(0, SECRETSTREAM_CHUNK_BYTES))
        @buf = @buf.byteslice(SECRETSTREAM_CHUNK_BYTES..) || +""
      end
      data.bytesize
    end

    alias << write

    # Flushes any buffered bytes as the stream's Final chunk. Idempotent - safe to call more than
    # once, matching normal Ruby `IO#close` semantics.
    def close
      return if @closed

      push_chunk(SECRETSTREAM_TAG_FINAL, @buf)
      @buf = +""
      @closed = true
    end

    private

    def push_chunk(tag, data)
      ciphertext, auth_tag = @push.push(tag, data)
      @out.write([tag].pack("C"))
      @out.write([data.bytesize].pack("V"))
      @out.write(ciphertext)
      @out.write(auth_tag)
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
      header = read_exact(32, "header")
      @pull = SecretStreamPullState.new(key, header)
      @done = false
    end

    def self.open(key, inp)
      reader = new(key, inp)
      yield reader
    end

    def each
      return enum_for(:each) unless block_given?

      yield next_chunk until @done
    end

    def read_all
      each.to_a.join
    end

    # No-op - present for symmetry with SecretStreamWriter and Ruby's own IO-like `close` idiom.
    def close; end

    private

    def next_chunk
      tag_byte = read_exact(1, "chunk tag").unpack1("C")
      chunk_len = read_exact(4, "chunk length").unpack1("V")
      # `chunk_len` is untrusted wire input, read before any tag verification - reject an
      # oversized declared length before acting on it (`read_exact` would otherwise try to
      # accumulate up to `chunk_len` bytes from `inp`, which for a socket/pipe could mean
      # gigabytes before ever failing). Matches `uacrypt decrypt`'s own
      # `CliError::SecretstreamChunkTooLarge` bound (`crates/uacrypt/src/lib.rs`).
      if chunk_len > SECRETSTREAM_CHUNK_BYTES
        raise DstuCore::Error,
              "secretstream chunk too large: declared #{chunk_len} bytes, max #{SECRETSTREAM_CHUNK_BYTES}"
      end
      ciphertext = read_exact(chunk_len, "chunk ciphertext")
      auth_tag = read_exact(SECRETSTREAM_AUTH_TAG_BYTES, "chunk auth tag")
      tag, plaintext = @pull.pull(tag_byte, ciphertext, auth_tag)
      if tag == SECRETSTREAM_TAG_FINAL
        # Matches `uacrypt decrypt`'s own `CliError::SecretstreamTrailingData` check - reject
        # bytes remaining after `Final` rather than silently ignoring them. Checked before
        # `plaintext` is returned, so a trailing-data stream never yields this last chunk either
        # via `each` or `read_all`.
        raise DstuCore::Error, "trailing data after the secretstream's Final chunk" if @inp.read(1)

        @done = true
      end
      plaintext
    end

    def read_exact(size, what)
      pieces = []
      remaining = size
      while remaining.positive?
        piece = @inp.read(remaining)
        break unless piece

        pieces << piece
        remaining -= piece.bytesize
      end
      data = pieces.join
      if data.bytesize != size
        raise DstuCore::Error, "truncated secretstream: expected #{size} bytes for #{what}, got #{data.bytesize}"
      end

      data
    end
  end
end
