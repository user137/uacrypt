# frozen_string_literal: true

require "json"
require "stringio"

# Streaming crypto_box/crypto_box384/crypto_box512 (T-265 format v3, T-269, T-297): BoxWriter/BoxReader and the 384/512
# pair over the core's seal_stream/open_stream. Happy path: the shared v3 vectors (one-shot
# box_open and the streaming reader), a round trip across record boundaries, one-shot/streaming
# byte equivalence. Security: tampering, a wrong key, trailing data. Misuse: wrong-length keys, a
# cut prefix, write after close, the 0.4-0.6 format. Error path: a raising block leaves no Final
# record (D-118). Mirrors bindings/python/tests/test_box_stream.py.
RSpec.describe "DstuCore streaming box" do
  vectors_dir = File.expand_path("../../../crates/dstu-core/tests/vectors/box", __dir__)
  load = ->(name) { JSON.parse(File.read(File.join(vectors_dir, name), encoding: "UTF-8")) }
  pattern = ->(n) { Array.new(n) { |i| ((i * 31) + 7) % 256 }.pack("C*") }
  hex = ->(s) { [s].pack("H*") }

  curves = {
    256 => { open: :box_open, writer: DstuCore::BoxWriter, reader: DstuCore::BoxReader,
             keygen: :box_keygen, public_key: :box_public_key, secret_field: "box256_secret_key_hex" },
    384 => { open: :box384_open, writer: DstuCore::Box384Writer, reader: DstuCore::Box384Reader,
             keygen: :box384_keygen, public_key: :box384_public_key, secret_field: "box384_secret_key_hex" },
    512 => { open: :box512_open, writer: DstuCore::Box512Writer, reader: DstuCore::Box512Reader,
             keygen: :box512_keygen, public_key: :box512_public_key, secret_field: "box512_secret_key_hex" }
  }

  curves.each do |curve, c|
    stream_open = ->(secret, sealed) { c[:reader].open(secret, StringIO.new(sealed), &:read_all) }
    seal_stream = lambda do |secret, message|
      out = StringIO.new
      c[:writer].open(DstuCore.public_send(c[:public_key], secret), out) do |w|
        w.write(message.byteslice(0, 7) || "")
        w.write(message.byteslice(7..) || "")
      end
      out.string
    end

    it "box#{curve}: shared v3 vectors give their expected outcome" do
      vectors = load.call("v3.json")
      secret = hex.call(vectors[c[:secret_field]])
      cases = vectors["cases"].select { |v| v["curve"] == curve }
      expect(cases).not_to be_empty
      cases.each do |v|
        sealed = hex.call(v["sealed_hex"])
        if v["expect"] == "ok"
          expected = pattern.call(v["plaintext_len"])
          expect(DstuCore.public_send(c[:open], secret, sealed)).to eq(expected)
          expect(stream_open.call(secret, sealed)).to eq(expected)
        else
          expect { DstuCore.public_send(c[:open], secret, sealed) }.to raise_error(DstuCore::Error)
          expect { stream_open.call(secret, sealed) }.to raise_error(DstuCore::Error)
        end
      end
    end

    it "box#{curve}: the 0.6 format is refused as unsupported" do
      if curve == 384
        # 0.4-0.6 had no l(p)=384 (T-297): a version-2 byte stands in for such a file.
        secret = DstuCore.public_send(c[:keygen])
        sealed = "\x02".b + ("\x00" * 240)
        expect { DstuCore.public_send(c[:open], secret, sealed) }.to raise_error(DstuCore::Error, /version/)
        expect { stream_open.call(secret, sealed) }.to raise_error(DstuCore::Error, /version/)
        next
      end
      vectors = load.call("legacy_v2.json")
      secret = hex.call(vectors[c[:secret_field]])
      vectors["cases"].select { |v| v["curve"] == curve }.each do |v|
        sealed = hex.call(v["sealed_hex"])
        expect { DstuCore.public_send(c[:open], secret, sealed) }.to raise_error(DstuCore::Error, /version/)
        expect { stream_open.call(secret, sealed) }.to raise_error(DstuCore::Error, /version/)
      end
    end

    [0, 1, 8 * 1024, (8 * 1024) + 1, (3 * 8 * 1024) + 5].each do |size|
      it "box#{curve}: a #{size}-byte stream reads back streaming and one-shot" do
        secret = DstuCore.public_send(c[:keygen])
        message = pattern.call(size)
        sealed = seal_stream.call(secret, message)
        expect(stream_open.call(secret, sealed)).to eq(message)
        expect(DstuCore.public_send(c[:open], secret, sealed)).to eq(message)
      end
    end

    it "box#{curve}: tampering, a wrong key and trailing data fail closed" do
      secret = DstuCore.public_send(c[:keygen])
      sealed = seal_stream.call(secret, pattern.call(100))
      expect { stream_open.call(DstuCore.public_send(c[:keygen]), sealed) }.to raise_error(DstuCore::Error)
      [1, sealed.bytesize / 2, sealed.bytesize - 1].each do |index|
        bad = sealed.dup
        bad.setbyte(index, bad.getbyte(index) ^ 0x01)
        expect { stream_open.call(secret, bad) }.to raise_error(DstuCore::Error)
      end
      expect { stream_open.call(secret, "#{sealed}\x00".b) }.to raise_error(DstuCore::Error)
    end

    it "box#{curve}: misuse is refused" do
      secret = DstuCore.public_send(c[:keygen])
      expect { c[:writer].new("\x01".b * 3, StringIO.new) }.to raise_error(ArgumentError)
      expect { c[:reader].new("\x01".b * 3, StringIO.new("\x03".b * 400)) }.to raise_error(ArgumentError)
      writer = c[:writer].new(DstuCore.public_send(c[:public_key], secret), StringIO.new)
      writer.close
      expect { writer.write("late") }.to raise_error(IOError)
      sealed = seal_stream.call(secret, pattern.call(10))
      [0, 1, 50].each do |cut|
        expect { stream_open.call(secret, sealed.byteslice(0, cut)) }.to raise_error(DstuCore::Error)
      end
    end

    it "box#{curve}: a raising block leaves no Final record" do
      secret = DstuCore.public_send(c[:keygen])
      out = StringIO.new
      expect do
        c[:writer].open(DstuCore.public_send(c[:public_key], secret), out) do |w|
          w.write(pattern.call(3 * 8 * 1024))
          raise "upstream failed"
        end
      end.to raise_error(RuntimeError, "upstream failed")
      expect { stream_open.call(secret, out.string) }.to raise_error(DstuCore::Error)
    end
  end
end
