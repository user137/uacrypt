using System.Runtime.InteropServices;
using DstuCore.Native;

namespace DstuCore;

/// <summary>Genuinely chunked/streaming AEAD master key (<c>crypto_secretstream</c>).</summary>
public sealed class SecretstreamKey : IDisposable
{
    internal readonly SecretstreamKeyHandle Handle;

    private SecretstreamKey(SecretstreamKeyHandle handle)
    {
        Handle = handle;
    }

    /// <summary>Generates a fresh key from the OS CSPRNG.</summary>
    public static SecretstreamKey Generate()
    {
        NativeStatus.ThrowIfError(NativeMethods.dstu_secretstream_key_generate(out var handle));
        return new SecretstreamKey(handle);
    }

    /// <summary>Builds a key from exactly <see cref="DstuConstants.SecretstreamKeyBytes"/> bytes.</summary>
    public static SecretstreamKey FromBytes(byte[] key)
    {
        ArgumentNullException.ThrowIfNull(key);
        if (key.Length != DstuConstants.SecretstreamKeyBytes)
        {
            throw new ArgumentException($"key must be exactly {DstuConstants.SecretstreamKeyBytes} bytes", nameof(key));
        }

        return new SecretstreamKey(NativeMethods.dstu_secretstream_key_from_bytes(key));
    }

    /// <summary>Copies out this key's raw <see cref="DstuConstants.SecretstreamKeyBytes"/>-byte encoding.</summary>
    public byte[] ToBytes()
    {
        var outBytes = new byte[DstuConstants.SecretstreamKeyBytes];
        NativeMethods.dstu_secretstream_key_bytes(Handle, outBytes);
        return outBytes;
    }

    public void Dispose() => Handle.Dispose();
}

/// <summary>
/// Encrypts a write-side <see cref="System.IO.Stream"/> into <c>uacrypt encrypt</c>'s own wire
/// format: a version byte and a 32-byte header, then <c>tag(1) || len_u32_le(4) || ciphertext ||
/// authTag(16)</c> records. Every record but the <c>Final</c> one carries exactly
/// <see cref="DstuConstants.SecretstreamChunkBytes"/> bytes (part of the format since D-208). The
/// framing is dstu-core's stream-file codec (T-284) through the C ABI; this class only buffers and
/// writes.
///
/// <para><b>Deliberately does not flush a <see cref="SecretStreamTag.Final"/> chunk from
/// <see cref="Dispose"/></b> - unlike <c>CryptoStream</c>/<c>GZipStream</c>'s own close-flushes
/// convention. Call <see cref="Complete"/> explicitly once all plaintext has been written; a
/// stream disposed without it is deliberately left without a <c>Final</c> chunk, so a reader fails
/// closed on it instead of accepting a truncated file as complete (D-65 - the same property
/// <c>uacrypt encrypt</c>'s own temp-file-then-rename gets for free, and the concrete D-118
/// pitfall found building <c>bindings/python</c>'s own wrapper).</para>
/// </summary>
public sealed class SecretStreamEncryptStream : Stream
{
    private const int ChunkBytes = DstuConstants.SecretstreamChunkBytes;
    private readonly Stream _inner;
    private readonly bool _leaveOpen;
    private readonly FileEncryptorHandle _enc;
    private readonly byte[] _buffer = new byte[ChunkBytes];
    private readonly byte[] _record = new byte[DstuConstants.SecretstreamMaxRecordBytes];
    private int _bufferLen;
    private bool _completed;

    public SecretStreamEncryptStream(Stream inner, SecretstreamKey key, bool leaveOpen = false)
        : this(inner, StartWithKey(key), leaveOpen)
    {
    }

    private SecretStreamEncryptStream(Stream inner, (FileEncryptorHandle Enc, byte[] Prefix) started, bool leaveOpen)
    {
        ArgumentNullException.ThrowIfNull(inner);
        _inner = inner;
        _leaveOpen = leaveOpen;
        _enc = started.Enc;
        try
        {
            _inner.Write(started.Prefix, 0, started.Prefix.Length);
        }
        catch
        {
            _enc.Dispose();
            throw;
        }
    }

    /// <summary><c>crypto_box</c> sealed to <paramref name="recipient"/> as a stream (format v3,
    /// T-265/T-269): the same bytes <see cref="BoxPublicKey.Seal"/> returns, written chunk by
    /// chunk. <see cref="Complete"/> rules as for a key stream.</summary>
    public static SecretStreamEncryptStream ForBox(Stream inner, BoxPublicKey recipient, bool leaveOpen = false)
    {
        ArgumentNullException.ThrowIfNull(inner);
        ArgumentNullException.ThrowIfNull(recipient);
        var prefix = new byte[DstuConstants.BoxSealStreamPrefixBytes];
        NativeStatus.ThrowIfError(NativeMethods.dstu_box_seal_stream(recipient.Handle, prefix, out var enc));
        return new SecretStreamEncryptStream(inner, (enc, prefix), leaveOpen);
    }

    /// <summary><c>crypto_box512</c> counterpart of <see cref="ForBox"/>.</summary>
    public static SecretStreamEncryptStream ForBox512(Stream inner, Box512PublicKey recipient, bool leaveOpen = false)
    {
        ArgumentNullException.ThrowIfNull(inner);
        ArgumentNullException.ThrowIfNull(recipient);
        var prefix = new byte[DstuConstants.Box512SealStreamPrefixBytes];
        NativeStatus.ThrowIfError(NativeMethods.dstu_box512_seal_stream(recipient.Handle, prefix, out var enc));
        return new SecretStreamEncryptStream(inner, (enc, prefix), leaveOpen);
    }

    /// <summary>A passphrase file (D-219/D-240) - the bytes <c>uacrypt encrypt --passphrase</c>
    /// writes. Runs Argon2id (256 MiB, t=3, about a second) on the calling thread before writing
    /// anything. An empty passphrase is refused with <see cref="ArgumentException"/>.</summary>
    public static SecretStreamEncryptStream ForPassphrase(Stream inner, byte[] passphrase, bool leaveOpen = false)
    {
        ArgumentNullException.ThrowIfNull(inner);
        CheckPassphrase(passphrase);
        var prefix = new byte[DstuConstants.PassphraseFileSealStreamPrefixBytes];
        NativeStatus.ThrowIfError(NativeMethods.dstu_passphrase_file_seal_stream(
            passphrase, (nuint)passphrase.Length, prefix, out var enc));
        return new SecretStreamEncryptStream(inner, (enc, prefix), leaveOpen);
    }

    internal static void CheckPassphrase(byte[] passphrase)
    {
        ArgumentNullException.ThrowIfNull(passphrase);
        if (passphrase.Length == 0)
        {
            throw new ArgumentException("the passphrase is empty", nameof(passphrase));
        }
    }

    private static (FileEncryptorHandle, byte[]) StartWithKey(SecretstreamKey key)
    {
        ArgumentNullException.ThrowIfNull(key);
        var prefix = new byte[DstuConstants.SecretstreamFilePrefixBytes];
        NativeStatus.ThrowIfError(NativeMethods.dstu_secretstream_file_encryptor_new(key.Handle, prefix, out var enc));
        return (enc, prefix);
    }

    public override bool CanRead => false;
    public override bool CanSeek => false;
    public override bool CanWrite => true;
    public override long Length => throw new NotSupportedException();

    public override long Position
    {
        get => throw new NotSupportedException();
        set => throw new NotSupportedException();
    }

    public override int Read(byte[] buffer, int offset, int count) => throw new NotSupportedException();
    public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();
    public override void SetLength(long value) => throw new NotSupportedException();
    public override void Flush() => _inner.Flush();

    /// <summary>Buffers the bytes, sealing every full chunk that is certain not to be the last
    /// one; the last (even a full one) waits for <see cref="Complete"/>. Full chunks are sealed
    /// straight from <paramref name="buffer"/>.</summary>
    public override void Write(byte[] buffer, int offset, int count)
    {
        ArgumentNullException.ThrowIfNull(buffer);
        ArgumentOutOfRangeException.ThrowIfNegative(offset);
        ArgumentOutOfRangeException.ThrowIfNegative(count);
        ArgumentOutOfRangeException.ThrowIfGreaterThan(count, buffer.Length - offset);
        if (_completed)
        {
            throw new InvalidOperationException("this stream has already been Complete()d");
        }

        if (_bufferLen + count <= ChunkBytes)
        {
            Array.Copy(buffer, offset, _buffer, _bufferLen, count);
            _bufferLen += count;
            return;
        }

        var pos = offset;
        var end = offset + count;
        if (_bufferLen > 0)
        {
            var taken = ChunkBytes - _bufferLen;
            Array.Copy(buffer, pos, _buffer, _bufferLen, taken);
            pos += taken;
            SealChunk(_buffer);
            _bufferLen = 0;
        }

        while (end - pos > ChunkBytes)
        {
            SealChunk(buffer.AsSpan(pos, ChunkBytes));
            pos += ChunkBytes;
        }

        Array.Copy(buffer, pos, _buffer, 0, end - pos);
        _bufferLen = end - pos;
    }

    /// <summary>Writes all buffered plaintext as the <see cref="SecretStreamTag.Final"/> record,
    /// flushes, and marks this stream complete. Must be called once, on the success path, before
    /// <c>Dispose()</c> - see the class doc comment for why <c>Dispose()</c> itself never does
    /// this.</summary>
    public void Complete()
    {
        if (_completed)
        {
            return;
        }

        NativeStatus.ThrowIfError(NativeMethods.dstu_secretstream_file_encryptor_seal_final(
            _enc, _buffer.AsSpan(0, _bufferLen), (nuint)_bufferLen, _record, (nuint)_record.Length, out var recordLen));
        _inner.Write(_record, 0, (int)recordLen);
        _bufferLen = 0;
        _completed = true;
        _inner.Flush();
    }

    private void SealChunk(ReadOnlySpan<byte> chunk)
    {
        NativeStatus.ThrowIfError(NativeMethods.dstu_secretstream_file_encryptor_seal_chunk(
            _enc, chunk, (nuint)chunk.Length, _record, (nuint)_record.Length));
        _inner.Write(_record, 0, _record.Length);
    }

    protected override void Dispose(bool disposing)
    {
        if (disposing)
        {
            _enc.Dispose();
            if (!_leaveOpen)
            {
                _inner.Dispose();
            }
        }

        base.Dispose(disposing);
    }
}

/// <summary>
/// Decrypts a read-side <see cref="System.IO.Stream"/> produced by
/// <see cref="SecretStreamEncryptStream"/> or <c>uacrypt encrypt</c>. Every check - the untrusted
/// length field, the 8 KiB rule, truncation, trailing bytes after the <c>Final</c> chunk - is
/// dstu-core's stream-file codec (T-284); this class only reads, and reports the codec's own
/// message. The <c>Final</c> chunk is returned only once the input is known to end right after
/// it, so a stream with trailing data never yields its last chunk.
/// </summary>
public sealed class SecretStreamDecryptStream : Stream
{
    private readonly Stream _inner;
    private readonly bool _leaveOpen;
    private readonly FileDecryptorHandle _dec;
    private readonly byte[] _plaintext = new byte[DstuConstants.SecretstreamChunkBytes];
    private int _pendingPos;
    private int _pendingLen;
    private bool _done;

    public SecretStreamDecryptStream(Stream inner, SecretstreamKey key, bool leaveOpen = false)
        : this(inner, NewWithKey(key), leaveOpen)
    {
    }

    /// <summary>Reads a <c>crypto_box</c> stream (or a <see cref="BoxPublicKey.Seal"/> blob) with
    /// bounded memory.</summary>
    public static SecretStreamDecryptStream ForBox(Stream inner, BoxSecretKey secret, bool leaveOpen = false)
    {
        ArgumentNullException.ThrowIfNull(inner);
        ArgumentNullException.ThrowIfNull(secret);
        var prefix = ReadPrefix(inner, DstuConstants.BoxOpenStreamPrefixBytes, "sealed message");
        NativeStatus.ThrowIfError(NativeMethods.dstu_box_open_stream(secret.Handle, prefix, out var dec));
        return new SecretStreamDecryptStream(inner, dec, leaveOpen);
    }

    /// <summary><c>crypto_box512</c> counterpart of <see cref="ForBox"/>.</summary>
    public static SecretStreamDecryptStream ForBox512(Stream inner, Box512SecretKey secret, bool leaveOpen = false)
    {
        ArgumentNullException.ThrowIfNull(inner);
        ArgumentNullException.ThrowIfNull(secret);
        var prefix = ReadPrefix(inner, DstuConstants.Box512OpenStreamPrefixBytes, "sealed message");
        NativeStatus.ThrowIfError(NativeMethods.dstu_box512_open_stream(secret.Handle, prefix, out var dec));
        return new SecretStreamDecryptStream(inner, dec, leaveOpen);
    }

    /// <summary>Reads a passphrase file. The header is checked before Argon2 runs (on the calling
    /// thread); a wrong passphrase throws <see cref="DstuException"/> at the first record.</summary>
    public static SecretStreamDecryptStream ForPassphrase(Stream inner, byte[] passphrase, bool leaveOpen = false)
    {
        ArgumentNullException.ThrowIfNull(inner);
        SecretStreamEncryptStream.CheckPassphrase(passphrase);
        var header = ReadPrefix(inner, DstuConstants.PassphraseFileHeaderBytes, "passphrase file header");
        NativeStatus.ThrowIfError(NativeMethods.dstu_passphrase_file_open_stream(
            header, passphrase, (nuint)passphrase.Length, out var dec));
        return new SecretStreamDecryptStream(inner, dec, leaveOpen);
    }

    /// <summary>The bytes in front of the stream file; a shorter input cannot be opened.</summary>
    private static byte[] ReadPrefix(Stream inner, int size, string what)
    {
        var prefix = new byte[size];
        var got = 0;
        while (got < size)
        {
            var r = inner.Read(prefix, got, size - got);
            if (r == 0)
            {
                throw new DstuException($"input too short to contain a {what}");
            }

            got += r;
        }

        return prefix;
    }

    private static FileDecryptorHandle NewWithKey(SecretstreamKey key)
    {
        ArgumentNullException.ThrowIfNull(key);
        return NativeMethods.dstu_secretstream_file_decryptor_new(key.Handle);
    }

    private SecretStreamDecryptStream(Stream inner, FileDecryptorHandle dec, bool leaveOpen)
    {
        ArgumentNullException.ThrowIfNull(inner);
        _inner = inner;
        _leaveOpen = leaveOpen;
        _dec = dec;
        try
        {
            // The version byte and header, read now so a wrong version fails at construction.
            Step();
            Step();
        }
        catch
        {
            _dec.Dispose();
            throw;
        }
    }

    public override bool CanRead => true;
    public override bool CanSeek => false;
    public override bool CanWrite => false;
    public override long Length => throw new NotSupportedException();

    public override long Position
    {
        get => throw new NotSupportedException();
        set => throw new NotSupportedException();
    }

    public override void Write(byte[] buffer, int offset, int count) => throw new NotSupportedException();
    public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();
    public override void SetLength(long value) => throw new NotSupportedException();
    public override void Flush()
    {
    }

    public override int Read(byte[] buffer, int offset, int count)
    {
        ArgumentNullException.ThrowIfNull(buffer);
        while (_pendingPos == _pendingLen)
        {
            if (_done)
            {
                return 0;
            }

            _pendingLen = Step();
            _pendingPos = 0;
        }

        var toCopy = Math.Min(_pendingLen - _pendingPos, count);
        Array.Copy(_plaintext, _pendingPos, buffer, offset, toCopy);
        _pendingPos += toCopy;
        return toCopy;
    }

    /// <summary>Feeds the codec one <c>next_len</c> read; returns how many plaintext bytes that
    /// released into <c>_plaintext</c> (at end of input, the <c>Final</c> chunk's).</summary>
    private int Step()
    {
        var want = (int)NativeMethods.dstu_secretstream_file_decryptor_next_len(_dec);
        var data = new byte[want];
        var got = 0;
        while (got < want)
        {
            var r = _inner.Read(data, got, want - got);
            if (r == 0)
            {
                break;
            }

            got += r;
        }

        nuint len;
        DstuStatus status;
        if (got < want)
        {
            _done = true;
            status = NativeMethods.dstu_secretstream_file_decryptor_finish(
                _dec, _plaintext, (nuint)_plaintext.Length, out len);
        }
        else
        {
            status = NativeMethods.dstu_secretstream_file_decryptor_feed(
                _dec, data, (nuint)want, _plaintext, (nuint)_plaintext.Length, out len);
        }

        if (status != DstuStatus.Ok)
        {
            var message = NativeMethods.dstu_secretstream_file_decryptor_last_error(_dec);
            if (message != IntPtr.Zero)
            {
                throw new DstuException(Marshal.PtrToStringUTF8(message)!);
            }

            NativeStatus.ThrowIfError(status);
        }

        return (int)len;
    }

    protected override void Dispose(bool disposing)
    {
        if (disposing)
        {
            _dec.Dispose();
            if (!_leaveOpen)
            {
                _inner.Dispose();
            }
        }

        base.Dispose(disposing);
    }
}
