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
    {
        ArgumentNullException.ThrowIfNull(inner);
        ArgumentNullException.ThrowIfNull(key);
        _inner = inner;
        _leaveOpen = leaveOpen;
        var prefix = new byte[DstuConstants.SecretstreamFilePrefixBytes];
        NativeStatus.ThrowIfError(NativeMethods.dstu_secretstream_file_encryptor_new(key.Handle, prefix, out _enc));
        _inner.Write(prefix, 0, prefix.Length);
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
    {
        ArgumentNullException.ThrowIfNull(inner);
        ArgumentNullException.ThrowIfNull(key);
        _inner = inner;
        _leaveOpen = leaveOpen;
        _dec = NativeMethods.dstu_secretstream_file_decryptor_new(key.Handle);
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
