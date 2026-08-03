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
/// format: a 32-byte header, then <c>tag(1) || len_u32_le(4) || ciphertext || authTag(16)</c>
/// records framed at <see cref="DstuConstants.SecretstreamChunkBytes"/>-byte plaintext boundaries.
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
    private readonly Stream _inner;
    private readonly bool _leaveOpen;
    private readonly PushStateHandle _state;
    private readonly byte[] _buffer = new byte[DstuConstants.SecretstreamChunkBytes];
    private byte[]? _pendingChunk;
    private int _bufferLen;
    private bool _completed;

    public SecretStreamEncryptStream(Stream inner, SecretstreamKey key, bool leaveOpen = false)
    {
        ArgumentNullException.ThrowIfNull(inner);
        ArgumentNullException.ThrowIfNull(key);
        _inner = inner;
        _leaveOpen = leaveOpen;
        var header = new byte[DstuConstants.SecretstreamHeaderBytes];
        NativeStatus.ThrowIfError(NativeMethods.dstu_secretstream_push_init(key.Handle, out _state, header));
        _inner.Write(header, 0, header.Length);
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

    public override void Write(byte[] buffer, int offset, int count)
    {
        ArgumentNullException.ThrowIfNull(buffer);
        if (_completed)
        {
            throw new InvalidOperationException("this stream has already been Complete()d");
        }

        var pos = offset;
        var remaining = count;
        while (remaining > 0)
        {
            var take = Math.Min(remaining, _buffer.Length - _bufferLen);
            Array.Copy(buffer, pos, _buffer, _bufferLen, take);
            _bufferLen += take;
            pos += take;
            remaining -= take;
            if (_bufferLen == _buffer.Length)
            {
                FlushPendingAsMessage();
                _pendingChunk = (byte[])_buffer.Clone();
                _bufferLen = 0;
            }
        }
    }

    /// <summary>Flushes all buffered plaintext as a <see cref="SecretStreamTag.Final"/> chunk and
    /// marks this stream complete. Must be called once, on the success path, before
    /// <c>Dispose()</c> - see the class doc comment for why <c>Dispose()</c> itself
    /// never does this.</summary>
    public void Complete()
    {
        if (_completed)
        {
            return;
        }

        if (_bufferLen > 0)
        {
            FlushPendingAsMessage();
            WriteChunk(SecretStreamTag.Final, _buffer, _bufferLen);
        }
        else if (_pendingChunk is { } pending)
        {
            WriteChunk(SecretStreamTag.Final, pending, pending.Length);
            _pendingChunk = null;
        }
        else
        {
            WriteChunk(SecretStreamTag.Final, [], 0);
        }

        _completed = true;
        _inner.Flush();
    }

    private void FlushPendingAsMessage()
    {
        if (_pendingChunk is { } pending)
        {
            WriteChunk(SecretStreamTag.Message, pending, pending.Length);
            _pendingChunk = null;
        }
    }

    private void WriteChunk(SecretStreamTag tag, byte[] plaintext, int len)
    {
        var pt = len == plaintext.Length ? plaintext : plaintext[..len];
        var ciphertext = new byte[len];
        var tagOut = new byte[DstuConstants.SecretstreamTagBytes];
        NativeStatus.ThrowIfError(NativeMethods.dstu_secretstream_push(_state, tag, pt, (nuint)len, ciphertext, (nuint)len, tagOut));

        _inner.WriteByte((byte)tag);
        var lenBytes = BitConverter.GetBytes((uint)len);
        if (!BitConverter.IsLittleEndian)
        {
            Array.Reverse(lenBytes);
        }

        _inner.Write(lenBytes, 0, 4);
        _inner.Write(ciphertext, 0, len);
        _inner.Write(tagOut, 0, tagOut.Length);
    }

    protected override void Dispose(bool disposing)
    {
        if (disposing)
        {
            _state.Dispose();
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
/// <see cref="SecretStreamEncryptStream"/> or <c>uacrypt encrypt</c>. Bounds every untrusted
/// length-prefixed <c>chunkLen</c> field against <see cref="DstuConstants.SecretstreamChunkBytes"/>
/// before using it to size a read, and rejects trailing bytes after the <c>Final</c> chunk - both
/// checks the wire format's own framing does not provide for free (D-118's second pitfall; mirrors
/// <c>uacrypt</c>'s own <c>CliError::SecretstreamChunkTooLarge</c>/<c>SecretstreamTrailingData</c>).
/// </summary>
public sealed class SecretStreamDecryptStream : Stream
{
    private readonly Stream _inner;
    private readonly bool _leaveOpen;
    private readonly PullStateHandle _state;
    private byte[] _pendingPlaintext = [];
    private int _pendingPos;
    private bool _finalized;

    public SecretStreamDecryptStream(Stream inner, SecretstreamKey key, bool leaveOpen = false)
    {
        ArgumentNullException.ThrowIfNull(inner);
        ArgumentNullException.ThrowIfNull(key);
        _inner = inner;
        _leaveOpen = leaveOpen;
        var header = ReadExactly(DstuConstants.SecretstreamHeaderBytes);
        _state = NativeMethods.dstu_secretstream_pull_init(key.Handle, header);
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
        if (_pendingPos == _pendingPlaintext.Length)
        {
            if (_finalized || !ReadNextChunk())
            {
                if (!_finalized)
                {
                    throw new DstuException("secretstream ended before a Final chunk was seen - the input is truncated");
                }

                return 0;
            }
        }

        var available = _pendingPlaintext.Length - _pendingPos;
        var toCopy = Math.Min(available, count);
        Array.Copy(_pendingPlaintext, _pendingPos, buffer, offset, toCopy);
        _pendingPos += toCopy;
        return toCopy;
    }

    private bool ReadNextChunk()
    {
        var tagByte = _inner.ReadByte();
        if (tagByte < 0)
        {
            return false;
        }

        var lenBytes = ReadExactly(4);
        if (!BitConverter.IsLittleEndian)
        {
            Array.Reverse(lenBytes);
        }

        var len = BitConverter.ToUInt32(lenBytes);
        if (len > DstuConstants.SecretstreamChunkBytes)
        {
            throw new DstuException(
                $"secretstream chunk length {len} exceeds the maximum {DstuConstants.SecretstreamChunkBytes} bytes - the input is corrupted");
        }

        var ciphertext = ReadExactly((int)len);
        var authTag = ReadExactly(DstuConstants.SecretstreamTagBytes);
        var plaintextOut = new byte[len];
        NativeStatus.ThrowIfError(NativeMethods.dstu_secretstream_pull(
            _state, (byte)tagByte, ciphertext, len, authTag, plaintextOut, len, out var outTag));

        _pendingPlaintext = plaintextOut;
        _pendingPos = 0;
        if (outTag == SecretStreamTag.Final)
        {
            _finalized = true;
            if (_inner.ReadByte() != -1)
            {
                throw new DstuException("secretstream has trailing data after its Final chunk");
            }
        }

        return true;
    }

    private byte[] ReadExactly(int n)
    {
        var buf = new byte[n];
        var read = 0;
        while (read < n)
        {
            var r = _inner.Read(buf, read, n - read);
            if (r == 0)
            {
                throw new DstuException("secretstream ended unexpectedly mid-chunk - the input is truncated");
            }

            read += r;
        }

        return buf;
    }

    protected override void Dispose(bool disposing)
    {
        if (disposing)
        {
            _state.Dispose();
            if (!_leaveOpen)
            {
                _inner.Dispose();
            }
        }

        base.Dispose(disposing);
    }
}
