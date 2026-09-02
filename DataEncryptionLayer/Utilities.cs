using System.Security.Cryptography;
using System.Text;

namespace DataEncryptionLayer;

/// <summary>
/// Contains the default values and methods for AES cryptography
/// </summary>
public static class Utilities
{
    #region Constants

    /// <summary>
    /// The default AES key.
    /// Can be 16, 24, or 32 bytes.
    /// Base64: OvKccbTlCG0fyYdSqzTQ/kahK8OeeBRg3wW7KW+T7Qo=
    /// </summary>
    public static readonly byte[] DefaultKey =
    {
        0x3A, 0xF2, 0x9C, 0x71,
        0xB4, 0xE5, 0x08, 0x6D,
        0x1F, 0xC9, 0x87, 0x52,
        0xAB, 0x34, 0xD0, 0xFE,
        0x46, 0xA1, 0x2B, 0xC3,
        0x9E, 0x78, 0x14, 0x60,
        0xDF, 0x05, 0xBB, 0x29,
        0x6F, 0x93, 0xED, 0x0A
    };

    /// <summary>
    /// The default block.
    /// Must be 16 bytes.
    /// Base64: ZzS/fZgKLUPE64FFT0u3HQ==
    /// </summary>
    public static readonly byte[] DefaultIv =
    {
        0x67, 0x34, 0xBF, 0x7D,
        0x98, 0x0A, 0x2D, 0x43,
        0xC4, 0xEB, 0x81, 0x45,
        0x4F, 0x4B, 0xB7, 0x1D
    };

    /// <summary>
    /// The salt value.
    /// Must be 16 bytes.
    /// Base64: +oMpAVt+TJowGhjvYsqHdQ==
    /// </summary>
    public static readonly byte[] Salt = {
        0xFA, 0x83, 0x29, 0x01,
        0x5B, 0x7E, 0x4C, 0x9A,
        0x3D, 0x18, 0xEF, 0x62,
        0xCA, 0x07, 0x9D, 0x55
    };

    /// <summary>
    /// How many bytes <see cref="IsStreamEncrypted"/> samples when inspecting a stream.
    /// Must be a multiple of the block size.
    /// </summary>
    private const int SampleSize = 4096;

    #endregion
    
    
    #region Encryption/Decryption Routines
    
    /// <summary>
    /// Returns an encrypted ByteArray
    /// </summary>
    /// <param name="bytesToEncrypt">The text to encrypt</param>
    /// <param name="aesKey">A 16, 24 or 32-byte key</param>
    /// <param name="aesIv">A 16-byte block</param>
    /// <returns></returns>
    public static byte[] Encrypt(byte[] bytesToEncrypt, byte[] aesKey, byte[] aesIv)
    {
        using ICryptoTransform transform = GetEncryptor(aesKey, aesIv);
        return Transform(bytesToEncrypt, transform);
    }
    
    /// <summary>
    /// Returns a decrypted byte array
    /// </summary>
    /// <param name="bytesToDecrypt">An array of bytes to decrypt</param>
    /// <param name="aesKey">A 16, 24 or 32-byte key</param>
    /// <param name="aesIv">A 16-byte block</param>
    /// <returns></returns>
    public static byte[] Decrypt(byte[] bytesToDecrypt, byte[] aesKey, byte[] aesIv)
    {
        using ICryptoTransform transform = GetDecryptor(aesKey, aesIv);
        return Transform(bytesToDecrypt, transform);
    }
    
    #endregion
    
    
    #region Detection Methods

    /// <summary>
    /// Try to determine if a chunk of data is encrypted
    /// </summary>
    /// <param name="data">The data</param>
    /// <returns><c>true</c> if data is determined to be encrypted</returns>
    private static bool IsDataEncrypted(byte[] data)
    {
        // AES encryption results in a uniform distribution of byte values from 0-255, which is
        // dense with control characters and with sequences that are not legal UTF-8. Text files
        // (XML, XAML, et al) decode cleanly as UTF-8 and use only a narrow band of control
        // characters. If the sample does not look like text, we assume the data is encrypted.
        if (data.Length == 0) return false;

        // The sample may stop part way through a multi-byte character, which would otherwise be
        // indistinguishable from corruption. Drop any trailing partial sequence before decoding.
        int length = TrimPartialUtf8Sequence(data);
        if (length == 0) return true;

        string text;
        try
        {
            text = new UTF8Encoding(false, true).GetString(data, 0, length);
        }
        catch (ArgumentException)
        {
            // not legal UTF-8, so not text
            return true;
        }

        return text.Any(c => !IsTextCharacter(c));
    }

    /// <summary>
    /// Determine whether a character is one that occurs in ordinary text files
    /// </summary>
    /// <param name="character">The character to test</param>
    /// <returns><c>true</c> if the character is plausible in a text file</returns>
    private static bool IsTextCharacter(char character)
    {
        // tab, newline, carriage return, form feed and the byte order marker are all
        // legitimate in a text file even though they are control characters
        if (character is '\t' or '\n' or '\r' or '\f' or '\uFEFF') return true;

        // any other control character is a strong signal of non-text data
        return !char.IsControl(character);
    }

    /// <summary>
    /// Find the length of <paramref name="data"/> excluding any incomplete UTF-8 sequence
    /// left dangling at the end by sampling
    /// </summary>
    /// <param name="data">The data to inspect</param>
    /// <returns>The length to decode</returns>
    private static int TrimPartialUtf8Sequence(byte[] data)
    {
        // walk back over trailing continuation bytes (10xxxxxx) looking for the lead byte
        int index = data.Length - 1;
        int continuationBytes = 0;
        while (index >= 0 && (data[index] & 0xC0) == 0x80 && continuationBytes < 3)
        {
            continuationBytes++;
            index--;
        }

        // nothing but continuation bytes: let the decoder reject it
        if (index < 0) return data.Length;

        int expectedContinuationBytes = (data[index] & 0xE0) == 0xC0 ? 1
            : (data[index] & 0xF0) == 0xE0 ? 2
            : (data[index] & 0xF8) == 0xF0 ? 3
            : 0;

        // if the lead byte promises more continuation bytes than the sample holds, the
        // sequence is merely truncated rather than invalid, so leave it out of the decode
        return expectedContinuationBytes > continuationBytes ? index : data.Length;
    }

    /// <summary>
    /// Try to determine if a stream is AES-encrypted.
    /// </summary>
    /// <param name="inputStream">The stream to check. Stream must be Seekable</param>
    /// <returns><c>true</c> if data is determined to be encrypted</returns>
    /// <exception cref="ArgumentException"></exception>
    public static bool IsStreamEncrypted(Stream inputStream)
    {
        // catch input exceptions
        ArgumentNullException.ThrowIfNull(inputStream);
        if (!inputStream.CanSeek) throw new ArgumentException("Stream must be seekable", nameof(inputStream));

        // measure from the current position rather than the whole stream, so that a
        // partially read stream is not misjudged on length and cannot overrun the read below
        long restorePosition = inputStream.Position;
        long dataLength = inputStream.Length - restorePosition;

        // no data
        if (dataLength <= 0) return false;

        // We are using default padding for AesManaged, which pads output to a multiple of the block size.
        // If the file's length is not a multiple of the block size, we know it's NOT encrypted.
        int blockSize = DefaultIv.Length;
        if (dataLength % blockSize != 0) return false;

        // fast check failed, look at a sample of the data
        byte[] testChunk = new byte[(int)Math.Min(dataLength, SampleSize)];
        try
        {
            inputStream.ReadExactly(testChunk, 0, testChunk.Length);
        }
        finally
        {
            inputStream.Position = restorePosition;
        }

        return IsDataEncrypted(testChunk);
    }
    
    #endregion
    
    
    #region Implementation Helpers

    /// <summary>
    /// Get an AES decryptor transform, defaulting to default key/iv.
    /// </summary>
    /// <returns>The decryptor</returns>
    public static ICryptoTransform GetDecryptor(byte[]? key = null, byte[]? iv = null)
    {
        // the transform holds its own copy of the key material, so the Aes instance
        // that produced it can be released straight away
        using Aes aes = Aes.Create();
        aes.Key = key ?? DefaultKey;
        aes.IV = iv ?? DefaultIv;

        return aes.CreateDecryptor();
    }

    /// <summary>
    /// Get an AES encryptor transform, defaulting to default key/iv.
    /// </summary>
    /// <returns>The encryptor</returns>
    public static ICryptoTransform GetEncryptor(byte[]? key = null, byte[]? iv = null)
    {
        // the transform holds its own copy of the key material, so the Aes instance
        // that produced it can be released straight away
        using Aes aes = Aes.Create();
        aes.Key = key ?? DefaultKey;
        aes.IV = iv ?? DefaultIv;

        return aes.CreateEncryptor();
    }

    /// <summary>
    /// Perform a cryptographic transformation on a stream.
    /// </summary>
    /// <param name="bytesToTransform">The byte array to transform</param>
    /// <param name="transform">The CryptoTransform to use</param>
    /// <returns>The transformed byte array</returns>
    private static byte[] Transform(byte[] bytesToTransform, ICryptoTransform transform)
    {
        // send the bytes to the crypto stream
        using (MemoryStream memoryStream = new MemoryStream())
        {
            using (CryptoStream cryptoStream = new CryptoStream(memoryStream, transform, CryptoStreamMode.Write))
            {
                cryptoStream.Write(bytesToTransform, 0, bytesToTransform.Length);
                cryptoStream.Close();
            }
            return memoryStream.ToArray();
        }
    }
    
    #endregion
}