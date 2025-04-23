using System.Security.Cryptography;

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
        return Transform(bytesToEncrypt, GetEncryptor(aesKey, aesIv));
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
        return Transform(bytesToDecrypt, GetDecryptor(aesKey, aesIv));
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
        // AES encryption results in a uniform distribution of byte values from 0-255.
        // In text files (XML,XAML,et al), most values are not represented at all.
        // If we encounter only those byte values, we assume the data is encrypted.
        foreach (byte b in data)
        {
            if ((b < 32 || b > 127)
                && !( // a few exceptions within those ranges, only tested if the previous test didn't short circuit:
                        (b == 13 || b == 10) // CR,LF
                        || (b == 239 || b == 187 || b == 191) // 239 187 191 is the byte order marker for UTF-8
                    )
               ) return true;
        }

        return false;
    }
    
    /// <summary>
    /// Try to determine if a stream is AES-encrypted.
    /// </summary>
    /// <param name="inputStream">The stream to check. Stream must be Seekable</param>
    /// <returns><c>true</c> if data is determined to be encrypted</returns>
    public static bool IsStreamEncrypted(Stream inputStream)
    {
        long dataLength = inputStream.Length;
        
        // no data
        if (dataLength == 0) return false;
        
        // We are using default padding for AesManaged, which pads output to a multiple of the block size.
        // If the file's length is not a multiple of the block size, we know it's NOT encrypted.
        int blockSize = DefaultIv.Length;
        if (dataLength % blockSize != 0) return false;
        
        // fast check failed, look at a sample of the data
        long restorePosition = inputStream.Position;
        byte[] testChunk = new byte[blockSize];
        inputStream.ReadExactly(testChunk, 0, testChunk.Length);
        inputStream.Position = restorePosition;
        
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
        Aes aes = Aes.Create();
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
        Aes aes = Aes.Create();
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