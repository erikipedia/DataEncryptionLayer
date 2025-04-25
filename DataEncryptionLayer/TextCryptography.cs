using System.Security.Cryptography;
using System.Text;

namespace DataEncryptionLayer;

/// <summary>
/// Static class for encrypting and decrypting strings
/// </summary>
public static class TextCryptography
{
    #region Encrypt

    /// <summary>
    /// Encrypts a string using the default key/block pair 
    /// </summary>
    /// <param name="textToEncrypt">The text to encrypt</param>
    /// <returns>An encrypted base-64 string</returns>
    public static string Encrypt(string textToEncrypt)
    {
        // call the overload using the default key/block pair
        return Encrypt(textToEncrypt, Utilities.DefaultKey, Utilities.DefaultIv);
    }

    /// <summary>
    /// Encrypts a string using a password to generate a unique key/block pair
    /// </summary>
    /// <param name="textToEncrypt">The text to encrypt</param>
    /// <param name="password">The password</param>
    /// <returns>An encrypted base-64 string</returns>
    public static string Encrypt(string textToEncrypt, string password)
    {
        // convert the password into a 48-byte array, and render the key/block pair
        Rfc2898DeriveBytes pdb = new Rfc2898DeriveBytes(password, Utilities.Salt, 1000, HashAlgorithmName.SHA1);
        byte[] aesKey = pdb.GetBytes(32);
        byte[] aesIv = pdb.GetBytes(16);
        
        // call the overload using the new key/block
        return Encrypt(textToEncrypt, aesKey, aesIv);
    }

    /// <summary>
    /// Encrypts a string using a custom key/block pair
    /// </summary>
    /// <param name="textToEncrypt">The text to encrypt</param>
    /// <param name="aesKey">A 16, 24, or 32-byte key</param>
    /// <param name="aesIv">A 16-byte block</param>
    /// <returns>An encrypted base-64 string</returns>
    public static string Encrypt(string textToEncrypt, byte[] aesKey, byte[] aesIv)
    {
        // convert the text to a UTF8 byte array, call the base-level encryptor, and convert to base-64
        UTF8Encoding utf8 = new UTF8Encoding();
        byte[] bytesToEncrypt = utf8.GetBytes(textToEncrypt);
        return Convert.ToBase64String(Utilities.Encrypt(bytesToEncrypt, aesKey, aesIv));
    }
    
    #endregion
    
    
    #region Decrypt

    /// <summary>
    /// Decrypts a string using the default key/block pair
    /// </summary>
    /// <param name="textToDecrypt">The text to decrypt</param>
    /// <returns>A decrypted UTF8 string</returns>
    public static string Decrypt(string textToDecrypt)
    {
        // call the overload using the default key/block pair
        return Decrypt(textToDecrypt, Utilities.DefaultKey, Utilities.DefaultIv);
    }

    /// <summary>
    /// Try to decrypt a string, catching any exception and returning a pass/fail result
    /// </summary>
    /// <param name="textToDecrypt">The text to decrypt</param>
    /// <param name="result">A decrypted UTF8 string, or null</param>
    public static bool TryDecrypt(string textToDecrypt, out string? result)
    {
        try
        {
            result = Decrypt(textToDecrypt, Utilities.DefaultKey, Utilities.DefaultIv);
            return true;
        }
        catch (Exception)
        {
            result = null;
            return false;
        }
    }

    /// <summary>
    /// Decrypts a string using a password to generate the key/block pair
    /// </summary>
    /// <param name="textToDecrypt">The text to decrypt</param>
    /// <param name="password">The password</param>
    /// <returns>A decrypted UTF8 string</returns>
    public static string Decrypt(string textToDecrypt, string password)
    {
        // convert the password to a 48-byte array, and render the key/block pair
        Rfc2898DeriveBytes pdb = new Rfc2898DeriveBytes(password, Utilities.Salt, 1000, HashAlgorithmName.SHA1);
        byte[] aesKey = pdb.GetBytes(32);
        byte[] aesIv = pdb.GetBytes(16);
        
        // call the overload using the new key/block
        return Decrypt(textToDecrypt, aesKey, aesIv);
    }

    /// <summary>
    /// Decrypts a string using a custom key/block pair
    /// </summary>
    /// <param name="textToDecrypt">The text to decrypt</param>
    /// <param name="aesKey">A 16, 24, or 32-byte key</param>
    /// <param name="aesIv">A 16-byte block</param>
    /// <returns>A decrypted UTF8 string</returns>
    public static string Decrypt(string textToDecrypt, byte[] aesKey, byte[] aesIv)
    {
        // convert from base-64, call the base-level decryptor, and convert to UTF8
        byte[] bytesToDecrypt = Convert.FromBase64String(textToDecrypt);
        UTF8Encoding utf8 = new UTF8Encoding();
        return utf8.GetString(Utilities.Decrypt(bytesToDecrypt, aesKey, aesIv));
    }
    
    #endregion
}