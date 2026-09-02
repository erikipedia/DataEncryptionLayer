using System.Security.Cryptography;

namespace DataEncryptionLayer;

/// <summary>
/// Static class for encrypting and decrypting files
/// </summary>
public static class FileCryptography
{
    /// <summary>
    /// The extension given to encrypted files
    /// </summary>
    private const string EncryptedExtension = ".crypt";

    #region Path Helpers

    /// <summary>
    /// Work out the encrypted path for a plaintext file, folding the original extension
    /// into the filename so that <see cref="GetDecryptedPath"/> can restore it.
    /// "name.ext" becomes "name_ext.crypt"; a file with no extension becomes "name_.crypt".
    /// </summary>
    /// <param name="path">The plaintext path</param>
    /// <returns>The encrypted path</returns>
    private static string GetEncryptedPath(string path)
    {
        // only rewrite the filename: a directory may legitimately contain '.' or '_'
        string directory = Path.GetDirectoryName(path) ?? string.Empty;
        string name = Path.GetFileNameWithoutExtension(path);
        string extension = Path.GetExtension(path);

        // a trailing separator records "there was no extension", which keeps the
        // transformation reversible for extensionless names that contain '_'
        string encryptedName = $"{name}_{extension.TrimStart('.')}";

        return Path.Combine(directory, encryptedName + EncryptedExtension);
    }

    /// <summary>
    /// Work out the plaintext path for an encrypted file, restoring the extension that
    /// <see cref="GetEncryptedPath"/> folded into the filename.
    /// "name_ext.crypt" becomes "name.ext".
    /// </summary>
    /// <param name="path">The encrypted path</param>
    /// <returns>The plaintext path</returns>
    /// <exception cref="ArgumentException"></exception>
    private static string GetDecryptedPath(string path)
    {
        // only inspect the filename: a directory may legitimately contain '.' or '_'
        string directory = Path.GetDirectoryName(path) ?? string.Empty;
        string name = Path.GetFileNameWithoutExtension(path);

        int separator = name.LastIndexOf('_');
        string decryptedName;
        if (separator < 0)
        {
            // no recorded extension, so restore the name as it stands
            decryptedName = name;
        }
        else
        {
            string extension = name[(separator + 1)..];
            decryptedName = extension.Length > 0
                ? $"{name[..separator]}.{extension}"
                : name[..separator];
        }

        if (decryptedName.Length == 0) throw new ArgumentException("Cannot determine the original filename", nameof(path));

        return Path.Combine(directory, decryptedName);
    }

    /// <summary>
    /// Delete a file, ignoring any failure. Used to roll back a partial write without
    /// masking the exception that caused the rollback.
    /// </summary>
    /// <param name="path">The file to delete</param>
    private static void TryDelete(string path)
    {
        try
        {
            File.Delete(path);
        }
        catch
        {
            // best effort only: the original exception is the one worth reporting
        }
    }

    #endregion


    #region File IO Factory Methods

    /// <summary>
    /// Gets the file output stream.
    /// </summary>
    /// <param name="filename">The name of the file</param>
    /// <param name="encryptOutputFile">if set to <c>true</c> [encrypt output file]</param>
    /// <returns>The file stream</returns>
    public static Stream GetFileOutputStream(string filename, bool encryptOutputFile)
    {
        return encryptOutputFile
            ? GetFileOutputStream(filename, Utilities.DefaultKey, Utilities.DefaultIv)
            : File.Create(filename);
    }

    /// <summary>
    /// Gets the file output stream
    /// </summary>
    /// <param name="filename">The name of the file</param>
    /// <param name="aesKey">The AES key</param>
    /// <param name="aesIv">The AES block</param>
    /// <returns>The file stream</returns>
    public static Stream GetFileOutputStream(string filename, byte[] aesKey, byte[] aesIv)
    {
        // catch input exceptions
        ArgumentException.ThrowIfNullOrEmpty(filename);
        
        Stream outputStream = File.Create(filename);
        try
        {
            return new CryptoStream(outputStream, Utilities.GetEncryptor(aesKey, aesIv), CryptoStreamMode.Write);
        }
        catch
        {
            // don't leave the file handle open if the transform can't be built
            outputStream.Dispose();
            throw;
        }
    }

    /// <summary>
    /// Gets the file input stream, detects if the file is encrypted and adds a decrypt flag if needed
    /// </summary>
    /// <param name="filename">The name of the file</param>
    /// <returns>The file stream</returns>
    /// <exception cref="FileNotFoundException"></exception>
    public static Stream GetFileInputStream(string filename)
    {
        // catch input exceptions
        ArgumentException.ThrowIfNullOrEmpty(filename);
        if (!File.Exists(filename)) throw new FileNotFoundException(filename);
        
        Stream inputStream = File.OpenRead(filename);
        try
        {
            // we weren't given a password, so try to pass the defaults
            return Utilities.IsStreamEncrypted(inputStream)
                ? GetFileInputStream(inputStream, Utilities.DefaultKey, Utilities.DefaultIv)
                : inputStream;
        }
        catch
        {
            // don't leave the file handle open if detection or the transform fails
            inputStream.Dispose();
            throw;
        }
    }
    
    /// <summary>
    /// Gets the file input stream
    /// </summary>
    /// <param name="filename">The name of the file</param>
    /// <param name="aesKey">The AES key</param>
    /// <param name="aesIv">The AES block</param>
    /// <returns>The file stream</returns>
    /// <exception cref="FileNotFoundException"></exception>
    public static Stream GetFileInputStream(string filename, byte[] aesKey, byte[] aesIv)
    {
        // catch input exceptions
        ArgumentException.ThrowIfNullOrEmpty(filename);
        if (!File.Exists(filename)) throw new FileNotFoundException(filename);
        
        Stream inputStream = File.OpenRead(filename);
        try
        {
            return GetFileInputStream(inputStream, aesKey, aesIv);
        }
        catch
        {
            // don't leave the file handle open if the transform can't be built
            inputStream.Dispose();
            throw;
        }
    }
    
    /// <summary>
    /// Gets the file input stream
    /// </summary>
    /// <param name="inputStream">The input stream</param>
    /// <param name="aesKey">The AES key</param>
    /// <param name="aesIv">The AES block</param>
    /// <returns>The file stream</returns>
    private static Stream GetFileInputStream(Stream inputStream, byte[] aesKey, byte[] aesIv)
    {
        return new CryptoStreamReader(inputStream, Utilities.GetDecryptor(aesKey, aesIv), CryptoStreamMode.Read);
    }
    
    #endregion
    
    
    #region Encrypt

    /// <summary>
    /// Encrypt a file using the default key/block pair
    /// </summary>
    /// <param name="fileToEncrypt">The file to encrypt</param>
    public static void Encrypt(string fileToEncrypt)
    {
        // call the overload using the default key/block pair
        Encrypt(fileToEncrypt, Utilities.DefaultKey, Utilities.DefaultIv);
    }

    /// <summary>
    /// Encrypt a file using a password
    /// </summary>
    /// <param name="fileToEncrypt">The file to encrypt</param>
    /// <param name="password">The password</param>
    public static void Encrypt(string fileToEncrypt, string password)
    {
        // convert the password to a 48-byte array, and render the key/block pair
        using Rfc2898DeriveBytes pdb = new Rfc2898DeriveBytes(password, Utilities.Salt, 1000, HashAlgorithmName.SHA1);
        byte[] aesKey = pdb.GetBytes(32);
        byte[] aesIv = pdb.GetBytes(16);

        // call the overload using the new key/block
        Encrypt(fileToEncrypt, aesKey, aesIv);
    }
    
    /// <summary>
    /// Encrypt a file using a custom key/block pair
    /// </summary>
    /// <param name="fileToEncrypt">The file to encrypt</param>
    /// <param name="aesKey">A 16, 24, or 32-byte key</param>
    /// <param name="aesIv">A 16-byte block</param>
    /// <exception cref="FileNotFoundException"></exception>
    public static void Encrypt(string fileToEncrypt, byte[] aesKey, byte[] aesIv)
    {
        // catch input exceptions
        ArgumentException.ThrowIfNullOrEmpty(fileToEncrypt);
        if (!File.Exists(fileToEncrypt)) throw new FileNotFoundException(fileToEncrypt);
        
        // work out the new filename and path
        string newFileString = GetEncryptedPath(fileToEncrypt);

        // read the input file and send it to the encrypter
        byte[] byteArrayOutput = Utilities.Encrypt(File.ReadAllBytes(fileToEncrypt), aesKey, aesIv);

        // write the encrypted data, then retire the original
        try
        {
            File.WriteAllBytes(newFileString, byteArrayOutput);
            File.Delete(fileToEncrypt);
        }
        catch
        {
            TryDelete(newFileString);
            throw;
        }
    }
    
    #endregion
    
    
    #region Decrypt

    /// <summary>
    /// Decrypts a file using the default key/block pair
    /// </summary>
    /// <param name="fileToDecrypt">The file to decrypt</param>
    public static void Decrypt(string fileToDecrypt)
    {
        // call the overload using the default key/block pair
        Decrypt(fileToDecrypt, Utilities.DefaultKey, Utilities.DefaultIv);
    }
    
    /// <summary>
    /// Decrypts a file using a password
    /// </summary>
    /// <param name="fileToDecrypt">The file to decrypt</param>
    /// <param name="password">The password</param>
    public static void Decrypt(string fileToDecrypt, string password)
    {
        // convert the password to a 48-byte array, and render the key/block pair
        using Rfc2898DeriveBytes pdb = new Rfc2898DeriveBytes(password, Utilities.Salt, 1000, HashAlgorithmName.SHA1);
        byte[] aesKey = pdb.GetBytes(32);
        byte[] aesIv = pdb.GetBytes(16);

        // call the overload using the new key/block
        Decrypt(fileToDecrypt, aesKey, aesIv);
    }
    
    /// <summary>
    /// Decrypts a file using a custom key/block pair
    /// </summary>
    /// <param name="fileToDecrypt">The file to decrypt</param>
    /// <param name="aesKey">The AES key</param>
    /// <param name="aesIv">The AES block</param>
    /// <exception cref="FileNotFoundException"></exception>
    /// <exception cref="ArgumentException"></exception>
    public static void Decrypt(string fileToDecrypt, byte[] aesKey, byte[] aesIv)
    {
        // catch input exceptions
        ArgumentException.ThrowIfNullOrEmpty(fileToDecrypt);
        if (!File.Exists(fileToDecrypt)) throw new FileNotFoundException(fileToDecrypt);
        if (!Path.GetExtension(fileToDecrypt).Equals(EncryptedExtension, StringComparison.OrdinalIgnoreCase))
            throw new ArgumentException($"Not a {EncryptedExtension} file", nameof(fileToDecrypt));

        // restore the original filename and extension
        string newFileString = GetDecryptedPath(fileToDecrypt);

        // read the encrypted file and call the base-level decryptor
        byte[] byteArrayOutput = Utilities.Decrypt(File.ReadAllBytes(fileToDecrypt), aesKey, aesIv);

        // write the decrypted data, then retire the encrypted file
        try
        {
            File.WriteAllBytes(newFileString, byteArrayOutput);
            File.Delete(fileToDecrypt);
        }
        catch
        {
            TryDelete(newFileString);
            throw;
        }
    }
    
    #endregion
}