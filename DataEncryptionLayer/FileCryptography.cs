using System.Security.Cryptography;

namespace DataEncryptionLayer;

/// <summary>
/// Static class for encrypting and decrypting files
/// </summary>
public class FileCryptography
{
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
        outputStream = new CryptoStream(outputStream, Utilities.GetEncryptor(aesKey, aesIv), CryptoStreamMode.Write);
        return outputStream;
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

        if (Utilities.IsStreamEncrypted(inputStream))
        {
            // we weren't given a password, so try to pass the defaults
            inputStream = GetFileInputStream(inputStream, Utilities.DefaultKey, Utilities.DefaultIv);
        }

        return inputStream;
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
        inputStream = GetFileInputStream(inputStream, aesKey, aesIv);
        return inputStream;
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
        Rfc2898DeriveBytes pdb = new Rfc2898DeriveBytes(password, Utilities.Salt);
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
        
        // write the new filename and path
        string newFileString = fileToEncrypt.Substring(0, fileToEncrypt.LastIndexOf('.')) + "_" +
                               fileToEncrypt.Substring(fileToEncrypt.LastIndexOf('.') + 1) + ".crypt";
        
        // read the input file into a byte array
        FileStream fsInput = new FileStream(fileToEncrypt, FileMode.Open, FileAccess.Read);
        byte[] byteArrayInput = new byte[fsInput.Length];
        fsInput.Read(byteArrayInput, 0, byteArrayInput.Length);
        fsInput.Close();

        // send the input array to the encrypter
        byte[] byteArrayOutput = Utilities.Encrypt(byteArrayInput, aesKey, aesIv);
        FileStream fsOutput = new FileStream(newFileString, FileMode.Create, FileAccess.Write);
        
        // write the encrypted data to the filestream
        try
        {
            fsOutput.Write(byteArrayOutput, 0, byteArrayOutput.Length);
            fsOutput.Close();
            File.Delete(fileToEncrypt);
        }
        catch
        {
            fsOutput.Close();
            File.Delete(newFileString);
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
        Rfc2898DeriveBytes pdb = new Rfc2898DeriveBytes(password, Utilities.Salt);
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
        if (fileToDecrypt.Substring(fileToDecrypt.LastIndexOf('.')) != ".crypt") throw new ArgumentException("Not a .crypt file", nameof(fileToDecrypt));
        
        // remove the .crypt extension
        string newFileString = fileToDecrypt.Substring(0, fileToDecrypt.LastIndexOf('_')) + "." +
                               fileToDecrypt.Substring(fileToDecrypt.LastIndexOf('_') + 1,
                                   fileToDecrypt.LastIndexOf('.') -
                                   fileToDecrypt.LastIndexOf('_') - 1);
        
        // read the encrypted file
        FileStream fsInput = new FileStream(fileToDecrypt, FileMode.Open, FileAccess.Read);
        byte[] byteArrayInput = new byte[fsInput.Length];
        fsInput.Read(byteArrayInput, 0, byteArrayInput.Length);
        fsInput.Close();

        // call the base-level decryptor and read into an output stream
        byte[] byteArrayOutput = Utilities.Decrypt(byteArrayInput, aesKey, aesIv);
        FileStream fsOutput = new FileStream(newFileString, FileMode.Create, FileAccess.Write);

        // write the decrypted stream to the new file
        try
        {
            fsOutput.Write(byteArrayOutput, 0, byteArrayOutput.Length);
            fsOutput.Close();
            File.Delete(fileToDecrypt);
        }
        catch
        {
            fsOutput.Close();
            File.Delete(newFileString);
            throw;
        }
    }
    
    #endregion
}