using System.Security.Cryptography;

namespace DataEncryptionLayer;

/// <summary>
/// A static class for comparing/inspecting files using MD5 cryptography
/// </summary>
public class FileSigning
{
    /// <summary>
    /// Check a file for internal changes
    /// </summary>
    /// <param name="filename">The file to check</param>
    /// <param name="checksum">The checksum value</param>
    /// <returns>Whether the file's checksum matches the given checksum</returns>
    /// <exception cref="ArgumentException"></exception>
    public static bool CheckFile(string filename, string checksum)
    {
        // check input exceptions
        ArgumentException.ThrowIfNullOrEmpty(filename);
        ArgumentException.ThrowIfNullOrEmpty(checksum);
        if (checksum.Length != 32) throw new ArgumentException("The checksum must be 32 characters long.", nameof(checksum));
        
        // calculate the file checksum value and compare
        return ComputeChecksum(filename) == checksum.ToUpper();
    }
    
    /// <summary>
    /// Compare the contents of two files
    /// </summary>
    /// <param name="file1">The left filename</param>
    /// <param name="file2">The right filename</param>
    /// <returns>Whether the contents of the two files are identical</returns>
    public static bool CompareFiles(string file1, string file2)
    {
        // call the overload for each file, and compare their checksums
        string check1 = ComputeChecksum(file1);
        string check2 = ComputeChecksum(file2);

        return check1 == check2;
    }
    
    /// <summary>
    /// Compute the MD5 checksum for a file
    /// </summary>
    /// <param name="filename">The file to check</param>
    /// <returns>A 16-byte hexadecimal string</returns>
    public static string ComputeChecksum(string filename)
    {
        // call the base checksum generator and return as string
        return String.Join("", ComputeMd5Checksum(filename).Select(b => b.ToString("X2")).ToArray());
    }
    
    /// <summary>
    /// The base method for computing an MD5 checksum
    /// </summary>
    /// <param name="filename">The file to check</param>
    /// <returns>The MD5 checksum as a byte array</returns>
    /// <exception cref="FileNotFoundException"></exception>
    private static IEnumerable<byte> ComputeMd5Checksum(string filename)
    {
        // catch input exceptions
        ArgumentException.ThrowIfNullOrEmpty(filename);
        if (!File.Exists(filename)) throw new FileNotFoundException(filename);
        
        // read the file into an MD5 hash table
        using FileStream fs = new FileStream(filename, FileMode.Open, FileAccess.Read);
        MD5 md5 = new MD5CryptoServiceProvider();
        byte[] byteArrayOutput = md5.ComputeHash(fs);
        fs.Close();

        // return the MD5 hash
        return byteArrayOutput;
    }
}