using System.Reflection;
using System.Security.Cryptography;
using DataEncryptionLayer;

namespace DataEncryptionLayer.Tests;

[TestFixture]
[TestOf(typeof(FileCryptography))]
public class FileCryptographyTests
{
    #region Private Fields
    
    private readonly string? _filePath = Path.GetDirectoryName(Assembly.GetExecutingAssembly().Location);
    private const string U_FILE_1 = "testFile1.txt";
    private const string C_FILE_1 = "testFile1_txt.crypt";
    private const string U_FILE_2 = "testFile2.txt";
    private const string C_FILE_2 = "testFile2_txt.crypt";
    
    #endregion
    
    #region Setup/Teardown
    
    [SetUp]
    public void SetUp()
    {
        
        if (!File.Exists($"{_filePath}/{U_FILE_1}")) File.Copy($"{_filePath}/Resources/TestFile.txt", $"{_filePath}/{U_FILE_1}");
        if (!File.Exists($"{_filePath}/{U_FILE_2}")) File.Copy($"{_filePath}/Resources/TestFile.txt", $"{_filePath}/{U_FILE_2}");
    }

    [TearDown]
    public void TearDown()
    {
        if (File.Exists($"{_filePath}/{U_FILE_1}")) File.Delete($"{_filePath}/{U_FILE_1}");
        if (File.Exists($"{_filePath}/{U_FILE_2}")) File.Delete($"{_filePath}/{U_FILE_2}");
        if (File.Exists($"{_filePath}/{C_FILE_1}")) File.Delete($"{_filePath}/{C_FILE_1}");
        if (File.Exists($"{_filePath}/{C_FILE_2}")) File.Delete($"{_filePath}/{C_FILE_2}");
    }
    
    #endregion
    
    [Test]
    public void TestFileEncryptDecrypt()
    {
        using (FileStream fileStream = File.OpenRead($"{_filePath}/{U_FILE_1}"))
        {
            Assert.That(Utilities.IsStreamEncrypted(fileStream), Is.False);
        }

        string fileChecksum = FileSigning.ComputeChecksum($"{_filePath}/{U_FILE_1}");
        Console.WriteLine($"File checksum is: {fileChecksum}");
        Assert.Multiple(() =>
        {
            Assert.That(FileSigning.ComputeChecksum($"{_filePath}/{U_FILE_2}"), Is.EqualTo(fileChecksum));
            Assert.That(FileSigning.CompareFiles($"{_filePath}/{U_FILE_1}", $"{_filePath}/{U_FILE_2}"), Is.True);
        });

        FileCryptography.Encrypt($"{_filePath}/{U_FILE_1}");
        Assert.Multiple(() =>
        {
            Assert.That(File.Exists($"{_filePath}/{U_FILE_1}"), Is.False);
            Assert.That(File.Exists($"{_filePath}/{C_FILE_1}"), Is.True);
        });

        using (FileStream fileStream = File.OpenRead($"{_filePath}/{C_FILE_1}"))
        {
            Assert.That(Utilities.IsStreamEncrypted(fileStream), Is.True);
        }

        fileChecksum = FileSigning.ComputeChecksum($"{_filePath}/{C_FILE_1}");
        Console.WriteLine($"New file checksum is: {fileChecksum}");
        Assert.Multiple(() =>
        {
            Assert.That(FileSigning.ComputeChecksum($"{_filePath}/{U_FILE_2}"), Is.Not.EqualTo(fileChecksum));
            Assert.That(FileSigning.CompareFiles($"{_filePath}/{C_FILE_1}", $"{_filePath}/{U_FILE_2}"), Is.False);
        });

        FileCryptography.Encrypt($"{_filePath}/{U_FILE_2}", "Un1v3rs3!");
        fileChecksum = FileSigning.ComputeChecksum($"{_filePath}/{C_FILE_2}");
        Console.WriteLine($"Second file checksum is: {fileChecksum}");
        Assert.Multiple(() =>
        {
            Assert.That(FileSigning.ComputeChecksum($"{_filePath}/{C_FILE_1}"), Is.Not.EqualTo(fileChecksum));
            Assert.That(FileSigning.CompareFiles($"{_filePath}/{C_FILE_1}", $"{_filePath}/{C_FILE_2}"), Is.False);
        });
        
        FileCryptography.Decrypt($"{_filePath}/{C_FILE_1}");

        Assert.Throws<CryptographicException>(() => FileCryptography.Decrypt($"{_filePath}/{C_FILE_2}"));
        FileCryptography.Decrypt($"{_filePath}/{C_FILE_2}", "Un1v3rs3!");
        
        Assert.Multiple(() =>
        {
            Assert.That(File.Exists($"{_filePath}/{C_FILE_1}"), Is.False);
            Assert.That(File.Exists($"{_filePath}/{U_FILE_1}"), Is.True);
        });
        
        fileChecksum = FileSigning.ComputeChecksum($"{_filePath}/{U_FILE_1}");
        Console.WriteLine($"File checksum should now be original: {fileChecksum}");
        Assert.Multiple(() =>
        {
            Assert.That(FileSigning.ComputeChecksum($"{_filePath}/{U_FILE_2}"), Is.EqualTo(fileChecksum));
            Assert.That(FileSigning.CompareFiles($"{_filePath}/{U_FILE_1}", $"{_filePath}/{U_FILE_2}"), Is.True);
        });
        
    }
}