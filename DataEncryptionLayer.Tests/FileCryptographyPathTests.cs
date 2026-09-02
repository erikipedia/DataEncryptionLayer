using System.Text;

namespace DataEncryptionLayer.Tests;

/// <summary>
/// Covers how <see cref="FileCryptography"/> derives the encrypted and decrypted
/// filenames, which used to be done with raw index arithmetic over the whole path.
/// </summary>
[TestFixture]
[TestOf(typeof(FileCryptography))]
public class FileCryptographyPathTests
{
    #region Setup/Teardown

    private string _directory = string.Empty;

    [SetUp]
    public void SetUp()
    {
        _directory = Path.Combine(Path.GetTempPath(), $"DataEncryptionLayer_{Guid.NewGuid():N}");
        Directory.CreateDirectory(_directory);
    }

    [TearDown]
    public void TearDown()
    {
        if (Directory.Exists(_directory)) Directory.Delete(_directory, true);
    }

    #endregion

    #region Helpers

    /// <summary>
    /// Write a file encrypted with the default key/block pair, without going through
    /// <see cref="FileCryptography.Encrypt(string)"/>, so that the decrypted name can be
    /// derived from a filename this library would not itself have produced.
    /// </summary>
    private void WriteEncryptedFile(string path, string content)
    {
        File.WriteAllBytes(path, Utilities.Encrypt(Encoding.UTF8.GetBytes(content), Utilities.DefaultKey, Utilities.DefaultIv));
    }

    #endregion

    [TestCase("report.txt", "report_txt.crypt")]
    [TestCase("archive.tar.gz", "archive.tar_gz.crypt")]
    [TestCase("already_underscored.txt", "already_underscored_txt.crypt")]
    [TestCase("notes", "notes_.crypt")]
    [TestCase("my_notes", "my_notes_.crypt")]
    public void RoundTripsFilenames(string original, string encrypted)
    {
        string originalPath = Path.Combine(_directory, original);
        string encryptedPath = Path.Combine(_directory, encrypted);
        File.WriteAllText(originalPath, "some content worth protecting");
        string checksum = FileSigning.ComputeChecksum(originalPath);

        FileCryptography.Encrypt(originalPath);
        Assert.Multiple(() =>
        {
            Assert.That(File.Exists(originalPath), Is.False, "the plaintext file should be retired");
            Assert.That(File.Exists(encryptedPath), Is.True, "the encrypted file should take the derived name");
        });

        FileCryptography.Decrypt(encryptedPath);
        Assert.Multiple(() =>
        {
            Assert.That(File.Exists(encryptedPath), Is.False, "the encrypted file should be retired");
            Assert.That(File.Exists(originalPath), Is.True, "the original name should be restored");
            Assert.That(FileSigning.ComputeChecksum(originalPath), Is.EqualTo(checksum), "the contents should survive the round trip");
        });
    }

    [Test]
    public void EncryptsAFileWithNoExtension()
    {
        // regression: deriving the name indexed from the last '.', so a file without one
        // threw ArgumentOutOfRangeException before it ever reached the cipher
        string originalPath = Path.Combine(_directory, "LICENSE");
        File.WriteAllText(originalPath, "no extension here");

        Assert.DoesNotThrow(() => FileCryptography.Encrypt(originalPath));
        Assert.That(File.Exists(Path.Combine(_directory, "LICENSE_.crypt")), Is.True);
    }

    [Test]
    public void DecryptsIntoADirectoryContainingAnUnderscore()
    {
        // regression: the restored name was cut at the last '_' anywhere in the path, so a
        // directory containing one was spliced into the filename when the stem had none
        string subdirectory = Path.Combine(_directory, "my_folder");
        Directory.CreateDirectory(subdirectory);

        string encryptedPath = Path.Combine(subdirectory, "payload.crypt");
        WriteEncryptedFile(encryptedPath, "hand named");

        FileCryptography.Decrypt(encryptedPath);

        Assert.Multiple(() =>
        {
            Assert.That(File.Exists(Path.Combine(subdirectory, "payload")), Is.True);
            Assert.That(File.ReadAllText(Path.Combine(subdirectory, "payload")), Is.EqualTo("hand named"));
        });
    }

    [Test]
    public void EncryptsIntoADirectoryContainingADot()
    {
        // regression: deriving the name indexed from the last '.' anywhere in the path, so a
        // dot in a directory name was mistaken for the file's extension
        string subdirectory = Path.Combine(_directory, "v1.2");
        Directory.CreateDirectory(subdirectory);

        string originalPath = Path.Combine(subdirectory, "notes");
        File.WriteAllText(originalPath, "dotted directory");

        FileCryptography.Encrypt(originalPath);

        Assert.That(File.Exists(Path.Combine(subdirectory, "notes_.crypt")), Is.True);
    }

    [Test]
    public void AcceptsTheEncryptedExtensionRegardlessOfCase()
    {
        string encryptedPath = Path.Combine(_directory, "payload_txt.CRYPT");
        WriteEncryptedFile(encryptedPath, "mixed case extension");

        FileCryptography.Decrypt(encryptedPath);

        Assert.That(File.Exists(Path.Combine(_directory, "payload.txt")), Is.True);
    }

    [Test]
    public void RejectsAFileThatIsNotEncrypted()
    {
        string path = Path.Combine(_directory, "plain.txt");
        File.WriteAllText(path, "not encrypted");

        Assert.Throws<ArgumentException>(() => FileCryptography.Decrypt(path));
    }

    [Test]
    public void RejectsAFileWithNoExtensionOnDecrypt()
    {
        // regression: this indexed from the last '.' before validating, so it threw
        // ArgumentOutOfRangeException rather than reporting the real problem
        string path = Path.Combine(_directory, "extensionless");
        File.WriteAllText(path, "not encrypted");

        Assert.Throws<ArgumentException>(() => FileCryptography.Decrypt(path));
    }

    [Test]
    public void LeavesTheOriginalInPlaceWhenEncryptionCannotBeWritten()
    {
        string originalPath = Path.Combine(_directory, "locked.txt");
        File.WriteAllText(originalPath, "should survive a failed write");
        string checksum = FileSigning.ComputeChecksum(originalPath);

        // occupy the destination path with a directory so the write cannot succeed. The
        // rollback then also fails to delete it, which must not mask the real failure.
        Directory.CreateDirectory(Path.Combine(_directory, "locked_txt.crypt"));

        Assert.Catch(() => FileCryptography.Encrypt(originalPath));
        Assert.Multiple(() =>
        {
            Assert.That(File.Exists(originalPath), Is.True, "a failed encryption must not delete the original");
            Assert.That(FileSigning.ComputeChecksum(originalPath), Is.EqualTo(checksum), "the original must be left intact");
        });
    }
}
