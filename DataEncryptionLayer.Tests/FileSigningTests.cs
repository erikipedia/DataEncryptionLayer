namespace DataEncryptionLayer.Tests;

[TestFixture]
[TestOf(typeof(FileSigning))]
public class FileSigningTests
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

    private string WriteFile(string name, string content)
    {
        string path = Path.Combine(_directory, name);
        File.WriteAllText(path, content);
        return path;
    }

    #endregion

    [Test]
    public void ComputesAThirtyTwoCharacterUppercaseChecksum()
    {
        string path = WriteFile("sample.txt", "the quick brown fox");

        string checksum = FileSigning.ComputeChecksum(path);

        Assert.Multiple(() =>
        {
            Assert.That(checksum, Has.Length.EqualTo(32));
            Assert.That(checksum, Does.Match("^[0-9A-F]{32}$"));
        });
    }

    [Test]
    public void ChecksAFileAgainstItsOwnChecksum()
    {
        string path = WriteFile("sample.txt", "the quick brown fox");
        string checksum = FileSigning.ComputeChecksum(path);

        Assert.That(FileSigning.CheckFile(path, checksum), Is.True);
    }

    [Test]
    public void ChecksAFileRegardlessOfChecksumCase()
    {
        string path = WriteFile("sample.txt", "the quick brown fox");
        string checksum = FileSigning.ComputeChecksum(path);

        Assert.That(FileSigning.CheckFile(path, checksum.ToLowerInvariant()), Is.True);
    }

    [Test]
    public void DetectsAChangedFile()
    {
        string path = WriteFile("sample.txt", "the quick brown fox");
        string checksum = FileSigning.ComputeChecksum(path);

        File.WriteAllText(path, "the quick brown dog");

        Assert.That(FileSigning.CheckFile(path, checksum), Is.False);
    }

    [Test]
    public void RejectsAChecksumOfTheWrongLength()
    {
        string path = WriteFile("sample.txt", "the quick brown fox");

        Assert.Throws<ArgumentException>(() => FileSigning.CheckFile(path, "TOOSHORT"));
    }

    [Test]
    public void ComparesFilesByContent()
    {
        string first = WriteFile("first.txt", "identical content");
        string second = WriteFile("second.txt", "identical content");
        string third = WriteFile("third.txt", "different content");

        Assert.Multiple(() =>
        {
            Assert.That(FileSigning.CompareFiles(first, second), Is.True);
            Assert.That(FileSigning.CompareFiles(first, third), Is.False);
        });
    }

    [Test]
    public void ThrowsWhenTheFileIsMissing()
    {
        Assert.Throws<FileNotFoundException>(() => FileSigning.ComputeChecksum(Path.Combine(_directory, "nope.txt")));
    }
}
