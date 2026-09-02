using System.Text;

namespace DataEncryptionLayer.Tests;

[TestFixture]
[TestOf(typeof(Utilities))]
public class UtilitiesTests
{
    #region Helpers

    /// <summary>
    /// Build a stream of text padded to a multiple of the AES block size, so that the
    /// length heuristic in <see cref="Utilities.IsStreamEncrypted"/> cannot short-circuit
    /// and the content inspection is actually exercised.
    /// </summary>
    private static MemoryStream TextStream(string text)
    {
        byte[] bytes = Encoding.UTF8.GetBytes(text);

        int blockSize = Utilities.DefaultIv.Length;
        byte[] buffer = new byte[(bytes.Length + blockSize - 1) / blockSize * blockSize];
        Array.Fill(buffer, (byte)' ');
        bytes.CopyTo(buffer, 0);

        return new MemoryStream(buffer);
    }

    #endregion

    [Test]
    public void TabSeparatedTextIsNotReportedAsEncrypted()
    {
        // regression: tab is below the printable range, and used to be classified as
        // non-text even though it is ubiquitous in real text files
        using MemoryStream stream = TextStream("id\tname\tvalue\n1\tfirst\t100\n2\tsecond\t200\n");

        Assert.That(Utilities.IsStreamEncrypted(stream), Is.False);
    }

    [Test]
    public void AccentedTextIsNotReportedAsEncrypted()
    {
        // regression: every byte above 127 used to be classified as non-text, so any
        // UTF-8 text outside ASCII was mistaken for ciphertext
        using MemoryStream stream = TextStream("café, résumé, naïve, Ünicode, jalapeño");

        Assert.That(Utilities.IsStreamEncrypted(stream), Is.False);
    }

    [Test]
    public void TextIsNotReportedAsEncryptedWhenTheSampleCutsAMultiByteCharacter()
    {
        // the sample is a fixed size, so it can land mid-character on multi-byte text.
        // Each of these characters is three bytes, so a 4096-byte sample splits one.
        using MemoryStream stream = TextStream(new string('日', 1400));

        Assert.That(Utilities.IsStreamEncrypted(stream), Is.False);
    }

    [Test]
    public void EncryptedDataIsReportedAsEncrypted()
    {
        byte[] cipherText = Utilities.Encrypt(
            Encoding.UTF8.GetBytes("Lorem ipsum dolor sit amet, consectetur adipiscing elit."),
            Utilities.DefaultKey,
            Utilities.DefaultIv);

        using MemoryStream stream = new MemoryStream(cipherText);

        Assert.That(Utilities.IsStreamEncrypted(stream), Is.True);
    }

    [Test]
    public void BinaryDataIsReportedAsEncrypted()
    {
        // a NUL byte does not occur in the text files this heuristic is meant to pass
        using MemoryStream stream = new MemoryStream(new byte[Utilities.DefaultIv.Length]);

        Assert.That(Utilities.IsStreamEncrypted(stream), Is.True);
    }

    [Test]
    public void EmptyStreamIsNotReportedAsEncrypted()
    {
        using MemoryStream stream = new MemoryStream();

        Assert.That(Utilities.IsStreamEncrypted(stream), Is.False);
    }

    [Test]
    public void DetectionRestoresTheStreamPosition()
    {
        byte[] cipherText = Utilities.Encrypt(
            Encoding.UTF8.GetBytes("position should be left untouched"),
            Utilities.DefaultKey,
            Utilities.DefaultIv);

        using MemoryStream stream = new MemoryStream(cipherText);
        stream.Position = Utilities.DefaultIv.Length;

        Assert.Multiple(() =>
        {
            Assert.That(Utilities.IsStreamEncrypted(stream), Is.True);
            Assert.That(stream.Position, Is.EqualTo(Utilities.DefaultIv.Length));
        });
    }

    [Test]
    public void DetectionOnAPartiallyReadStreamDoesNotOverrun()
    {
        // regression: the length test measured the whole stream but the read started from
        // the current position. A stream whose total length is a whole number of blocks but
        // whose remainder is not would pass the length test and then overrun the read.
        using MemoryStream stream = TextStream("some text padded out to a whole number of blocks");
        stream.Position = stream.Length - 8;

        Assert.That(Utilities.IsStreamEncrypted(stream), Is.False);
    }

    [Test]
    public void RoundTripsBytesThroughEncryptAndDecrypt()
    {
        byte[] original = Encoding.UTF8.GetBytes("round trip me");

        byte[] cipherText = Utilities.Encrypt(original, Utilities.DefaultKey, Utilities.DefaultIv);
        byte[] plainText = Utilities.Decrypt(cipherText, Utilities.DefaultKey, Utilities.DefaultIv);

        Assert.That(plainText, Is.EqualTo(original));
    }
}
