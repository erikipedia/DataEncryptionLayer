using System.Security.Cryptography;

namespace DataEncryptionLayer.Tests;

[TestFixture]
[TestOf(typeof(TextCryptography))]
public class TextCryptographyTests
{

    [Test]
    public void TestDefaultEncryptDecrypt()
    {
        string textToEncrypt = "Hello there!";
        string encryptedText = TextCryptography.Encrypt(textToEncrypt);
        Assert.That(encryptedText, Is.Not.EqualTo(textToEncrypt));
        string decryptedText = TextCryptography.Decrypt(encryptedText);
        Console.WriteLine(encryptedText + ":" + decryptedText);
        Assert.That(decryptedText, Is.EqualTo(textToEncrypt));
    }

    [Test]
    public void TestPasswordEncryptDecrypt()
    {
        string textToEncrypt = "Hey, dummy!";
        string encryptedText = TextCryptography.Encrypt(textToEncrypt, "Un1v3rs3!");
        Assert.That(encryptedText, Is.Not.EqualTo(textToEncrypt));
        Assert.That(TextCryptography.Encrypt(textToEncrypt), Is.Not.EqualTo(encryptedText));
        Assert.Throws<CryptographicException>(() => TextCryptography.Decrypt(encryptedText, "WrongPassword!"));
        string decryptedText = TextCryptography.Decrypt(encryptedText, "Un1v3rs3!");
        Console.WriteLine(encryptedText + ":" + decryptedText);
        Assert.That(decryptedText, Is.EqualTo(textToEncrypt));
    }
}