namespace DataEncryptionLayer.Tests;

[TestFixture]
[TestOf(typeof(NumberSigning))]
public class NumberSigningTests
{
    [Test]
    public void TestLuhnAlgorithm()
    {
        string number = "412345678901234";
        string checkDigit = NumberSigning.ComputeCheckDigit(number);
        Assert.That(checkDigit, Is.EqualTo("9"));
        bool checkNumber = NumberSigning.CheckNumber("4123456789012349");
        Assert.That(checkNumber, Is.True);
    }
}