using System.Reflection;
using DataEncryptionLayer;

namespace DataEncryptionLayer.Tests;

[TestFixture]
[TestOf(typeof(FileCryptography))]
public class FileCryptographyTests
{
    #region Private Fields
    
    private string _filePath = Assembly.GetExecutingAssembly().Location;
    
    #endregion
    
    #region Setup/Teardown
    
    [SetUp]
    public void SetUp()
    {
        
    }

    [TearDown]
    public void TearDown()
    {
        
    }
    
    #endregion
    
    [Test]
    public void TestFileEncryptDecrypt()
    {
        
    }
}