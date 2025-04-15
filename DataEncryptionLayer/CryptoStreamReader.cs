using System.Security.Cryptography;

namespace DataEncryptionLayer;

/// <summary>
/// This class encapsulates a workaround for a design flaw in the CryptoStream class,
/// which results in an exception when closing a stream that has only been partial read.
/// The workaround suggested by the owner of that class at Microsoft (Shawn Farkas) is to 
/// simply catch the exception and ignore it.
/// 
/// This is only a problem for *input* streams (and only on partial reads), so we only use it
/// with GetFileInputStream.
/// </summary>
public class CryptoStreamReader(Stream stream, ICryptoTransform transform, CryptoStreamMode mode) : CryptoStream(stream, transform, mode)
{
    public override void Close()
    {
        try
        {
            base.Close();
        }
        catch (CryptographicException)
        {
            // ignore
        }
    }
}