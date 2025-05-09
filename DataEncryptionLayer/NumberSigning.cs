using System.Text.RegularExpressions;

namespace DataEncryptionLayer;

/// <summary>
/// Simple number validation using the Luhn algorithm
/// </summary>
public static class NumberSigning
{
    /// <summary>
    /// Determine if a number is valid using the Luhn check digit algorithm
    /// </summary>
    /// <param name="number">The number to check</param>
    /// <param name="modulus">The modulus (binary, octal, decimal, or hexadecimal). Defaults to decimal(10).</param>
    /// <returns></returns>
    /// <exception cref="ArgumentOutOfRangeException"></exception>
    /// <exception cref="ArgumentException"></exception>
    public static bool CheckNumber(string number, int modulus = 10)
    {
        // catch input exceptions
        ArgumentException.ThrowIfNullOrEmpty(number);

        Regex numberFormat = modulus switch
        {
            2 => new Regex("^[0-1]+$"),
            8 => new Regex("^[0-7]+$"),
            10 => new Regex("^[0-9]+$"),
            16 => new Regex("^[0-9a-fA-F]+$"),
            _ => throw new ArgumentOutOfRangeException(nameof(modulus))
        };
        if (!numberFormat.IsMatch(number)) throw new ArgumentException("Number format does not match Modulus parameter", nameof(number));

        return (number.ToCharArray()
            .Reverse()
            .Select(c => Convert.ToInt32(c.ToString(), modulus))
            .Select((d, i) => i % 2 != 0 ? d * 2 : d)
            .Select(s => s > modulus - 1 ? s - (modulus - 1) : s)
            .Sum()) % modulus == 0;
    }
    
    /// <summary>
    /// Create a check digit using the Luhn algorithm
    /// </summary>
    /// <param name="number">The number</param>
    /// <param name="modulus">The modulus (binary, octal, decimal, or hexadecimal). Defaults to decimal(10).</param>
    /// <returns>The check digit result</returns>
    /// <exception cref="ArgumentOutOfRangeException"></exception>
    /// <exception cref="ArgumentException"></exception>
    public static string ComputeCheckDigit(string number, int modulus = 10)
    {
        // catch input exceptions
        ArgumentException.ThrowIfNullOrEmpty(number);

        Regex numberFormat = modulus switch
        {
            2 => new Regex("^[0-1]+$"),
            8 => new Regex("^[0-7]+$"),
            10 => new Regex("^[0-9]+$"),
            16 => new Regex("^[0-9a-fA-F]+$"),
            _ => throw new ArgumentOutOfRangeException(nameof(modulus))
        };
        if (!numberFormat.IsMatch(number)) throw new ArgumentException("Number format does not match Modulus parameter", nameof(number));
        
        return ((modulus - (number.ToCharArray()
            .Reverse()
            .Select(c => Convert.ToInt32(c.ToString(), modulus))
            .Select((d, i) => i % 2 == 0 ? d * 2 : d)
            .Select(s => s > modulus - 1 ? s - (modulus - 1) : s)
            .Sum()) % modulus) % modulus).ToString("X");
    }
}