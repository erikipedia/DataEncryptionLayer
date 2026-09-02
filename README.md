# DataEncryptionLayer

A small .NET class library that wraps AES encryption, file checksums and Luhn check digits
behind a handful of static helpers. It is aimed at the common case of "encrypt this string
or this file without me having to think about `CryptoStream`".

Targets .NET 10.

## Contents

| Type | Purpose |
|---|---|
| `TextCryptography` | Encrypt and decrypt strings, returning base-64 |
| `FileCryptography` | Encrypt and decrypt files in place, and open encrypted streams |
| `FileSigning` | MD5 checksums for comparing files and detecting changes |
| `NumberSigning` | Luhn check digit generation and validation |
| `Utilities` | The default key material, byte-array primitives and encryption detection |
| `CryptoStreamReader` | A `CryptoStream` that tolerates being closed after a partial read |

Every type is a static class except `CryptoStreamReader`.

## Before you use this

**The default key, IV and salt are compiled into the library and published in this
repository.** They are in [`Utilities.cs`](DataEncryptionLayer/Utilities.cs), including their
base-64 forms in the doc comments. Anything encrypted with the defaults should be treated as
obfuscated, not protected — anyone with a copy of this library can decrypt it.

The defaults exist so the no-argument overloads work out of the box. If your data has any
real confidentiality requirement, pass your own key and IV, or a password, on every call.

Two further properties worth knowing before you build on this:

- **Encryption is deterministic.** The salt and IV are fixed, so the same plaintext with the
  same password always produces the same ciphertext. That reveals which records are equal to
  each other, which matters if you are encrypting a column of similar values.
- **Ciphertext is not authenticated.** This is AES-CBC with no MAC, so tampering is not
  detected; a decrypt of modified data either yields garbage or throws.

Neither is a bug in the code — they follow from the design — but they decide whether this
library is the right fit for what you are doing.

## Usage

### Text

```csharp
using DataEncryptionLayer;

// with the built-in defaults
string withDefaults = TextCryptography.Encrypt("Hello there!");
string plainText    = TextCryptography.Decrypt(withDefaults);

// with a password (recommended)
string withPassword = TextCryptography.Encrypt("Hello there!", "Un1v3rs3!");
string samePlainText = TextCryptography.Decrypt(withPassword, "Un1v3rs3!");

// with your own key material: a 16, 24 or 32-byte key and a 16-byte IV
string withOwnKey = TextCryptography.Encrypt("Hello there!", myKey, myIv);
```

`Encrypt` returns base-64. Decrypting with the wrong password throws
`CryptographicException`; `TryDecrypt` swallows that and reports success instead, though it
only ever tries the defaults:

```csharp
if (TextCryptography.TryDecrypt(cipherText, out string? result))
{
    Console.WriteLine(result);
}
```

### Files

```csharp
// encrypt, then decrypt again
FileCryptography.Encrypt("report.txt");                // -> report_txt.crypt
FileCryptography.Decrypt("report_txt.crypt");          // -> report.txt

// or with a password
FileCryptography.Encrypt("report.txt", "Un1v3rs3!");
FileCryptography.Decrypt("report_txt.crypt", "Un1v3rs3!");
```

**These calls delete the input file.** `Encrypt` writes the encrypted file and then removes
the plaintext original; `Decrypt` does the reverse. If the write fails the new file is
removed and the original is left in place, but there is no point at which both exist, so
copy anything you cannot afford to lose before calling either. Note also that an existing
file at the destination is overwritten without warning.

The original extension is folded into the filename so that it can be restored:

| Original | Encrypted |
|---|---|
| `report.txt` | `report_txt.crypt` |
| `archive.tar.gz` | `archive.tar_gz.crypt` |
| `notes` (no extension) | `notes_.crypt` |

The trailing separator on the last row is what records "there was no extension", which keeps
the round trip reversible for names that already contain an underscore. Only the filename is
rewritten; the directory is left alone.

### Streams

`GetFileOutputStream` and `GetFileInputStream` hand back a stream you can read or write
through, with the cipher already attached. Dispose it as usual.

```csharp
using (Stream output = FileCryptography.GetFileOutputStream("data.bin", encryptOutputFile: true))
{
    output.Write(payload);
}

// the single-argument reader sniffs the file and attaches a decryptor if it looks encrypted
using (Stream input = FileCryptography.GetFileInputStream("data.bin"))
{
    input.ReadExactly(buffer);
}
```

That sniffing is a heuristic — see [Encryption detection](#encryption-detection) below. If you
know the file is encrypted, pass the key and IV explicitly instead and skip the guesswork.

### Checksums

```csharp
string checksum = FileSigning.ComputeChecksum("report.txt");   // 32-char uppercase hex
bool unchanged  = FileSigning.CheckFile("report.txt", checksum);
bool identical  = FileSigning.CompareFiles("first.txt", "second.txt");
```

`CheckFile` accepts the checksum in either case. These are MD5, which is fine for spotting
accidental change or comparing two files you control, but is not collision resistant — do
not use it to decide whether a file has been tampered with by someone who could choose its
contents.

### Check digits

```csharp
string checkDigit = NumberSigning.ComputeCheckDigit("412345678901234");   // "9"
bool valid        = NumberSigning.CheckNumber("4123456789012349");        // true
```

Both take an optional `modulus` of 2, 8, 10 or 16, defaulting to decimal:

```csharp
string hexCheckDigit = NumberSigning.ComputeCheckDigit("1A2B3C", 16);
```

The digits must match the modulus — `CheckNumber("9", 2)` throws `ArgumentException`, and any
modulus other than the four supported throws `ArgumentOutOfRangeException`. The check digit
comes back as a hexadecimal string, so a modulus of 16 can return `A` through `F`.

### Encryption detection

`Utilities.IsStreamEncrypted` guesses whether a seekable stream holds ciphertext. It first
checks whether the remaining length is a whole number of AES blocks, and if it is, samples up
to 4 KiB and asks whether that sample decodes as UTF-8 text without stray control characters.

It is a guess, and it is wrong in a predictable direction: **any binary file whose length is
a multiple of 16 will be reported as encrypted**, because a JPEG and a block of ciphertext
look equally unlike text. It is reliable at recognising text as *not* encrypted, so treat it
as a text-versus-not-text test rather than proof of encryption. `GetFileInputStream(string)`
relies on it, which is why the explicit overload is the better choice when you already know
what you are opening.

## Building

Requires the [.NET 10 SDK](https://dotnet.microsoft.com/download).

```
dotnet restore
dotnet build
dotnet test
```

Tests are NUnit and live in `DataEncryptionLayer.Tests`.

## Changelog

See [CHANGELOG.md](CHANGELOG.md).
