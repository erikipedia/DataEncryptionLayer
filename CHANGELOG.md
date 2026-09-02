# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this
project aims to follow [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

No versions have been tagged yet, so everything below sits under Unreleased. This file starts
at the .NET 10 upgrade; anything earlier is in the commit log.

## [Unreleased]

### Added

- `README` covering the public API, the `.crypt` naming convention, and the security
  properties of the built-in defaults.
- This changelog.
- Test fixtures for `Utilities` and `FileSigning`, neither of which had any coverage, and one
  for the encrypted/decrypted filename derivation. ([#3])

### Changed

- Both projects now target .NET 10. .NET 9 is an STS release that has reached end of support
  and no longer receives security fixes. ([#2])
- `Utilities.IsStreamEncrypted` now samples up to 4 KiB rather than a single 16-byte block,
  and decides by decoding the sample as UTF-8 instead of rejecting individual byte values.
  ([#3])
- `FileSigning.ComputeChecksum` returns the same 32-character uppercase hex string as before,
  but via `Convert.ToHexString`. `CheckFile` now compares case-insensitively rather than
  upper-casing its argument. ([#3])

### Fixed

Filenames were derived with index arithmetic over the whole path, which threw or produced the
wrong name in several ordinary cases. All of the following are fixed in ([#3]); the on-disk
format is unchanged, and existing `name_ext.crypt` files still decrypt.

- `Encrypt` threw `ArgumentOutOfRangeException` on a file with no extension. Such a file now
  encrypts to `name_.crypt`, the trailing separator recording the absent extension so the
  round trip stays reversible for names that already contain an underscore.
- `Encrypt` treated a dot in a *directory* name as the file's extension, so `v1.2/notes`
  produced a mangled path.
- `Decrypt` cut the restored name at the last underscore anywhere in the path, so a directory
  containing one was spliced into the filename when the filename itself had none.
- `Decrypt` indexed from the last dot before validating, so a file with no extension threw
  `ArgumentOutOfRangeException` instead of reporting that it was not an encrypted file.
- The `.crypt` extension check was case sensitive, rejecting `payload_txt.CRYPT`.

Encryption detection classified every byte above 127, and every control byte other than CR
and LF, as ciphertext ([#3]):

- Any file containing a **tab** was reported as encrypted.
- Any **non-ASCII UTF-8** file was reported as encrypted, since the only high bytes accepted
  were the three bytes of the byte order mark. Detection now decodes the sample and tolerates
  a multi-byte character split by the sample boundary.
- `IsStreamEncrypted` measured length across the whole stream but read from the current
  position, so a partially read stream could pass the length test and then overrun the read.
  It now measures the remainder, and restores the position even if the read throws.

Resource handling ([#3]):

- `Aes`, `ICryptoTransform`, `Rfc2898DeriveBytes` and `MD5` instances were created and never
  disposed.
- `GetFileOutputStream` and `GetFileInputStream` leaked the inner `FileStream` if the
  transform could not be constructed.
- Rollback after a failed write called `File.Delete` directly, so a failure to clean up
  replaced the exception that caused the rollback. Cleanup is now best-effort.

## Known limitations

Not defects, but consequences of the current design, recorded here so they are not mistaken
for regressions:

- The default key, IV and salt are compiled in and published in this repository. Data
  encrypted with the no-argument overloads is obfuscated rather than protected.
- Because the salt and IV are fixed, encryption is deterministic: the same plaintext and
  password always yield the same ciphertext.
- Ciphertext is AES-CBC with no MAC, so tampering is not detected.
- `FileSigning` uses MD5, which is not collision resistant.
- `Encrypt` and `Decrypt` delete their input file, and overwrite an existing destination
  without warning.
- Encryption detection cannot tell ciphertext from other binary data whose length happens to
  be a multiple of the block size.

[#2]: https://github.com/erikipedia/DataEncryptionLayer/pull/2
[#3]: https://github.com/erikipedia/DataEncryptionLayer/pull/3
