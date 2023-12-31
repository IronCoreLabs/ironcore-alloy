# Simple Round-Trip Example

```bash
export STANDALONE_SECRET='R8xfozIf4T4WZkERh1rpN4mdIe7bL2vK'
cargo run
```

This should produce output like:

```text
Using tenant tenant-gcp-l
Decrypted SSN: 000-12-2345
Decrypted address: 2825-519 Stone Creek Rd, Bozeman, MT 59715
Decrypted name: Jim Bridger
```

The decrypted output is printed after round-tripping encryption and decryption of the customer record.

If you look in the current directory, you'll find a _success.jpg_ file. The example code encrypted
that file to produce a _success.jpg.enc_ file containing the encrypted file data, and a second file
_success.jpg.edek_ that contains the Encrypted Data Encryption Key (EDEK) that is required to
decrypt the file. It then used that EDEK to decrypt the _.enc_ file, writing a _decrypted.jpg_ file.

If you do a `cksum success.jpg decrypted.jpg`, you can confirm that the decrypted file is identical
to the original.
