# Simple Round-Trip Example

```bash
export STANDALONE_SECRET='KcWARR00N05VrvRyuQDvOImCijN3eJmC'
cargo run
```

This should produce output like:

```text
Decrypted SSN: 000-12-2345
Decrypted address: 2825-519 Stone Creek Rd, Bozeman, MT 59715
Decrypted name: Jim Bridger
```

The decrypted output is printed after round-tripping encryption and decryption of the customer record.
