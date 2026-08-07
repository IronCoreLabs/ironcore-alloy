# Python Examples

## Setup

To run the examples, you must first activate the virtual environment; we use `hatch` to manage this. 
If you don't have `hatch` installed, directions for installing it can be found 
[here](https://hatch.pypa.io/latest/install/).

From the `examples/python` folder, run 

```bash
hatch shell
```

Once the environment is activated, decide if you would like to run the Standalone or SaaS Shield examples and navigate
to the respective directory. If you choose SaaS Shield, be sure to startup the TSP as described [here](../README.md).

## Examples

### Vector roundtrip

This example shows creating a plaintext vector associated with a tenant, encrypting the vector, then decrypting it. 
Because of floating point arithmetic, the decrypted vector may not perfectly match the plaintext.

```
python vector-roundtrip.py
```

Each time you run the example, the encrypted vector will change significantly, but nearest-neighbor searches
will still function.

### Vector search

This example shows creating a plaintext vector associated with a tenant, encrypting the vector, then generating
query vectors that can be used for nearest-neighbor searches on the original plaintext.

```
python vector-search.py
```

### Standard roundtrip

This example shows creating a plaintext document containing personal information associated with a tenant, encrypting
the document, then decrypting it. 

```
python standard-roundtrip.py
```

### Standard streaming roundtrip

This example streams a file through standard encryption to disk and back, in 64 KiB chunks, so the whole file never has
to be held in memory at once. It also demonstrates the release-of-unverified-plaintext contract: decrypted chunks are
written to a temporary file and only committed once the authentication tag is verified.

```
python streaming-roundtrip.py
```