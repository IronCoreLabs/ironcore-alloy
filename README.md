# IronCore Labs Alloy SDK

[![Mentioned in Awesome Security Solutions for AI Systems](https://awesome.re/mentioned-badge-flat.svg)](https://github.com/zmre/awesome-security-for-ai/)
![Crates.io Version](https://img.shields.io/crates/v/ironcore-alloy)

The Alloy SDK brings together a set of tools that you can use for your different Application Layer Encryption needs. It
unifies functionality that was provided in our [SaaS Shield](https://ironcorelabs.com/products/saas-shield/) [Tenant Security Client (TSC) SDKs](https://ironcorelabs.com/docs/saas-shield/tenant-security-client/overview/) and our new [Cloaked AI](https://ironcorelabs.com/products/cloaked-ai/) tools
in a single library that you can include in your application. This library provides tools to encrypt data using
_standard_, _deterministic_, and _vector_ encryption algorithms.

Whether you are handling structured or unstructured documents, fields that are stored in a relational database or key value
store, vectors that are stored in a vector database, or some combination of these, the Alloy SDK provides the tools you need
to protect the private or sensitive data your apps process.

## Language Support

- [Java](https://central.sonatype.com/artifact/com.ironcorelabs/ironcore-alloy-java)
- [Kotlin](https://central.sonatype.com/artifact/com.ironcorelabs/ironcore-alloy)
- [Python](https://pypi.org/project/ironcore-alloy)
- [Rust](https://crates.io/crates/ironcore-alloy)

This SDK was written in Rust and is using [uniffi](https://github.com/mozilla/uniffi-rs) to generate the foreign language bindings. If your language is not listed above, feel free to open an issue and we can take a look!

## Getting Started

Follow the links above to get the latest version for the appropriate language.
You can see the examples on our main docs site [here](https://ironcorelabs.com/docs/). We also have specific [vector database integration examples](https://ironcorelabs.com/docs/cloaked-ai/integrations/) for our Cloaked AI functionality showing how to protect embeddings in various vector databases.

### Prerequisites

Across all languages:

- glibc 2.29+

## Building Locally

- `cargo t --release` will build Kotlin and Python bindings as well as run Rust and foreign code integration tests. It'll leave the binding project's directories in a state that they could be released from. This requires Python and Kotlin infrastructure to be installed.
- `cargo t` will do almost the same faster but will leave the binding project's directories in an inefficient form not to be released.
- `cargo t --lib` will build and run only the Rust tests, not integration tests. This doesn't require any Python or Kotlin infrastructure to be installed. This is used in Rust CI.

This project defaults to compiling with the `metadata` feature on for now, but `--no-default-features` will turn it off and the resulting foreign library will not have the metadata ops in it. `--no-default-features` could be used by a Rust SDK consumer if they don't want `metadata` functionality.

After either of the non-`--lib` `cargo` commands have been run, the Kotlin and Python project directories will be in a state that you can play around with them as though they were native libraries of that language.

- `cd kotlin; ./gradlew test` will manually run only the Kotlin tests.
- `cd java; ./gradlew test` will manually run only the Java tests.
- `cd python/ironcore-alloy; hatch run test:test` will manually run only the Python tests.
- See `python/ironcore-alloy/README.md` for more information about manually releasing that package and other available `hatch` commands.

## Integration Tests

Running tests with the `integration_tests` feature flag enables SaaS Shield integration tests. These require a TSP running at `http://localhost:32804` with the configuration provided in `tests/demo-tsp.conf`. This can be started by running `docker compose up` from the `tests` directory.

Run tests:

```bash
cargo test --features integration_tests -- --nocapture
```

## Benchmarks

We provide benchmarks of ironcore-alloy in [Rust](./benches/README.md), [Kotlin](./kotlin/benchmarks/src/README.md), [Java](https://github.com/IronCoreLabs/ironcore-alloy/tree/main/java/src/jmh/java/com/ironcorelabs/ironcore_alloy_java), and [Python](https://github.com/IronCoreLabs/ironcore-alloy/blob/main/python/ironcore-alloy/bench.py). These benchmark folders each contain a Docker Compose file that will start up a TSP with a predefined configuration for testing purposes.

# Cryptography Notice

This repository includes cryptographic software. The country in which you currently reside may have restrictions on the import, possession, use, and/or re-export to another country, of encryption software. BEFORE using any encryption software, please check your country's laws, regulations and policies concerning the import, possession, or use, and re-export of encryption software, to see if this is permitted. See https://www.wassenaar.org/ for more information.

The U.S. Government Department of Commerce, Bureau of Industry and Security (BIS), has classified this software as Export Commodity Control Number (ECCN) 5D002, which includes information security software using or performing cryptographic functions. The form and manner of this distribution makes it eligible for export under the License Exception ENC (see the BIS Export Administration Regulations, Section 740.17.B.3.i.B and also the publicly available source code exemption, under 742.15; notice has been given to BIS and NSA).

## License

`ironcore-alloy` is licensed under the [GNU Affero General Public License](LICENSE). We also offer commercial licenses - [email](mailto:info@ironcorelabs.com) for more information or check pricing on our [website](https://ironcorelabs.com/).
