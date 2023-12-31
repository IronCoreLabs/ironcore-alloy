# IronCore Labs Alloy SDK

The Alloy SDK brings together a set of tools that you can use for your different Application Layer Encryption needs. It
unifies functionality that was provided in our SaaS Shield Tenant Security Client (TSC) SDKs and our new Cloaked AI tools
in a single library that you can include in your application. This library provides tools to encrypt data using
_standard_, _deterministic_, and _vector_ encryption algorithms.

Whether you are handling structured or unstructured documents, fields that are stored in a relational database or key value
store, vectors that are stored in a vector database, or some combination of these, the Alloy SDK provides the tools you need
to protect the private or sensitive data your apps process.

## Language Support

- [Java](https://central.sonatype.com/artifact/com.ironcorelabs/ironcore-alloy)
- [Kotlin](https://central.sonatype.com/artifact/com.ironcorelabs/ironcore-alloy)
- [Python](https://pypi.org/project/ironcore-alloy)
- Rust - Depend on this repo using a git dependency.

This SDK was written in Rust and is using [uniffi](https://github.com/mozilla/uniffi-rs) to generate the foreign language bindings. If your language is not listed above, feel free to open an issue and we can take a look!

## Getting Started

Follow the links above to get the latest version for the appropriate language.
You can see the examples on our main docs site [here](https://docs.ironcorelabs.com).

## Building Locally

- `cargo t --release` will build Kotlin and Python bindings as well as run Rust and foreign code integration tests. It'll leave the binding project's directories in a state that they could be released from. This requires Python and Kotlin infrastructure to be installed.
- `cargo t` will do almost the same faster but will leave the binding project's directories in an inefficient form not to be released.
- `cargo t --lib` will build and run only the Rust tests, not integration tests. This doesn't require any Python or Kotlin infrastructure to be installed. This is used in Rust CI.

This project defaults to compiling with the `metadata` feature on for now, but `--no-default-features` will turn it off and the resulting foreign library will not have the metadata ops in it. `--no-default-features` could be used by a Rust SDK consumer if they don't want `metadata` functionality.

After either of the non-`--lib` `cargo` commands have been run, the Kotlin and Python project directories will be in a state that you can play around with them as though they were native libraries of that language.

- `cd kotlin; ./gradlew test` will manually run only the Kotlin tests.
- `cd python/ironcore-alloy; hatch run test:test` will manually run only the Python tests.
- See `python/ironcore-alloy/README.md` for more information about manually releasing that package and other available `hatch` commands.

## Integration Tests

Running tests with the `integration_tests` feature flag enables SaaS Shield integration tests. These require a TSP running at `http://localhost:32804` with the configuration provided in `tests/demo-tsp.conf`. This can be started by running `docker compose up` from the `tests` directory.

Run tests:

```bash
cargo test --features integration_tests
```

## License

`ironcore-alloy` is licensed under the [GNU Affero General Public License](LICENSE). We also offer commercial licenses - [email](mailto:info@ironcorelabs.com) for more information or check pricing on our [website](https://ironcorelabs.com/).
