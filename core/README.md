# IronCore Labs Alloy SDK

- `cargo t --release` will build Kotlin and Python bindings as well as run Rust and foreign code integration tests. It'll leave the binding project's directories in a state that they could be released from. This requires Python and Kotlin infrastructure to be installed.
- `cargo t` will do almost the same faster but will leave the binding project's directories in an inefficient form not to be released.
- `cargo t --lib` will build and run only the Rust tests, not integration tests. This doesn't require any Python or Kotlin infrastructure to be installed. This is used in Rust CI.

This project defaults to compiling with the `metadata` feature on for now, but `--no-default-features` will turn it off and the resulting foreign library will not have the metadata ops in it. `--no-default-features` could be used by a Rust SDK consumer if they don't want `metadata` functionality.

After either of the non-`--lib` `cargo` commands have been run, the Kotlin and Python project directories will be in a state that you can play around with them as though they were native libraries of that language.

- `cd kotlin; ./gradlew test` will manually run only the Kotlin tests.
- `cd python/ironcore-alloy; hatch run test:test` will manually run only the Python tests.
- See `python/ironcore-alloy/README.md` for more information about manually releasing that package and other available `hatch` commands.

## License

`ironcore-alloy` is licensed under the [GNU Affero General Public License](https://github.com/IronCoreLabs/ironoxide/blob/main/LICENSE). We also offer commercial licenses - [email](mailto:info@ironcorelabs.com) for more information or check pricing on our [website](https://ironcorelabs.com/).
