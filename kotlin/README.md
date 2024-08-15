# Kotlin build and publish info

## Build

Ensure the library and source have been created, typically done by running `cargo t` in `../`.

## Testing

`./gradlew test`

## Benchmarking

You can run the benchmarks `./gradlew bench`.

More information about the benchmarks is in its [README](./benchmarks/src/README.md).

## Publishing

You can test publishing `./gradlew publishToMavenLocal`.

### Signing information

The `.github/gradle.properties.iron` file contains all the signing information. It should be decrypted and put in the `kotlin` directory. It mandates that the signing key be put in `/tmp/9FA43559.asc`, which is the decrypted gpg key.
