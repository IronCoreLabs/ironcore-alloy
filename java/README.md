# Java build and publish info

## Requirements

- Java 22+
- [enable native access](https://docs.oracle.com/en/java/javase/25/core/restricted-methods.html)

## Build

Ensure the library and source have been created, typically done by running `cargo t` in `../`.

## Testing

`./gradlew test`

## Benchmarking

More information about the benchmarks is in its [README](/java/src/jmh/java/com/ironcorelabs/ironcore_alloy_java/README.md).

## Publishing

You can test publishing `./gradlew publishToMavenLocal`.

### Signing information

The `.github/gradle.properties.iron` file contains all the signing information. It should be decrypted and put in the `java` directory. It mandates that the signing key be put in `/tmp/9FA43559.asc`, which is the decrypted gpg key.
