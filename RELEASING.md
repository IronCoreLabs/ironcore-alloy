# Release Checklist

- Update to the new version number using the [Bump Version](https://github.com/IronCoreLabs/ironcore-alloy/actions/workflows/bump-version.yaml) workflow. This will be used as the Rust/Python/Kotlin/Java version number.
- The [Python/Kotlin/Java/Rust Release](https://github.com/IronCoreLabs/ironcore-alloy/actions/workflows/sdk-release.yaml) action will automatically publish the Python/Kotlin/Java/Rust SDKs.
- When the JVM artifacts have been deployed, you can watch their publishing progress at https://central.sonatype.com/publishing/deployments, but no action should be required.
