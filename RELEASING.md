# Release Checklist

- Update to the new version number using the [Bump Version](https://github.com/IronCoreLabs/cloaked-ai/actions/workflows/bump-version.yaml) workflow. This will be used as the Rust/Python/Kotlin version number.
- The [Python/Kotlin Release](https://github.com/IronCoreLabs/cloaked-ai/actions/workflows/sdk-release.yaml) action will automatically publish the Python/Kotlin SDKs.
- When the JVM artifacts have been deployed, go to https://oss.sonatype.org, log in using the `icl-devops` username and
  password from `sonatype-info.txt`, and find the new release in the _Staging Repositories_. Close that repository and then release it in order to actually push the package out to the public repo.