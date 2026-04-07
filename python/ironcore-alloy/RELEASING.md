# Building

_Note that we expect releases to be done by automation (directions in [root RELEASING.md](../../../RELEASING.md)), but manual directions are here for reference.

## Table of Contents

- [Build](#build)
- [Release](#release)

## Build

```console
cargo t --release
```

That will build the cdylib and generate the foreign code, placing them into the right place. If it's not possible to run this command (in CI), the steps can be done manually:

```console
cargo b --release
cargo run --release --bin uniffi-bindgen generate --library ./target/release/libironcore_alloy.so --language python --out-dir python/ironcore-alloy/ironcore_alloy/
cp ./target/release/libironcore_alloy.so python/ironcore-alloy/ironcore_alloy/
```

However the integration tests are guaranteed to always have the most current method of managing these files.
Once you have a built environment, some common `hatch` commands you may want to use are:

```console
cd python/ironcore-alloy
hatch build -t wheel   # to produce .whl file for release
hatch shell            # to get a local pyenv with the sdk installed
hatch test --all       # to run unit tests across all Python versions
```

> Note: the generate step needs debug symbols to work on Linux, don't strip them before running it (they can be stripped afterwards)

## Documentation

Docs can be previewed locally with `hatch run docs:serve`, or manually built with `hatch run docs:build`.

Docs are automatically built and hosted by [ReadTheDocs](https://readthedocs.com). Because building the
Rust library from source exceeds RTD's build time limits, SDK CI builds the docs HTML and uploads it as a
GitHub Actions artifact. RTD then downloads the pre-built HTML via the GitHub API.

### RTD Setup

RTD's automatic GitHub webhook must be **disabled** in the RTD project settings — builds are
triggered by SDK CI after the docs artifact is ready. If the automatic webhook is left enabled,
RTD will try to build before CI has produced the artifact and fail.

RTD needs a GitHub token to download artifacts from CI. Configure this in the
[RTD project settings](https://readthedocs.org/dashboard/) under **Environment Variables**:

| Variable       | Value                                                                 |
|----------------|-----------------------------------------------------------------------|
| `GITHUB_TOKEN` | A GitHub fine-grained personal access token or GitHub App token with `actions:read` permission on `IronCoreLabs/ironcore-alloy` |

The SDK CI workflow also needs two secrets to trigger RTD builds for PRs:

| GitHub Secret      | Value                                                      |
|--------------------|------------------------------------------------------------|
| `RTD_WEBHOOK_TOKEN` | Token from the RTD integration webhook settings           |
| `RTD_WEBHOOK_ID`    | Numeric ID from the RTD webhook URL                       |

## Release

### Manual

Workflow automation will do this, and instructions for triggering that automation will be added here. The rough structure is:

1. run `cargo t --release` to generate and copy the dynamic library and source into the python project (or pull them from CI artifacts)
1. set `CDYLIB_PLATFORM` to one of `"linux-x86-64"`, `"linux-arm"`, `"darwin-x86-64"`, `"darwin-aarch64"`\*
1. run `hatch build -t wheel`\*\*
1. `hatch publish --repo test --user __token__ --auth "TEST_API_TOKEN"` to release all `.whl`s in `dist` to test pypi \*\*\*
1. after confirming the results `hatch publish --repo main --user __token__ --auth "API_TOKEN"` to release all `.whl`s in `dist` to pypi

> \* support for additional platforms can be added to `hatch_build.py` > \*\* steps 2 and 3 can be repeated for each platform we're going to support, and will result in a bunch of `.whl` files in `dist` > \*\*\* `python3 -m pip install --force --index-url https://test.pypi.org/simple/ ironcore-alloy`, check installation and use
