## 0.13.0

- Dependency updates
- Added a `new_seeded_for_testing` constructor for `StandaloneConfiguration` which allows for testing with deterministic known values. DO NOT USE IN PRODUCTION CODE.

### Breaking Changes

- Default constructors for `VectorSecret` and `SaasShieldConfiguration` now set the scaling factor to 1. If you want to continuing using the scaling factor you can call the `new_with_scaling_factor` on the respective classes.

## 0.12.0

- Dependency updates
- Async functionality now runs fully in the host language's async runtime; there is no longer sometimes a Tokio (a Rust async runtime) runtime created to manage async tasks.

### Breaking Changes

- Updated SaaS Shield Clients to take a native http client as an argument. The client must implement HttpClient, which requires only a `postJson` function. See tests in the various languages for example implementations.

## 0.11.2

- Dependency updates
- Dropped build for Mac OS 12 and replaced it with Mac OS 13.

## 0.11.1

Breaking changes:

- Dropped support for Python 3.8
- Reworked several type aliases into newtype structs. In Rust this will require creating structs, but Python and Kotlin are unaffected.
- Renamed `StandaloneAttachedStandardClient` to `StandaloneStandardAttachedClient`.
- Changed Standard Attached `get_searchable_edek_prefix` to be synchronous.
- Changed several constructors to require keyword arguments.

Other changes:

- Added Java bindings, `ironcore-alloy-java`
- Added batch functionality to all SDK traits.
- Fixed a bug where Standard Attached wasn't accessible for SaaS Shield clients.
- Added rekey functionality for standard_attached data.

## 0.10.2

- Added SaaS Shield security events
- Added SaaS Shield vector rotation
- Added support for standard attached documents
- Added backwards compatibility with TSC and Cloaked Search libraries
- Reworked AlloyError to allow easier matching on error responses

## 0.9.0

Initial release of Alloy. This library is intended to eventually replace the Tenant Security Client libraries, and include additional functionality. Right now this includes:

- our standard (probabilistic, fully random) encryption
- deterministic encryption
- Cloaked AI vector encryption

All three of these support standalone and SaaS Shield modes in this SDK.

Notable features coming soon:

- SaaS Shield security events
- backwards compatibility with TSC libraries
- batch APIs
- rekey and rotate functionality

### Compatibility

Requires TSP 4.12.0+.
