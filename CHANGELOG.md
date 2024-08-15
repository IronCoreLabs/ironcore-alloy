## 0.11.1

Breaking changes:

- Dropped support for Python 3.8
- Reworked several type aliases into newtype structs. In Rust this will require creating structs, but Python and Kotlin are unaffected.
- Renamed `StandaloneAttachedStandardClient` to `StandaloneStandardAttachedClient`.
- Changed Standard Attached `get_searchable_edek_prefix` to be synchronous.

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
