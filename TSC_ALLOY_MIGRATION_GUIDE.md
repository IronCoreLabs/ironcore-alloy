# TSC to Alloy Migration Guide


## Overview

This guide covers migrating from `tenant-security-client-*` (TSC) SDKs to `ironcore-alloy` with minimal disruption. The `legacy_tsc_compatible_write_format` configuration option allows an in-place upgrade: switch to Alloy for performance benefits while continuing to write the old document format, then upgrade to V5 format on your own timeline.

This setting only affects standard (detached) encryption. Attached, deterministic, and vector encryption are unaffected because they have no TSC equivalent (deterministic is already byte-compatible without any flag).

## Migration Steps

### Step 1: Drop-in replacement (legacy format)

- Initialize `SaasShieldConfiguration` with `legacy_tsc_compatible_write_format: true`
- All new standard encryption writes to V3 format (compatible with existing TSC data and clients)
- Reads by Alloy clients work for both V3 and V5 data automatically
- Deterministic encryption is already byte-compatible between TSC and Alloy (no flag needed)

You could stay at this step for as long as you want while reaping the performance benefits of Alloy, and using new features like attached standard documents or vector encryption. If you want the ability to prefix match EDEK or document bytes by the config ID used to encrypt them, you'll need to continue through the steps.

### Step 2: Switch to V5 format

Once all services are deployed using Alloy with `legacy_tsc_compatible_write_format: true` and there are no more TSC-based services deployed, then you can move to this step.

- Change `legacy_tsc_compatible_write_format` to `false` (the default)
- New writes use V5 format with `key_id_header` prefix
- Old V3 data continues to decrypt without any changes
- `get_searchable_edek_prefix` becomes available for new V5 documents

### Step 3 (optional): Bulk rekey to V5

EDEKs that have been rekeyed can be pretty reliably identified by byte 5 being `0x02` and byte 6 being `0x00`, V3 was raw protobuf at those positions and won't likely match. So a query to find V3 EDEKs that need to be rekeyed would be something like:

```psql
SELECT * FROM documents WHERE substring(edek FROM 5 FOR 2) != '\x0200'::bytea;
```

- Use `rekey_edeks` to upgrade existing V3 EDEKs to V5
- After rekeying, all documents are discoverable via `get_searchable_edek_prefix`
- Note: rekey never downgrades — a V5 EDEK stays V5 even if `legacy_tsc_compatible_write_format` is still `true`

## Rolling Deployments

The legacy format support is safe for rolling deployments where some services are on `legacy_tsc_compatible_write_format: true` and others have already switched to `false`:

- All Alloy instances read both V3 and V5 data regardless of write format configuration
- Rekey never downgrades: a V5 EDEK stays V5 even if processed by a legacy-configured service
- Only when both the input EDEK is V3 *and* the service is legacy-configured will a V3 EDEK be written on rekey

This means you can safely roll out the V5 switch incrementally without coordinating a simultaneous deployment. You can also re-enable the legacy format if you notice any issues, written V5 documents can still be read by any Alloy client and V3 will be written.

## Known Friction Points

### `encrypt_with_existing_edek` does not upgrade EDEKs

When migrating from V3 to V5 format, `encrypt_with_existing_edek` will re-encrypt document fields in V5 format but will **not** automatically upgrade the provided EDEK. The EDEK remains in whatever format it was originally created in.

This means that after disabling `legacy_tsc_compatible_write_format`:
- Documents updated via `encrypt_with_existing_edek` with a V3 EDEK will have V5-formatted fields but a V3 EDEK
- These documents will decrypt correctly (the decrypt path handles mixed formats)
- However, the V3 EDEK will **not** be discoverable via `get_searchable_edek_prefix`

To fully migrate a document to V5, you should call `rekey_edeks` on the EDEK to upgrade it as well. This can be done before or after re-encrypting fields — the order doesn't matter since both formats decrypt correctly regardless of the other's format.

### `get_searchable_edek_prefix` is V5-only

This method returns an error when the SDK is configured with `legacy_tsc_compatible_write_format: true`, because V3 EDEKs do not have a fixed searchable prefix. Disable the legacy flag before relying on prefix-based search.

### Standard Attached is V5-only

`StandardAttachedDocumentOps` always uses V5 format because TSC never had an attached encryption concept. The `legacy_tsc_compatible_write_format` flag does not affect it.

## Deterministic Encryption

No migration steps needed. TSC and Alloy SaaS Shield deterministic encryption produce byte-identical output (same AES-256-SIV algorithm, same 6-byte header format). Data encrypted by TSC deterministic can be decrypted by Alloy and vice versa without any configuration.

## Standard Encryption Format Differences

| Component       | TSC (V3)                                              | Alloy V5                                          |
| --------------- | ----------------------------------------------------- | ------------------------------------------------- |
| EDEK            | Raw `EncryptedDeks` protobuf                          | `[key_id_header][V4DocumentHeader protobuf]`      |
| Encrypted field | `[3][IRON][header_len][v3DocumentHeader][IV][cipher]` | `[0][IRON][IV][cipher]`                           |
| Searchable      | No prefix-based search                                | `get_searchable_edek_prefix` returns header bytes |
