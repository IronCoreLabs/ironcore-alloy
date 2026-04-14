# TSC to Alloy Migration Guide


## Overview

This guide covers migrating from `tenant-security-client-*` (TSC) SDKs to `ironcore-alloy` with minimal disruption. The `legacy_tsc_write_format` configuration option allows an in-place upgrade: switch to Alloy for performance benefits while continuing to write the old document format, then upgrade to V5 format on your own timeline.

This setting only affects standard (detached) encryption. Attached, deterministic, and vector encryption are unaffected because they have no TSC equivalent (deterministic is already byte-compatible without any flag).

## Migration Steps

### Step 1: Drop-in replacement (legacy format)

- Initialize `SaasShieldConfiguration` with `legacy_tsc_write_format: true`
- All new standard encryption writes to V3 format (compatible with existing TSC data and clients)
- Reads by Alloy clients work for both V3 and V5 data automatically
- Deterministic encryption is already byte-compatible between TSC and Alloy (no flag needed)

You could stay at this step for as long as you want while reaping the performance benefits of Alloy, and using new features like attached standard documents or vector encryption. If you want the ability to prefix match EDEK or document bytes by the config ID used to encrypt them, you'll need to continue through the steps.

### Step 2: Switch to V5 format

Once all services are deployed using Alloy with `legacy_tsc_write_format: true` and there are no more TSC-based services deployed, then you can move to this step.

- Change `legacy_tsc_write_format` to `false` (the default)
- New writes use V5 format with `key_id_header` prefix
- Old V3 data continues to decrypt without any changes
- `get_searchable_edek_prefix` becomes available for new V5 documents

### Step 3 (optional): Bulk rekey to V5

EDEKs that have been rekeyed can be reliably identified by byte 5 being `0x02` and byte 6 being `0x00`, V3 was raw protobuf at those positions and won't likely match. It won't hurt to rekey something already in the target format. So a query to find V3 EDEKs that need to be rekeyed would be something like:

```psql
SELECT * FROM documents WHERE substring(edek FROM 5 FOR 2) != '\x0200'::bytea;
```

- Use `rekey_edeks` to upgrade existing V3 EDEKs to V5
- After rekeying, all documents are discoverable via `get_searchable_edek_prefix`
- Rekey always writes in the configured format. A non-legacy client will upgrade V3 EDEKs to V5, and a legacy client will downgrade V5 EDEKs to V3. This makes rekey the tool for intentional format migration in either direction.

## Rolling Deployments

It is safe to rolling deploy a switch from TSC-based services to `legacy_tsc_write_format: true` Alloy-based services. Both will read and write the same format.

The legacy format support is safe for rolling deployments where some services are on `legacy_tsc_write_format: true` and others have already switched to `false`:

- All Alloy instances read both V3 and V5 data regardless of write format configuration
- `encrypt` and `rekey_edeks` write in the configured format
- `encrypt_with_existing_edek` matches its field format to the provided EDEK's format, so it won't produce mismatched documents regardless of which service handles it

This means you can safely roll out the V5 switch incrementally without coordinating a simultaneous deployment. If you need to roll back to legacy after some services have already written V5 data, re-enable the legacy flag and use `rekey_edeks` to downgrade V5 EDEKs back to V3 (invert the command in Step 3 to find them). V5 documents can still be read by any Alloy client in the meantime, but if you still have active TSC-based services they will fail to read V5 documents.

## Known Friction Points

### `encrypt_with_existing_edek` matches the EDEK format

`encrypt_with_existing_edek` ignores the `legacy_tsc_write_format` setting. Instead, it matches the field format to the provided EDEK. A V3 EDEK produces V3 fields, a V5 EDEK produces V5 fields. This ensures the EDEK and fields are always in the same format.

To upgrade a document from V3 to V5, first call `rekey_edeks` in a `legacy_tsc_write_format: false` client to get a V5 EDEK, then use the rekeyed EDEK with `encrypt_with_existing_edek`. To roll back from V5 to the TSC-compatible V3, do the same with a `legacy_tsc_write_format: true` client.

### `get_searchable_edek_prefix` only matches V5 EDEKs

The prefix returned by this method will not match V3 EDEKs, since V3 EDEKs do not have a fixed searchable prefix. It can still be called regardless of the `legacy_tsc_write_format` setting. If your store contains a mix of V3 and V5 data, the prefix will match the V5 entries.

### Standard Attached is V5-only

`StandardAttachedDocumentOps` always uses V5 format because TSC never had an attached encryption concept. The `legacy_tsc_write_format` flag does not affect it.

## Deterministic Encryption

No migration steps needed. TSC and Alloy SaaS Shield deterministic encryption produce byte-identical output (same AES-256-SIV algorithm, same 6-byte header format). Data encrypted by TSC deterministic can be decrypted by Alloy and vice versa without any configuration.

## Standard Encryption Format Differences

| Component       | TSC (V3)                                              | Alloy V5                                          |
| --------------- | ----------------------------------------------------- | ------------------------------------------------- |
| EDEK            | Raw `EncryptedDeks` protobuf                          | `[key_id_header][V4DocumentHeader protobuf]`      |
| Encrypted field | `[3][IRON][header_len][v3DocumentHeader][IV][cipher]` | `[0][IRON][IV][cipher]`                           |
| Searchable      | No prefix-based search                                | `get_searchable_edek_prefix` returns header bytes |
