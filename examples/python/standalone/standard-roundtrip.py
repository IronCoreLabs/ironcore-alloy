import ironcore_alloy as alloy
import os
import asyncio
import json


async def main():
    tenant_id = os.environ.get('TENANT_ID', 'tenant-gcp')
    # Note: in practice this must be 32 cryptographically-secure bytes
    key_bytes = b"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
    vector_secrets = {}
    standard_secrets = alloy.StandardSecrets(1, [alloy.StandaloneSecret(1, alloy.Secret(key_bytes))])
    deterministic_secrets = {}
    config = alloy.StandaloneConfiguration(standard_secrets, deterministic_secrets, vector_secrets)
    sdk = alloy.Standalone(config)

    jim_original = json.dumps({
        "name": "Jim Bridger",
        "address": "2825-519 Stone Creek Rd, Bozeman, MT 59715",
        "ssn": "000-12-2345"
    })
    metadata = alloy.AlloyMetadata.new_simple(tenant_id)
    # Encrypt Jim's personal information
    encrypted = await sdk.standard().encrypt({"jim": bytes(jim_original, "utf-8")}, metadata)
    # Store off the `document` and `edek`

    # -----------------------------

    # Later, retrieve the `document` and `edek`
    encrypted_recreated = alloy.EncryptedDocument(encrypted.edek, encrypted.document)
    # Decrypt Jim's personal information
    decrypted = await sdk.standard().decrypt(encrypted_recreated, metadata)
    jim_decrypted = json.loads(decrypted["jim"])

    print("Decrypted SSN: ", jim_decrypted["ssn"])
    print("Decrypted address: ", jim_decrypted["address"])
    print("Decrypted name: ", jim_decrypted["name"])


if __name__ == '__main__':
    loop = asyncio.get_event_loop()
    loop.run_until_complete(main())
