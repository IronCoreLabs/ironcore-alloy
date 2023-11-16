import ironcore_alloy as alloy
import os
import asyncio

async def main():
    tenant_id = os.environ.get('TENANT_ID', 'tenant-gcp')
    # Note: in practice this must be 32 cryptographically-secure bytes
    key_bytes = b"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
    approximation_factor = 7.2
    vector_secrets = {
        "contacts":
        alloy.VectorSecret(
            approximation_factor,
            alloy.RotatableSecret(alloy.StandaloneSecret(1, alloy.Secret(key_bytes)), None),
        )
    }
    standard_secrets = alloy.StandardSecrets(None, [])
    deterministic_secrets = {}
    config = alloy.StandaloneConfiguration(standard_secrets, deterministic_secrets, vector_secrets)
    sdk = alloy.Standalone(config)

    data = [1.2, -1.23, 3.24, 2.37]
    print("Plaintext vector: ", data)
    plaintext = alloy.PlaintextVector(data, "contacts", "conversation-sentiment")
    metadata = alloy.AlloyMetadata.new_simple(tenant_id)
    encrypted = await sdk.vector().encrypt(plaintext, metadata)
    print("Encrypted vector: ", encrypted.encrypted_vector)
    # Store off encrypted_vector and paired_icl_info

    decrypted = await sdk.vector().decrypt(encrypted, metadata)
    print("Decrypted vector: ", decrypted.plaintext_vector)
    print("Note that the encryption/decryption is lossy due to floating point math.")

if __name__ ==  '__main__':
    loop = asyncio.get_event_loop()
    loop.run_until_complete(main())
