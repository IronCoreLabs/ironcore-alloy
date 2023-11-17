import ironcore_alloy as alloy
import os
import asyncio


async def main():
    tenant_id = os.environ.get('TENANT_ID', 'tenant-gcp')
    # Note: in practice this must be 32 cryptographically-secure bytes
    key_bytes_1 = b"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
    key_bytes_2 = b"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
    approximation_factor = 7.2
    vector_secrets = {
        "contacts":
            alloy.VectorSecret(
                approximation_factor,
                alloy.RotatableSecret(alloy.StandaloneSecret(1, alloy.Secret(key_bytes_1)),
                                      alloy.StandaloneSecret(2, alloy.Secret(key_bytes_2))),
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
    # The vector is encrypted with the `current_secret` (with `id` 1 in this case)
    encrypted = await sdk.vector().encrypt(plaintext, metadata)
    print("Encrypted vector: ", encrypted.encrypted_vector)
    # Store off `encrypted_vector` and `paired_icl_data`.
    # Note that `paired_icl_data` is required for decryption. If you only need to support querying,
    # then storing `paired_icl_data` is not required.

    search_vector = alloy.PlaintextVector([1.4, -1.32, 4.32, 2.37], "contacts", "conversation-sentiment")
    query_vectors = (await sdk.vector().generate_query_vectors({"vec_1": search_vector}, metadata))["vec_1"]
    query_vectors_embeddings = map(lambda vector: vector.encrypted_vector, query_vectors)
    print("Query vectors:    ", list(query_vectors_embeddings))
    print(
        "Note that the query vectors are a nested list. Because this tenant has both a current key and an in-rotation key,"
    )
    print(
        "there are two vectors resulting query vectors. In this case, both vectors must be used in conjunction when querying."
    )


if __name__ == '__main__':
    loop = asyncio.get_event_loop()
    loop.run_until_complete(main())
