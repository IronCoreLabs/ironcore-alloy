import ironcore_alloy as alloy
import os
import asyncio


async def main():
    tenant_id = os.environ.get('TENANT_ID', 'tenant-gcp')
    api_key = os.environ.get('API_KEY', '0WUaXesNgbTAuLwn')
    tsp_uri = "http://localhost:32804"
    approximation_factor = 7.2
    config = alloy.SaasShieldConfiguration(tsp_uri, api_key, False, approximation_factor)
    sdk = alloy.SaasShield(config)

    data = [1.2, -1.23, 3.24, 2.37]
    print("Plaintext vector: ", data)
    plaintext = alloy.PlaintextVector(data, "contacts", "conversation-sentiment")
    metadata = alloy.AlloyMetadata.new_simple(tenant_id)
    encrypted = await sdk.vector().encrypt(plaintext, metadata)
    print("Encrypted vector: ", encrypted.encrypted_vector)
    # Store off `encrypted_vector` and `paired_icl_data`.
    # Note that `paired_icl_data` is required for decryption. If you only need to support querying,
    # then storing `paired_icl_data` is not required.

    search_vector = alloy.PlaintextVector([1.4, -1.32, 4.32, 2.37], "contacts", "conversation-sentiment")
    query_vectors = (await sdk.vector().generate_query_vectors({"vec_1": search_vector}, metadata))["vec_1"]
    query_vectors_embeddings = map(lambda vector: vector.encrypted_vector, query_vectors)
    print("Query vectors:    ", list(query_vectors_embeddings))
    print("Note that the query vectors are a nested list. If this tenant had an in-rotation key, two vectors")
    print("would be in the result. In that case, both vectors must be used in conjunction when querying.")


if __name__ == '__main__':
    loop = asyncio.get_event_loop()
    loop.run_until_complete(main())
