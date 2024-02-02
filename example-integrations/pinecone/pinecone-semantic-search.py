import asyncio
from pinecone_datasets import load_dataset
import pinecone
import ironcore_alloy as alloy
import base64
import time
from sentence_transformers import SentenceTransformer
import torch
import os


async def main():
    dataset = load_dataset('quora_all-MiniLM-L6-bm25')
    dataset.documents.drop(['metadata'], axis=1, inplace=True)
    dataset.documents.rename(columns={'blob': 'metadata'}, inplace=True)
    # we will use 80K rows of the dataset between rows 240K -> 320K
    dataset.documents.drop(dataset.documents.index[320_000:], inplace=True)
    dataset.documents.drop(dataset.documents.index[:240_000], inplace=True)
    dataset.head()

    # get api key from app.pinecone.io
    PINECONE_API_KEY = os.getenv("PINECONE_API_KEY", default=None)
    PINECONE_ENV = os.getenv("PINECONE_ENV", default='gcp-starter')

    pinecone.init(
        api_key=PINECONE_API_KEY,
        environment=PINECONE_ENV
    )


    index_name = 'semantic-search-fast-encrypted'

    # only create index if it doesn't exist
    if index_name not in pinecone.list_indexes():
        pinecone.create_index(
            name=index_name,
            dimension=len(dataset.documents.iloc[0]['values']),
            metric='cosine'
        )
        # wait a moment for the index to be fully initialized
        time.sleep(1)

    # now connect to the index
    index = pinecone.GRPCIndex(index_name)

    # Note: in practice this must be 32 cryptographically-secure bytes
    key_bytes = b"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
    approximation_factor = 2.0
    vector_secrets = {
        "quora":
            alloy.VectorSecret(
                approximation_factor,
                alloy.RotatableSecret(alloy.StandaloneSecret(1, alloy.Secret(key_bytes)), None),
            )
    }
    standard_secrets = alloy.StandardSecrets(1, [alloy.StandaloneSecret(1, alloy.Secret(key_bytes))])
    deterministic_secrets = {}
    tenant_id = alloy.AlloyMetadata.new_simple("") # not needed in our case so we'll leave it blank
    config = alloy.StandaloneConfiguration(standard_secrets, deterministic_secrets, vector_secrets) # sdk gets set up with required master secrets
    sdk = alloy.Standalone(config)

    print("Encrypting embeddings and their associated text.")
    # first we'll encrypt the vectors
    for row in dataset.documents.itertuples():
        plaintext_vector = alloy.PlaintextVector(row.values, "quora", "sentence") # each index and set of vectors encrypted with different derived keys
        # first we encrypt the dense vector
        encrypted_vector = await sdk.vector().encrypt(plaintext_vector, tenant_id)
        # then we encrypt the "metadata" -- in this case the source text used to create the vector
        encrypted_metadata = await sdk.standard().encrypt({"text": bytes(row.metadata["text"], "utf-8")}, tenant_id)
        # update those values in place
        dataset.documents.at[row.Index, 'values'] = encrypted_vector.encrypted_vector
        dataset.documents.at[row.Index, 'metadata'] = {"text": base64.b64encode(encrypted_metadata.document["text"]).decode(), "edek": base64.b64encode(encrypted_metadata.edek).decode()}
    dataset.head()

    for batch in dataset.iter_documents(batch_size=100):
        index.upsert(batch)

    device = 'cuda' if torch.cuda.is_available() else 'cpu'
    model = SentenceTransformer('all-MiniLM-L6-v2', device=device)

    query = "which city has the highest population in the world?"
    print(f"\nQuery: {query}")
    # create the query vector
    plaintext_query = model.encode(query).tolist()
    xq = alloy.PlaintextVector(plaintext_query, "quora", "sentence")
    query_vectors = (await sdk.vector().generate_query_vectors({"vec_1": xq},tenant_id))["vec_1"]

    # now query Pinecone
    xc = index.query(vector=query_vectors[0].encrypted_vector, top_k=5, include_metadata=True)
    xc

    for result in xc['matches']:
        recreated = alloy.EncryptedDocument(base64.b64decode(result['metadata']['edek']), {"text":base64.b64decode(result['metadata']['text'])})
        decrypted = await sdk.standard().decrypt(recreated, tenant_id) # decrypt the metadata
        # we could also decrypt the vector, but it isn't returned and we don't need it
        print(f"{round(result['score'], 2)}: {decrypted['text'].decode('utf-8')}")
    
    query = "which metropolis has the highest number of people?"
    print(f"\nQuery: {query}")
    # create the query vector
    xq = alloy.PlaintextVector(model.encode(query).tolist(), "quora", "sentence")
    query_vectors = (await sdk.vector().generate_query_vectors({"vec_1": xq}, tenant_id))["vec_1"]
    # now query
    xc = index.query(vector=query_vectors[0].encrypted_vector, top_k=5, include_metadata=True)

    for result in xc['matches']:
        recreated = alloy.EncryptedDocument(base64.b64decode(result['metadata']['edek']), {"text":base64.b64decode(result['metadata']['text'])})
        decrypted = await sdk.standard().decrypt(recreated, tenant_id)
        print(f"{round(result['score'], 2)}: {decrypted['text'].decode('utf-8')}")
        
    pinecone.delete_index(index_name)

if __name__ == "__main__":
    loop = asyncio.get_event_loop()
    loop.run_until_complete(main())