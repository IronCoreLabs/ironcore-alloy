# PREREQUISITE:
#   Start up Weaviate locally as described on the [Docker Compose](https://weaviate.io/developers/weaviate/installation/docker-compose)
#   installation guide.
# DEPENDENCIES:
#   `pip install -U weaviate_client sentence_transformers ironcore-alloy`
# REFERENCES:
#   This is based on the Weaviate [Bring your own vectors](https://weaviate.io/developers/weaviate/starter-guides/custom-vectors) starter guide.

import asyncio
import weaviate
import ironcore_alloy as alloy
import base64
from sentence_transformers import SentenceTransformer
import json
import weaviate.classes as wvc
from urllib.request import urlopen


async def main():
    # anonymous, authentication is enabled.
    client = weaviate.connect_to_local()

    # Dataset containing 1,000 Jeopardy questions and answers
    url = "https://raw.githubusercontent.com/databyjp/wv_demo_uploader/main/weaviate_datasets/data/jeopardy_1k.json"
    response = urlopen(url)
    data = json.loads(response.read())

    model = SentenceTransformer("all-MiniLM-L6-v2")

    class_name = "Jeopardy"

    # Delete the collection if it exists from a previous run
    client.collections.delete(class_name)

    # Create the collection
    # We set the vectorizer to none because we'll be providing vectors, not text
    questions = client.collections.create(
        class_name,
        vectorizer_config=wvc.config.Configure.Vectorizer.none(),
    )

    # Note: in practice this must be 32 cryptographically-secure bytes
    key_bytes = b"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
    standalone_secret = alloy.StandaloneSecret(1, alloy.Secret(key_bytes))
    approximation_factor = 2.5
    vector_secrets = {
        "jeopardy": alloy.VectorSecret(
            approximation_factor,
            alloy.RotatableSecret(standalone_secret, None),
        )
    }
    standard_secrets = alloy.StandardSecrets(1, [standalone_secret])
    deterministic_secrets = {}
    config = alloy.StandaloneConfiguration(
        standard_secrets, deterministic_secrets, vector_secrets
    )
    alloy_client = alloy.Standalone(config)

    tenant_id = alloy.AlloyMetadata.new_simple("tenant-one")

    print("Transforming questions to vectors and encrypting them...")
    question_objs = list()
    for row in data:
        question_emb = model.encode(row["Question"]).tolist()  # type: ignore
        # each index and set of vectors is encrypted with different derived keys
        plaintext_vector = alloy.PlaintextVector(question_emb, "jeopardy", "sentence")
        # Some questions contain HTML tags that muddle the results, so we'll skip inserting those ones
        if "<" in row["Question"]:
            continue
        # Encrypt both the vector and the question itself
        (encrypted_vector, encrypted_metadata) = await asyncio.gather(
            alloy_client.vector().encrypt(plaintext_vector, tenant_id),
            alloy_client.standard_attached().encrypt(
                bytes(row["Question"], "utf-8"), tenant_id
            ),
        )
        question_objs.append(
            wvc.data.DataObject(
                properties={
                    "question": base64.b64encode(encrypted_metadata).decode(),
                },
                vector=encrypted_vector.encrypted_vector,
            )
        )

    print(f"Inserting {len(question_objs)} encrypted questions.")
    # Insert the properties and vectors to Weaviate
    questions.data.insert_many(question_objs)

    query = "biology"
    print(f"Querying database with input: '{query}'")

    # Create the query embedding
    query_emb = model.encode(query).tolist()  # type: ignore
    plaintext_query = alloy.PlaintextVector(query_emb, "jeopardy", "sentence")
    # `generate_query_vectors` returns a list because the secret involved may be in rotation. In that case you should
    # search for both resulting vectors. Weaviate currently doesn't support searching over multiple vectors. A workaround is
    # searching for each separately and combining them in the client.
    # Because our secret isn't in rotation, we can just use the first entry in the list.
    query_vector = (
        await alloy_client.vector().generate_query_vectors(
            {"vec_1": plaintext_query}, tenant_id
        )
    )["vec_1"][0].encrypted_vector

    # Query Weaviate, returning the top 5 encrypted questions and their certainties
    response = questions.query.near_vector(
        near_vector=query_vector,
        limit=5,
        return_metadata=wvc.query.MetadataQuery(certainty=True),
        return_properties=["question"],
    )

    # Decrypt the results and display them
    for result in response.objects:
        recreated = base64.b64decode(result.properties["question"])  # type: ignore
        decrypted = await alloy_client.standard_attached().decrypt(recreated, tenant_id)
        print(f"{round(result.metadata.certainty, 2)}: {decrypted.decode()}")  # type: ignore

    client.close()


if __name__ == "__main__":
    loop = asyncio.get_event_loop()
    loop.run_until_complete(main())