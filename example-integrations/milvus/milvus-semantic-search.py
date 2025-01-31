import asyncio
import ironcore_alloy as alloy
import base64
from sentence_transformers import SentenceTransformer
import json
from urllib.request import urlopen
from pymilvus import (
    CollectionSchema,
    FieldSchema,
    DataType,
    Collection,
    utility,
    Hits,
    connections,
)


async def display_results(
    response: list[Hits],
    alloy_client: alloy.Standalone,
    metadata: alloy.AlloyMetadata,
    secret_path: str,
    derivation_path: str,
):
    # Decrypt the results and display them
    for result in response:
        recreated_question = base64.b64decode(result.entity.get("question"))  # type: ignore
        decrypted_question = await alloy_client.standard_attached().decrypt(
            recreated_question, metadata
        )
        recreated_round = alloy.EncryptedField(encrypted_field=base64.b64decode(result.entity.get("round")), secret_path=secret_path, derivation_path=derivation_path)  # type: ignore
        # We have to deterministically decrypt the round because it was deterministically encrypted earlier
        decrypted_round = await alloy_client.deterministic().decrypt(
            recreated_round, metadata
        )
        print(f"{round(result.distance, 2)}: {decrypted_question.decode()} ({decrypted_round.plaintext_field.decode()})")  # type: ignore


async def main():
    connections.connect(
        alias="default",
        uri="http://localhost:19530",
        token="root:Milvus",
    )
    collection_name = "jeopardy"
    utility.drop_collection(collection_name)
    id_field = FieldSchema(
        name="id",
        dtype=DataType.INT64,
        auto_id=True,
        is_primary=True,
    )
    question_field = FieldSchema(
        name="question", dtype=DataType.VARCHAR, max_length=10000
    )
    round_field = FieldSchema(name="round", dtype=DataType.VARCHAR, max_length=100)
    embedding = FieldSchema(name="embedding", dtype=DataType.FLOAT_VECTOR, dim=384)
    schema = CollectionSchema(
        fields=[id_field, question_field, round_field, embedding],
        description="Jeopardy Question Search",
        enable_dynamic_field=True,
    )
    collection = Collection(
        name=collection_name, schema=schema, using="default", shards_num=2
    )
    index_params = {
        "metric_type": "COSINE",
        "index_type": "IVF_FLAT",
        "params": {"nlist": 1024},
    }
    collection.create_index(field_name="embedding", index_params=index_params)
    utility.index_building_progress("jeopardy")

    # Dataset containing 1,000 Jeopardy questions and answers
    url = "https://raw.githubusercontent.com/databyjp/wv_demo_uploader/main/weaviate_datasets/data/jeopardy_1k.json"
    response = urlopen(url)
    data = json.loads(response.read())
    model = SentenceTransformer("all-MiniLM-L6-v2")

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
    deterministic_secrets = {"jeopardy": alloy.RotatableSecret(standalone_secret, None)}
    config = alloy.StandaloneConfiguration(
        standard_secrets, deterministic_secrets, vector_secrets
    )
    alloy_client = alloy.Standalone(config)
    metadata = alloy.AlloyMetadata.new_simple("tenant-one")
    secret_path = "jeopardy"
    derivation_path = "sentence"
    print("Transforming questions to vectors and encrypting them...")
    question_objs = list()

    for row in data:
        question_emb = model.encode(row["Question"]).tolist()  # type: ignore
        # each index and set of vectors is encrypted with different derived keys
        plaintext_vector = alloy.PlaintextVector(
            plaintext_vector=question_emb,
            secret_path=secret_path,
            derivation_path=derivation_path,
        )
        # Some questions contain HTML tags that muddle the results, so we'll skip inserting those ones
        if "<" in row["Question"]:
            continue
        # Encrypt the vector, the question itself, and the round
        # The round is deterministically encrypted so that we can filter on it later
        (encrypted_vector, encrypted_question, encrypted_round) = await asyncio.gather(
            alloy_client.vector().encrypt(plaintext_vector, metadata),
            alloy_client.standard_attached().encrypt(
                bytes(row["Question"], "utf-8"), metadata
            ),
            alloy_client.deterministic().encrypt(
                alloy.PlaintextField(
                    plaintext_field=bytes(row["Round"], "utf-8"),
                    secret_path=secret_path,
                    derivation_path=derivation_path,
                ),
                metadata,
            ),
        )
        question_objs.append(
            {
                "question": base64.b64encode(encrypted_question).decode(),
                "round": base64.b64encode(encrypted_round.encrypted_field).decode(),
                "embedding": encrypted_vector.encrypted_vector,
            }
        )
    print(f"Inserting {len(question_objs)} encrypted questions.")
    collection.insert(question_objs)

    query = "biology"
    print(f"\nQuerying database with input: '{query}'")

    # Create the query embedding
    query_emb = model.encode(query).tolist()  # type: ignore
    plaintext_query = alloy.PlaintextVector(
        plaintext_vector=query_emb,
        secret_path=secret_path,
        derivation_path=derivation_path,
    )
    # `generate_query_vectors` returns a list because the secret involved may be in rotation. In that case you should
    # search for both resulting vectors.
    query_vector = (
        await alloy_client.vector().generate_query_vectors(
            {"vec_1": plaintext_query}, metadata
        )
    )["vec_1"][0].encrypted_vector

    collection.load()
    search_params = {
        "metric_type": "COSINE",
        "offset": 0,
        "ignore_growing": False,
        "params": {"nprobe": 10},
    }
    response = collection.search(
        data=[query_vector],
        anns_field="embedding",
        param=search_params,
        limit=5,
        output_fields=["question", "round"],
    )
    await display_results(
        response[0], alloy_client, metadata, secret_path, derivation_path
    )

    print("\nQuerying again, this time only for Double Jeopardy questions.")
    # Now we'll query a second time, only returning answers from the Double Jeopardy round
    round_filter = await alloy_client.deterministic().encrypt(
        alloy.PlaintextField(
            plaintext_field=bytes("Double Jeopardy!", "utf-8"),
            secret_path=secret_path,
            derivation_path=derivation_path,
        ),
        metadata,
    )
    encoded_round_filter = base64.b64encode(round_filter.encrypted_field).decode()
    response = collection.search(
        data=[query_vector],
        anns_field="embedding",
        param=search_params,
        limit=5,
        expr=f"round == '{encoded_round_filter}'",
        output_fields=["question", "round"],
    )
    await display_results(
        response[0], alloy_client, metadata, secret_path, derivation_path
    )

    collection.release()


if __name__ == "__main__":
    loop = asyncio.get_event_loop()
    loop.run_until_complete(main())
