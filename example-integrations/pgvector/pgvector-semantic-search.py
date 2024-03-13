import asyncio
import ironcore_alloy as alloy
import base64
from sentence_transformers import SentenceTransformer
import asyncpg
import json
from pgvector.asyncpg import register_vector
from urllib.request import urlopen


async def display_results(
    response: list[asyncpg.Record],
    alloy_client: alloy.Standalone,
    metadata: alloy.AlloyMetadata,
    secret_path: str,
    derivation_path: str,
):
    # Decrypt the results and display them
    for result in response:
        question, round_str, certainty = result[0]
        recreated_question = base64.b64decode(question)  # type: ignore
        decrypted_question = await alloy_client.standard_attached().decrypt(
            recreated_question, metadata
        )
        recreated_round = alloy.EncryptedField(base64.b64decode(round_str), secret_path, derivation_path)  # type: ignore
        # We have to deterministically decrypt the round because it was deterministically encrypted earlier
        decrypted_round = await alloy_client.deterministic().decrypt(
            recreated_round, metadata
        )
        print(f"{round(certainty, 2)}: {decrypted_question.decode()} ({decrypted_round.plaintext_field.decode()})")  # type: ignore


async def main():
    conn = await asyncpg.connect("postgresql://postgres@localhost:8888/postgres")
    await conn.execute("CREATE EXTENSION IF NOT EXISTS vector")
    await register_vector(conn)
    await conn.execute("DROP TABLE IF EXISTS questions")
    await conn.execute(
        "CREATE TABLE questions (id bigserial PRIMARY KEY, question TEXT, round TEXT, embedding vector(384))"
    )
    await conn.execute("CREATE INDEX ON questions USING hnsw (embedding vector_l2_ops)")

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
            question_emb, secret_path, derivation_path
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
                    bytes(row["Round"], "utf-8"), secret_path, derivation_path
                ),
                metadata,
            ),
        )
        question_objs.append(
            [
                base64.b64encode(encrypted_question).decode(),
                base64.b64encode(encrypted_round.encrypted_field).decode(),
                encrypted_vector.encrypted_vector,
            ]
        )

    print(f"Inserting {len(question_objs)} encrypted questions.")
    await conn.executemany(
        "INSERT INTO questions (question, round, embedding) VALUES ($1, $2, $3)",
        question_objs,
    )

    query = "biology"
    print(f"\nQuerying database with input: '{query}'")

    # Create the query embedding
    query_emb = model.encode(query).tolist()  # type: ignore
    plaintext_query = alloy.PlaintextVector(query_emb, secret_path, derivation_path)
    # `generate_query_vectors` returns a list because the secret involved may be in rotation. In that case you should
    # search for both resulting vectors.
    query_vector = (
        await alloy_client.vector().generate_query_vectors(
            {"vec_1": plaintext_query}, metadata
        )
    )["vec_1"][0].encrypted_vector

    response = await conn.fetch(
        "SELECT (question, round, 1 - (embedding <=> $1)) FROM questions ORDER BY embedding <=> $1 LIMIT 5",
        query_vector,
    )
    await display_results(
        response, alloy_client, metadata, secret_path, derivation_path
    )

    print("\nQuerying again, this time only for Double Jeopardy questions.")
    # Now we'll query a second time, only returning answers from the Double Jeopardy round
    round_filter = await alloy_client.deterministic().encrypt(
        alloy.PlaintextField(
            bytes("Double Jeopardy!", "utf-8"), secret_path, derivation_path
        ),
        metadata,
    )
    encoded_round_filter = base64.b64encode(round_filter.encrypted_field).decode()
    response = await conn.fetch(
        "SELECT (question, round, 1 - (embedding <=> $1)) FROM questions WHERE round = $2 ORDER BY embedding <=> $1 LIMIT 5",
        query_vector,
        encoded_round_filter,
    )
    await display_results(
        response, alloy_client, metadata, secret_path, derivation_path
    )

    # Close the connection.
    await conn.close()


if __name__ == "__main__":
    loop = asyncio.get_event_loop()
    loop.run_until_complete(main())
