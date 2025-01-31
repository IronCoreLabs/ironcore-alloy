from sentence_transformers import SentenceTransformer
from elasticsearch import Elasticsearch
import ironcore_alloy as alloy
import json
from urllib.request import urlopen
import asyncio


def pretty_response(response):
    if len(response["hits"]["hits"]) == 0:
        print("Your search returned no results.")
    else:
        for hit in response["hits"]["hits"]:
            id = hit["_id"]
            publication_date = hit["_source"]["publish_date"]
            title = hit["_source"]["title"]
            summary = hit["_source"]["summary"]
            publisher = hit["_source"]["publisher"]
            pretty_output = f"\nID: {id}\nPublication date: {publication_date}\nTitle: {title}\nPublisher: {publisher}\nSummary: {summary}"
            print(pretty_output)


def pretty_encrypted_response(response):
    if len(response["hits"]["hits"]) == 0:
        print("Your search returned no results.")
    else:
        for hit in response["hits"]["hits"]:
            id = hit["_id"]
            publication_date = hit["_source"]["publish_date"]
            title = hit["_source"]["_icl_p_title"]
            summary = hit["_source"]["_icl_p_summary"]
            publisher = hit["_source"]["_icl_p_publisher"]
            pretty_output = f"\nID: {id}\nPublication date: {publication_date}\nTitle: {title}\nPublisher: {publisher}\nSummary: {summary}"
            print(pretty_output)


async def main():
    # Setup the embedding model
    model = SentenceTransformer("all-MiniLM-L6-v2")

    # Initialize the Elasticsearch client
    client = Elasticsearch(hosts=["http://localhost:8675"])

    # Initialize the IronCore Cloaked AI standalone client
    tenant_id = "tenant-one"
    # Note: in practice this must be 32 cryptographically-secure bytes
    key_bytes_1 = b"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
    approximation_factor = 2.5
    vector_secrets = {
        "book_index": alloy.VectorSecret(
            approximation_factor,
            alloy.RotatableSecret(
                alloy.StandaloneSecret(1, alloy.Secret(key_bytes_1)), None
            ),
        )
    }
    standard_secrets = alloy.StandardSecrets(None, [])
    deterministic_secrets = {}
    config = alloy.StandaloneConfiguration(
        standard_secrets, deterministic_secrets, vector_secrets
    )
    sdk = alloy.Standalone(config)

    # Use the book_index that elasticsearch uses in their example. First make sure `book_index` doesn't exist.
    client.indices.delete(index="book_index", ignore_unavailable=True)

    # Define a mapping with a title embedding
    mappings = {
        "properties": {
            "title_vector": {
                "type": "dense_vector",
                "dims": 384,
                "index": "true",
                "similarity": "cosine",
            }
        }
    }

    # Create the book index
    client.indices.create(index="book_index", mappings=mappings)

    # Index the book data
    url = "https://raw.githubusercontent.com/elastic/elasticsearch-labs/main/notebooks/search/data.json"
    response = urlopen(url)
    books = json.loads(response.read())

    operations = []
    metadata = alloy.AlloyMetadata.new_simple(tenant_id)
    for book in books:
        # Transforming the title into an embedding using the model
        title_embedding = model.encode(book["title"]).tolist()
        # Encrypt the title embedding with IronCore Labs' Cloaked AI
        encrypted_title_embedding = await sdk.vector().encrypt(
            alloy.PlaintextVector(
                plaintext_vector=title_embedding,
                secret_path="book_index",
                derivation_path="",
            ),
            metadata,
        )
        operations.append({"index": {"_index": "book_index"}})
        book["title_vector"] = encrypted_title_embedding.encrypted_vector
        book["tenant_id"] = tenant_id
        operations.append(book)
    bulk_resp = client.bulk(index="book_index", operations=operations, refresh=True)

    # Run a hybrid query
    title_query_embedding = model.encode("python programming").tolist()
    # `generate_query_vectors` returns a list because the secret involved may be in rotation. In that case you should
    # search for both resulting vectors. Elasticsearch [doesn't explicitly support multiple vectors](https://discuss.elastic.co/t/run-multi-vectors-knn-search/299958/2) yet. Two workarounds are
    # searching for each separately and combining them in the client or boolean ANDing the knn query for the same field twice (which is what we've done here).
    encrypted_title_query_embeddings = await sdk.vector().generate_query_vectors(
        {
            "title": alloy.PlaintextVector(
                plaintext_vector=title_query_embedding,
                secret_path="book_index",
                derivation_path="",
            )
        },
        metadata,
    )
    embedding_queries = [
        {
            "knn": {
                "field": "title_vector",
                "query_vector": title_embedding.encrypted_vector,
                "num_candidates": 10,
                "boost": 2.0,
            }
        }
        for title_embedding in encrypted_title_query_embeddings["title"]
    ]
    # Better results can be attained by tweaking the `boost` on the `knn` query so the distances become more relevant to the combined search.
    # Even better is using a top level `knn` query (as a neighbor of `knn`) with RRF ranking enabled (requires Elasticsearch Platinum or Enterprise).
    response = client.search(
        index="book_index",
        size=5,
        query={
            "bool": {
                "filter": {"term": {"tenant_id.keyword": tenant_id}},
                "should": [
                    {"match": {"summary": "python programming"}},
                ]
                + embedding_queries,
            }
        },
    )

    # Response through Cloaked Search with all results decrypted
    pretty_response(response)

    # Take a look at the elasticsearch index directly to see what an over-curious admin or someone who exfiltrated
    # the index would see.
    document_ids = [r["_id"] for r in response["hits"]["hits"]]
    bypass_client = Elasticsearch(hosts=["http://localhost:9200"])
    bypass_response = bypass_client.search(
        index="book_index", size=5, query={"terms": {"_id": document_ids}}
    )

    pretty_encrypted_response(bypass_response)


asyncio.run(main())
