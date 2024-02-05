from sentence_transformers import SentenceTransformer
from opensearchpy import OpenSearch
import ironcore_alloy as alloy
import json
from urllib.request import urlopen
import asyncio


def pretty_response(response):
    if len(response["hits"]["hits"]) == 0:
        print("\nYour search returned no results.")
    else:
        print("\n#### Cloaked Search Response: ####")
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
        print("\nYour search returned no results.")
    else:
        print("\n#### OpenSearch Direct Response: ####")
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

    # Initialize the OpenSearch client
    client = OpenSearch(
        hosts=[{"host": "localhost", "port": 8675}],
        use_ssl=False,
        verify_certs=False,
        ssl_assert_hostname=False,
        ssl_show_warn=False,
    )

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

    # First make sure `book_index` doesn't exist.
    client.indices.delete(index="book_index", ignore_unavailable=True)

    # Define a mapping with a title embedding
    index_definition = {
        "settings": {"index": {"knn": True, "knn.algo_param.ef_search": 100}},
        "mappings": {
            "properties": {
                "title_vector": {
                    "type": "knn_vector",
                    "dimension": 384,
                    "method": {"name": "hnsw"},
                }
            }
        },
    }

    # Create the book index
    client.indices.create(index="book_index", body=index_definition)

    # Index book data
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
            alloy.PlaintextVector(title_embedding, "book_index", ""), metadata
        )
        operations.append({"index": {"_index": "book_index"}})
        book["title_vector"] = encrypted_title_embedding.encrypted_vector
        book["tenant_id"] = tenant_id
        operations.append(book)
    bulk_resp = client.bulk("\n".join(map(json.dumps, operations)), refresh=True)

    # Run a hybrid query
    title_query_embedding = model.encode("python programming").tolist()
    # `generate_query_vectors` returns a list because the secret involved may be in rotation.
    encrypted_title_query_embeddings = await sdk.vector().generate_query_vectors(
        {"title": alloy.PlaintextVector(title_query_embedding, "book_index", "")},
        metadata,
    )
    embedding_queries = [
        {"knn": {"title_vector": {"vector": title_embedding.encrypted_vector, "k": 5}}}
        for title_embedding in encrypted_title_query_embeddings["title"]
    ]
    search_query = {
        "size": 5,
        "query": {
            "bool": {
                "filter": {"term": {"tenant_id.keyword": tenant_id}},
                "should": [
                    {"match": {"summary": "python programming"}},
                ]
                + embedding_queries,
            }
        },
    }
    response = client.search(index="book_index", body=search_query)
    # Response through Cloaked Search with all results decrypted
    pretty_response(response)

    # Take a look at the OpenSearch index directly to see what an over-curious admin or someone who exfiltrated
    # the index would see.
    document_ids = [r["_id"] for r in response["hits"]["hits"]]
    bypass_client = OpenSearch(
        hosts=[{"host": "localhost", "port": 9200}],
        use_ssl=False,
        verify_certs=False,
        ssl_assert_hostname=False,
        ssl_show_warn=False,
    )
    bypass_response = bypass_client.search(
        index="book_index", body={"size": 5, "query": {"terms": {"_id": document_ids}}}
    )

    pretty_encrypted_response(bypass_response)


asyncio.run(main())
