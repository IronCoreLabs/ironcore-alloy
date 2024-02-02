# PREREQUISITE:
#   Start up OpenSearch with cloaked search as shown in our
#   [try-cloaked-search](https://ironcorelabs.com/docs/cloaked-search/try-cloaked-search/) example.
#   No need to populate or create an index yet, we'll do that as part of this process.
# DEPENDENCIES:
#   `pip install opensearch-py sentence_transformers ironcore-alloy`
# REFERENCES:
#   This uses [approximate kNN](https://opensearch.org/docs/latest/search-plugins/knn/approximate-knn/) and documentation.
#   The `hybrid` and `neural` query types aren't supported by Cloaked Search yet.

# IMPORTS
from sentence_transformers import SentenceTransformer
from opensearchpy import OpenSearch
import ironcore_alloy as alloy
import json
from urllib.request import urlopen
import asyncio

import logging


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

    # In `try-cloaked-search` create an `indices/book_index.json` to this index configuration so
    # IronCore Labs' Cloaked Search protects the text of the document.
    # {
    #   "tenant_id_index_field": "tenant_id",
    #   "tenant_id_search_field": "tenant_id.keyword",
    #   "mappings": {
    #     "properties": {
    #       "summary": {
    #         "type": "text"
    #       },
    #       "publisher": {
    #         "type": "text"
    #       },
    #       "title": {
    #         "type": "text"
    #       }
    #     }
    #   }
    # }

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


#### Cloaked Search Response ####
# ID: 7beZW40B2fCVUOIdvs_x
# Publication date: 2019-05-03
# Title: Python Crash Course
# Publisher: no starch press
# Summary: A fast-paced, no-nonsense guide to programming in Python

# ID: 8beZW40B2fCVUOIdvs_x
# Publication date: 2018-12-04
# Title: Eloquent JavaScript
# Publisher: no starch press
# Summary: A modern introduction to programming

# ID: 8LeZW40B2fCVUOIdvs_x
# Publication date: 2015-03-27
# Title: You Don't Know JS: Up & Going
# Publisher: oreilly
# Summary: Introduction to JavaScript and programming as a whole

# ID: 7LeZW40B2fCVUOIdvs_x
# Publication date: 2019-10-29
# Title: The Pragmatic Programmer: Your Journey to Mastery
# Publisher: addison-wesley
# Summary: A guide to pragmatic programming for software engineers and developers

# ID: 9beZW40B2fCVUOIdvs_y
# Publication date: 2012-06-27
# Title: Introduction to the Theory of Computation
# Publisher: cengage learning
# Summary: Introduction to the theory of computation and complexity theory

#### OpenSearch Direct Response ####
# ID: 7LeZW40B2fCVUOIdvs_x
# Publication date: 2019-10-29
# Title: fc7a6114 92cafafc 32d4b16c a4acc8f1 548291a5 ca8e89c7 1688797c
# Publisher: 8c8667b3 32bf2837
# Summary: 315770f2 8f65c6f2 b6c9e8f1 1efc1699 e88dfce6 41fcf8de 5bf4d0fa 185ebb23 3b07cc3 b4c8f372

# ID: 7beZW40B2fCVUOIdvs_x
# Publication date: 2019-05-03
# Title: 758c4e8d dde900e4 c9231a15
# Publisher: 854f9e52 fba4fa11 836c2d3
# Summary: c0c32b9f b6c9e8f1 344eff27 757f5077 ad79819 1efc1699 8ddba080 8f65c6f2 b4c8f372 31d9c5e9

# ID: 8LeZW40B2fCVUOIdvs_x
# Publication date: 2015-03-27
# Title: 3773ec4a 75629c5b 1ccac6c eb8aca2 1807fe44 cf1ad8e6
# Publisher: 13a660aa
# Summary: c7763222 5bf4d0fa 29f3cb15 8f65c6f2 b4c8f372 b6c9e8f1 c5e67ee4 27356f39

# ID: 8beZW40B2fCVUOIdvs_x
# Publication date: 2018-12-04
# Title: 97da4c51 c7bfc0b1
# Publisher: fba4fa11 854f9e52 836c2d3
# Summary: b4c8f372 7800ad6a c7763222 8f65c6f2 b6c9e8f1

# ID: 9beZW40B2fCVUOIdvs_y
# Publication date: 2012-06-27
# Title: 666686cf 32d4b16c ca8e89c7 5f9ae8b3 91c0a6c 418b5a90
# Publisher: b5e919b5 a8cb2030
# Summary: c7763222 f62f2efb 25de61e8 684bdbc7 ebf02d00 4afe5723 b4c8f372 5bf4d0fa
