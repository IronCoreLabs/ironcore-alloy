# PREREQUISITE:
#   Start up elasticsearch with cloaked search as shown in our
#   [try-cloaked-search](https://ironcorelabs.com/docs/cloaked-search/try-cloaked-search/) example.
#   No need to populate or create an index yet, we'll do that as part of this process.
# DEPENDENCIES:
#   `pip install elasticsearch sentence_transformers ironcore-alloy`
# REFERENCES:
#   This is based on the elasticsearch jupyter notebooks [quick-start](https://github.com/elastic/elasticsearch-labs/blob/main/notebooks/search/00-quick-start.ipynb)
#   and [hybrid-search](https://colab.research.google.com/github/elastic/elasticsearch-labs/blob/main/notebooks/search/02-hybrid-search.ipynb).

# IMPORTS
from sentence_transformers import SentenceTransformer
from elasticsearch import Elasticsearch
import ironcore_alloy as alloy
import json
from urllib.request import urlopen
import asyncio

import logging


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

    # Create the IndexError
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
            alloy.PlaintextVector(title_embedding, "book_index", ""), metadata
        )
        operations.append({"index": {"_index": "book_index"}})
        book["title_vector"] = encrypted_title_embedding.encrypted_vector
        book["tenant_id"] = tenant_id
        operations.append(book)
    bulk_resp = client.bulk(index="book_index", operations=operations, refresh=True)

    # Run a hybrid query
    title_query_embedding = model.encode("python programming").tolist()
    # `generate_query_vectors` returns a list because the secret involved may be in rotation. In that case you should
    # search for both resulting vectors. Elasticsearch [doesn't support multiple vectors](https://discuss.elastic.co/t/run-multi-vectors-knn-search/299958/2) yet. Two workarounds are
    # searching for each separately and combining them in the client or possibly boolean ANDing the knn query for the same field twice.
    encrypted_title_query_embeddings = await sdk.vector().generate_query_vectors(
        {"title": alloy.PlaintextVector(title_query_embedding, "book_index", "")},
        metadata,
    )
    response = client.search(
        index="book_index",
        size=5,
        query={
            "bool": {
                "filter": {"term": {"tenant_id.keyword": tenant_id}},
                "should": [
                    {"match": {"summary": "python programming"}},
                    {
                        "knn": {
                            "field": "title_vector",
                            "query_vector": encrypted_title_query_embeddings["title"][
                                0
                            ].encrypted_vector,
                            "num_candidates": 10,
                        }
                    },
                ],
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


# Example response:
#
# ID: UxAnQo0BlFbaZBbWjkzE
# Publication date: 2019-05-03
# Title: Python Crash Course
# Summary: A fast-paced, no-nonsense guide to programming in Python

# ID: VxAnQo0BlFbaZBbWjkzE
# Publication date: 2018-12-04
# Title: Eloquent JavaScript
# Summary: A modern introduction to programming

# ID: UhAnQo0BlFbaZBbWjkzE
# Publication date: 2019-10-29
# Title: The Pragmatic Programmer: Your Journey to Mastery
# Summary: A guide to pragmatic programming for software engineers and developers

# ID: VhAnQo0BlFbaZBbWjkzE
# Publication date: 2015-03-27
# Title: You Don't Know JS: Up & Going
# Summary: Introduction to JavaScript and programming as a whole

# ID: WRAnQo0BlFbaZBbWjkzE
# Publication date: 2011-05-13
# Title: The Clean Coder: A Code of Conduct for Professional Programmers
# Summary: A guide to professional conduct in the field of software engineering

# Example bypass document
# ID: UhAnQo0BlFbaZBbWjkzE
# Publication date: 2019-10-29
# Title: 32d4b16c 548291a5 ca8e89c7 1688797c fc7a6114 92cafafc a4acc8f1
# Summary: 185ebb23 8f65c6f2 1efc1699 b4c8f372 e88dfce6 b6c9e8f1 315770f2 5bf4d0fa 3b07cc3 41fcf8de
