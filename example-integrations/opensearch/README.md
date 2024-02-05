# OpenSearch integration example

This example shows how to integrate both Cloaked AI and Cloaked Search with OpenSearch. It uses [approximate kNN](https://opensearch.org/docs/latest/search-plugins/knn/approximate-knn/). The `hybrid` and `neural` query types aren't supported by Cloaked Search yet.

Starting with a dataset of books, this example:

- Transforms the book titles into vector embeddings using the `all-MiniLM-L6-v2` model
- Uses Cloaked AI to encrypt the embeddings
- Indexes the books into OpenSearch through Cloaked Search
    - Each book's summary, publisher, and title are automatically encrypted before indexing
- Transforms a text query into a vector embedding
- Encrypts the query embedding
- Queries OpenSearch through Cloaked Search for relevant results combining `knn` search with a text `match` search
    - Each book's summary, publisher, and title are automatically decrypted when querying
- Queries OpenSearch directly to show each book's encrypted tokens stored in the database

## Running the example

1. Check out [try-cloaked-search](https://ironcorelabs.com/docs/cloaked-search/try-cloaked-search/) for an easy starting point running Cloaked Search.

2. In `try-cloaked-search` create a file `indices/book_index.json` with this index configuration so that Cloaked Search protects the text of the document.

```json
{
  "tenant_id_index_field": "tenant_id",
  "tenant_id_search_field": "tenant_id.keyword",
  "mappings": {
    "properties": {
      "summary": {
        "type": "text"
      },
      "publisher": {
        "type": "text"
      },
      "title": {
        "type": "text"
      }
    }
  }
}
```

3. Start up `try-cloaked-search`:

```
docker-compose -f open-search/docker-compose.yml up -d
```

4. Run the example:

```
hatch shell
python opensearch-cloaked-hybrid-search.py
```

## Sample output through Cloaked Search

```
ID: tZ8CbI0Bpyo8kheN7bgE
Publication date: 2019-05-03
Title: Python Crash Course
Publisher: no starch press
Summary: A fast-paced, no-nonsense guide to programming in Python

ID: uZ8CbI0Bpyo8kheN7bgE
Publication date: 2018-12-04
Title: Eloquent JavaScript
Publisher: no starch press
Summary: A modern introduction to programming

ID: uJ8CbI0Bpyo8kheN7bgE
Publication date: 2015-03-27
Title: You Don't Know JS: Up & Going
Publisher: oreilly
Summary: Introduction to JavaScript and programming as a whole

ID: tJ8CbI0Bpyo8kheN7bgD
Publication date: 2019-10-29
Title: The Pragmatic Programmer: Your Journey to Mastery
Publisher: addison-wesley
Summary: A guide to pragmatic programming for software engineers and developers

ID: vZ8CbI0Bpyo8kheN7bgF
Publication date: 2012-06-27
Title: Introduction to the Theory of Computation
Publisher: cengage learning
Summary: Introduction to the theory of computation and complexity theory
```

## Sample output through OpenSearch directly

```
ID: tJ8CbI0Bpyo8kheN7bgD
Publication date: 2019-10-29
Title: 1688797c 32d4b16c a4acc8f1 fc7a6114 548291a5 92cafafc ca8e89c7
Publisher: 8c8667b3 32bf2837
Summary: b6c9e8f1 3b07cc3 1efc1699 b4c8f372 e88dfce6 5bf4d0fa 185ebb23 315770f2 41fcf8de 8f65c6f2

ID: tZ8CbI0Bpyo8kheN7bgE
Publication date: 2019-05-03
Title: 758c4e8d dde900e4 c9231a15
Publisher: fba4fa11 836c2d3 854f9e52
Summary: 8f65c6f2 31d9c5e9 b4c8f372 344eff27 1efc1699 8ddba080 757f5077 c0c32b9f ad79819 b6c9e8f1

ID: uJ8CbI0Bpyo8kheN7bgE
Publication date: 2015-03-27
Title: cf1ad8e6 3773ec4a 1ccac6c 75629c5b eb8aca2 1807fe44
Publisher: 13a660aa
Summary: c5e67ee4 27356f39 8f65c6f2 b4c8f372 29f3cb15 b6c9e8f1 5bf4d0fa c7763222

ID: uZ8CbI0Bpyo8kheN7bgE
Publication date: 2018-12-04
Title: c7bfc0b1 97da4c51
Publisher: fba4fa11 836c2d3 854f9e52
Summary: 8f65c6f2 c7763222 b6c9e8f1 7800ad6a b4c8f372

ID: vZ8CbI0Bpyo8kheN7bgF
Publication date: 2012-06-27
Title: 666686cf 418b5a90 ca8e89c7 5f9ae8b3 91c0a6c 32d4b16c
Publisher: a8cb2030 b5e919b5
Summary: 5bf4d0fa b4c8f372 ebf02d00 4afe5723 25de61e8 f62f2efb 684bdbc7 c7763222
```