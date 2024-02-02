# Elasticsearch integration example

This example is based on the Elasticsearch Jupyter notebooks [quick-start](https://github.com/elastic/elasticsearch-labs/blob/main/notebooks/search/00-quick-start.ipynb)
and [hybrid-search](https://colab.research.google.com/github/elastic/elasticsearch-labs/blob/main/notebooks/search/02-hybrid-search.ipynb).
It shows how to integrate both Cloaked AI and Cloaked Search with Elasticsearch.

Starting with a dataset of books, this example:

- Transforms the book titles into vector embeddings using the `all-MiniLM-L6-v2` model
- Uses Cloaked AI to encrypt the embeddings
- Indexes the books into Elasticsearch through Cloaked Search
    - Each book's summary, publisher, and title are automatically encrypted before indexing
- Transforms a text query into a vector embedding
- Encrypts the query embedding
- Queries Elasticsearch through Cloaked Search for relevant results combining `knn` search with a text `match` search
    - Each book's summary, publisher, and title are automatically decrypted when querying
- Queries Elasticsearch directly to show each book's encrypted tokens stored in the database

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
docker-compose -f elasticsearch/docker-compose.yml up -d
```

4. Run the example:

```
hatch shell
python elasticsearch-cloaked-hybrid-search.py
```

## Sample output through Cloaked Search

```
ID: Nu3ua40B3sc3zumz9Ud-
Publication date: 2019-05-03
Title: Python Crash Course
Publisher: no starch press
Summary: A fast-paced, no-nonsense guide to programming in Python

ID: Ne3ua40B3sc3zumz9Ud8
Publication date: 2019-10-29
Title: The Pragmatic Programmer: Your Journey to Mastery
Publisher: addison-wesley
Summary: A guide to pragmatic programming for software engineers and developers

ID: Ou3ua40B3sc3zumz9Ud-
Publication date: 2018-12-04
Title: Eloquent JavaScript
Publisher: no starch press
Summary: A modern introduction to programming

ID: Oe3ua40B3sc3zumz9Ud-
Publication date: 2015-03-27
Title: You Don't Know JS: Up & Going
Publisher: oreilly
Summary: Introduction to JavaScript and programming as a whole

ID: Pu3ua40B3sc3zumz9Ud-
Publication date: 2012-06-27
Title: Introduction to the Theory of Computation
Publisher: cengage learning
Summary: Introduction to the theory of computation and complexity theory
```

## Sample output through Elasticsearch directly

```
ID: Ne3ua40B3sc3zumz9Ud8
Publication date: 2019-10-29
Title: ca8e89c7 1688797c fc7a6114 32d4b16c a4acc8f1 548291a5 92cafafc
Publisher: 32bf2837 8c8667b3
Summary: 5bf4d0fa 185ebb23 3b07cc3 8f65c6f2 1efc1699 e88dfce6 b4c8f372 b6c9e8f1 315770f2 41fcf8de

ID: Nu3ua40B3sc3zumz9Ud-
Publication date: 2019-05-03
Title: dde900e4 c9231a15 758c4e8d
Publisher: fba4fa11 836c2d3 854f9e52
Summary: 344eff27 8f65c6f2 8ddba080 c0c32b9f 757f5077 b6c9e8f1 ad79819 1efc1699 b4c8f372 31d9c5e9

ID: Oe3ua40B3sc3zumz9Ud-
Publication date: 2015-03-27
Title: 1ccac6c 1807fe44 75629c5b cf1ad8e6 3773ec4a eb8aca2
Publisher: 13a660aa
Summary: 5bf4d0fa 8f65c6f2 c5e67ee4 b4c8f372 b6c9e8f1 c7763222 29f3cb15 27356f39

ID: Ou3ua40B3sc3zumz9Ud-
Publication date: 2018-12-04
Title: 97da4c51 c7bfc0b1
Publisher: fba4fa11 854f9e52 836c2d3
Summary: b6c9e8f1 8f65c6f2 b4c8f372 7800ad6a c7763222

ID: Pu3ua40B3sc3zumz9Ud-
Publication date: 2012-06-27
Title: ca8e89c7 5f9ae8b3 418b5a90 666686cf 32d4b16c 91c0a6c
Publisher: b5e919b5 a8cb2030
Summary: 5bf4d0fa 4afe5723 f62f2efb c7763222 684bdbc7 25de61e8 b4c8f372 ebf02d00
```