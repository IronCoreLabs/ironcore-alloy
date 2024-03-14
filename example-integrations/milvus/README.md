# Milvus integration example

Starting with a dataset of Jeopardy questions, this example:

- Transforms the questions into vector embeddings using the `all-MiniLM-L6-v2` model
- Uses Cloaked AI to encrypt the embeddings, the text questions themselves, and the round
    - The round is encrypted deterministically so that it can be used in a query
- Inserts the encrypted embeddings and encrypted questions and rounds into Milvus
- Transforms a text query into a vector embedding
- Encrypts the query embedding
- Queries Milvus for relevant results
- Decrypts the original text and round from the returned result
- Queries Milvus again, this time filtering results to a specific round
- Decrypts the original text and round from the returned result

## Running the example

Start up Milvus locally:

```
docker compose up -d
```

Ensure that `http://localhost:9091/healthz` reports OK, then run the example:

```
hatch shell
python milvus-semantic-search.py
```

Note: If you receive the error message `Fail connecting to server on localhost:19530, illegal connection params or server unavailable`,
this often means that the Milvus server hasn't finished started up. Check the health endpoint `http://localhost:9091/healthz` then
re-run the example.

## Sample output

```
Transforming questions to vectors and encrypting them...
Inserting 981 encrypted questions.

Querying database with input: 'biology'
0.28: They're the tiny threadlike structures that carry the genes - you have 23 pairs (Double Jeopardy!)
0.28: Paramecia & amoebas are types of this single-celled organism (Jeopardy!)
0.24: Shock researcher Walter Cannon coined this word for an organism's ability to maintain internal equilibrium (Jeopardy!)
0.24: The 5-kingdom system is made up of animals, bacteria, plants, protists & these (Jeopardy!)
0.23: A map of your blood-pumping organ (Double Jeopardy!)

Querying again, this time only for Double Jeopardy questions.
0.28: They're the tiny threadlike structures that carry the genes - you have 23 pairs (Double Jeopardy!)
0.23: A map of your blood-pumping organ (Double Jeopardy!)
0.2: Scientists divide these toothless whales into 3 groups: right whales, gray whales & rorquals (Double Jeopardy!)
0.18: University of Aberdeen in this country was the first in Great Britain to train students in medicine (Double Jeopardy!)
0.17: An amphibian avenue (Double Jeopardy!)
```

Note that even though none of the questions contain the word 'biology', they all relate to the field in some way.
