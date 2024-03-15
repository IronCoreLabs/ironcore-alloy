# pgvector integration example

Starting with a dataset of Jeopardy questions, this example:

- Transforms the questions into vector embeddings using the `all-MiniLM-L6-v2` model
- Uses Cloaked AI to encrypt the embeddings, the text questions themselves, and the round
    - The round is encrypted deterministically so that it can be used in a query
- Inserts the encrypted embeddings and encrypted questions and rounds into Postgres
- Transforms a text query into a vector embedding
- Encrypts the query embedding
- Queries Postgres for relevant results
- Decrypts the original text and round from the returned result
- Queries Postgres again, this time limiting results to a specific round
- Decrypts the original text and round from the returned result

## Running the example

Start up Postgres/pgvector locally (bound to port 8888):

```
docker compose up -d
```

Run the example:

```
hatch shell
python pgvector-semantic-search.py
```

## Sample output

```
Transforming questions to vectors and encrypting them...
Inserting 981 encrypted questions.

Querying database with input: 'biology'
0.28: A map of your blood-pumping organ (Double Jeopardy!)
0.26: Shock researcher Walter Cannon coined this word for an organism's ability to maintain internal equilibrium (Jeopardy!)
0.26: They're the tiny threadlike structures that carry the genes - you have 23 pairs (Double Jeopardy!)
0.23: Paramecia & amoebas are types of this single-celled organism (Jeopardy!)
0.22: The 5-kingdom system is made up of animals, bacteria, plants, protists & these (Jeopardy!)

Querying again, this time only for Double Jeopardy questions.
0.28: A map of your blood-pumping organ (Double Jeopardy!)
0.26: They're the tiny threadlike structures that carry the genes - you have 23 pairs (Double Jeopardy!)
0.19: The Phoenicians used a liquid from several species of this gastropod to make Tyrian purple dye (Double Jeopardy!)
0.18: In 1831 this artist & naturalist began to write "The Ornithological Biography" (Double Jeopardy!)
0.16: An amphibian avenue (Double Jeopardy!)
```

Note that even though none of the questions contain the word 'biology', they all relate to the field in some way.
