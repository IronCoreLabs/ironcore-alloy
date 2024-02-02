# Weaviate integration example

This example is based on the Weaviate [Bring your own vectors](https://weaviate.io/developers/weaviate/starter-guides/custom-vectors) starter guide.

Starting with a dataset of Jeopardy questions, this example:

- Transforms the questions into vector embeddings using the `all-MiniLM-L6-v2` model
- Uses Cloaked AI to encrypt the embeddings as well as the text questions themselves
- Inserts the encrypted embeddings and encrypted questions into Weaviate
- Transforms a text query into a vector embedding
- Encrypts the query embedding
- Queries Weaviate for relevant results
- Decrypts the original text from the returned result

Note that we currently do not support Weaviate's vectorizer method of inserting data.

## Running the example

Start up Weaviate locally:

```
docker compose up -d
```

Run the example:

```
hatch shell
python weaviate-semantic-search.py
```

## Sample output

```
Transforming questions to vectors and encrypting them...
Inserting 981 encrypted questions.
Query: 'biology'
0.66: The 5-kingdom system is made up of animals, bacteria, plants, protists & these
0.64: A map of your blood-pumping organ
0.64: Shock researcher Walter Cannon coined this word for an organism's ability to maintain internal equilibrium
0.64: Paramecia & amoebas are types of this single-celled organism
0.63: They're the tiny threadlike structures that carry the genes - you have 23 pairs
```

Note that even though none of the questions contain the word 'biology', they all relate to the field in some way.
