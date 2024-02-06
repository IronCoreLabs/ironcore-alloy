# Weaviate integration example

This example is based on the Weaviate [Bring your own vectors](https://weaviate.io/developers/weaviate/starter-guides/custom-vectors) starter guide.

Starting with a dataset of Jeopardy questions, this example:

- Transforms the questions into vector embeddings using the `all-MiniLM-L6-v2` model
- Uses Cloaked AI to encrypt the embeddings, the text questions themselves, and the round
    - The round is encrypted deterministically so that it can be used as a query filter
- Inserts the encrypted embeddings and encrypted questions into Weaviate
- Transforms a text query into a vector embedding
- Encrypts the query embedding
- Queries Weaviate for relevant results
- Decrypts the original text and round from the returned result
- Queries Weaviate again, this time with a filter on the round
- Decrypts the original text and round from the returned result

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

Querying database with input: 'biology'
0.63: Paramecia & amoebas are types of this single-celled organism (Jeopardy!)
0.63: A map of your blood-pumping organ (Double Jeopardy!)
0.61: They're the tiny threadlike structures that carry the genes - you have 23 pairs (Double Jeopardy!)
0.61: Shock researcher Walter Cannon coined this word for an organism's ability to maintain internal equilibrium (Jeopardy!)
0.6: A grub is this soft, thick stage of metamorphosis of flies, wasps & beetles (Jeopardy!)

Querying again, this time only for Double Jeopardy questions.
0.63: A map of your blood-pumping organ (Double Jeopardy!)
0.61: They're the tiny threadlike structures that carry the genes - you have 23 pairs (Double Jeopardy!)
0.59: Stephen Hawking's 1988 bio of the universe that was a No. 1 hit for Jim Croce (Double Jeopardy!)
0.58: In "Gulliver's Travels", Swift described this type of creature as "the most unteachable of all brutes" (Double Jeopardy!)
0.57: In computers or audio amplifiers, it's the process in which part of the output returns to the input (Double Jeopardy!)
```

Note that even though none of the questions contain the word 'biology', they all relate to the field in some way.
