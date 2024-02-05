# Pinecone integration example

This example is based on the Pinecone [semantic search](https://github.com/pinecone-io/examples/blob/master/learn/search/semantic-search/semantic-search.ipynb) example.

Starting with a dataset of Quora questions, this example:

- Transforms the questions into vector embeddings using the `all-MiniLM-L6-v2` model
- Uses Cloaked AI to encrypt the embeddings as well as the text questions themselves
- Inserts the encrypted embeddings and encrypted questions into Pinecone
- Transforms a text query into a vector embedding
- Encrypts the query embedding
- Queries Pinecone for relevant results
- Decrypts the original text from the returned result

## Running the example

Export environment variables with your Pinecone API key and environment name:

```
export PINECONE_API_KEY=<your API key>
export PINECONE_ENV=<your environment>
```

Run the example:

```
hatch shell
python pinecone-semantic-search.py
```

## Sample output

```
Encrypting embeddings and their associated text.

Query: which city has the highest population in the world?
0.65:  What's the world's largest city?
0.6:  What is the biggest city?
0.56:  What are the world's most advanced cities?
0.54:  Where is the most beautiful city in the world?
0.54:  What is the greatest, most beautiful city in the world?

Query: which metropolis has the highest number of people?
0.51:  What is the biggest city?
0.5:  What is the most dangerous city in USA?
0.49:  How many people to in the United States?
0.49:  What's the world's largest city?
0.48:  What are some of the most dangerous cities in America?
```
