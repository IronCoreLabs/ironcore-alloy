# Qdrant demo

This is a port of the demo from the [README](https://github.com/qdrant/rust-client/tree/master?tab=readme-ov-file#usage) on their rust crate. It is very very simple, but I think still demonstrates that the encrypted vector still matches well based on scoring.

In their example, it matches with 1.000000001 score and with the vector encrypted it matches with a 0.99995 score.

## Usage

Run Qdrant with enabled gRPC interface:

```bash
# With env variable
docker run -p 6333:6333 -p 6334:6334 \
    -e QDRANT__SERVICE__GRPC_PORT="6334" \
    qdrant/qdrant
```

Then run this main using:

`cargo run`
