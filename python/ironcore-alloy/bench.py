import ironcore_alloy
import time, random, string, asyncio, statistics
import pyperf

# This benchmark tests a single standard roundtrip call to get an idea of how much time is being added by the FFI.
# Run this benchmark with `hatch run bench:standard_roundtrip -o batch.json`
# Review stats with `hatch run bench:pyperf stats bench.json`


def create_sdk_shared_key(key_bytes: bytearray) -> ironcore_alloy.Standalone:
    secret = ironcore_alloy.Secret(key_bytes)
    standalone_secret = ironcore_alloy.StandaloneSecret(1, secret)
    rotatable_secret = ironcore_alloy.RotatableSecret(standalone_secret, None)
    standard_secrets = ironcore_alloy.StandardSecrets(1, [standalone_secret])
    deterministic_secrets = {"secret_path": rotatable_secret}
    vector_secrets = {
        "secret_path": ironcore_alloy.VectorSecret(1.23, rotatable_secret)
    }
    config = ironcore_alloy.StandaloneConfiguration(
        standard_secrets, deterministic_secrets, vector_secrets
    )
    sdk = ironcore_alloy.Standalone(config)
    return sdk


def random_word(length: int):
    return "".join(random.choice(string.ascii_lowercase) for i in range(length))


async def standard_roundtrip(
    sdk: ironcore_alloy.Standalone,
    word: bytearray,
    metadata: ironcore_alloy.AlloyMetadata,
):
    encrypted = await sdk.standard().encrypt({"foo": word}, metadata)
    await sdk.standard().decrypt(encrypted, metadata)


random_word = random_word(10).encode("utf-8")
metadata = ironcore_alloy.AlloyMetadata.new_simple("tenant")
key_bytes = "awholelotoftotallyrandomdatathatcanbeusedasasecurecryptokey".encode(
    "utf-8"
)
sdk = create_sdk_shared_key(key_bytes)
runner = pyperf.Runner()
runner.metadata["description"] = "Run the IronCore Alloy Standard Roundtrip benchmark."
runner.bench_async_func(
    "standard_roundtrip",
    standard_roundtrip,
    sdk,
    random_word,
    metadata,
)
