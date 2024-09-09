from ironcore_alloy import *
import time, random, string, asyncio, statistics
import pyperf

# Run this benchmark with `hatch run bench:bench`
# Review stats with `hatch run bench:stats`


## STANDALONE
def create_sdk_shared_key(key_bytes: bytearray) -> ironcore_alloy.Standalone:
    secret = ironcore_alloy.Secret(key_bytes)
    standalone_secret = ironcore_alloy.StandaloneSecret(1, secret)
    rotatable_secret = ironcore_alloy.RotatableSecret(standalone_secret, None)
    standard_secrets = ironcore_alloy.StandardSecrets(1, [standalone_secret])
    deterministic_secrets = {"secret_path": rotatable_secret}
    vector_secrets = {"secret_path": ironcore_alloy.VectorSecret(2.5, rotatable_secret)}
    config = ironcore_alloy.StandaloneConfiguration(
        standard_secrets, deterministic_secrets, vector_secrets
    )
    sdk = ironcore_alloy.Standalone(config)
    return sdk


def random_word(length: int):
    return "".join(random.choice(string.ascii_lowercase) for i in range(length))


# This benchmark tests a single standard roundtrip call to get an idea of how much time is being added by the FFI.
async def standard_roundtrip(
    sdk: ironcore_alloy.Standalone,
    word: bytearray,
    metadata: ironcore_alloy.AlloyMetadata,
):
    encrypted = await sdk.standard().encrypt({"foo": word}, metadata)
    await sdk.standard().decrypt(encrypted, metadata)


async def vector_encrypt(
    sdk: ironcore_alloy.Standalone,
    vector: list[float],
    metadata: ironcore_alloy.AlloyMetadata,
):
    plaintext_vector = ironcore_alloy.PlaintextVector(
        plaintext_vector=vector,
        secret_path="secret_path",
        derivation_path="derivation_path",
    )
    await sdk.vector().encrypt(plaintext_vector, metadata)


async def vector_batch_encrypt(
    sdk: ironcore_alloy.Standalone,
    plaintext_vectors: dict[ironcore_alloy.FieldId, ironcore_alloy.PlaintextField],
    metadata: ironcore_alloy.AlloyMetadata,
):
    await sdk.vector().encrypt_batch(plaintext_vectors, metadata)


async def vector_roundtrip(
    sdk: ironcore_alloy.Standalone,
    vector: list[float],
    metadata: ironcore_alloy.AlloyMetadata,
):
    plaintext_vector = ironcore_alloy.PlaintextVector(
        plaintext_vector=vector,
        secret_path="secret_path",
        derivation_path="derivation_path",
    )
    encrypted_vector = await sdk.vector().encrypt(plaintext_vector, metadata)
    await sdk.vector().decrypt(encrypted_vector, metadata)


def random_floats(dimensions: int):
    return [random.uniform(-1.0, 1.0) for _ in range(dimensions)]


metadata = ironcore_alloy.AlloyMetadata.new_simple("tenant")
key_bytes = "awholelotoftotallyrandomdatathatcanbeusedasasecurecryptokey".encode(
    "utf-8"
)
sdk = create_sdk_shared_key(key_bytes)

runner = pyperf.Runner()
runner.metadata["description"] = "Run the IronCore Alloy benchmarks."

### standalone vector
runner.bench_async_func(
    "vector encrypt d=384",
    vector_encrypt,
    sdk,
    random_floats(384),
    metadata,
)
runner.bench_async_func(
    "vector encrypt d=768",
    vector_encrypt,
    sdk,
    random_floats(768),
    metadata,
)
runner.bench_async_func(
    "vector encrypt d=1536",
    vector_encrypt,
    sdk,
    random_floats(1536),
    metadata,
)
runner.bench_async_func(
    "vector encrypt d=2048",
    vector_encrypt,
    sdk,
    random_floats(2048),
    metadata,
)
runner.bench_async_func(
    "vector batch (100) encrypt d=768",
    vector_batch_encrypt,
    sdk,
    {
        str(idx): ironcore_alloy.PlaintextVector(
            plaintext_vector=vector,
            secret_path="secret_path",
            derivation_path="derivation_path",
        )
        for idx, vector in enumerate([random_floats(768) for _ in range(100)])
    },
    metadata,
)
runner.bench_async_func(
    "vector batch (1000) encrypt d=768",
    vector_batch_encrypt,
    sdk,
    {
        str(idx): ironcore_alloy.PlaintextVector(
            plaintext_vector=vector,
            secret_path="secret_path",
            derivation_path="derivation_path",
        )
        for idx, vector in enumerate([random_floats(768) for _ in range(1000)])
    },
    metadata,
)

### standalone standard
random_small_word = random_word(10).encode("utf-8")
runner.bench_async_func(
    "standard_roundtrip_small",
    standard_roundtrip,
    sdk,
    random_small_word,
    metadata,
)
random_medium_word = random_word(10 * 1000).encode("utf-8")
runner.bench_async_func(
    "standard_roundtrip_medium", standard_roundtrip, sdk, random_medium_word, metadata
)
random_large_word = random_word(10 * 10000).encode("utf-8")
runner.bench_async_func(
    "standard_roundtrip_large", standard_roundtrip, sdk, random_large_word, metadata
)
