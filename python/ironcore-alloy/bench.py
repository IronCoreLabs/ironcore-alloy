import ironcore_alloy
import time, random, string, asyncio, statistics

key_bytes = "awholelotoftotallyrandomdatathatcanbeusedasasecurecryptokey".encode(
    "utf-8"
)
secret = ironcore_alloy.Secret(key_bytes)
standalone_secret = ironcore_alloy.StandaloneSecret(1, secret)
rotatable_secret = ironcore_alloy.RotatableSecret(standalone_secret, None)
standard_secrets = ironcore_alloy.StandardSecrets(1, [standalone_secret])
deterministic_secrets = {"secret_path": rotatable_secret}
vector_secrets = {"secret_path": ironcore_alloy.VectorSecret(1.23, rotatable_secret)}
config = ironcore_alloy.StandaloneConfiguration(
    standard_secrets, deterministic_secrets, vector_secrets
)
sdk = ironcore_alloy.Standalone(config)
metadata = ironcore_alloy.AlloyMetadata.new_simple("tenant")


def random_word(length):
    return "".join(random.choice(string.ascii_lowercase) for i in range(length))


repetitions = 10000
random_words = [random_word(10).encode("utf-8") for idx in range(repetitions)]


async def test_function(word):
    encrypted = await sdk.standard().encrypt({"foo": word}, metadata)
    await sdk.standard().decrypt(encrypted, metadata)


async def bench():
    microsecond_measurements = []
    for random_word in random_words:
        start = time.perf_counter_ns()
        await test_function(random_word)
        stop = time.perf_counter_ns()
        microsecond_measurements.append((stop - start) / 1000)
    return microsecond_measurements


timing_data = asyncio.run(bench())

print(
    f"[no_regression {statistics.mean(timing_data)} µs {statistics.median(timing_data)} µs]"
)
