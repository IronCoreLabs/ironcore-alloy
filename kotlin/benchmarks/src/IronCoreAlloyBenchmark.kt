package test

import org.openjdk.jmh.annotations.*
import java.util.concurrent.*
import com.ironcorelabs.ironcore_alloy.*
import kotlinx.coroutines.*
import kotlin.system.*
import java.util.Base64


fun String.base64ToByteArray(): ByteArray = Base64.getDecoder().decode(this)


@State(Scope.Benchmark)
@Fork(1)
@Warmup(iterations = 1)
@BenchmarkMode(Mode.AverageTime)
@OutputTimeUnit(TimeUnit.MICROSECONDS)
@Measurement(iterations = 1, time = 1, timeUnit = TimeUnit.SECONDS)
class IronCoreAlloyBenchmark {
    // See setup for initialization
    var smallWord: ByteArray = "".toByteArray()
    var mediumWord: ByteArray = "".toByteArray()
    var largeWord: ByteArray = "".toByteArray()


    val keyByteArray = "hJdwvEeg5mxTu9qWcWrljfKs1ga4MpQ9MzXgLxtlkwX//yA=".base64ToByteArray()
    val approximationFactor = 1.1f
    val standardSecrets = StandardSecrets(10, listOf(StandaloneSecret(10, Secret(keyByteArray))))
    val deterministicSecrets =
            mapOf(
                    "" to
                            RotatableSecret(
                                    StandaloneSecret(2, Secret(keyByteArray)),
                                    StandaloneSecret(1, Secret(keyByteArray))
                            )
            )
    val vectorSecrets =
            mapOf(
                    "" to
                            VectorSecret(
                                    approximationFactor,
                                    RotatableSecret(
                                            StandaloneSecret(2, Secret(keyByteArray)),
                                            StandaloneSecret(1, Secret(keyByteArray))
                                    )
                            )
            )
    val config = StandaloneConfiguration(standardSecrets, deterministicSecrets, vectorSecrets)
    val sdk = Standalone(config)

    fun randomWord(length: Int): String {
        val source = ('A'..'Z') + ('a'..'z') + ('0'..'9')
        return (1..length).map { source.random() }.joinToString("")
    }


    @Setup
    fun setUp() {
        smallWord = randomWord(10).toByteArray()
        mediumWord = randomWord(10 * 1000).toByteArray()
        largeWord = randomWord(10 * 10000).toByteArray()
    }

    @Benchmark
    fun roundtripStandardSmall() {
        val metadata = AlloyMetadata.newSimple("tenant")
        runBlocking {
            val encrypted = sdk.standard().encrypt(mapOf("foo" to smallWord), metadata)
            sdk.standard().decrypt(encrypted, metadata)
         }
    }

    @Benchmark
    fun roundtripStandardMedium() {
        val metadata = AlloyMetadata.newSimple("tenant")
        runBlocking {
            val encrypted = sdk.standard().encrypt(mapOf("foo" to mediumWord), metadata)
            sdk.standard().decrypt(encrypted, metadata)
         }
    }

    @Benchmark
    fun roundtripStandardLarge() {
        val metadata = AlloyMetadata.newSimple("tenant")
        runBlocking {
            val encrypted = sdk.standard().encrypt(mapOf("foo" to largeWord), metadata)
            sdk.standard().decrypt(encrypted, metadata)
         }
    }

}
