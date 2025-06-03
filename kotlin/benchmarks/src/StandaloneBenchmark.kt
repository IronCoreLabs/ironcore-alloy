package test

import com.ironcorelabs.ironcore_alloy.*
import java.util.Base64
import java.util.Random
import java.util.concurrent.*
import kotlin.ByteArray
import kotlin.system.*
import kotlinx.coroutines.*
import org.openjdk.jmh.annotations.*

fun String.base64ToByteArray(): ByteArray = Base64.getDecoder().decode(this)

@State(Scope.Benchmark)
@Fork(1)
@Warmup(iterations = 1)
@BenchmarkMode(Mode.AverageTime)
@OutputTimeUnit(TimeUnit.MICROSECONDS)
@Measurement(iterations = 5, time = 1, timeUnit = TimeUnit.SECONDS)
class StandaloneBenchmark {
    // See setup for initialization
    var smallWord: ByteArray = "".toByteArray()
    var mediumWord: ByteArray = "".toByteArray()
    var largeWord: ByteArray = "".toByteArray()

    val keyByteArray = "hJdwvEeg5mxTu9qWcWrljfKs1ga4MpQ9MzXgLxtlkwX//yA=".base64ToByteArray()
    val approximationFactor = 2.5f
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
    val standaloneConfig =
            StandaloneConfiguration(standardSecrets, deterministicSecrets, vectorSecrets)
    val standaloneSdk = Standalone(standaloneConfig)

    val metadata = AlloyMetadata.newSimple("tenant-gcp-l")

    fun randomWord(length: Int): String {
        val source = ('A'..'Z') + ('a'..'z') + ('0'..'9')
        return (1..length).map { source.random() }.joinToString("")
    }

    @Setup
    fun setUp() {
        smallWord = randomWord(10).toByteArray()
        mediumWord = randomWord(10 * 1000).toByteArray()
        largeWord = randomWord(100 * 1000).toByteArray()
    }

    @State(Scope.Thread)
    open class Vector384State {
        var vector: List<Float> = (1..384).map { Random().nextFloat() }
    }

    @Benchmark
    fun standaloneVectorEncrypt384d(s: Vector384State) {
        runBlocking { standaloneSdk.vector().encrypt(PlaintextVector(s.vector, "", ""), metadata) }
    }

    @Benchmark
    fun standaloneRoundtripStandard10B() {
        runBlocking {
            val encrypted = standaloneSdk.standard().encrypt(mapOf("foo" to smallWord), metadata)
            standaloneSdk.standard().decrypt(encrypted, metadata)
        }
    }

    @Benchmark
    fun standaloneRoundtripStandard10Kb() {
        runBlocking {
            val encrypted = standaloneSdk.standard().encrypt(mapOf("foo" to mediumWord), metadata)
            standaloneSdk.standard().decrypt(encrypted, metadata)
        }
    }

    @Benchmark
    fun standaloneRoundtripStandard100Kb() {
        runBlocking {
            val encrypted = standaloneSdk.standard().encrypt(mapOf("foo" to largeWord), metadata)
            standaloneSdk.standard().decrypt(encrypted, metadata)
        }
    }
}
