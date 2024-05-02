package test

import com.ironcorelabs.ironcore_alloy.*
import java.util.concurrent.*
import kotlin.random.Random
import kotlin.system.*
import kotlinx.coroutines.*
import org.openjdk.jmh.annotations.*

@State(Scope.Benchmark)
@Fork(1)
@Warmup(iterations = 1)
@BenchmarkMode(Mode.AverageTime)
@OutputTimeUnit(TimeUnit.MICROSECONDS)
@Measurement(iterations = 5, time = 1, timeUnit = TimeUnit.SECONDS)
class SaasShieldBenchmark {
    // See setup for initialization
    var smallPlaintext: PlaintextDocument = emptyMap()
    var mediumPlaintext: PlaintextDocument = emptyMap()
    var largePlaintext: PlaintextDocument = emptyMap()
    var extraLargePlaintext: PlaintextDocument = emptyMap()
    var smallEncrypted: EncryptedDocument = EncryptedDocument("".toByteArray(), emptyMap())
    var mediumEncrypted: EncryptedDocument = EncryptedDocument("".toByteArray(), emptyMap())
    var largeEncrypted: EncryptedDocument = EncryptedDocument("".toByteArray(), emptyMap())
    var extraLargeEncrypted: EncryptedDocument = EncryptedDocument("".toByteArray(), emptyMap())
    var batchPlaintexts: PlaintextDocuments = emptyMap()

    val approximationFactor = 1.1f
    val tspUri = System.getenv("TSP_ADDRESS") ?: "http://localhost"
    val tspPort = System.getenv("TSP_PORT") ?: "32804"
    val tenantId = System.getenv("TENANT_ID") ?: "tenant-gcp-l"
    val apiKey = System.getenv("API_KEY") ?: "0WUaXesNgbTAuLwn"
    val saasShieldConfig =
            SaasShieldConfiguration(tspUri + ":" + tspPort, apiKey, true, approximationFactor)
    val saasShieldSdk = SaasShield(saasShieldConfig)
    val metadata = AlloyMetadata.newSimple(tenantId)

    @Setup
    fun setUp() {
        smallPlaintext = generatePlaintextDocument(1, 1)
        mediumPlaintext = generatePlaintextDocument(100, 1)
        largePlaintext = generatePlaintextDocument(10_000, 1)
        extraLargePlaintext = generatePlaintextDocument(1_000_000, 1)
        val numDocuments = 10
        val numFields = 10
        val fieldSize = 10
        var newBatchPlaintexts = HashMap<String, PlaintextDocument>()
        for (i in 1..numDocuments) {
            newBatchPlaintexts.put("doc" + i, generatePlaintextDocument(fieldSize, numFields))
        }
        batchPlaintexts = newBatchPlaintexts

        runBlocking {
            smallEncrypted = saasShieldSdk.standard().encrypt(smallPlaintext, metadata)
            mediumEncrypted = saasShieldSdk.standard().encrypt(mediumPlaintext, metadata)
            largeEncrypted = saasShieldSdk.standard().encrypt(largePlaintext, metadata)
            extraLargeEncrypted = saasShieldSdk.standard().encrypt(extraLargePlaintext, metadata)
        }
    }

    fun generatePlaintextDocument(bytesPerField: Int, numFields: Int): PlaintextDocument {
        val documentMap = HashMap<String, PlaintextBytes>()
        for (i in 1..numFields) {
            val byteArray = ByteArray(bytesPerField)
            kotlin.random.Random.nextBytes(byteArray)
            documentMap.put("doc" + i, byteArray)
        }
        return documentMap
    }

    fun encrypt(plaintext: PlaintextDocument) {
        runBlocking { saasShieldSdk.standard().encrypt(plaintext, metadata) }
    }

    fun decrypt(document: EncryptedDocument) {
        runBlocking { saasShieldSdk.standard().decrypt(document, metadata) }
    }

    @Benchmark
    fun tspEncrypt1B() {
        encrypt(smallPlaintext)
    }

    @Benchmark
    fun tspEncrypt100B() {
        encrypt(mediumPlaintext)
    }

    @Benchmark
    fun tspEncrypt10KB() {
        encrypt(largePlaintext)
    }

    @Benchmark
    fun tspEncrypt1MB() {
        encrypt(extraLargePlaintext)
    }

    @Benchmark
    fun tspDecrypt1B() {
        decrypt(smallEncrypted)
    }

    @Benchmark
    fun tspDecrypt100B() {
        decrypt(mediumEncrypted)
    }

    @Benchmark
    fun tspDecrypt10KB() {
        decrypt(largeEncrypted)
    }

    @Benchmark
    fun tspDecrypt1MB() {
        decrypt(extraLargeEncrypted)
    }

    @Benchmark
    fun batchEncrypt10DocsOf100B() {
        runBlocking { saasShieldSdk.standard().encryptBatch(batchPlaintexts, metadata) }
    }
}
