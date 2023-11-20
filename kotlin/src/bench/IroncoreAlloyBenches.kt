package com.ironcorelabs.not_ironcore_alloy

import com.ironcorelabs.ironcore_alloy.*
import kotlin.system.*
import kotlin.test.*
import kotlin.time.*
import kotlinx.coroutines.*

class IroncoreAlloyBench {
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

    fun median(list: List<Long>) =
            list.sorted().let {
                if (it.size % 2 == 0) (it[it.size / 2] + it[(it.size - 1) / 2]) / 2
                else it[it.size / 2]
            }

    @Test
    fun benchmarkStandardRoundtrip() {
        val repetitions = 10000
        val timingResults: MutableList<Long> = ArrayList()
        val words = (1..repetitions).map { _ -> randomWord(10).toByteArray() }
        val metadata = AlloyMetadata.newSimple("tenant")
        runBlocking {
            for (word in words) {
                @OptIn(ExperimentalTime::class)
                val elapsed = measureTime {
                    val encrypted = sdk.standard().encrypt(mapOf("foo" to word), metadata)
                    sdk.standard().decrypt(encrypted, metadata)
                }
                timingResults.add(elapsed.inWholeMicroseconds)
            }
        }
        val mean = timingResults.average()
        val median = median(timingResults)
        println("[no_regression ${mean} µs ${median} µs]")
    }
}
