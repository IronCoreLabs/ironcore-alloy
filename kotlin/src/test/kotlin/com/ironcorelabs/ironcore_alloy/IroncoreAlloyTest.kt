package com.ironcorelabs.not_ironcore_alloy

import com.ironcorelabs.ironcore_alloy.*
import java.util.Base64
import kotlin.math.abs
import kotlin.system.*
import kotlin.test.*
import kotlin.time.*
import kotlinx.coroutines.*

fun ByteArray.toBase64(): String = String(Base64.getEncoder().encode(this))

fun String.base64ToByteArray(): ByteArray = Base64.getDecoder().decode(this)

fun Float.sameValueAs(other: Float): Boolean {
    return (abs(this - other) < 0.0000000001)
}

class IroncoreAlloyTest {
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

    val integrationSdk =
            SaasShield(
                    SaasShieldConfiguration(
                            "http://localhost:32804",
                            "0WUaXesNgbTAuLwn",
                            false,
                            1.1f
                    )
            )

    @Test
    fun sdkVectorRoundtrip() {
        val data = listOf(1.0f, 2.0f, 3.0f)
        val plaintext = PlaintextVector(data, "", "")
        val metadata = AlloyMetadata.newSimple("tenant")
        runBlocking {
            val encrypted = sdk.vector().encrypt(plaintext, metadata)
            val decrypted = sdk.vector().decrypt(encrypted, metadata)
            for (i in 0..(data.size - 1)) {
                data.get(i).sameValueAs(decrypted.plaintextVector.get(i))
            }
        }
    }

    @Test
    fun sdkVectorDecrypt() {
        val ciphertext = listOf(11374474.0f, 5756342.0f, 15267408.0f)
        val iclMetadata =
                "AAAAAoEACgxPGmuySl4VniL/cbMSIOykrH8Xa9rVT4vtQZE73EM3G6AOrEae4tVgIpxA3lhp".base64ToByteArray()
        val encrypted = EncryptedVector(ciphertext, "", "", iclMetadata)
        val metadata = AlloyMetadata.newSimple("tenant")
        runBlocking {
            val decrypted = sdk.vector().decrypt(encrypted, metadata)
            assertContentEquals(
                    decrypted.plaintextVector,
                    listOf(1.0f, 2.0f, 3.0f),
            )
        }
    }

    @Test
    fun sdkVectorRotateDifferentTenant() {
        val ciphertext = listOf(11374474.0f, 5756342.0f, 15267408.0f)
        val iclMetadata =
                "AAAAAoEACgxPGmuySl4VniL/cbMSIOykrH8Xa9rVT4vtQZE73EM3G6AOrEae4tVgIpxA3lhp".base64ToByteArray()
        val encrypted = EncryptedVector(ciphertext, "", "", iclMetadata)
        val vectors = mapOf("vector" to encrypted)
        val metadata = AlloyMetadata.newSimple("tenant")
        runBlocking {
            val rotated = sdk.vector().rotateVectors(vectors, metadata, "tenant2")
            assertEquals(rotated.successes.size, 1)
            assertEquals(rotated.failures.size, 0)
            assert(rotated.successes.containsKey("vector"))
            val newMetadata = AlloyMetadata.newSimple("tenant2")
            val decrypted = sdk.vector().decrypt(rotated.successes.get("vector")!!, newMetadata)
            val expected = listOf(1.0f, 2.0f, 3.0f)
            for (i in 0..(decrypted.plaintextVector.size - 1)) {
                decrypted.plaintextVector.get(i).sameValueAs(expected.get(i))
            }
        }
    }

    @Test
    fun sdkVectorRotateDifferentKey() {
        val vectorSecrets2 =
                mapOf(
                        "" to
                                VectorSecret(
                                        approximationFactor,
                                        RotatableSecret(
                                                // Switched current and in-rotation vs original sdk
                                                StandaloneSecret(1, Secret(keyByteArray)),
                                                StandaloneSecret(2, Secret(keyByteArray)),
                                        )
                                )
                )
        val config2 = StandaloneConfiguration(standardSecrets, deterministicSecrets, vectorSecrets2)
        val sdk2 = Standalone(config2)
        val ciphertext = listOf(11374474.0f, 5756342.0f, 15267408.0f)
        val iclMetadata =
                "AAAAAoEACgxPGmuySl4VniL/cbMSIOykrH8Xa9rVT4vtQZE73EM3G6AOrEae4tVgIpxA3lhp".base64ToByteArray()
        val encrypted = EncryptedVector(ciphertext, "", "", iclMetadata)
        val vectors = mapOf("vector" to encrypted)
        val metadata = AlloyMetadata.newSimple("tenant")
        runBlocking {
            val rotated =
                    sdk2.vector().rotateVectors(vectors, metadata, "tenant") // unchanged tenant
            assertEquals(rotated.successes.size, 1)
            assertEquals(rotated.failures.size, 0)
            assert(rotated.successes.containsKey("vector"))
            // Now that it's rotated, sometime in the future we have an SDK with only the new
            // current
            val vectorSecrets3 =
                    mapOf(
                            "" to
                                    VectorSecret(
                                            approximationFactor,
                                            RotatableSecret(
                                                    StandaloneSecret(1, Secret(keyByteArray)),
                                                    null
                                            )
                                    )
                    )
            val config3 =
                    StandaloneConfiguration(standardSecrets, deterministicSecrets, vectorSecrets3)
            val sdk3 = Standalone(config3)
            val decrypted = sdk3.vector().decrypt(rotated.successes.get("vector")!!, metadata)
            val expected = listOf(1.0f, 2.0f, 3.0f)
            for (i in 0..(decrypted.plaintextVector.size - 1)) {
                decrypted.plaintextVector.get(i).sameValueAs(expected.get(i))
            }
        }
    }

    @Test
    fun sdkEncryptDeterministic() {
        val field = PlaintextField("My data".toByteArray(), "", "")
        val metadata = AlloyMetadata.newSimple("tenant")
        runBlocking {
            val encrypted = sdk.deterministic().encrypt(field, metadata)
            val expected = "AAAAAoAAUvfq7IxbDEtW26wr4H8x2JCtyB4DCzk=".base64ToByteArray()
            assertContentEquals(expected, encrypted.encryptedField)
        }
    }

    @Test
    fun sdkStandardRoundtrip() {
        val plaintextDocument = mapOf("foo" to "My data".toByteArray())
        val metadata = AlloyMetadata.newSimple("tenant")
        runBlocking {
            val encrypted = sdk.standard().encrypt(plaintextDocument, metadata)
            assertContains(encrypted.document, "foo")
            val decrypted = sdk.standard().decrypt(encrypted, metadata)
            assertContentEquals(decrypted.get("foo"), plaintextDocument.get("foo"))
        }
    }

    @Test
    fun sdkStandardBatchRoundtrip() {
        val plaintextDocument = mapOf("foo" to "My data".toByteArray())
        val plaintextDocuments = mapOf("doc" to plaintextDocument)
        val metadata = AlloyMetadata.newSimple("tenant")
        runBlocking {
            val encrypted = sdk.standard().encryptBatch(plaintextDocuments, metadata)
            assertEquals(encrypted.successes.size, 1)
            assertEquals(encrypted.failures.size, 0)
            val decrypted = sdk.standard().decryptBatch(encrypted.successes, metadata)
            assertEquals(decrypted.successes.size, 1)
            assertEquals(decrypted.failures.size, 0)
        }
    }

    @Test
    fun sdkStandardAttachedRoundtrip() {
        val plaintextDocument = "My data".toByteArray()
        val metadata = AlloyMetadata.newSimple("tenant")
        runBlocking {
            val encrypted = sdk.standardAttached().encrypt(plaintextDocument, metadata)
            val decrypted = sdk.standardAttached().decrypt(encrypted, metadata)
            assertContentEquals(decrypted, plaintextDocument)
        }
    }

    @Test
    fun sdkStandardRekeyEdeks() {
        val plaintextDocument = mapOf("foo" to "My data".toByteArray())
        val metadata = AlloyMetadata.newSimple("tenant")
        val newTenantId = "tenant2"
        val newMetadata = AlloyMetadata.newSimple(newTenantId)
        runBlocking {
            val encrypted = sdk.standard().encrypt(plaintextDocument, metadata)
            assertContains(encrypted.document, "foo")
            val edeks = mapOf("edek" to encrypted.edek)
            val rekeyed = sdk.standard().rekeyEdeks(edeks, metadata, newTenantId)
            assertEquals(rekeyed.successes.size, 1)
            assertEquals(rekeyed.failures.size, 0)
            val remadeDocument =
                    EncryptedDocument(rekeyed.successes.getValue("edek"), encrypted.document)
            val decrypted = sdk.standard().decrypt(remadeDocument, newMetadata)
            assertContentEquals(decrypted.get("foo"), plaintextDocument.get("foo"))
        }
    }

    @Test
    fun sdkStandardEncryptWithExistingEdek() {
        val plaintextDocument = mapOf("foo" to "My data".toByteArray())
        val plaintextDocument2 = mapOf("foo" to "My data2".toByteArray())

        val metadata = AlloyMetadata.newSimple("tenant")
        runBlocking {
            val encrypted = sdk.standard().encrypt(plaintextDocument, metadata)
            val encrypted2 =
                    sdk.standard()
                            .encryptWithExistingEdek(
                                    PlaintextDocumentWithEdek(encrypted.edek, plaintextDocument2),
                                    metadata
                            )
            val decrypted = sdk.standard().decrypt(encrypted2, metadata)
            assertContentEquals(encrypted.edek, encrypted2.edek)
            assertContentEquals(decrypted.get("foo"), plaintextDocument2.get("foo"))
        }
    }

    @Test
    fun sdkStandardEncryptWithExistingEdekBatch() {
        val plaintextDocument = mapOf("foo" to "My data".toByteArray())
        val plaintextDocument2 = mapOf("foo" to "My data2".toByteArray())

        val metadata = AlloyMetadata.newSimple("tenant")
        runBlocking {
            val encrypted = sdk.standard().encrypt(plaintextDocument, metadata)
            val plaintexts =
                    mapOf("doc" to PlaintextDocumentWithEdek(encrypted.edek, plaintextDocument2))
            val batchEncrypted = sdk.standard().encryptWithExistingEdekBatch(plaintexts, metadata)
            assertEquals(batchEncrypted.successes.size, 1)
            assertEquals(batchEncrypted.failures.size, 0)
            val encrypted2 = batchEncrypted.successes.get("doc")!!
            val decrypted = sdk.standard().decrypt(encrypted2, metadata)
            assertContentEquals(encrypted.edek, encrypted2.edek)
            assertContentEquals(decrypted.get("foo"), plaintextDocument2.get("foo"))
        }
    }

    @Test
    fun sdkDecryptDeterministic() {
        val ciphertext = "AAAAAoAAUvfq7IxbDEtW26wr4H8x2JCtyB4DCzk=".base64ToByteArray()
        val encryptedField = EncryptedField(ciphertext, "", "")
        val metadata = AlloyMetadata.newSimple("tenant")
        runBlocking {
            val decrypted = sdk.deterministic().decrypt(encryptedField, metadata)
            val expected = "My data".toByteArray()
            assertContentEquals(expected, decrypted.plaintextField)
        }
    }

    @Test
    fun sdkBatchRoundtripDeterministic() {
        val plaintextInput = "My data".toByteArray()
        val field = PlaintextField(plaintextInput, "", "")
        val badField = PlaintextField("My data".toByteArray(), "bad_path", "bad_path")
        val metadata = AlloyMetadata.newSimple("tenant")
        val plaintextFields = mapOf("doc" to field, "badDoc" to badField)
        runBlocking {
            val encrypted = sdk.deterministic().encryptBatch(plaintextFields, metadata)
            assertEquals(encrypted.successes.size, 1)
            assertEquals(encrypted.failures.size, 1)
            assertEquals(
                    encrypted.failures.get("badDoc")?.message,
                    "msg=Provided secret path `bad_path` does not exist in the deterministic configuration."
            )
            val decrypted = sdk.deterministic().decryptBatch(encrypted.successes, metadata)
            assertEquals(decrypted.successes.size, 1)
            assertEquals(decrypted.failures.size, 0)
            assertContentEquals(decrypted.successes.get("doc")?.plaintextField, plaintextInput)
        }
    }

    @Test
    fun sdkStandardDecryptWrongType() {
        val err =
                assertFailsWith<AlloyException.InvalidInput>() {
                    val documentFields =
                            mapOf(
                                    "foo" to
                                            "AAAAAoAA4hdzU2eh2aeCoUSq6NQiWYczhmQQNak=".base64ToByteArray()
                            )
                    val metadata = AlloyMetadata.newSimple("tenant")
                    val edek =
                            "AAAACoAACiQKID/RxqsV0L1yky5NMwXNlNtn5s5vi+PR92RKN7Iqa5TtEAESRxJFGkMKDPgVFQkpAEd89NH8lxIwTTUTiyiyB1GgXxLRBjVwJ94065fjRYvQzwggXAQcO35ZV2CxkS2nS44xDvlHHc9GGgEx"
                    val document = EncryptedDocument(edek.base64ToByteArray(), documentFields)
                    runBlocking { sdk.standard().decrypt(document, metadata) }
                }
        assertContains(err.message, " not a Standalone Standard EDEK wrapped value.")
    }

    @Test
    // This test is ignored by default because it requires the TSP from tests/docker-compose.yml to
    // be running. Uncomment to test as needed
    @Ignore
    fun integrationSdkUnknownTenant() {
        val err =
                assertFailsWith<AlloyException.TspException>() {
                    val data = listOf(1.0f, 2.0f, 3.0f)
                    val plaintext = PlaintextVector(data, "", "")
                    val metadata = AlloyMetadata.newSimple("fake-tenant")
                    runBlocking { integrationSdk.vector().encrypt(plaintext, metadata) }
                }
        assertContains(err.msg, "Tenant either doesn't exist")
    }
}
