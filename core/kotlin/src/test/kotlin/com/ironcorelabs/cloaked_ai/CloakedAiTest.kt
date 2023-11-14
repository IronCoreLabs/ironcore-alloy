package com.ironcorelabs.cloaked_ai

import java.util.Base64
import kotlin.system.*
import kotlin.test.*
import kotlinx.coroutines.*

fun ByteArray.toBase64(): String = String(Base64.getEncoder().encode(this))

fun String.base64ToByteArray(): ByteArray = Base64.getDecoder().decode(this)

class CloakedAiTest {
    val keyByteArray = "hJdwvEeg5mxTu9qWcWrljfKs1ga4MpQ9MzXgLxtlkwX//yA=".toByteArray()
    val scalingFactor = 12345.0f
    val key = Key(scalingFactor, keyByteArray)
    val approximationFactor = 1.1f
    val standardSecrets = StandardSecrets(10u, listOf(StandaloneSecret(10u, Secret(keyByteArray))))
    val deterministicSecrets =
            mapOf(
                    "" to
                            RotatableSecret(
                                    StandaloneSecret(2u, Secret(keyByteArray)),
                                    StandaloneSecret(1u, Secret(keyByteArray))
                            )
            )
    val vectorSecrets =
            mapOf(
                    "" to
                            VectorSecret(
                                    approximationFactor,
                                    RotatableSecret(
                                            StandaloneSecret(2u, Secret(keyByteArray)),
                                            StandaloneSecret(1u, Secret(keyByteArray))
                                    )
                            )
            )
    val config = StandaloneConfiguration(standardSecrets, deterministicSecrets, vectorSecrets)
    val sdk = Standalone(config)
    // val seededSdk = CloakedAiStandalone.newTestSeeded(key, approximationFactor, 123.toULong())
    // val docMetadata = DocumentMetadata("Tenant")

    @Test
    fun sdkVectorRoundtrip() {
        val data = listOf(1.0f, 2.0f, 3.0f)
        val plaintext = PlaintextVector(data, "", "")
        val metadata = IronCoreMetadata.newSimple("tenant")
        runBlocking {
            val encrypted = sdk.vector().encrypt(plaintext, metadata)
            val decrypted = sdk.vector().decrypt(encrypted, metadata)
            assertContentEquals(
                    data,
                    decrypted.plaintextVector,
            )
        }
    }

    // TODO
    // @Test
    // fun sdkEncryptSeeded() {
    //     val data = listOf(1.0f, 2.0f, 3.0f)
    //     val metadata = DocumentMetadata("tenant")
    //     val encrypted = seededSdk.encrypt(data, metadata)
    //     val expected = listOf(11864.771f, 26402.541f, 35622.992f)
    //     assertEquals(
    //             expected,
    //             encrypted.ciphertext,
    //     )
    // }

    @Test
    fun sdkVectorDecrypt() {
        val ciphertext = listOf(5826192.0f, 15508204.0f, 11420345.0f)
        val iclMetadata =
                "AAAAAoEACgyVAnirL57DGDIdC28SIH9FFpmMs5yi5CcTcQjcUjldEE0OEdZDWtpyNI++ALnf".base64ToByteArray()
        val encrypted = EncryptedVector(ciphertext, "", "", iclMetadata)
        val metadata = IronCoreMetadata.newSimple("tenant")
        runBlocking {
            val decrypted = sdk.vector().decrypt(encrypted, metadata)
            assertContentEquals(
                    decrypted.plaintextVector,
                    listOf(1.0f, 2.0f, 3.0f),
            )
        }
    }

    // TODO
    // @Test
    // fun sdkEncryptDeterministicMetadata() {
    //     val documentFields = mapOf("foo" to "My data".toByteArray())
    //     val metadata = DocumentMetadata("tenant")
    //     val encrypted = sdk.deterministic().encrypt()
    //     // encryptDocumentDeterministic(documentFields, metadata)
    //     val expected =
    //             mapOf("foo" to "AAAAAAAAMs7OVNXWuwUuW1DJVxlTbqoRTFdWKzM=".base64ToByteArray())
    //     assertContentEquals(expected.get("foo"), encrypted.get("foo"))
    // }

    @Test
    fun sdkStandardRoundtrip() {
        val plaintextDocument = mapOf("foo" to "My data".toByteArray())
        val metadata = IronCoreMetadata.newSimple("tenant")
        val err =
                assertFailsWith<InternalException>("foo") {
                    runBlocking {
                        val encrypted = sdk.standard().encrypt(plaintextDocument, metadata)
                        assertContains(encrypted.document, "foo")
                        val decrypted = sdk.standard().decrypt(encrypted, metadata)
                        assertContentEquals(decrypted.get("foo"), plaintextDocument.get("foo"))
                    }
                }
        // TODO: shouldn't fail at all
        assertContains(err.message.toString(), "not yet implemented")
    }

    // TODO
    // @Test
    // fun sdkEncryptProbabilisticMetadata() {
    //     val documentFields = mapOf("foo" to "My data".toByteArray())
    //     val metadata = DocumentMetadata("tenant")
    //     val encrypted = seededSdk.encryptDocument(documentFields, metadata)
    //     val expected =
    //             mapOf(
    //                     "foo" to
    //
    // "AElST047XW9umwlxe053wEV18Vn5REOO4xh1s+2PAJk9E/h2lSug0A==".base64ToByteArray()
    //             )
    //     assertContentEquals(expected.get("foo"), encrypted.document.get("foo"))
    // }

    // TODO
    // @Test
    // fun sdkDecryptDeterministicMetadata() {
    //     val ciphertext =
    //             mapOf("foo" to "AAAAAAAAMs7OVNXWuwUuW1DJVxlTbqoRTFdWKzM=".base64ToByteArray())
    //     val metadata = DocumentMetadata("tenant")
    //     val decrypted = sdk.decryptDocumentDeterministic(ciphertext, metadata)
    //     val expected = mapOf("foo" to "My data".toByteArray())
    //     assertContentEquals(expected.get("foo"), decrypted.get("foo"))
    // }

    @Test
    fun sdkStandardDecryptWrongType() {
        val err =
        // TODO
        // assertFailsWith<CloakedAiException.DocumentException>("foo") {
        assertFailsWith<InternalException>("foo") {
                    val documentFields =
                            mapOf(
                                    "foo" to
                                            "AAAAAAAAMs7OVNXWuwUuW1DJVxlTbqoRTFdWKzM=".base64ToByteArray()
                            )
                    val metadata = IronCoreMetadata.newSimple("tenant")
                    val document = EncryptedDocument("edek".toByteArray(), documentFields)
                    runBlocking { sdk.standard().decrypt(document, metadata) }
                }
        // assertContains(err.message.toString(), "Failed encrypting/decrypting document")
        assertContains(err.message.toString(), "not yet implemented")
    }

    // TODO
    // @Test
    // fun sdkDeterministicDecryptWrongLabel() {
    //     val err =
    //             assertFailsWith<CloakedAiException.DocumentException> {
    //                 // was encrypted with "foo"
    //                 val documentFields =
    //                         mapOf(
    //                                 "bar" to
    //
    // "AAAAAAAAMs7OVNXWuwUuW1DJVxlTbqoRTFdWKzM=".base64ToByteArray()
    //                         )
    //                 val metadata = DocumentMetadata("tenant")
    //                 sdk.decryptDocumentDeterministic(documentFields, metadata)
    //             }
    //     assertContains(err.message.toString(), "Failed encrypting/decrypting document")
    // }
}
