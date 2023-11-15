package com.ironcorelabs.ironcore_alloy

import java.util.Base64
import kotlin.system.*
import kotlin.test.*
import kotlinx.coroutines.*

fun ByteArray.toBase64(): String = String(Base64.getEncoder().encode(this))

fun String.base64ToByteArray(): ByteArray = Base64.getDecoder().decode(this)

class IroncoreAlloyTest {
    val keyByteArray = "hJdwvEeg5mxTu9qWcWrljfKs1ga4MpQ9MzXgLxtlkwX//yA=".toByteArray()
    val scalingFactor = 12345.0f
    val key = VectorEncryptionKey(scalingFactor, keyByteArray)
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
    // val seededSdk = IroncoreAlloyStandalone.newTestSeeded(key, approximationFactor,
    // 123.toULong())
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

    @Test
    fun sdkEncryptDeterministicMetadata() {
        val field = PlaintextField("My data".toByteArray(), "", "")
        val metadata = IronCoreMetadata.newSimple("tenant")
        runBlocking {
            val encrypted = sdk.deterministic().encrypt(field, metadata)
            val expected = "AAAAAoAA4hdzU2eh2aeCoUSq6NQiWYczhmQQNak=".base64ToByteArray()
            assertContentEquals(expected, encrypted.encryptedField)
        }
    }

    @Test
    fun sdkStandardRoundtrip() {
        val plaintextDocument = mapOf("foo" to "My data".toByteArray())
        val metadata = IronCoreMetadata.newSimple("tenant")
        runBlocking {
            val encrypted = sdk.standard().encrypt(plaintextDocument, metadata)
            assertContains(encrypted.document, "foo")
            val decrypted = sdk.standard().decrypt(encrypted, metadata)
            assertContentEquals(decrypted.get("foo"), plaintextDocument.get("foo"))
        }
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

    @Test
    fun sdkDecryptDeterministicMetadata() {
        val ciphertext = "AAAAAoAA4hdzU2eh2aeCoUSq6NQiWYczhmQQNak=".base64ToByteArray()
        val encryptedField = EncryptedField(ciphertext, "", "")
        val metadata = IronCoreMetadata.newSimple("tenant")
        runBlocking {
            val decrypted = sdk.deterministic().decrypt(encryptedField, metadata)
            val expected = "My data".toByteArray()
            assertContentEquals(expected, decrypted.plaintextField)
        }
    }

    @Test
    fun sdkStandardDecryptWrongType() {
        val err =
                assertFailsWith<AlloyException.InvalidInput>("foo") {
                    val documentFields =
                            mapOf(
                                    "foo" to
                                            "AAAAAoAA4hdzU2eh2aeCoUSq6NQiWYczhmQQNak=".base64ToByteArray()
                            )
                    val metadata = IronCoreMetadata.newSimple("tenant")
                    val edek =
                            "AAAACoAACiQKID/RxqsV0L1yky5NMwXNlNtn5s5vi+PR92RKN7Iqa5TtEAESRxJFGkMKDPgVFQkpAEd89NH8lxIwTTUTiyiyB1GgXxLRBjVwJ94065fjRYvQzwggXAQcO35ZV2CxkS2nS44xDvlHHc9GGgEx"
                    val document = EncryptedDocument(edek.base64ToByteArray(), documentFields)
                    runBlocking { sdk.standard().decrypt(document, metadata) }
                }
        assertContains(err.message.toString(), " not a Standalone Standard wrapped value.")
    }
}
