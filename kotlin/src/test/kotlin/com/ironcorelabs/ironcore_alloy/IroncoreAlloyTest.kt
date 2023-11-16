package com.ironcorelabs.not_ironcore_alloy

import com.ironcorelabs.ironcore_alloy.*
import java.util.Base64
import kotlin.math.abs
import kotlin.system.*
import kotlin.test.*
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
    fun sdkStandardDecryptWrongType() {
        val err =
                assertFailsWith<AlloyException.InvalidInput>("foo") {
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
        assertContains(err.message.toString(), " not a Standalone Standard wrapped value.")
    }
}
