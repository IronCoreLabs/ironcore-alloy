package com.ironcorelabs.not_ironcore_alloy_java;

import com.ironcorelabs.ironcore_alloy_java.*;
import org.junit.jupiter.api.*;
import static org.junit.jupiter.api.Assertions.*;

import java.util.*;
import java.util.Base64;
import java.util.stream.Collectors;
import java.util.concurrent.ExecutionException;

@TestInstance(TestInstance.Lifecycle.PER_CLASS)
public class IroncoreAlloyTest {
    private byte[] keyByteArray = "hJdwvEeg5mxTu9qWcWrljfKs1ga4MpQ9MzXgLxtlkwX//yA=".getBytes();
    private float approximationFactor = 1.1f;
    // TODO(java): 0.000_000_000_1f is the delta for Kotlin, but Java requires this, why so much worse accuracy?
    private float floatComparisonDelta = 0.000_000_3f;
    
    private StandardSecrets standardSecrets;
    private Map<SecretPath, RotatableSecret> deterministicSecrets;
    private Map<SecretPath, VectorSecret> vectorSecrets;
    private StandaloneConfiguration config; 
    private Standalone sdk;
    private SaasShield integrationSdk;

    @BeforeAll
    public void setUp() throws AlloyException {
        standardSecrets = new StandardSecrets(10, Arrays.asList(new StandaloneSecret(10, new Secret(keyByteArray))));
        deterministicSecrets = 
            Map.of(new SecretPath(""), new RotatableSecret(new StandaloneSecret(2, new Secret(keyByteArray)),
                new StandaloneSecret(1, new Secret(keyByteArray))));
        vectorSecrets = 
            Map.of(new SecretPath(""), new VectorSecret(approximationFactor, new RotatableSecret(
                new StandaloneSecret(2, new Secret(keyByteArray)),
                new StandaloneSecret(1, new Secret(keyByteArray))
            )));
        config = new StandaloneConfiguration(standardSecrets, deterministicSecrets, vectorSecrets);
        sdk = new Standalone(config);
        integrationSdk = new SaasShield(new SaasShieldConfiguration("http://localhost:32804", "0WUaXesNgbTAuLwn", false, 1.1f));
    }
    
    @Test
    public void sdkVectorRoundtrip() throws InterruptedException, ExecutionException {
        List<Float> data = Arrays.asList(1.0f, 2.0f, 3.0f);
        PlaintextVector plaintext = new PlaintextVector(data, new SecretPath(""), new DerivationPath(""));
        AlloyMetadata metadata = AlloyMetadata.newSimple(new TenantId("tenant"));

        EncryptedVector encrypted = sdk.vector().encrypt(plaintext, metadata).get();
        PlaintextVector decrypted = sdk.vector().decrypt(encrypted, metadata).get();

        for (int i = 0; i < data.size(); i++) {
            assertEquals(data.get(i), decrypted.plaintextVector().get(i), floatComparisonDelta);
        }
    }

    @Test
    public void sdkVectorDecrypt() throws InterruptedException, ExecutionException {
        List<Float> ciphertext = Arrays.asList(4422816.0f, 15091436.0f, 9409391.0f);
        byte[] iclMetadata = base64ToByteArray("AAAAAoEACgxFUZiS8PORQubGnk8SIJKbkabplwXSyzEJvXKalrg+Os+OCyDFzMZ2Tf3rei8g");
        EncryptedVector encrypted = new EncryptedVector(ciphertext, new SecretPath(""), new DerivationPath(""), new EncryptedBytes(iclMetadata));
        AlloyMetadata metadata = AlloyMetadata.newSimple(new TenantId("tenant"));

        PlaintextVector decrypted = sdk.vector().decrypt(encrypted, metadata).get();
        assertEquals(Arrays.asList(1.0f, 2.0f, 3.0f), decrypted.plaintextVector());
    }

    @Test
    public void sdkBatchRoundtripVector() throws InterruptedException, ExecutionException {
        List<Float> data = Arrays.asList(1.0f, 2.0f, 3.0f);
        PlaintextVector plaintext = new PlaintextVector(data, new SecretPath(""), new DerivationPath(""));
        PlaintextVector badVector = new PlaintextVector(data, new SecretPath("bad_path"), new DerivationPath("bad_path"));
        AlloyMetadata metadata = AlloyMetadata.newSimple(new TenantId("tenant"));
        PlaintextVectors plaintextVectors = new PlaintextVectors(Map.of(new VectorId("vec"), plaintext, new VectorId("badVec"), badVector));

        VectorEncryptBatchResult encrypted = sdk.vector().encryptBatch(plaintextVectors, metadata).get();
        assertEquals(1, encrypted.successes().value().size());
        assertEquals(1, encrypted.failures().size());
        assertEquals("msg=Provided secret path `bad_path` does not exist in the vector configuration.", 
                     encrypted.failures().get(new VectorId("badVec")).getMessage());

        VectorDecryptBatchResult decrypted = sdk.vector().decryptBatch(encrypted.successes(), metadata).get();
        assertEquals(1, decrypted.successes().value().size());
        assertEquals(0, decrypted.failures().size());
        for (int i = 0; i < data.size(); i++) {
            assertEquals(data.get(i), decrypted.successes().value().get(new VectorId("vec")).plaintextVector().get(i), floatComparisonDelta);
        }
    }

    @Test
    public void sdkVectorRotateDifferentTenant() throws InterruptedException, ExecutionException {
        List<Float> ciphertext = Arrays.asList(4422816.0f, 15091436.0f, 9409391.0f);
        byte[] iclMetadata = base64ToByteArray("AAAAAoEACgxFUZiS8PORQubGnk8SIJKbkabplwXSyzEJvXKalrg+Os+OCyDFzMZ2Tf3rei8g");
        EncryptedVector encrypted = new EncryptedVector(ciphertext, new SecretPath(""), new DerivationPath(""), new EncryptedBytes(iclMetadata));
        EncryptedVectors vectors = new EncryptedVectors(Map.of(new VectorId("vector"), encrypted));
        AlloyMetadata metadata = AlloyMetadata.newSimple(new TenantId("tenant"));

        VectorRotateResult rotated = sdk.vector().rotateVectors(vectors, metadata, new TenantId("tenant2")).get();
        assertEquals(1, rotated.successes().size());
        assertEquals(0, rotated.failures().size());
        assertTrue(rotated.successes().containsKey(new VectorId("vector")));

        AlloyMetadata newMetadata = AlloyMetadata.newSimple(new TenantId("tenant2"));
        PlaintextVector decrypted = sdk.vector().decrypt(rotated.successes().get(new VectorId("vector")), newMetadata).get();
        List<Float> expected = Arrays.asList(1.0f, 2.0f, 3.0f);
        for (int i = 0; i < decrypted.plaintextVector().size(); i++) {
            var roundtripped = decrypted.plaintextVector().get(i);
            var expectedV = expected.get(i);
            assertEquals(expectedV, roundtripped, floatComparisonDelta);
        }
    }

    @Test
    public void sdkVectorRotateDifferentKey() throws InterruptedException, ExecutionException, AlloyException {
        Map<SecretPath, VectorSecret> vectorSecrets2 = Map.of(
            new SecretPath(""), new VectorSecret(approximationFactor, new RotatableSecret(
                new StandaloneSecret(1, new Secret(keyByteArray)),
                new StandaloneSecret(2, new Secret(keyByteArray))
            ))
        );
        StandaloneConfiguration config2 = new StandaloneConfiguration(standardSecrets, deterministicSecrets, vectorSecrets2);
        Standalone sdk2 = new Standalone(config2);
        List<Float> ciphertext = Arrays.asList(4422816.0f, 15091436.0f, 9409391.0f);
        byte[] iclMetadata = base64ToByteArray("AAAAAoEACgxFUZiS8PORQubGnk8SIJKbkabplwXSyzEJvXKalrg+Os+OCyDFzMZ2Tf3rei8g");
        EncryptedVector encrypted = new EncryptedVector(ciphertext, new SecretPath(""), new DerivationPath(""), new EncryptedBytes(iclMetadata));
        VectorId testVecId = new VectorId("vector");
        TenantId testTenantId = new TenantId("tenant");
        EncryptedVectors vectors = new EncryptedVectors(Map.of(testVecId, encrypted));
        AlloyMetadata metadata = AlloyMetadata.newSimple(testTenantId);

        VectorRotateResult rotated = sdk2.vector().rotateVectors(vectors, metadata, new TenantId("tenant")).get();
        assertEquals(1, rotated.successes().size());
        assertEquals(0, rotated.failures().size());
        assertTrue(rotated.successes().containsKey(testVecId));

        Map<SecretPath, VectorSecret> vectorSecrets3 = Map.of(
            new SecretPath(""), new VectorSecret(approximationFactor, new RotatableSecret(
                new StandaloneSecret(1, new Secret(keyByteArray)), null
            ))
        );
        StandaloneConfiguration config3 = new StandaloneConfiguration(standardSecrets, deterministicSecrets, vectorSecrets3);
        Standalone sdk3 = new Standalone(config3);
        PlaintextVector decrypted = sdk3.vector().decrypt(rotated.successes().get(testVecId), metadata).get();
        List<Float> expected = Arrays.asList(1.0f, 2.0f, 3.0f);
        for (int i = 0; i < decrypted.plaintextVector().size(); i++) {
            assertEquals(expected.get(i), floatComparisonDelta, decrypted.plaintextVector().get(i));
        }
    }

    @Test
    public void sdkEncryptDeterministic() throws InterruptedException, ExecutionException {
        PlaintextField field = new PlaintextField(new PlaintextBytes("My data".getBytes()), new SecretPath(""), new DerivationPath(""));
        AlloyMetadata metadata = AlloyMetadata.newSimple(new TenantId("tenant"));

        EncryptedField encrypted = sdk.deterministic().encrypt(field, metadata).get();
        byte[] expected = base64ToByteArray("AAAAAoAA4hdzU2eh2aeCoUSq6NQiWYczhmQQNak=");
        assertArrayEquals(expected, encrypted.encryptedField().value());
    }

    @Test
    public void sdkStandardRoundtrip() throws InterruptedException, ExecutionException {
        FieldId testFieldId = new FieldId("foo");
        PlaintextDocument plaintextDocument = new PlaintextDocument(Map.of(testFieldId, new PlaintextBytes("My data".getBytes())));
        AlloyMetadata metadata = AlloyMetadata.newSimple(new TenantId("tenant"));

        EncryptedDocument encrypted = sdk.standard().encrypt(plaintextDocument, metadata).get();
        assertTrue(encrypted.document().containsKey(testFieldId));
        PlaintextDocument decrypted = sdk.standard().decrypt(encrypted, metadata).get();
        assertArrayEquals(plaintextDocument.value().get(testFieldId).value(), decrypted.value().get(testFieldId).value());
    }

    @Test
    public void sdkStandardBatchRoundtrip() throws InterruptedException, ExecutionException {
        PlaintextDocument plaintextDocument = new PlaintextDocument(Map.of(new FieldId("foo"), new PlaintextBytes("My data".getBytes())));
        PlaintextDocuments plaintextDocuments = new PlaintextDocuments(Map.of(new DocumentId("doc"), plaintextDocument));
        AlloyMetadata metadata = AlloyMetadata.newSimple(new TenantId("tenant"));

        StandardEncryptBatchResult encrypted = sdk.standard().encryptBatch(plaintextDocuments, metadata).get();
        assertEquals(1, encrypted.successes().value().size());
        assertEquals(0, encrypted.failures().size());

        StandardDecryptBatchResult decrypted = sdk.standard().decryptBatch(encrypted.successes(), metadata).get();
        assertEquals(1, decrypted.successes().value().size());
        assertEquals(0, decrypted.failures().size());
    }
    
    @Test
    public void sdkStandardAttachedRoundtrip() throws InterruptedException, ExecutionException {
        PlaintextAttachedDocument plaintextDocument = new PlaintextAttachedDocument(new PlaintextBytes("My data".getBytes()));
        AlloyMetadata metadata = AlloyMetadata.newSimple(new TenantId("tenant"));

        EncryptedAttachedDocument encrypted = sdk.standardAttached().encrypt(plaintextDocument, metadata).get();
        PlaintextAttachedDocument decrypted = sdk.standardAttached().decrypt(encrypted, metadata).get();
        assertArrayEquals(plaintextDocument.value().value(), decrypted.value().value());
    }

    @Test
    public void sdkStandardAttachedRoundtripBatch() throws InterruptedException, ExecutionException {
        PlaintextAttachedDocument plaintextDocument = new PlaintextAttachedDocument(new PlaintextBytes("My data".getBytes()));
        AlloyMetadata metadata = AlloyMetadata.newSimple(new TenantId("tenant"));
        DocumentId testDocId = new DocumentId("doc");
        PlaintextAttachedDocuments documents = new PlaintextAttachedDocuments(Map.of(testDocId, plaintextDocument));

        StandardAttachedEncryptBatchResult encrypted = sdk.standardAttached().encryptBatch(documents, metadata).get();
        assertEquals(1, encrypted.successes().value().size());
        assertEquals(0, encrypted.failures().size());

        EncryptedAttachedDocuments newEncrypted = new EncryptedAttachedDocuments(Map.of(
            new DocumentId("badDoc"), new EncryptedAttachedDocument(new EncryptedBytes("bad".getBytes())), 
            new DocumentId("doc"), encrypted.successes().value().get(testDocId)
        ));
        StandardAttachedDecryptBatchResult decrypted = sdk.standardAttached().decryptBatch(newEncrypted, metadata).get();
        assertEquals(1, decrypted.successes().value().size());
        assertEquals(1, decrypted.failures().size());
        assertArrayEquals(plaintextDocument.value().value(), decrypted.successes().value().get(testDocId).value().value());
    }

    @Test
    public void sdkStandardAttachedDecryptV4() throws InterruptedException, ExecutionException {
        EncryptedAttachedDocument encryptedDocument = new EncryptedAttachedDocument(new EncryptedBytes(base64ToByteArray(
          "BElST04AdgokCiAsN4NHsRTS4bq0a6wE9QUJFbWSf67pqkIgrzHPfztA3RABEk4STBpKCgxVKAX2fYD7F4W13dwSMN6LnbYAlUgekKbpI0z9LFeoUNNJZTUDX7WqoDZSWJ+uSEOoR7U8YSnaBlTBG8tw5hoIOX50ZW5hbnRIXNdHBgvQNRD/s1lTAxgMaKrMv0CL2AwLFuNtKPpLjObeLmdAkYKpe+uwbg=="
        )));  
        AlloyMetadata metadata = AlloyMetadata.newSimple(new TenantId("tenant"));
        PlaintextAttachedDocument decrypted = sdk.standardAttached().decrypt(encryptedDocument, metadata).get();
        assertArrayEquals("{\"title\":\"blah\"}".getBytes(), decrypted.value().value());
    }

 
    public static String toBase64(byte[] byteArray) {
        return Base64.getEncoder().encodeToString(byteArray);
    }

    public static byte[] base64ToByteArray(String base64String) {
        return Base64.getDecoder().decode(base64String);
    }
}
