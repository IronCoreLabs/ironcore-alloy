package com.ironcorelabs.not_ironcore_alloy_java;

import com.ironcorelabs.ironcore_alloy_java.*;
import org.junit.jupiter.api.*;
import static org.junit.jupiter.api.Assertions.*;
import okhttp3.*;
import java.util.*;
import java.util.stream.Collectors;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.CompletableFuture;


@TestInstance(TestInstance.Lifecycle.PER_CLASS)
public class IroncoreAlloyTest {
    class JavaHttpClient implements HttpClient {
        OkHttpClient client;

        public JavaHttpClient() {
            this.client = new OkHttpClient();        
        }

        @Override
        public CompletableFuture<AlloyHttpClientResponse> postJson(String url, String jsonBody, AlloyHttpClientHeaders headers) {
            RequestBody body = RequestBody.create(jsonBody, MediaType.get("application/json"));
            Request request = new Request.Builder()
                .url(url)
                .header("Content-Type", headers.contentType())
                .header("Authorization", headers.authorization())
                .post(body)
                .build();
            CompletableFuture<AlloyHttpClientResponse> future = new CompletableFuture<>();
            client.newCall(request).enqueue(new Callback() {
                @Override public void onFailure(Call call, java.io.IOException e) {
                    future.completeExceptionally(new AlloyException.RequestException("Failed to make JSON post request: " + e.getMessage()));
                }

                @Override public void onResponse(Call call, Response response) throws java.io.IOException {
                    future.complete(new AlloyHttpClientResponse(response.body().string(), (short) response.code()));
                }
            });
            return future;
        }
    }
    
    private byte[] keyByteArray = "hJdwvEeg5mxTu9qWcWrljfKs1ga4MpQ9MzXgLxtlkwX//yA=".getBytes();
    private float approximationFactor = 1.1f;
    // TODO(java): 0.000_000_000_1f is the delta for Kotlin, but Java requires this, why so much worse accuracy?
    private float floatComparisonDelta = 0.000_000_3f;
    
    private StandardSecrets standardSecrets;
    private Map<SecretPath, RotatableSecret> deterministicSecrets;
    private Map<SecretPath, VectorSecret> vectorSecrets;
    private StandaloneConfiguration config; 
    private Standalone sdk;
    private Standalone seededSdk;
    // SDK which will use the scaling factor
    private Standalone sdkWithScaling;
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
        seededSdk = new Standalone(StandaloneConfiguration.newSeededForTesting(standardSecrets, deterministicSecrets, vectorSecrets,1));
        sdkWithScaling = new Standalone(new StandaloneConfiguration(standardSecrets, deterministicSecrets,
                Map.of(new SecretPath(""), VectorSecret.newWithScalingFactor(approximationFactor, new RotatableSecret(
                        new StandaloneSecret(2, new Secret(keyByteArray)),
                        new StandaloneSecret(1, new Secret(keyByteArray)))))));
        IroncoreAlloyTest.JavaHttpClient httpClient = new IroncoreAlloyTest.JavaHttpClient();
        integrationSdk = new SaasShield(new SaasShieldConfiguration("http://localhost:32804", "0WUaXesNgbTAuLwn", 1.1f, httpClient, true));
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
    public void seededSdkVectorEncrypt() throws InterruptedException, ExecutionException {
        List<Float> data = Arrays.asList(0.1f, -0.2f);
        PlaintextVector plaintext = new PlaintextVector(data, new SecretPath(""), new DerivationPath(""));
        AlloyMetadata metadata = AlloyMetadata.newSimple(new TenantId("tenant"));

        EncryptedVector encrypted = seededSdk.vector().encrypt(plaintext, metadata).get();
        // Values match other tests using the same seed.
        assertEquals(encrypted.encryptedVector(), Arrays.asList(0.1299239844083786f, -0.3532053828239441f));
    }

    @Test
    public void sdkVectorDecrypt() throws InterruptedException, ExecutionException {
        List<Float> ciphertext = Arrays.asList(4422816.0f, 15091436.0f, 9409391.0f);
        byte[] iclMetadata = base64ToByteArray("AAAAAoEACgxFUZiS8PORQubGnk8SIJKbkabplwXSyzEJvXKalrg+Os+OCyDFzMZ2Tf3rei8g");
        EncryptedVector encrypted = new EncryptedVector(ciphertext, new SecretPath(""), new DerivationPath(""), new EncryptedBytes(iclMetadata));
        AlloyMetadata metadata = AlloyMetadata.newSimple(new TenantId("tenant"));

        PlaintextVector decrypted = sdkWithScaling.vector().decrypt(encrypted, metadata).get();
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

        VectorRotateResult rotated = sdkWithScaling.vector().rotateVectors(vectors, metadata, new TenantId("tenant2")).get();
        assertEquals(1, rotated.successes().size());
        assertEquals(0, rotated.failures().size());
        assertTrue(rotated.successes().containsKey(new VectorId("vector")));

        AlloyMetadata newMetadata = AlloyMetadata.newSimple(new TenantId("tenant2"));
        PlaintextVector decrypted = sdkWithScaling.vector().decrypt(rotated.successes().get(new VectorId("vector")), newMetadata).get();
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
    public void seededSdkStandardEncrypt() throws InterruptedException, ExecutionException {
        FieldId testFieldId = new FieldId("foo");
        PlaintextDocument plaintextDocument = new PlaintextDocument(Map.of(testFieldId, new PlaintextBytes("My data".getBytes())));
        AlloyMetadata metadata = AlloyMetadata.newSimple(new TenantId("tenant"));

        EncryptedDocument encrypted = seededSdk.standard().encrypt(plaintextDocument, metadata).get();
        assertTrue(encrypted.document().containsKey(testFieldId));
        // Same value as tests from other languages with the same seed
        assertEquals(toBase64(encrypted.document().get(testFieldId).value()),"AElST04OFx9g3p5TQTSIGaJrUPuq79Di9DmR0uK5/n6lXAis5Ip45Q==");
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

    @Test
    public void sdkStandardAttachedRekeyV4() throws InterruptedException, ExecutionException {
        byte[] encryptedDocument = base64ToByteArray(
                "BElST04AdgokCiAsN4NHsRTS4bq0a6wE9QUJFbWSf67pqkIgrzHPfztA3RABEk4STBpKCgxVKAX2fYD7F4W13dwSMN6LnbYAlUgekKbpI0z9LFeoUNNJZTUDX7WqoDZSWJ+uSEOoR7U8YSnaBlTBG8tw5hoIOX50ZW5hbnRIXNdHBgvQNRD/s1lTAxgMaKrMv0CL2AwLFuNtKPpLjObeLmdAkYKpe+uwbg=="
        );
        AlloyMetadata metadata = AlloyMetadata.newSimple(new TenantId("tenant"));
        EncryptedAttachedDocuments documents = new EncryptedAttachedDocuments(Map.of(new DocumentId("doc"), new EncryptedAttachedDocument(new EncryptedBytes(encryptedDocument))));

        RekeyAttachedDocumentsBatchResult rekeyed = sdk.standardAttached().rekeyDocuments(documents, metadata, null).get();
        assertEquals(1, rekeyed.successes().size());
        assertEquals(0, rekeyed.failures().size());

        PlaintextAttachedDocument decrypted = sdk.standardAttached().decrypt(rekeyed.successes().get(new DocumentId("doc")), metadata).get();
        byte[] expected = "{\"title\":\"blah\"}".getBytes();
        assertArrayEquals(expected, decrypted.value().value());
    }

    @Test
    public void sdkStandardAttachedRekeyNewTenant() throws InterruptedException, ExecutionException {
        byte[] plaintextDocument = "My data".getBytes();
        AlloyMetadata metadata = AlloyMetadata.newSimple(new TenantId("tenant"));
        PlaintextAttachedDocuments documents = new PlaintextAttachedDocuments(Map.of(new DocumentId("doc"), new PlaintextAttachedDocument(new PlaintextBytes(plaintextDocument))));

        StandardAttachedEncryptBatchResult encrypted = sdk.standardAttached().encryptBatch(documents, metadata).get();
        RekeyAttachedDocumentsBatchResult rekeyed = sdk.standardAttached().rekeyDocuments(encrypted.successes(), metadata, new TenantId("new_tenant")).get();
        assertEquals(1, rekeyed.successes().size());
        assertEquals(0, rekeyed.failures().size());

        CompletableFuture<PlaintextAttachedDocument> result = sdk.standardAttached().decrypt(rekeyed.successes().get(new DocumentId("doc")), metadata);
        ExecutionException err = assertThrows(ExecutionException.class, result::get);
        AlloyException.DecryptException err2 = assertThrows(AlloyException.DecryptException.class, () -> {
            throw err.getCause();
        });
        assertTrue(err2.getMessage().contains("Ensure the data and key are correct."));

        AlloyMetadata newMetadata = AlloyMetadata.newSimple(new TenantId("new_tenant"));
        PlaintextAttachedDocument decrypted = sdk.standardAttached().decrypt(rekeyed.successes().get(new DocumentId("doc")), newMetadata).get();
        assertArrayEquals(plaintextDocument, decrypted.value().value());
    }

    @Test
    public void sdkStandardRekeyEdeks() throws InterruptedException, ExecutionException {
        PlaintextDocument plaintextDocument = new PlaintextDocument(Map.of(new FieldId("foo"), new PlaintextBytes("My data".getBytes())));
        AlloyMetadata metadata = AlloyMetadata.newSimple(new TenantId("tenant"));
        TenantId newTenantId = new TenantId("tenant2");
        AlloyMetadata newMetadata = AlloyMetadata.newSimple(newTenantId);

        EncryptedDocument encrypted = sdk.standard().encrypt(plaintextDocument, metadata).get();
        assertTrue(encrypted.document().containsKey(new FieldId("foo")));

        Map<DocumentId, EdekWithKeyIdHeader> edeks = Map.of(new DocumentId("edek"), encrypted.edek());
        RekeyEdeksBatchResult rekeyed = sdk.standard().rekeyEdeks(edeks, metadata, newTenantId).get();
        assertEquals(1, rekeyed.successes().size());
        assertEquals(0, rekeyed.failures().size());

        EncryptedDocument remadeDocument = new EncryptedDocument(rekeyed.successes().get(new DocumentId("edek")), encrypted.document());
        PlaintextDocument decrypted = sdk.standard().decrypt(remadeDocument, newMetadata).get();
        assertArrayEquals(plaintextDocument.value().get(new FieldId("foo")).value(), decrypted.value().get(new FieldId("foo")).value());
    }

    @Test
    public void sdkStandardEncryptWithExistingEdek() throws InterruptedException, ExecutionException {
        PlaintextDocument plaintextDocument = new PlaintextDocument(Map.of(new FieldId("foo"), new PlaintextBytes("My data".getBytes())));
        PlaintextDocument plaintextDocument2 = new PlaintextDocument(Map.of(new FieldId("foo"), new PlaintextBytes("My data2".getBytes())));

        AlloyMetadata metadata = AlloyMetadata.newSimple(new TenantId("tenant"));
        EncryptedDocument encrypted = sdk.standard().encrypt(plaintextDocument, metadata).get();
        EncryptedDocument encrypted2 = sdk.standard().encryptWithExistingEdek(new PlaintextDocumentWithEdek(encrypted.edek(), plaintextDocument2), metadata).get();

        PlaintextDocument decrypted = sdk.standard().decrypt(encrypted2, metadata).get();
        assertArrayEquals(encrypted.edek().value().value(), encrypted2.edek().value().value());
        assertArrayEquals(plaintextDocument2.value().get(new FieldId("foo")).value(), decrypted.value().get(new FieldId("foo")).value());
    }

    @Test
    public void sdkStandardEncryptWithExistingEdekBatch() throws InterruptedException, ExecutionException {
        PlaintextDocument plaintextDocument = new PlaintextDocument(Map.of(new FieldId("foo"), new PlaintextBytes("My data".getBytes())));
        PlaintextDocument plaintextDocument2 = new PlaintextDocument(Map.of(new FieldId("foo"), new PlaintextBytes("My data2".getBytes())));

        AlloyMetadata metadata = AlloyMetadata.newSimple(new TenantId("tenant"));
        EncryptedDocument encrypted = sdk.standard().encrypt(plaintextDocument, metadata).get();

        PlaintextDocumentsWithEdeks plaintexts = new PlaintextDocumentsWithEdeks(Map.of(new DocumentId("doc"), new PlaintextDocumentWithEdek(encrypted.edek(), plaintextDocument2)));
        StandardEncryptBatchResult batchEncrypted = sdk.standard().encryptWithExistingEdekBatch(plaintexts, metadata).get();
        assertEquals(1, batchEncrypted.successes().value().size());
        assertEquals(0, batchEncrypted.failures().size());

        EncryptedDocument encrypted2 = batchEncrypted.successes().value().get(new DocumentId("doc"));
        PlaintextDocument decrypted = sdk.standard().decrypt(encrypted2, metadata).get();
        assertArrayEquals(encrypted.edek().value().value(), encrypted2.edek().value().value());
        assertArrayEquals(plaintextDocument2.value().get(new FieldId("foo")).value(), decrypted.value().get(new FieldId("foo")).value());
    }

    @Test
    public void sdkDecryptDeterministic() throws InterruptedException, ExecutionException {
        EncryptedBytes ciphertext = new EncryptedBytes(base64ToByteArray("AAAAAoAA4hdzU2eh2aeCoUSq6NQiWYczhmQQNak="));
        EncryptedField encryptedField = new EncryptedField(ciphertext, new SecretPath(""), new DerivationPath(""));
        AlloyMetadata metadata = AlloyMetadata.newSimple(new TenantId("tenant"));

        PlaintextField decrypted = sdk.deterministic().decrypt(encryptedField, metadata).get();
        byte[] expected = "My data".getBytes();
        assertArrayEquals(expected, decrypted.plaintextField().value());
    }

    @Test
    public void sdkBatchRoundtripDeterministic() throws InterruptedException, ExecutionException {
        PlaintextBytes plaintextInput = new PlaintextBytes("My data".getBytes());
        PlaintextField field = new PlaintextField(plaintextInput, new SecretPath(""), new DerivationPath(""));
        PlaintextField badField = new PlaintextField(new PlaintextBytes("My data".getBytes()), new SecretPath("bad_path"), new DerivationPath("bad_path"));
        AlloyMetadata metadata = AlloyMetadata.newSimple(new TenantId("tenant"));
        PlaintextFields plaintextFields = new PlaintextFields(Map.of(new FieldId("doc"), field, new FieldId("badDoc"), badField));

        DeterministicEncryptBatchResult encrypted = sdk.deterministic().encryptBatch(plaintextFields, metadata).get();
        assertEquals(1, encrypted.successes().value().size());
        assertEquals(1, encrypted.failures().size());
        assertEquals("msg=Provided secret path `bad_path` does not exist in the deterministic configuration.",
                encrypted.failures().get(new FieldId("badDoc")).getMessage());

        DeterministicDecryptBatchResult decrypted = sdk.deterministic().decryptBatch(encrypted.successes(), metadata).get();
        assertEquals(1, decrypted.successes().value().size());
        assertEquals(0, decrypted.failures().size());
        assertArrayEquals(plaintextInput.value(), decrypted.successes().value().get(new FieldId("doc")).plaintextField().value());
    }

    @Test
    public void sdkStandardDecryptWrongType() {
        Map<FieldId, EncryptedBytes> documentFields = Map.of(new FieldId("foo"), new EncryptedBytes(base64ToByteArray("AAAAAoAA4hdzU2eh2aeCoUSq6NQiWYczhmQQNak=")));
        AlloyMetadata metadata = AlloyMetadata.newSimple(new TenantId("tenant"));
        byte[] edek = base64ToByteArray("AAAACoAACiQKID/RxqsV0L1yky5NMwXNlNtn5s5vi+PR92RKN7Iqa5TtEAESRxJFGkMKDPgVFQkpAEd89NH8lxIwTTUTiyiyB1GgXxLRBjVwJ94065fjRYvQzwggXAQcO35ZV2CxkS2nS44xDvlHHc9GGgEx");
        EncryptedDocument document = new EncryptedDocument(new EdekWithKeyIdHeader(new EncryptedBytes(edek)), documentFields);
        CompletableFuture<PlaintextDocument> result = sdk.standard().decrypt(document, metadata);
        ExecutionException err = assertThrows(ExecutionException.class, result::get);
        assertThrows(AlloyException.InvalidInput.class, () -> {
            throw err.getCause(); 
        });
        assertTrue(err.getCause().getMessage().contains(" not a Standalone Standard EDEK wrapped value."));
    }

    @Test
    @Disabled // This test requires the TSP from tests/docker-compose.yml to be running. Uncomment to test as needed.
    public void integrationSdkUnknownTenant() {
        AlloyException.TspException err = assertThrows(AlloyException.TspException.class, () -> {
            List<Float> data = Arrays.asList(1.0f, 2.0f, 3.0f);
            PlaintextVector plaintext = new PlaintextVector(data, new SecretPath(""), new DerivationPath(""));
            AlloyMetadata metadata = AlloyMetadata.newSimple(new TenantId("fake-tenant"));
            sdk.vector().encrypt(plaintext, metadata).get();
        });
        assertTrue(err.getMessage().contains("Tenant either doesn't exist"));
    }
 
    public static String toBase64(byte[] byteArray) {
        return Base64.getEncoder().encodeToString(byteArray);
    }

    public static byte[] base64ToByteArray(String base64String) {
        return Base64.getDecoder().decode(base64String);
    }

    @Test
    public void badConfigurationTest() throws AlloyException, ExecutionException, InterruptedException {
        IroncoreAlloyTest.JavaHttpClient httpClient = new IroncoreAlloyTest.JavaHttpClient();
        var badSdk = new SaasShield(new SaasShieldConfiguration("https://bad-url", "0WUaXesNgbTAuLwn", 1.1f, httpClient, false));
        List<Float> data = Arrays.asList(1.0f, 2.0f, 3.0f);
        PlaintextVector plaintext = new PlaintextVector(data, new SecretPath(""), new DerivationPath(""));
        var metadata = AlloyMetadata.newSimple(new TenantId("fake_tenant"));
        var result = badSdk.vector().encrypt(plaintext, metadata);
        ExecutionException err = assertThrows(ExecutionException.class, result::get);
        assertThrows(AlloyException.RequestException.class, () -> {
            throw err.getCause(); 
        });
        assertTrue(err.getCause().getMessage().contains("JSON post request"));
    }
    
    @Test
    public void httpNotAllowed() throws AlloyException, ExecutionException, InterruptedException {
        IroncoreAlloyTest.JavaHttpClient httpClient = new IroncoreAlloyTest.JavaHttpClient();
        AlloyException err = assertThrows(AlloyException.InvalidConfiguration.class, () ->{
            new SaasShieldConfiguration("http://bad-url", "0WUaXesNgbTAuLwn", 1.1f, httpClient, false);
        });
        assertTrue(err.getMessage().contains("insecure"));
    }
}
