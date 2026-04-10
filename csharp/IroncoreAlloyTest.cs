using uniffi.ironcore_alloy;
using Xunit;

namespace IroncoreAlloy.Tests;

class CSharpHttpClient : uniffi.ironcore_alloy.HttpClient
{
    private readonly System.Net.Http.HttpClient _client = new();

    public async Task<AlloyHttpClientResponse> PostJson(string url, string jsonBody, AlloyHttpClientHeaders headers)
    {
        try
        {
            var content = new StringContent(jsonBody, System.Text.Encoding.UTF8, headers.ContentType);
            var request = new HttpRequestMessage(HttpMethod.Post, url);
            request.Content = content;
            request.Headers.TryAddWithoutValidation("Authorization", headers.Authorization);
            var response = await _client.SendAsync(request);
            var body = await response.Content.ReadAsStringAsync();
            return new AlloyHttpClientResponse(body, (ushort)response.StatusCode);
        }
        catch (Exception e)
        {
            throw new AlloyException.RequestException($"Failed to make JSON post request: {e.Message}");
        }
    }
}

public class IroncoreAlloyTest
{
    private static readonly byte[] KeyByteArray =
        System.Text.Encoding.UTF8.GetBytes("hJdwvEeg5mxTu9qWcWrljfKs1ga4MpQ9MzXgLxtlkwX//yA=");

    private static readonly float ApproximationFactor = 1.1f;
    private static readonly float FloatComparisonDelta = 0.000_000_3f;

    private readonly StandardSecrets _standardSecrets;
    private readonly Dictionary<string, RotatableSecret> _deterministicSecrets;
    private readonly Dictionary<string, VectorSecret> _vectorSecrets;
    private readonly StandaloneConfiguration _config;
    private readonly Standalone _sdk;
    private readonly Standalone _seededSdk;
    private readonly Standalone _sdkWithScaling;

    public IroncoreAlloyTest()
    {
        _standardSecrets = new StandardSecrets(
            10,
            new StandaloneSecret[] { new StandaloneSecret(10, new Secret(KeyByteArray)) }
        );
        _deterministicSecrets = new Dictionary<string, RotatableSecret>
        {
            {
                "",
                new RotatableSecret(
                    new StandaloneSecret(2, new Secret(KeyByteArray)),
                    new StandaloneSecret(1, new Secret(KeyByteArray))
                )
            }
        };
        _vectorSecrets = new Dictionary<string, VectorSecret>
        {
            {
                "",
                new VectorSecret(
                    ApproximationFactor,
                    new RotatableSecret(
                        new StandaloneSecret(2, new Secret(KeyByteArray)),
                        new StandaloneSecret(1, new Secret(KeyByteArray))
                    )
                )
            }
        };
        _config = new StandaloneConfiguration(_standardSecrets, _deterministicSecrets, _vectorSecrets);
        _sdk = new Standalone(_config);
        _seededSdk = new Standalone(
            StandaloneConfiguration.NewSeededForTesting(
                _standardSecrets, _deterministicSecrets, _vectorSecrets, 1
            )
        );
        _sdkWithScaling = new Standalone(
            new StandaloneConfiguration(
                _standardSecrets,
                _deterministicSecrets,
                new Dictionary<string, VectorSecret>
                {
                    {
                        "",
                        VectorSecret.NewWithScalingFactor(
                            ApproximationFactor,
                            new RotatableSecret(
                                new StandaloneSecret(2, new Secret(KeyByteArray)),
                                new StandaloneSecret(1, new Secret(KeyByteArray))
                            )
                        )
                    }
                }
            )
        );
    }

    [Fact]
    public async Task SdkVectorRoundtrip()
    {
        var data = new float[] { 1.0f, 2.0f, 3.0f };
        var plaintext = new PlaintextVector(data, "", "");
        var metadata = AlloyMetadata.NewSimple("tenant");

        var encrypted = await _sdk.Vector().Encrypt(plaintext, metadata);
        var decrypted = await _sdk.Vector().Decrypt(encrypted, metadata);

        for (int i = 0; i < data.Length; i++)
        {
            Assert.InRange(
                Math.Abs(data[i] - decrypted.PlaintextVectorValue[i]),
                0f,
                FloatComparisonDelta
            );
        }
    }

    [Fact]
    public async Task SeededSdkVectorEncrypt()
    {
        var data = new float[] { 0.1f, -0.2f };
        var plaintext = new PlaintextVector(data, "", "");
        var metadata = AlloyMetadata.NewSimple("tenant");

        var encrypted = await _seededSdk.Vector().Encrypt(plaintext, metadata);
        Assert.Equal(new float[] { 0.1299239844083786f, -0.3532053828239441f }, encrypted.EncryptedVectorValue);
    }

    [Fact]
    public async Task SdkVectorDecrypt()
    {
        var ciphertext = new float[] { 4422816.0f, 15091436.0f, 9409391.0f };
        var iclMetadata = Convert.FromBase64String(
            "AAAAAoEACgxFUZiS8PORQubGnk8SIJKbkabplwXSyzEJvXKalrg+Os+OCyDFzMZ2Tf3rei8g"
        );
        var encrypted = new EncryptedVector(ciphertext, "", "", iclMetadata);
        var metadata = AlloyMetadata.NewSimple("tenant");

        var decrypted = await _sdkWithScaling.Vector().Decrypt(encrypted, metadata);
        Assert.Equal(new float[] { 1.0f, 2.0f, 3.0f }, decrypted.PlaintextVectorValue);
    }

    [Fact]
    public async Task SdkBatchRoundtripVector()
    {
        var data = new float[] { 1.0f, 2.0f, 3.0f };
        var plaintext = new PlaintextVector(data, "", "");
        var badVector = new PlaintextVector(data, "bad_path", "bad_path");
        var metadata = AlloyMetadata.NewSimple("tenant");
        var plaintextVectors = new Dictionary<string, PlaintextVector>
        {
            { "vec", plaintext },
            { "badVec", badVector }
        };

        var encrypted = await _sdk.Vector().EncryptBatch(plaintextVectors, metadata);
        Assert.Single(encrypted.Successes);
        Assert.Single(encrypted.Failures);
        Assert.Contains(
            "Provided secret path `bad_path` does not exist in the vector configuration.",
            encrypted.Failures["badVec"].Message
        );

        var decrypted = await _sdk.Vector().DecryptBatch(encrypted.Successes, metadata);
        Assert.Single(decrypted.Successes);
        Assert.Empty(decrypted.Failures);
        for (int i = 0; i < data.Length; i++)
        {
            Assert.InRange(
                Math.Abs(data[i] - decrypted.Successes["vec"].PlaintextVectorValue[i]),
                0,
                FloatComparisonDelta
            );
        }
    }

    [Fact]
    public async Task SdkVectorRotateDifferentTenant()
    {
        var ciphertext = new float[] { 4422816.0f, 15091436.0f, 9409391.0f };
        var iclMetadata = Convert.FromBase64String(
            "AAAAAoEACgxFUZiS8PORQubGnk8SIJKbkabplwXSyzEJvXKalrg+Os+OCyDFzMZ2Tf3rei8g"
        );
        var encrypted = new EncryptedVector(ciphertext, "", "", iclMetadata);
        var vectors = new Dictionary<string, EncryptedVector> { { "vector", encrypted } };
        var metadata = AlloyMetadata.NewSimple("tenant");

        var rotated = await _sdkWithScaling.Vector().RotateVectors(vectors, metadata, "tenant2");
        Assert.Single(rotated.Successes);
        Assert.Empty(rotated.Failures);
        Assert.True(rotated.Successes.ContainsKey("vector"));

        var newMetadata = AlloyMetadata.NewSimple("tenant2");
        var decrypted = await _sdkWithScaling.Vector().Decrypt(rotated.Successes["vector"], newMetadata);
        var expected = new float[] { 1.0f, 2.0f, 3.0f };
        for (int i = 0; i < decrypted.PlaintextVectorValue.Length; i++)
        {
            Assert.InRange(
                Math.Abs(expected[i] - decrypted.PlaintextVectorValue[i]),
                0f,
                FloatComparisonDelta
            );
        }
    }

    [Fact]
    public async Task SdkVectorRotateDifferentKey()
    {
        var vectorSecrets2 = new Dictionary<string, VectorSecret>
        {
            {
                "",
                VectorSecret.NewWithScalingFactor(
                    ApproximationFactor,
                    new RotatableSecret(
                        new StandaloneSecret(1, new Secret(KeyByteArray)),
                        new StandaloneSecret(2, new Secret(KeyByteArray))
                    )
                )
            }
        };
        var config2 = new StandaloneConfiguration(_standardSecrets, _deterministicSecrets, vectorSecrets2);
        var sdk2 = new Standalone(config2);
        var ciphertext = new float[] { 4422816.0f, 15091436.0f, 9409391.0f };
        var iclMetadata = Convert.FromBase64String(
            "AAAAAoEACgxFUZiS8PORQubGnk8SIJKbkabplwXSyzEJvXKalrg+Os+OCyDFzMZ2Tf3rei8g"
        );
        var encrypted = new EncryptedVector(ciphertext, "", "", iclMetadata);
        var vectors = new Dictionary<string, EncryptedVector> { { "vector", encrypted } };
        var metadata = AlloyMetadata.NewSimple("tenant");

        var rotated = await sdk2.Vector().RotateVectors(vectors, metadata, "tenant");
        Assert.Single(rotated.Successes);
        Assert.Empty(rotated.Failures);

        var vectorSecrets3 = new Dictionary<string, VectorSecret>
        {
            {
                "",
                VectorSecret.NewWithScalingFactor(
                    ApproximationFactor,
                    new RotatableSecret(
                        new StandaloneSecret(1, new Secret(KeyByteArray)),
                        null
                    )
                )
            }
        };
        var config3 = new StandaloneConfiguration(_standardSecrets, _deterministicSecrets, vectorSecrets3);
        var sdk3 = new Standalone(config3);
        var decrypted = await sdk3.Vector().Decrypt(rotated.Successes["vector"], metadata);
        var expected = new float[] { 1.0f, 2.0f, 3.0f };
        for (int i = 0; i < decrypted.PlaintextVectorValue.Length; i++)
        {
            Assert.InRange(
                Math.Abs(expected[i] - decrypted.PlaintextVectorValue[i]),
                0f,
                FloatComparisonDelta
            );
        }
    }

    [Fact]
    public async Task SdkEncryptDeterministic()
    {
        var field = new PlaintextField(
            System.Text.Encoding.UTF8.GetBytes("My data"), "", ""
        );
        var metadata = AlloyMetadata.NewSimple("tenant");

        var encrypted = await _sdk.Deterministic().Encrypt(field, metadata);
        var expected = Convert.FromBase64String("AAAAAoAA4hdzU2eh2aeCoUSq6NQiWYczhmQQNak=");
        Assert.Equal(expected, encrypted.EncryptedFieldValue);
    }

    [Fact]
    public async Task SdkDecryptDeterministic()
    {
        var ciphertext = Convert.FromBase64String("AAAAAoAA4hdzU2eh2aeCoUSq6NQiWYczhmQQNak=");
        var encryptedField = new EncryptedField(ciphertext, "", "");
        var metadata = AlloyMetadata.NewSimple("tenant");

        var decrypted = await _sdk.Deterministic().Decrypt(encryptedField, metadata);
        var expected = System.Text.Encoding.UTF8.GetBytes("My data");
        Assert.Equal(expected, decrypted.PlaintextFieldValue);
    }

    [Fact]
    public async Task SdkBatchRoundtripDeterministic()
    {
        var plaintextInput = System.Text.Encoding.UTF8.GetBytes("My data");
        var field = new PlaintextField(plaintextInput, "", "");
        var badField = new PlaintextField(
            System.Text.Encoding.UTF8.GetBytes("My data"), "bad_path", "bad_path"
        );
        var metadata = AlloyMetadata.NewSimple("tenant");
        var plaintextFields = new Dictionary<string, PlaintextField>
        {
            { "doc", field },
            { "badDoc", badField }
        };

        var encrypted = await _sdk.Deterministic().EncryptBatch(plaintextFields, metadata);
        Assert.Single(encrypted.Successes);
        Assert.Single(encrypted.Failures);
        Assert.Contains(
            "Provided secret path `bad_path` does not exist in the deterministic configuration.",
            encrypted.Failures["badDoc"].Message
        );

        var decrypted = await _sdk.Deterministic().DecryptBatch(encrypted.Successes, metadata);
        Assert.Single(decrypted.Successes);
        Assert.Empty(decrypted.Failures);
        Assert.Equal(plaintextInput, decrypted.Successes["doc"].PlaintextFieldValue);
    }

    [Fact]
    public async Task SdkStandardRoundtrip()
    {
        var plaintextDocument = new Dictionary<string, byte[]>
        {
            { "foo", System.Text.Encoding.UTF8.GetBytes("My data") }
        };
        var metadata = AlloyMetadata.NewSimple("tenant");

        var encrypted = await _sdk.Standard().Encrypt(plaintextDocument, metadata);
        Assert.True(encrypted.Document.ContainsKey("foo"));
        var decrypted = await _sdk.Standard().Decrypt(encrypted, metadata);
        Assert.Equal(plaintextDocument["foo"], decrypted["foo"]);
    }

    [Fact]
    public async Task SeededSdkStandardEncrypt()
    {
        var plaintextDocument = new Dictionary<string, byte[]>
        {
            { "foo", System.Text.Encoding.UTF8.GetBytes("My data") }
        };
        var metadata = AlloyMetadata.NewSimple("tenant");

        var encrypted = await _seededSdk.Standard().Encrypt(plaintextDocument, metadata);
        Assert.True(encrypted.Document.ContainsKey("foo"));
        Assert.Equal(
            "AElST04OFx9g3p5TQTSIGaJrUPuq79Di9DmR0uK5/n6lXAis5Ip45Q==",
            Convert.ToBase64String(encrypted.Document["foo"])
        );
    }

    [Fact]
    public async Task SdkStandardBatchRoundtrip()
    {
        var plaintextDocument = new Dictionary<string, byte[]>
        {
            { "foo", System.Text.Encoding.UTF8.GetBytes("My data") }
        };
        var plaintextDocuments = new Dictionary<string, Dictionary<string, byte[]>>
        {
            { "doc", plaintextDocument }
        };
        var metadata = AlloyMetadata.NewSimple("tenant");

        var encrypted = await _sdk.Standard().EncryptBatch(plaintextDocuments, metadata);
        Assert.Single(encrypted.Successes);
        Assert.Empty(encrypted.Failures);

        var decrypted = await _sdk.Standard().DecryptBatch(encrypted.Successes, metadata);
        Assert.Single(decrypted.Successes);
        Assert.Empty(decrypted.Failures);
    }

    [Fact]
    public async Task SdkStandardAttachedRoundtrip()
    {
        byte[] plaintextDocument = System.Text.Encoding.UTF8.GetBytes("My data");
        var metadata = AlloyMetadata.NewSimple("tenant");

        var encrypted = await _sdk.StandardAttached().Encrypt(plaintextDocument, metadata);
        var decrypted = await _sdk.StandardAttached().Decrypt(encrypted, metadata);
        Assert.Equal(plaintextDocument, decrypted);
    }

    [Fact]
    public async Task SdkStandardAttachedRoundtripBatch()
    {
        byte[] plaintextDocument = System.Text.Encoding.UTF8.GetBytes("My data");
        var metadata = AlloyMetadata.NewSimple("tenant");
        var documents = new Dictionary<string, byte[]> { { "doc", plaintextDocument } };

        var encrypted = await _sdk.StandardAttached().EncryptBatch(documents, metadata);
        Assert.Single(encrypted.Successes);
        Assert.Empty(encrypted.Failures);

        var newEncrypted = new Dictionary<string, byte[]>
        {
            { "badDoc", System.Text.Encoding.UTF8.GetBytes("bad") },
            { "doc", encrypted.Successes["doc"] }
        };
        var decrypted = await _sdk.StandardAttached().DecryptBatch(newEncrypted, metadata);
        Assert.Single(decrypted.Successes);
        Assert.Single(decrypted.Failures);
        Assert.Equal(plaintextDocument, decrypted.Successes["doc"]);
    }

    [Fact]
    public async Task SdkStandardAttachedDecryptV4()
    {
        var encryptedDocument = Convert.FromBase64String(
            "BElST04AdgokCiAsN4NHsRTS4bq0a6wE9QUJFbWSf67pqkIgrzHPfztA3RABEk4STBpKCgxVKAX2fYD7F4W13dwSMN6LnbYAlUgekKbpI0z9LFeoUNNJZTUDX7WqoDZSWJ+uSEOoR7U8YSnaBlTBG8tw5hoIOX50ZW5hbnRIXNdHBgvQNRD/s1lTAxgMaKrMv0CL2AwLFuNtKPpLjObeLmdAkYKpe+uwbg=="
        );
        var metadata = AlloyMetadata.NewSimple("tenant");
        var decrypted = await _sdk.StandardAttached().Decrypt(encryptedDocument, metadata);
        Assert.Equal(
            System.Text.Encoding.UTF8.GetBytes("{\"title\":\"blah\"}"),
            decrypted
        );
    }

    [Fact]
    public async Task SdkStandardAttachedRekeyV4()
    {
        var encryptedDocument = Convert.FromBase64String(
            "BElST04AdgokCiAsN4NHsRTS4bq0a6wE9QUJFbWSf67pqkIgrzHPfztA3RABEk4STBpKCgxVKAX2fYD7F4W13dwSMN6LnbYAlUgekKbpI0z9LFeoUNNJZTUDX7WqoDZSWJ+uSEOoR7U8YSnaBlTBG8tw5hoIOX50ZW5hbnRIXNdHBgvQNRD/s1lTAxgMaKrMv0CL2AwLFuNtKPpLjObeLmdAkYKpe+uwbg=="
        );
        var metadata = AlloyMetadata.NewSimple("tenant");
        var documents = new Dictionary<string, byte[]> { { "doc", encryptedDocument } };

        var rekeyed = await _sdk.StandardAttached().RekeyDocuments(documents, metadata, null);
        Assert.Single(rekeyed.Successes);
        Assert.Empty(rekeyed.Failures);

        var decrypted = await _sdk.StandardAttached().Decrypt(rekeyed.Successes["doc"], metadata);
        Assert.Equal(
            System.Text.Encoding.UTF8.GetBytes("{\"title\":\"blah\"}"),
            decrypted
        );
    }

    [Fact]
    public async Task SdkStandardAttachedRekeyNewTenant()
    {
        byte[] plaintextDocument = System.Text.Encoding.UTF8.GetBytes("My data");
        var metadata = AlloyMetadata.NewSimple("tenant");
        var documents = new Dictionary<string, byte[]> { { "doc", plaintextDocument } };

        var encrypted = await _sdk.StandardAttached().EncryptBatch(documents, metadata);
        var rekeyed = await _sdk.StandardAttached().RekeyDocuments(
            encrypted.Successes, metadata, "new_tenant"
        );
        Assert.Single(rekeyed.Successes);
        Assert.Empty(rekeyed.Failures);

        var ex = await Assert.ThrowsAsync<AlloyException.DecryptException>(async () =>
            await _sdk.StandardAttached().Decrypt(rekeyed.Successes["doc"], metadata)
        );
        Assert.Contains("Ensure the data and key are correct.", ex.Message);

        var newMetadata = AlloyMetadata.NewSimple("new_tenant");
        var decrypted = await _sdk.StandardAttached().Decrypt(rekeyed.Successes["doc"], newMetadata);
        Assert.Equal(plaintextDocument, decrypted);
    }

    [Fact]
    public async Task SdkStandardRekeyEdeks()
    {
        var plaintextDocument = new Dictionary<string, byte[]>
        {
            { "foo", System.Text.Encoding.UTF8.GetBytes("My data") }
        };
        var metadata = AlloyMetadata.NewSimple("tenant");
        var newTenantId = "tenant2";
        var newMetadata = AlloyMetadata.NewSimple(newTenantId);

        var encrypted = await _sdk.Standard().Encrypt(plaintextDocument, metadata);
        Assert.True(encrypted.Document.ContainsKey("foo"));

        var edeks = new Dictionary<string, byte[]> { { "edek", encrypted.Edek } };
        var rekeyed = await _sdk.Standard().RekeyEdeks(edeks, metadata, newTenantId);
        Assert.Single(rekeyed.Successes);
        Assert.Empty(rekeyed.Failures);

        var remadeDocument = new EncryptedDocument(rekeyed.Successes["edek"], encrypted.Document);
        var decrypted = await _sdk.Standard().Decrypt(remadeDocument, newMetadata);
        Assert.Equal(plaintextDocument["foo"], decrypted["foo"]);
    }

    [Fact]
    public async Task SdkStandardEncryptWithExistingEdek()
    {
        var plaintextDocument = new Dictionary<string, byte[]>
        {
            { "foo", System.Text.Encoding.UTF8.GetBytes("My data") }
        };
        var plaintextDocument2 = new Dictionary<string, byte[]>
        {
            { "foo", System.Text.Encoding.UTF8.GetBytes("My data2") }
        };
        var metadata = AlloyMetadata.NewSimple("tenant");

        var encrypted = await _sdk.Standard().Encrypt(plaintextDocument, metadata);
        var encrypted2 = await _sdk.Standard().EncryptWithExistingEdek(
            new PlaintextDocumentWithEdek(encrypted.Edek, plaintextDocument2), metadata
        );

        var decrypted = await _sdk.Standard().Decrypt(encrypted2, metadata);
        Assert.Equal(encrypted.Edek, encrypted2.Edek);
        Assert.Equal(plaintextDocument2["foo"], decrypted["foo"]);
    }

    [Fact]
    public async Task SdkStandardEncryptWithExistingEdekBatch()
    {
        var plaintextDocument = new Dictionary<string, byte[]>
        {
            { "foo", System.Text.Encoding.UTF8.GetBytes("My data") }
        };
        var plaintextDocument2 = new Dictionary<string, byte[]>
        {
            { "foo", System.Text.Encoding.UTF8.GetBytes("My data2") }
        };
        var metadata = AlloyMetadata.NewSimple("tenant");

        var encrypted = await _sdk.Standard().Encrypt(plaintextDocument, metadata);
        var plaintexts = new Dictionary<string, PlaintextDocumentWithEdek>
        {
            { "doc", new PlaintextDocumentWithEdek(encrypted.Edek, plaintextDocument2) }
        };
        var batchEncrypted = await _sdk.Standard().EncryptWithExistingEdekBatch(plaintexts, metadata);
        Assert.Single(batchEncrypted.Successes);
        Assert.Empty(batchEncrypted.Failures);

        var encrypted2 = batchEncrypted.Successes["doc"];
        var decrypted = await _sdk.Standard().Decrypt(encrypted2, metadata);
        Assert.Equal(encrypted.Edek, encrypted2.Edek);
        Assert.Equal(plaintextDocument2["foo"], decrypted["foo"]);
    }

    [Fact]
    public async Task SdkStandardDecryptWrongType()
    {
        var documentFields = new Dictionary<string, byte[]>
        {
            { "foo", Convert.FromBase64String("AAAAAoAA4hdzU2eh2aeCoUSq6NQiWYczhmQQNak=") }
        };
        var metadata = AlloyMetadata.NewSimple("tenant");
        var edek = Convert.FromBase64String(
            "AAAACoAACiQKID/RxqsV0L1yky5NMwXNlNtn5s5vi+PR92RKN7Iqa5TtEAESRxJFGkMKDPgVFQkpAEd89NH8lxIwTTUTiyiyB1GgXxLRBjVwJ94065fjRYvQzwggXAQcO35ZV2CxkS2nS44xDvlHHc9GGgEx"
        );
        var document = new EncryptedDocument(edek, documentFields);
        var ex = await Assert.ThrowsAsync<AlloyException.InvalidInput>(async () =>
            await _sdk.Standard().Decrypt(document, metadata)
        );
        Assert.Contains("not a Standalone Standard EDEK wrapped value.", ex.Message);
    }

    [Fact]
    public void HttpNotAllowed()
    {
        var ex = Assert.Throws<AlloyException.InvalidConfiguration>(() =>
            new SaasShieldConfiguration("http://bad-url", "0WUaXesNgbTAuLwn", 1.1f, null!, false)
        );
        Assert.Contains("insecure", ex.Message);
    }

    [Fact]
    public async Task BadConfigurationTest()
    {
        var httpClient = new CSharpHttpClient();
        var badSdk = new SaasShield(
            new SaasShieldConfiguration("https://bad-url", "0WUaXesNgbTAuLwn", 1.1f, httpClient, false)
        );
        var data = new float[] { 1.0f, 2.0f, 3.0f };
        var plaintext = new PlaintextVector(data, "", "");
        var metadata = AlloyMetadata.NewSimple("fake_tenant");
        var ex = await Assert.ThrowsAsync<AlloyException.RequestException>(async () =>
            await badSdk.Vector().Encrypt(plaintext, metadata)
        );
        Assert.Contains("JSON post request", ex.Message);
    }

    [Fact(Skip = "Integration test. Requires TSP running at localhost:32804. Remove Skip to run.")]
    public async Task IntegrationSdkUnknownTenant()
    {
        var httpClient = new CSharpHttpClient();
        var integrationSdk = new SaasShield(
            new SaasShieldConfiguration("http://localhost:32804", "0WUaXesNgbTAuLwn", 1.1f, httpClient, true)
        );
        var data = new float[] { 1.0f, 2.0f, 3.0f };
        var plaintext = new PlaintextVector(data, "", "");
        var metadata = AlloyMetadata.NewSimple("fake-tenant");
        var ex = await Assert.ThrowsAsync<AlloyException.TspException>(async () =>
            await integrationSdk.Vector().Encrypt(plaintext, metadata)
        );
        Assert.Contains("Tenant either doesn't exist", ex.Message);
    }
}
