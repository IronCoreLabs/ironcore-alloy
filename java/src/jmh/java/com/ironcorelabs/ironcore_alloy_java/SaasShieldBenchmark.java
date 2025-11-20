package test;

import com.ironcorelabs.ironcore_alloy_java.*;
import org.openjdk.jmh.annotations.*;
import java.util.*;
import java.util.concurrent.TimeUnit;
import okhttp3.*;
import java.util.concurrent.CompletableFuture;

class JavaHttpClient implements HttpClient {
    OkHttpClient client;

    public JavaHttpClient() {
        this.client = new OkHttpClient();
    }

    @Override
    public CompletableFuture<AlloyHttpClientResponse> postJson(String url, String jsonBody,
            AlloyHttpClientHeaders headers) {
        RequestBody body = RequestBody.create(jsonBody, MediaType.get("application/json"));
        Request request =
                new Request.Builder().url(url).header("Content-Type", headers.contentType())
                        .header("Authorization", headers.authorization()).post(body).build();
        CompletableFuture<AlloyHttpClientResponse> future = new CompletableFuture<>();
        client.newCall(request).enqueue(new Callback() {
            @Override
            public void onFailure(Call call, java.io.IOException e) {
                future.completeExceptionally(new AlloyException.RequestException(
                        "Failed to make JSON post request: " + e.getMessage()));
            }

            @Override
            public void onResponse(Call call, Response response) throws java.io.IOException {
                future.complete(new AlloyHttpClientResponse(response.body().string(),
                        (short) response.code()));
            }
        });
        return future;
    }
}


@State(Scope.Benchmark)
@Fork(1)
@Warmup(iterations = 1)
@BenchmarkMode(Mode.AverageTime)
@OutputTimeUnit(TimeUnit.MICROSECONDS)
@Measurement(iterations = 5, time = 1, timeUnit = TimeUnit.SECONDS)
public class SaasShieldBenchmark {

    private PlaintextDocument smallPlaintext;
    private PlaintextDocument mediumPlaintext;
    private PlaintextDocument largePlaintext;
    private PlaintextDocument extraLargePlaintext;
    private EncryptedDocument smallEncrypted;
    private EncryptedDocument mediumEncrypted;
    private EncryptedDocument largeEncrypted;
    private EncryptedDocument extraLargeEncrypted;
    private PlaintextDocuments batchPlaintexts;

    private final float approximationFactor = 1.1f;
    private final String tspUri = System.getenv().getOrDefault("TSP_ADDRESS", "http://localhost");
    private final String tspPort = System.getenv().getOrDefault("TSP_PORT", "32804");
    private final TenantId tenantId =
            new TenantId(System.getenv().getOrDefault("TENANT_ID", "tenant-gcp-l"));
    private final String apiKey = System.getenv().getOrDefault("API_KEY", "0WUaXesNgbTAuLwn");

    private JavaHttpClient httpClient;
    private SaasShieldConfiguration saasShieldConfig;
    private SaasShield saasShieldSdk;
    private final AlloyMetadata metadata = AlloyMetadata.newSimple(tenantId);

    @Setup
    public void setUp() throws Exception {
        httpClient = new JavaHttpClient();
        saasShieldConfig = new SaasShieldConfiguration(tspUri + ":" + tspPort, apiKey,
                approximationFactor, httpClient, true);
        saasShieldSdk = new SaasShield(saasShieldConfig);
        smallPlaintext = generatePlaintextDocument(1, 1);
        mediumPlaintext = generatePlaintextDocument(100, 1);
        largePlaintext = generatePlaintextDocument(10_000, 1);
        extraLargePlaintext = generatePlaintextDocument(1_000_000, 1);

        batchPlaintexts = new PlaintextDocuments(new HashMap<>());
        int numDocuments = 10;
        int numFields = 10;
        int fieldSize = 10;

        for (int i = 1; i <= numDocuments; i++) {
            batchPlaintexts.value().put(new DocumentId("doc" + i),
                    generatePlaintextDocument(fieldSize, numFields));
        }

        smallEncrypted = saasShieldSdk.standard().encrypt(smallPlaintext, metadata).get();
        mediumEncrypted = saasShieldSdk.standard().encrypt(mediumPlaintext, metadata).get();
        largeEncrypted = saasShieldSdk.standard().encrypt(largePlaintext, metadata).get();
        extraLargeEncrypted = saasShieldSdk.standard().encrypt(extraLargePlaintext, metadata).get();
    }

    @TearDown
    public void tearDown() {
        saasShieldSdk.close();
        httpClient.client.dispatcher().executorService().shutdown();
        httpClient.client.connectionPool().evictAll();
    }

    private PlaintextDocument generatePlaintextDocument(int bytesPerField, int numFields) {
        PlaintextDocument documentMap = new PlaintextDocument(new HashMap<>());
        for (int i = 1; i <= numFields; i++) {
            PlaintextBytes byteArray = new PlaintextBytes(new byte[bytesPerField]);
            new Random().nextBytes(byteArray.value());
            documentMap.value().put(new FieldId("field" + i), byteArray);
        }
        return documentMap;
    }

    private void encrypt(PlaintextDocument plaintext) throws Exception {
        saasShieldSdk.standard().encrypt(plaintext, metadata).get();
    }

    private void decrypt(EncryptedDocument document) throws Exception {
        saasShieldSdk.standard().decrypt(document, metadata).get();
    }

    @Benchmark
    public void tspEncrypt1B() throws Exception {
        encrypt(smallPlaintext);
    }

    @Benchmark
    public void tspEncrypt100B() throws Exception {
        encrypt(mediumPlaintext);
    }

    @Benchmark
    public void tspEncrypt10KB() throws Exception {
        encrypt(largePlaintext);
    }

    @Benchmark
    public void tspEncrypt1MB() throws Exception {
        encrypt(extraLargePlaintext);
    }

    @Benchmark
    public void tspDecrypt1B() throws Exception {
        decrypt(smallEncrypted);
    }

    @Benchmark
    public void tspDecrypt100B() throws Exception {
        decrypt(mediumEncrypted);
    }

    @Benchmark
    public void tspDecrypt10KB() throws Exception {
        decrypt(largeEncrypted);
    }

    @Benchmark
    public void tspDecrypt1MB() throws Exception {
        decrypt(extraLargeEncrypted);
    }

    @Benchmark
    public void batchEncrypt10DocsOf100B() throws Exception {
        saasShieldSdk.standard().encryptBatch(batchPlaintexts, metadata).get();
    }
}
