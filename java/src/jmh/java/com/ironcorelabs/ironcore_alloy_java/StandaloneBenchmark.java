package test;

import com.ironcorelabs.ironcore_alloy_java.*;
import org.openjdk.jmh.annotations.*;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.ThreadLocalRandom;

@State(Scope.Benchmark)
@Fork(1)
@Warmup(iterations = 1)
@BenchmarkMode(Mode.AverageTime)
@OutputTimeUnit(TimeUnit.MICROSECONDS)
@Measurement(iterations = 5, time = 1, timeUnit = TimeUnit.SECONDS)
public class StandaloneBenchmark {

    private PlaintextBytes smallWord;
    private PlaintextBytes mediumWord;
    private PlaintextBytes largeWord;

    private final byte[] keyByteArray = Base64.getDecoder().decode("hJdwvEeg5mxTu9qWcWrljfKs1ga4MpQ9MzXgLxtlkwX//yA=");
    private final float approximationFactor = 1.1f;

    private StandardSecrets standardSecrets;
    private Map<SecretPath, RotatableSecret> deterministicSecrets;
    private Map<SecretPath, VectorSecret> vectorSecrets;

    private StandaloneConfiguration standaloneConfig;
    private Standalone standaloneSdk;
    private final AlloyMetadata metadata = AlloyMetadata.newSimple(new TenantId("tenant-gcp-l"));

    @Setup
    public void setUp() throws Exception {
        standardSecrets = new StandardSecrets(10, java.util.List.of(new StandaloneSecret(10, new Secret(keyByteArray))));
        deterministicSecrets = 
            Map.of(new SecretPath(""), 
                new RotatableSecret(
                    new StandaloneSecret(2, new Secret(keyByteArray)),
                    new StandaloneSecret(1, new Secret(keyByteArray))
                )
            );
        vectorSecrets = 
            Map.of(new SecretPath(""), 
                new VectorSecret(
                    approximationFactor, 
                    new RotatableSecret(
                        new StandaloneSecret(2, new Secret(keyByteArray)),
                        new StandaloneSecret(1, new Secret(keyByteArray))
                    )
                )
            );

        standaloneConfig = new StandaloneConfiguration(standardSecrets, deterministicSecrets, vectorSecrets);
        standaloneSdk = new Standalone(standaloneConfig);
        smallWord = new PlaintextBytes(randomWord(1).getBytes());
        mediumWord = new PlaintextBytes(randomWord(10).getBytes());
        largeWord = new PlaintextBytes(randomWord(100).getBytes());
    }

    private String randomWord(int length) {
        char[] source = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789".toCharArray();
        char[] result = new char[length];
        for (int i = 0; i < length; i++) {
            result[i] = source[ThreadLocalRandom.current().nextInt(source.length)];
        }
        return new String(result);
    }

    @Benchmark
    public void standaloneRoundtripStandard10B() throws Exception {
        FieldId foo = new FieldId("foo");
        PlaintextDocument data = new PlaintextDocument(Map.of(foo, smallWord));

        EncryptedDocument encrypted = standaloneSdk.standard().encrypt(data, metadata).get();
        standaloneSdk.standard().decrypt(encrypted, metadata).get();
    }

    @Benchmark
    public void standaloneRoundtripStandard10Kb() throws Exception {
        FieldId foo = new FieldId("foo");
        PlaintextDocument data = new PlaintextDocument(Map.of(foo, mediumWord));

        EncryptedDocument encrypted = standaloneSdk.standard().encrypt(data, metadata).get();
        standaloneSdk.standard().decrypt(encrypted, metadata).get();
    }

    @Benchmark
    public void standaloneRoundtripStandard100Kb() throws Exception {
        FieldId foo = new FieldId("foo");
        PlaintextDocument data = new PlaintextDocument(Map.of(foo, largeWord));

        EncryptedDocument encrypted = standaloneSdk.standard().encrypt(data, metadata).get();
        standaloneSdk.standard().decrypt(encrypted, metadata).get();
    }
}
