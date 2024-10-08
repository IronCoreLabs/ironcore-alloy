# ironcore-alloy Rust Benchmarks

This directory contains a benchmark suite for the Rust version of ironcore-alloy.
To build and run the benchmark, just execute the following commands from this directory:

```
docker compose up -d
cargo bench
```

If you'd like to only run the benchmarks for standalone mode, which do not require a TSP, you can execute them by running:

```bash
cargo bench -- "^Standalone.*"
```

## Tenant Security Proxy

In order to run the benchmarks, ironcore-alloy needs to connect to a _Tenant Security Proxy (TSP)_.
This service is provided as a Docker container, so it is easy to run the proxy on any computer that has Docker
installed. IronCore Labs hosts the Docker container on a publicly accessible container registry, so you can pull
the image from there and run it locally.

In addition to the Docker containers, you need a configuration file that specifies how the TSP should communicate
with the IronCore Labs Configuration Broker and Data Control Platform, which work together to enable the end-to-end
encryption that keeps all of the tenant KMS configuration information secure. To simplify the process of running
these examples, we have created a demo vendor and tenants that you can use for the examples; all the necessary
configuration information is included in the [demo-tsp.conf](demo-tsp.conf) file in this directory.

**NOTE:** Normally, the file containing the configuration would be generated by the vendor and loaded into a
Kubernetes secret or similar mechanism for securely loading the configuration into the docker container. We
have included this configuration in the repository as a convenience. Also note that these accounts are all
created in IronCore's staging infrastructure.

Production TSPs will often be accompanied by one or more
[Tenant Security Logdriver](https://ironcorelabs.com/docs/saas-shield/tenant-security-logdriver/overview/) instances.
Because the purpose of this benchmark is to demonstrate the capabilities of ironcore-alloy Rust, we have chosen to not include
Logdriver in it. If you wish to modify the Docker Compose file to include Logdriver, be sure to consult its
[Deployment](https://ironcorelabs.com/docs/saas-shield/tenant-security-logdriver/deployment/) page to learn how to properly configure it
based on the resources you have available.

The following `docker compose` command will get a TSP running on your computer with the provided configuration:

```
docker compose up
```

This starts the TSP locally listening on port 32804. The benchmark expects to connect to the TSP at that address.

To connect with and use the TSP, you need to supply a couple more configuration values:
the first is the API key that the TSP uses to authenticate requests from ironcore-alloy,
and the second is the tenant ID to use.

The API key value is specified in the `demo-tsp.conf` file. You can just set the environment variable to the
same value:

`export API_KEY=0WUaXesNgbTAuLwn`

The benchmark can be run using a different cloud KMS by selecting a different tenant configured for our demo SaaS vendor.
There are six tenants defined; their IDs are the following:

- tenant-gcp
- tenant-aws
- tenant-azure
- tenant-gcp-l
- tenant-aws-l
- tenant-azure-l

The last three are similar to the first three, but they have _key leasing_ enabled.

By default, the benchmark will use the `tenant-gcp-l` tenant. If you would like to experiment with a different tenant, just do:

```bash
export TENANT_ID=<select tenant ID>
```

before running the benchmark.

## Interpreting Results

Since ironcore-alloy is a library that interacts with a back-end service (TSP), the benchmark results are not always straightforward to interpret. Most API calls in ironcore-alloy make a round-trip to the TSP, and the TSP also does some computation. If testing on a single machine, it is good to monitor the CPU/RAM usage of the TSP processes in addition to the Rust benchmark process to make sure you aren't resource constrained.

In general, operation latency is a function of latency to the TSP + latency to the tenant's KMS (if key-leasing is disabled).

The TSP's tenant logging mechanism has some tunable limits. By default, a TSP should be able to sustain 500 ops/sec/tenant, with the ability to burst higher for a limited time. The benchmark is using a single tenant, and (depending on your machine and benchmark config) can easily be executing a few thousand ops/sec. If you run a benchmark long enough you will overwhelm the TSP. In a real application, you would scale-out the TSP at this point. See [the TSP documentation](https://ironcorelabs.com/docs/saas-shield/tenant-security-proxy/deployment/) for more details.

## Other Languages

There are also benchmarks available in [Kotlin](https://github.com/IronCoreLabs/ironcore-alloy/tree/main/kotlin/benchmarks/src), [Java](https://github.com/IronCoreLabs/ironcore-alloy/tree/main/java/src/jmh/java/com/ironcorelabs/ironcore_alloy_java), and [Python](https://github.com/IronCoreLabs/ironcore-alloy/blob/main/python/ironcore-alloy/bench.py).

## Results

The following benchmarking run was done on August 30th, 2024 on a Lenovo Thinkpad X1 Extreme 2nd Gen with an i9-9880H CPU. It uses a locally-built TSP running with the configuration from `demo-tsp.conf`.

```
Standalone - vector_encrypt d=384
                        time:   [17.430 µs 17.573 µs 17.735 µs]
Standalone - vector_encrypt d=768
                        time:   [32.334 µs 32.547 µs 32.741 µs]
Standalone - vector_encrypt d=1536
                        time:   [60.878 µs 61.498 µs 62.147 µs]
Standalone - vector_encrypt d=2048
                        time:   [87.224 µs 88.124 µs 89.011 µs]
Standalone - vector_roundtrip d=384
                        time:   [39.432 µs 39.517 µs 39.622 µs]
Standalone - vector_roundtrip d=768
                        time:   [80.038 µs 80.114 µs 80.199 µs]
Standalone - vector_roundtrip d=1536
                        time:   [190.09 µs 191.63 µs 193.30 µs]
Standalone - vector_roundtrip d=2048
                        time:   [249.74 µs 251.00 µs 252.41 µs]
Standalone - roundtrip 10B
                        time:   [7.3951 µs 7.4709 µs 7.5491 µs]
Standalone - roundtrip 10KB
                        time:   [23.303 µs 23.426 µs 23.548 µs]
Standalone - roundtrip 100KB
                        time:   [179.20 µs 181.46 µs 183.65 µs]
TSP - vector_encrypt d=384
                        time:   [142.69 µs 152.19 µs 161.07 µs]
TSP - vector_encrypt d=768
                        time:   [172.72 µs 176.22 µs 181.64 µs]
TSP - vector_encrypt d=1536
                        time:   [218.59 µs 235.90 µs 248.05 µs]
TSP - vector_encrypt d=2048
                        time:   [270.12 µs 286.51 µs 298.61 µs]
TSP - vector_roundtrip d=384
                        time:   [312.78 µs 321.93 µs 333.69 µs]
TSP - vector_roundtrip d=768
                        time:   [383.62 µs 395.26 µs 409.41 µs]
TSP - vector_roundtrip d=1536
                        time:   [529.15 µs 545.48 µs 562.23 µs]
TSP - vector_roundtrip d=2048
                        time:   [651.78 µs 662.87 µs 675.18 µs]
TSP - encrypt 1B        time:   [126.73 µs 128.40 µs 130.31 µs]
TSP - encrypt 100B      time:   [130.53 µs 133.51 µs 135.96 µs]
TSP - encrypt 10KB      time:   [140.84 µs 143.25 µs 146.06 µs]
TSP - encrypt 1MB       time:   [1.2828 ms 1.3429 ms 1.4088 ms]
TSP - decrypt 1B        time:   [136.40 µs 144.30 µs 149.06 µs]
TSP - decrypt 100B      time:   [136.97 µs 141.28 µs 148.68 µs]
TSP - decrypt 10KB      time:   [159.37 µs 165.90 µs 175.01 µs]
TSP - decrypt 1MB       time:   [1.5501 ms 1.5733 ms 1.6051 ms]
TSP - batch encrypt 10 documents, 10 fields, 10B
                        time:   [412.43 µs 417.72 µs 421.34 µs]
```
