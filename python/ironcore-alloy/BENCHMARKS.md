# Python Benchmarks

See `project_root/benches/README.md` for more general information about benchmarks and interpretation, along with links to benchmarks in the other languages.

## Usage

`hatch run bench:bench` to run the benchmarks. Python benchmarks are all Standalone right now, if you'd like to see TSP benchmarks in Python open up an issue (or a PR :)).
`hatch run bench:stats` to view the in-depth statistics of the most recent run.

## Results

The following benchmarking run was done on March 24th, 2025 on a Macbook M2 Max.

```text
vector encrypt d=384: Mean +- std dev: 1.07 ms +- 0.02 ms
vector encrypt d=768: Mean +- std dev: 2.07 ms +- 0.05 ms
vector encrypt d=1536: Mean +- std dev: 4.00 ms +- 0.05 ms
vector encrypt d=2048: Mean +- std dev: 5.26 ms +- 0.06 ms
vector batch (100) encrypt d=768: Mean +- std dev: 192 ms +- 2 ms
vector batch (1000) encrypt d=768: Mean +- std dev: 1.91 sec +- 0.01 sec
standard_roundtrip_10b: Mean +- std dev: 178 us +- 12 us
standard_roundtrip_10kb: Mean +- std dev: 3.75 ms +- 0.05 ms
standard_roundtrip_100kb: Mean +- std dev: 35.2 ms +- 0.4 ms
```
