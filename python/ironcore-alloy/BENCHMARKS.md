# Python Benchmarks

See `project_root/benches/README.md` for more general information about benchmarks and interpretation, along with links to benchmarks in the other languages.

## Usage

`hatch run bench:bench` to run the benchmarks. Python benchmarks are all Standalone right now, if you'd like to see TSP benchmarks in Python open up an issue (or a PR :)).
`hatch run bench:stats` to view the in-depth statistics of the most recent run.

## Results

The following benchmarking run was done on August 30th, 2024 on a Lenovo Thinkpad X1 Extreme 2nd Gen with an i9-9880H CPU.

```
.....................
vector encrypt d=384: Mean +- std dev: 2.66 ms +- 0.14 ms
.....................
vector encrypt d=768: Mean +- std dev: 5.28 ms +- 0.25 ms
.....................
vector encrypt d=1536: Mean +- std dev: 10.3 ms +- 0.6 ms
.....................
vector encrypt d=2048: Mean +- std dev: 13.6 ms +- 0.7 ms
.....................
vector batch (100) encrypt d=768: Mean +- std dev: 416 ms +- 25 ms
.....................
vector batch (1000) encrypt d=768: Mean +- std dev: 4.14 sec +- 0.19 sec
.....................
standard_roundtrip_small: Mean +- std dev: 616 us +- 23 us
.....................
standard_roundtrip_medium: Mean +- std dev: 13.1 ms +- 0.6 ms
.....................
standard_roundtrip_large: Mean +- std dev: 124 ms +- 6 ms 
```
