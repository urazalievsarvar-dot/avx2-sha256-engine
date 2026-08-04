# High-Performance AVX2 SHA-256 Engine (C++)

Experimental SIMD-accelerated double SHA-256 implementation designed for algorithmic research and benchmarking on modern x86 architecture.

## Features
- **AVX2 Vectorization:** Batch hashing of 8 nonces in parallel.
- **Midstate Precomputation:** Optimizes header calculation by avoiding redundant initial block operations.
- **High Throughput:** Designed for native performance research.

## Build & Run
```bash
g++ -O3 -mavx2 demo_v6_main.cpp -o demo_v6.exe
./demo_v6.exe
