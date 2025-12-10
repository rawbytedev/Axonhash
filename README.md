# AxonHash

![Tests](https://github.com/rawbytedev/axonhash/actions/workflows/run_test.yml/badge.svg)
![GitHub last commit](https://img.shields.io/github/last-commit/rawbytedev/axonhash)
![Python](https://img.shields.io/badge/python-3.8+-blue.svg)

AxonHash is a research and prototyping cryptographic hash function based on ARX (Add-Rotate-Xor) permutation and Merkle tree construction. It is designed for educational, experimental, and benchmarking purposes.

## Features

- **ARX Permutation:** Modern, efficient mixing using add, rotate, and xor operations.
- **Merkle Tree Aggregation:** Parallelizable leaf hashing and secure digest aggregation.
- **Configurable Block Size:** User can set chunk size for flexibility and experimentation.
- **Domain Separation:** Supports domain tags for protocol separation.
- **Extendable Output (XOF):** Can produce digests of arbitrary length.
- **Profiling and Testing:** Includes scripts for benchmarking and avalanche/collision testing.

## Usage

### Hashing Example

```python
from main import Axon

# Hash a message
h = Axon(b"hello world")
digest = h.digest()           # Raw bytes
digest_hex = h.hexdigest()    # Hex string
print(digest_hex)
```

### Customization

- **Chunk Size:** Set via the `chunks` parameter (default: 64 bytes)
- **Rounds:** Set via the `round` parameter (default: 4)
- **Domain Tag:** Set via the `domain` parameter

```python
h = Axon(b"data", chunks=32, round=8, domain=0x42)
```

### Profiling

Run `profiler.py` to benchmark different stages of the hash pipeline.

### Testing

Run `axon_test.py` for avalanche, collision, and speed tests:

```bash
python axon_test.py
```

## File Structure

- `parallel.py`  : Standalone and parallelized hash utilities
- `profiler.py`  : Profiling and benchmarking script
- `axon_test.py` : Test suite for correctness and performance
- `axon.py`      : Shared core functions

## Security Notice

**AxonHash is experimental and has not undergone professional cryptanalysis. Do not use it for production or security-critical applications.**

## License

MIT License

## Author

[@rawbytedev](https://github.com/rawbytedev)
