"""
AxonHash Parallel and Utility Functions
--------------------------------------
This module provides parallelized hashing, permutation, Merkle tree construction, and utility functions
for the AxonHash cryptographic hash function. It is designed for research and prototyping purposes.

Author: rawbytedev 
"""
import time
from utils import *
from parallel import parallel_leaf_hashing
from axon import Axon
import random

def testbasichash():
    data = b"Hello, AxonHash!"
    state = ivfromidentity("AxonHash-1.0")
    chunks = chunk(data, 64)

    digests = [hashblock(chunk, i, state, 12) for i, chunk in enumerate(chunks)]
    root = buildmerkletree(digests)
    final = finalize(root.digest, len(data), domain_tag=0x01)

    output = xof(final, output_len=32)
    assert len(output) == 32
    print("Basic test passed:", output.hex())

def test_avalanche():
    data1 = b"The quick brown fox jumps over the lazy dog"
    data2 = bytearray(data1)
    data2[0] ^= 0x01  # Flip 1 bit

    def get_digest(data):
        state = ivfromidentity()
        chunks = chunk(data, 64)
        digests = [hashblock(chunk, i, state, 12) for i, chunk in enumerate(chunks)]
        root = buildmerkletree(digests)
        final = finalize(root.digest, len(data), 0x01)
        return xof(final, 32)

    digest1 = get_digest(data1)
    digest2 = get_digest(data2)

    diff_bits = sum(bin(a ^ b).count("1") for a, b in zip(digest1, digest2))
    print(f"Avalanche diff: {diff_bits} bits out of 256")
    assert diff_bits > 100, "Avalanche effect too weak"

def testcollisionresistance():
    base = b"FractusNode_"
    outputs = set()
    for i in range(50):
        msg = base + str(i).encode()
        state = ivfromidentity()
        chunks = chunk(msg, 64)
        digests = [hashblock(chunk, j, state, 12) for j, chunk in enumerate(chunks)]
        root = buildmerkletree(digests)
        final = finalize(root.digest, len(msg), 0x01)
        output = xof(final, 32)
        outputs.add(output)

    assert len(outputs) == 50, "Collision detected!"
    print("Collision test passed: 50 unique digests")

def benchmark():
    data = b"A" * 1024  # 1 KB input
    rounds = [8, 12, 16]
    for r in rounds:
        start = time.time()
        state = ivfromidentity()
        chunks = chunk(data, 64)
        digests = [hashblock(c, i, state, r) for i, c in enumerate(chunks)]
        root = buildmerkletree(digests)
        final = finalize(root.digest, len(data), 0x01)
        digest = xof(final, 32)
        elapsed = time.time() - start
        print(f"Rounds {r}: {elapsed:.4f}s — Digest: {digest.hex()}")

def benchmark_speed(input_size_kb=1024,rounds=12, output_len=32):
    print(f"\n Benchmarking {input_size_kb} KB input @ {rounds} rounds...")
    data = b"A"*(input_size_kb*1024)
    state = ivfromidentity()
    start = time.perf_counter()
    chunks = chunk(data, 64)
    digests = parallel_leaf_hashing(chunks=chunks, state=state,rounds=rounds)
    #digests =[hashblock(c, i , state, rounds) for i,c in enumerate(chunks)]
    root = buildmerkletree(digests)
    final_state = finalize(root.digest, len(data), domain_tag=0x01)
    digest = xof(final_state, output_len)
    elapsed = time.perf_counter() - start
    throughput_mb = (len(data)/1024/1024)/elapsed
    print(f"Digest: {digest.hex()}")
    print(f"Speed: {throughput_mb:.2f} MB/s ({elapsed:.4f}s elapsed)")

def bit_distribution_test(num_samples=10000, outputlen=32):
    bit_counts = [0] * (outputlen * 8)
    for _ in range(num_samples):
        data = random.randbytes(64)
        digest = Axon(data).digest()
        for i, byte in enumerate(digest):
            for b in range(8):
                if (byte >> b) & 1:
                    bit_counts[i*8 + b] += 1
    for i, count in enumerate(bit_counts):
        print(f'Bit {i}: {count/num_samples:.4f}')

# 1. Second Preimage Resistance Test
def test_second_preimage():
    data1 = b"AxonHash second preimage test"
    digest1 = Axon(data1).digest()
    # Try a few random modifications (should not match)
    for i in range(1000):
        data2 = bytearray(data1)
        idx = random.randint(0, len(data2)-1)
        data2[idx] ^= random.randint(1, 255)
        digest2 = Axon(bytes(data2)).digest()
        assert digest1 != digest2, "Second preimage found (unexpected)!"
    print("Second preimage test passed.")

# 2. Preimage Resistance Test
def test_preimage():
    data = b"AxonHash preimage test"
    digest = Axon(data).digest()
    # Try random inputs (should not match)
    for _ in range(1000):
        guess = random.randbytes(len(data))
        if Axon(guess).digest() == digest:
            raise AssertionError("Preimage found (unexpected)!")
    print("Preimage resistance test passed.")

# 3. Long Message Test
def test_long_message():
    data = b"A" * (10 * 1024 * 1024)  # 10 MB
    digest = Axon(data).digest()
    assert len(digest) == 32
    print("Long message test passed.")

# 4. Short Message Test
def test_short_message():
    for msg in [b"", b"A", b"B", b"123", b"\x00"]:
        digest = Axon(msg).digest()
        assert len(digest) == 32
    print("Short message test passed.")

# 5. Known Answer Test (KAT)
def test_known_answer():
    vectors = [
        (b"", "2c356f1e881b486469c807ecacf1ec2627f050f9783520f8cc44353f97612bef"),
        (b"abc", "baebca618da6d7e31e89cff1eac9c640a4a4ee6778bda49a4e4a12db56902c76"),
        (b"AxonHash", "9b1922517fcb0d3c8ae359ef21e2770b6a62e8e355a24e6c0fa8f530a77a9fe5"),
    ]
    # Fill in expected hex digests after first run
    for msg, expected in vectors:
        digest = Axon(msg).hexdigest()
        if expected:
            assert digest == expected, f"KAT failed for {msg!r}"
        else:
            print(f"KAT for {msg!r}: {digest}")
    print("Known answer test (KAT) completed.")

# 6. NIST SP 800-22 Randomness Test (data generation)
def generate_nist_randomness_file(filename="axonhash_nist.bin", num_hashes=10000):
    with open(filename, "wb") as f:
        for _ in range(num_hashes):
            data = random.randbytes(64)
            digest = Axon(data).digest()
            f.write(digest)
    print(f"Generated {filename} for NIST randomness tests.")

# 7. Thread Safety/Parallelism Test
import threading
def test_thread_safety():
    results = []
    def worker(data):
        results.append(Axon(data).digest())
    threads = []
    for i in range(10):
        t = threading.Thread(target=worker, args=(f"thread-{i}".encode(),))
        threads.append(t)
        t.start()
    for t in threads:
        t.join()
    assert len(results) == 10
    assert len(set(results)) == 10
    print("Thread safety test passed.")

# run all tests
def run_tests():
    testbasichash()
    test_avalanche()
    testcollisionresistance()
    benchmark()
    test_second_preimage()
    test_preimage()
    test_long_message()
    test_short_message()
    test_known_answer()
    test_thread_safety()
## 
def testspeed():
    for size in [64, 256]:
        for r in [2, 4, 6,8, 12, 16]:
            benchmark_speed(size, rounds=r)
if __name__ == '__main__':
    run_tests()
    bit_distribution_test()
    #generate_nist_randomness_file()
    #testbasichash()