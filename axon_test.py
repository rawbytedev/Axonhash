import time
from axon import *
from parallel import parallel_leaf_hashing

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


def run_tests():
    testbasichash()
    test_avalanche()
    testcollisionresistance()
    benchmark()
def testspeed():
    for size in [64, 256]:
        for r in [2, 4, 6,8, 12, 16]:
            benchmark_speed(size, rounds=r)
if __name__ == '__main__':
    testspeed()
    #run_tests()
    #testbasichash()