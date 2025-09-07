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

def profiledigestpipeline(data: bytes, rounds=12, output_len=32):
    timings = {}

    start = time.perf_counter()
    state = ivfromidentity()
    timings["ivgeneration"] = time.perf_counter() - start

    start = time.perf_counter()
    chunks = chunk(data, 64)
    timings["chunking"] = time.perf_counter() - start

    start = time.perf_counter()
    digests = parallel_leaf_hashing(chunks=chunks, state=state,rounds=rounds)
    #digests =[hashblock(c, i , state, rounds) for i,c in enumerate(chunks)]
    timings["leafhashing"] = time.perf_counter() - start

    start = time.perf_counter()
    root = buildmerkletree(digests)
    timings["merklebuild"] = time.perf_counter() - start

    start = time.perf_counter()
    finalstate = finalize(root.digest, len(data), domain_tag=0x01)
    timings["finalization"] = time.perf_counter() - start

    start = time.perf_counter()
    digest = xof(finalstate, output_len)
    timings["xofsqueeze"] = time.perf_counter() - start

    total = sum(timings.values())
    print(f"\n Digest profiling ({len(data)} bytes @ {rounds} rounds):")
    for stage, t in timings.items():
        print(f" - {stage:<15}: {t:.6f}s ({(t/total)*100:.1f}%)")
    print(f"\n Final digest ({output_len} bytes): {digest.hex()}")
    print(f" Total Time: {total:.6f}s")

for size in [64, 256]:
        for r in [8, 12, 16]:
            test_data = b"A" *(1024*size)  # 1 KB input
            profiledigestpipeline(test_data, rounds=r, output_len=32)