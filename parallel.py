"""
AxonHash Parallel and Utility Functions
--------------------------------------
This module provides parallelized hashing, permutation, Merkle tree construction, and utility functions
for the AxonHash cryptographic hash function. It is designed for research and prototyping purposes.

Author: rawbytedev 
"""

from concurrent.futures import ThreadPoolExecutor
from typing import List
from utils import *

def parallel_leaf_hashing(chunks: List[bytes], state: List[int], rounds: int) -> List[List[int]]:
    """
    Hashes all chunks in parallel using hashblock.
    Args:
        chunks: List of byte chunks to hash.
        state: Initial state (list of 16 ints).
        rounds: Number of permutation rounds.
    Returns:
        List of digests (each a list of ints).
    Raises:
        ValueError: If chunks is empty or state is not 16 words.
    """
    if not chunks:
        raise ValueError("No chunks provided for hashing.")
    if len(state) != 16:
        raise ValueError("State must be a list of 16 integers.")
    with ThreadPoolExecutor() as executor:
        return list(executor.map(
            lambda args: hashblock(*args),
            [(chunk, i, state, rounds) for i, chunk in enumerate(chunks)]
        ))

