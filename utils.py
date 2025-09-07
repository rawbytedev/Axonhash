from concurrent.futures import ThreadPoolExecutor
import hashlib
from typing import List

STATE_SIZE = 16  # 512-bit state as 16x 32-bit integers
class Node:
    def __init__(self, digest, left=None, right=None):
        self.digest = digest
        self.left = left
        self.right = right

def ivfromidentity(label: str = "AxonHash-1.0") -> List[int]:
        """
        Set the state from a label using SHA-256.
        Args:
            label: String label for domain separation.
        """
        digest = hashlib.sha256(label.encode()).digest()
        return [int.from_bytes(digest[i:i+4], 'little') for i in range(0, 64, 4)]
## ARX Permutation Function
def permute(state: List[int], round_const: int, rounds: int = 4) -> List[int]:
    """
    ARX permutation function for AxonHash.
    Args:
        state: List of 16 32-bit integers.
        round_const: Integer round constant.
        rounds: Number of rounds.
    Returns:
        Permuted state as a list of 16 ints.
    """
    if len(state) != 16:
        raise ValueError("State must be a list of 16 integers.")
    for r in range(rounds):
        state = mix_columns(state)
        state = diagonal_xor(state)
        state = [s ^ (s >> 11) for s in state]
        state[0] ^= round_const + r
        state = [s & 0xFFFFFFFF for s in state]
    return state

## Leaf Hashing
def hashblock(block: bytes, blockindex: int, state: List[int], rounds: int) -> List[int]:
    """
    Hash a single block with state and permutation.
    Args:
        block: Input bytes.
        blockindex: Index of the block.
        state: List of 16 ints.
        rounds: Number of rounds.
    Returns:
        Digest as a list of 16 ints.
    """
    padded = pad_to(block, 64)
    mixed = xor_state(state[:], padded)
    return permute(mixed, blockindex, rounds)

## Finalization & Squeeze
def finalize(rootdigest: List[int], totallen: int, domain_tag: int) -> List[int]:
    """
    Finalize the hash by permuting the root digest with domain separation.
    Args:
        rootdigest: List of 16 ints.
        totallen: Total length of input data.
        domain_tag: Integer domain tag.
    Returns:
        Finalized state as a list of 16 ints.
    """
    return permute(rootdigest[:STATE_SIZE], 0xDEAD ^ domain_tag ^ totallen)

def xof(state: List[int], output_len: int = 32) -> bytes:
    """
    Extendable output function (XOF) to squeeze output bytes from state.
    Args:
        state: List of 16 ints.
        output_len: Number of output bytes.
    Returns:
        Output bytes of requested length.
    """
    if len(state) != 16:
        raise ValueError("State must be a list of 16 integers.")
    if output_len <= 0:
        raise ValueError("Output length must be positive.")
    out = b''
    for i in range((output_len + 31) // 32):
        chunk = permute(state[:], i)
        out += intlistto_bytes(chunk[:8])  # 256 bits
    return out[:output_len]


def xor_state(state: List[int], block: bytes) -> List[int]:
    """
    XOR a block of bytes into the state.
    Args:
        state: List of 16 ints.
        block: Bytes (should be 64 bytes).
    Returns:
        Mutated state as a list of 16 ints.
    Raises:
        ValueError: If block is not 64 bytes.
    """
    if len(block) != 64:
        raise ValueError("Block must be exactly 64 bytes.")
    for i in range(16):
        word = int.from_bytes(block[i*4:i*4+4], 'little')
        state[i] ^= word
    return state
    

def pad_to(block: bytes, size: int) -> bytes:
    """
    Pad a block to the given size using 0x80 followed by zeros.
    Args:
        block: Input bytes.
        size: Desired size.
    Returns:
        Padded bytes.
    """
    pad_len = size - len(block)
    if pad_len <= 0:
        return block[:size]
    # Pad with 0x80 followed by zeros
    return block + b'\x80' + b'\x00' * (pad_len - 1)

def intlistto_bytes(ints: List[int]) -> bytes:
    """
    Convert a list of 32-bit integers to bytes (little-endian).
    Args:
        ints: List of ints.
    Returns:
        Bytes.
    """
    return b''.join(i.to_bytes(4, 'little') for i in ints)

def mix_columns(state: List[int]) -> List[int]:
    """
    Mix columns step for ARX permutation.
    Args:
        state: List of 16 ints.
    Returns:
        Mutated state as a list of 16 ints.
    """
    for i in range(0, 16, 4):
        a, b, c, d = state[i:i+4]
        state[i]     = (a + rotate_right(b, 7)) ^ d
        state[i+1]   = (b + rotate_right(c, 11)) ^ a
        state[i+2]   = (c + rotate_right(d, 17)) ^ b
        state[i+3]   = (d + rotate_right(a, 23)) ^ c
    return state

def rotate_right(x: int, n: int) -> int:
    """
    Rotate a 32-bit integer right by n bits.
    Args:
        x: Integer.
        n: Number of bits.
    Returns:
        Rotated integer.
    """
    return ((x >> n) | (x << (32 - n))) & 0xFFFFFFFF

###
def diagonal_xor(state: List[int]) -> List[int]:
    """
    Diagonal XOR step for ARX permutation.
    Args:
        state: List of 16 ints.
    Returns:
        Mutated state as a list of 16 ints.
    """
    for i in range(4):
        a = state[i]
        b = state[4 + ((i + 1) % 4)]
        c = state[8 + ((i + 2) % 4)]
        d = state[12 + ((i + 3) % 4)]

        state[i]         ^= d
        state[4 + i]     ^= a
        state[8 + i]     ^= b
        state[12 + i]    ^= c
    return state

def chunk(data: bytes, size: int) -> List[bytes]:
    """
    Split data into chunks of given size.
    Args:
        data: Input bytes.
        size: Chunk size.
    Returns:
        List of byte chunks.
    """
    if size <= 0:
        raise ValueError("Chunk size must be positive.")
    return [data[i:i+size] for i in range(0, len(data), size)]

def buildmerkletree(leaf_digests: List[List[int]]) -> Node:
    """
    Build a Merkle tree from leaf digests.
    Args:
        leaf_digests: List of digests (each a list of ints).
    Returns:
        Root Node of the Merkle tree.
    Raises:
        ValueError: If no leaf digests are provided.
    """
    if not leaf_digests:
        raise ValueError("No leaf digests provided for Merkle tree.")
    nodes = [Node(digest) for digest in leaf_digests]
    while len(nodes) > 1:
        paired = []
        for i in range(0, len(nodes), 2):
            left = nodes[i]
            right = nodes[i+1] if i+1 < len(nodes) else Node([0]*STATE_SIZE)
            combined = left.digest + right.digest
            parent_digest = permute(combined[:STATE_SIZE], 0xBEEF)
            paired.append(Node(parent_digest, left, right))
        nodes = paired
    return nodes[0]


if __name__ == '__main__':
    print(hashlib.sha256(b"").hexdigest())
    i = str(input())
    x =i.encode()
    l = len(i.encode())
    state = ivfromidentity()
    ls = chunk(i.encode(),32)
    leaf_digests = []
    for i in range(len(ls)):
        digest = hashblock(ls[i], i, state=state, rounds=4)
        leaf_digests.append(digest)
    n = buildmerkletree(leaf_digests=leaf_digests)
    final_s = finalize(n.digest, l, 0x01)
    digest = xof(final_s, 32)
    print(digest.hex())
    
    #print(Axon(x, round=4,domain=0x02).hexdigest())