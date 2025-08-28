
"""
AxonHash Main Implementation
---------------------------
This module provides the Axon class for hashing, including ARX permutation, Merkle tree, and utility methods.
For research and prototyping purposes.

Author: Rawbytedev
Date: 2025-08-25
"""

import hashlib
from typing import List, Optional, Any
from axon import ivfromidentity



STATE_SIZE = 16  # 512-bit state as 16x 32-bit integers

class Node:
    """
    Node for Merkle tree structure.
    """
    def __init__(self, digest: List[int], left: Optional[Any] = None, right: Optional[Any] = None):
        self.digest = digest
        self.left = left
        self.right = right


class Axon:
    """
    AxonHash main class for hashing data using ARX permutation and Merkle tree.
    """
    DEFAULT_DOMAIN: int = 0x01

    def __init__(self, data: bytes, state: Optional[List[int]] = None, chunks: int = 64, round: int = 4, domain: int = DEFAULT_DOMAIN):
        """
        Initialize AxonHash object.
        Args:
            data: Input bytes to hash.
            state: Optional initial state (16 ints).
            chunks: Chunk size in bytes.
            round: Number of permutation rounds.
            domain: Domain separation tag.
        """
        self.raw: bytes = data
        if state is not None:
            if len(state) != 16:
                raise ValueError("State must be a list of 16 integers.")
            self.state: List[int] = state
        else:
            self.state: List[int] = ivfromidentity()
        self.round: int = round
        self.domain: int = domain
        self.chunks: int = chunks
        self.leafs: List[List[int]] = []
        self.parent: List[int] = []
        self.finaldig: List[int] = []
        self.dig: Optional[bytes] = None
        self.tmpdigest: Optional[List[int]] = None

    def digest(self, outputlen: int = 32) -> bytes:
        """
        Compute the digest of the input data.
        Args:
            outputlen: Output digest length in bytes.
        Returns:
            Digest bytes.
        """
        raw = self.chunk()
        for i in range(len(raw)):
            self.tmpdigest = self.hashblock(raw[i], i)
            self.leafs.append(self.tmpdigest)
        self.buildmerkletree()
        self.finalize()
        self.xof(output_len=outputlen)
        return self.dig  # type: ignore

    def hexdigest(self) -> str:
        """
        Return the digest as a hexadecimal string.
        Returns:
            Hexadecimal digest string.
        """
        if self.dig is not None:
            return self.dig.hex()
        self.digest()
        return self.dig.hex()  # type: ignore

    def xof(self, output_len: int) -> None:
        """
        Squeeze output bytes from the final state.
        Args:
            output_len: Number of output bytes.
        """
        out = b''
        for i in range((output_len + 31) // 32):
            chunk = self.permute(self.finaldig[:], i)
            out += self.intlistto_bytes(chunk[:8])  # 256 bits
        self.dig = out[:output_len]

    def intlistto_bytes(self, ints: List[int]) -> bytes:
        """
        Convert a list of 32-bit integers to bytes (little-endian).
        Args:
            ints: List of ints.
        Returns:
            Bytes.
        """
        return b''.join(i.to_bytes(4, 'little') for i in ints)

    def hashblock(self, block: bytes, blockindex: int) -> List[int]:
        """
        Hash a single block with state and permutation.
        Args:
            block: Input bytes.
            blockindex: Index of the block.
        Returns:
            Digest as a list of 16 ints.
        """
        padded = self.pad_to(block, self.chunks)
        mixed = self.xor_state(self.state[:], padded)
        return self.permute(mixed, blockindex)

    def chunk(self) -> List[bytes]:
        """
        Split input data into chunks.
        Returns:
            List of byte chunks.
        """
        if self.chunks <= 0:
            raise ValueError("Chunk size must be positive.")
        return [self.raw[i:i+self.chunks] for i in range(0, len(self.raw), self.chunks)]

    def permute(self, state: List[int], round_const: int) -> List[int]:
        """
        ARX permutation function for AxonHash.
        Args:
            state: List of 16 32-bit integers.
            round_const: Integer round constant.
        Returns:
            Permuted state as a list of 16 ints.
        """
        if len(state) != 16:
            raise ValueError("State must be a list of 16 integers.")
        for r in range(self.round):
            state = self.mix_columns(state)
            state = self.diagonal_xor(state)
            state = [s ^ (s >> 11) for s in state]
            state[0] ^= round_const + r
            state = [s & 0xFFFFFFFF for s in state]
        return state

    def mix_columns(self, state: List[int]) -> List[int]:
        """
        Mix columns step for ARX permutation.
        Args:
            state: List of 16 ints.
        Returns:
            Mutated state as a list of 16 ints.
        """
        for i in range(0, 16, 4):
            a, b, c, d = state[i:i+4]
            state[i]     = (a + self.rotate_right(b, 7)) ^ d
            state[i+1]   = (b + self.rotate_right(c, 11)) ^ a
            state[i+2]   = (c + self.rotate_right(d, 17)) ^ b
            state[i+3]   = (d + self.rotate_right(a, 23)) ^ c
        return state

    def rotate_right(self, x: int, n: int) -> int:
        """
        Rotate a 32-bit integer right by n bits.
        Args:
            x: Integer.
            n: Number of bits.
        Returns:
            Rotated integer.
        """
        return ((x >> n) | (x << (32 - n))) & 0xFFFFFFFF

    def diagonal_xor(self, state: List[int]) -> List[int]:
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

    def pad_to(self, block: bytes, size: int) -> bytes:
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

    def xor_state(self, state: List[int], block: bytes) -> List[int]:
        """
        XOR a block of bytes into the state.
        Args:
            state: List of 16 ints.
            block: Bytes (should match self.chunks).
        Returns:
            Mutated state as a list of 16 ints.
        Raises:
            ValueError: If block is not the expected chunk size.
        """
        if len(block) != self.chunks:
            raise ValueError(f"Block must be exactly {self.chunks} bytes (got {len(block)} bytes).")
        for i in range(16):
            word = int.from_bytes(block[i*4:i*4+4], 'little')
            state[i] ^= word
        return state

    def finalize(self) -> None:
        """
        Finalize the hash by permuting the parent digest with domain separation.
        """
        self.finaldig = self.permute(self.parent[:STATE_SIZE], 0xDEAD ^ self.domain ^ len(self.raw))

    def buildmerkletree(self) -> None:
        """
        Build a Merkle tree from leaf digests and set the parent digest.
        """
        if not self.leafs:
            raise ValueError("No leaf digests to build Merkle tree.")
        nodes = [Node(digest) for digest in self.leafs]
        while len(nodes) > 1:
            paired = []
            for i in range(0, len(nodes), 2):
                left = nodes[i]
                right = nodes[i+1] if i+1 < len(nodes) else Node([0]*STATE_SIZE)
                combined = left.digest + right.digest
                parent_digest = self.permute(combined[:STATE_SIZE], 0xBEEF)
                paired.append(Node(parent_digest, left, right))
            nodes = paired
        self.parent = nodes[0].digest

    def ivfromidentity(self, label: str = "AxonHash-1.0") -> None:
        """
        Set the state from a label using SHA-256.
        Args:
            label: String label for domain separation.
        """
        digest = hashlib.sha256(label.encode()).digest()
        self.state = [int.from_bytes(digest[i:i+4], 'little') for i in range(0, 64, 4)]

##example
print(Axon("aren".encode()).hexdigest())
