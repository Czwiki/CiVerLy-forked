
r"""
Implementation of the Blink tweakable block cipher.

Blink is a low-latency tweakable block cipher based on the THF (Tweakable
Hasher Framework) mode.  This module provides two CiVerLy cipher classes:

* ``BLINK64_CVL`` -- 64-bit block size (variants ``"64a"`` and ``"64b"``).
* ``BLINK128_CVL`` -- 128-bit block size (variants ``"128a"``, ``"128b"``,
  ``"128A"`` and ``"128B"``).

Both classes work in two modes:

1. **THF mode** (activated by supplying ``k`` and ``t``): full tweakable
   block-cipher construction with key schedule, Toeplitz tweak hashing,
   round constants, whitening and the reflector.
2. **SPN mode** (backward compatible): bare iterated SPN
   :math:`R = P \circ AC \circ AK \circ M \circ S` with user-supplied
   round keys.

EXAMPLES:

Basic SPN-mode encryption with 64-bit block size::

    sage: from civerly.cipher_implementations.blink import BLINK64_CVL
    sage: from civerly.util import int_to_vec, vec_to_int
    sage: blink = BLINK64_CVL(R=2)
    sage: plaintext = int_to_vec(0x0, 64)
    sage: ciphertext = blink(plaintext)
    sage: len(ciphertext)
    64
    sage: vec_to_int(ciphertext)
    0

Basic SPN-mode encryption with 128-bit block size::

    sage: from civerly.cipher_implementations.blink import BLINK128_CVL
    sage: from civerly.util import int_to_vec, vec_to_int
    sage: blink = BLINK128_CVL(R=2)
    sage: plaintext = int_to_vec(0x0, 128)
    sage: ciphertext = blink(plaintext)
    sage: len(ciphertext)
    128
    sage: vec_to_int(ciphertext)
    0

Encrypted outputs for particular round keys (bare SPN)::

    sage: from civerly.cipher_implementations.blink import BLINK64_CVL, BLINK128_CVL
    sage: from civerly.util import int_to_vec, vec_to_int

    For Blink-64a (7 round keys, R=6)::

    sage: rks_64a = [
    ....:   0xd6a102d888a467e4, 0xd1d7dec33a246943, 0xe07c1dc6f302c57e,
    ....:   0x762c2df9de6f0d21, 0x6dd387874a0b52ce, 0x3022e0ad78c78a06,
    ....:   0x97779021b38e7fa1]
    sage: blink64 = BLINK64_CVL(R=6, rks=rks_64a)
    sage: result = vec_to_int(blink64(int_to_vec(0x0, 64)))
    sage: result == 0xe04d07b55f205fa5
    True

    For Blink-128a (8 round keys, R=7)::

    sage: rks_128a = [
    ....:   0xd6a102d888a467e4d1d7dec33a246943,
    ....:   0xe07c1dc6f302c57e762c2df9de6f0d21,
    ....:   0x6dd387874a0b52ce3022e0ad78c78a06,
    ....:   0x97779021b38e7fa15e2b66350517f80f,
    ....:   0x2961c648d578bae174d70cb769c30a45,
    ....:   0xcc40300fe8a342ca57a0bd0251ae39b6,
    ....:   0x21b8f104904374bbd6a102e234a664e4,
    ....:   0x21b8f104904374bbd6a102d888a666e4]
    sage: blink128 = BLINK128_CVL(R=7, rks=rks_128a)
    sage: result = vec_to_int(blink128(int_to_vec(0x0, 128)))
    sage: result == 0x1da156e3a7aed272a083cadf35c4d292
    True
"""
from civerly.cipher import Cipher
from civerly.wordsboxcipher import WordSBoxCipher
from civerly.component import Component, SBox_CVL, LinearLayer_CVL, PermuteLayer_CVL, RoundkeyXOR_CVL
from civerly.util import int_to_vec, vec_to_int
from sage.matrix.constructor import Matrix as matrix
from sage.rings.finite_rings.finite_field_constructor import GF
from sage.crypto.sbox import SBox


# Blink S-box (4-bit, involutory)
_BLINK_SBOX_VALUES = [0x1, 0x0, 0x9, 0x3, 0x8, 0x5, 0xe, 0x7,
                      0x4, 0x2, 0xc, 0xb, 0xa, 0xf, 0x6, 0xd]

# Shuffle permutations from the Blink specification
_BLINK_P_64 = [0, 5, 11, 10, 1, 6, 4, 13, 2, 12, 9, 15, 3, 7, 14, 8]
_BLINK_P_128 = [5, 12, 4, 1, 17, 9, 10, 16, 28, 14, 21, 22, 11, 27, 8, 13,
                2, 25, 18, 3, 30, 6, 19, 20, 0, 23, 24, 31, 7, 15, 29, 26]


def _create_blink_mixcolumn_matrix(block_size_bits):
    r"""
    Create the MixColumn matrix for Blink.

    The Blink MixColumn uses the Midori MixColumn matrix:
    M = [[0, 1, 1, 1],
         [1, 0, 1, 1],
         [1, 1, 0, 1],
         [1, 1, 1, 0]]

    This matrix is applied to each 4-nibble column independently.
    The number of columns is block_size_bits / 16 (since each column has 4 nibbles).

    EXAMPLES::

        sage: from civerly.cipher_implementations.blink import _create_blink_mixcolumn_matrix
        sage: M = _create_blink_mixcolumn_matrix(64)
        sage: M.nrows(), M.ncols()
        (64, 64)
        sage: M.det() != 0
        True

    The MixColumn matrix is involutory (M^2 = I)::

        sage: M = _create_blink_mixcolumn_matrix(64)
        sage: Msq = M**2
        sage: all(Msq[i,i] == 1 for i in range(64))  # diagonal is all 1
        True
        sage: all(Msq[i,j] == 0 for i in range(64) for j in range(64) if i != j)  # off-diagonal is all 0
        True
    """
    M_nibble = [[0, 1, 1, 1],
                [1, 0, 1, 1],
                [1, 1, 0, 1],
                [1, 1, 1, 0]]

    block_size_words = block_size_bits // 4
    num_columns = block_size_words // 4

    # Create block-diagonal matrix with the 4x4 nibble matrix applied
    # to each Blink column.  In the paper the state is row-major:
    #   column j consists of s_j, s_{j+4}, s_{j+8}, s_{j+12}.
    # Mapping from CiVerLy word index w to paper nibble s_x is
    #   w = block_size_words - 1 - x  (word 0 is the MSB nibble).
    M = matrix(GF(2), block_size_bits, block_size_bits)
    for j in range(num_columns):
        col_words = [block_size_words - 1 - (j + r * num_columns) for r in range(4)]
        for row in range(4):
            for col in range(4):
                if M_nibble[row][col] == 1:
                    for bit in range(4):
                        out_bit = col_words[row] * 4 + bit
                        in_bit = col_words[col] * 4 + bit
                        M[out_bit, in_bit] = 1

    return M


def blink_round_constants_64():
    r"""
    Return the 64-bit round constants for Blink.

    The constants correspond to the values given in Appendix D of the
    Blink specification (THF paper).

    OUTPUT:

    A pair ``(rc, rc_prime)`` where each is a list of five 64-bit
    integers.

    EXAMPLES::

        sage: from civerly.cipher_implementations.blink import blink_round_constants_64
        sage: rc, rc_prime = blink_round_constants_64()
        sage: len(rc), len(rc_prime)
        (5, 5)
        sage: hex(rc[0])
        '0x13198a2e03707344'
        sage: format(rc_prime[0], '#018x')
        '0x0d95748f728eb658'
    """
    rc = [
        0x13198a2e03707344,
        0x082efa98ec4e6c89,
        0xbe5466cf34e90c6c,
        0x3f84d5b5b5470917,
        0xd1310ba698dfb5ac,
    ]
    rc_prime = [
        0x0d95748f728eb658,
        0x7b54a41dc25a59b5,
        0xc5d1b023286085f0,
        0x8e79dcb0603a180e,
        0xd71577c1bd314b27,
    ]
    return rc, rc_prime


def blink_round_constants_128():
    r"""
    Return the 128-bit round constants for Blink.

    The constants correspond to the values given in Appendix D of the
    Blink specification (THF paper).

    OUTPUT:

    A pair ``(rc, rc_prime)`` where each is a list of eight 128-bit
    integers.

    EXAMPLES::

        sage: from civerly.cipher_implementations.blink import blink_round_constants_128
        sage: rc, rc_prime = blink_round_constants_128()
        sage: len(rc), len(rc_prime)
        (8, 8)
        sage: hex(rc[0])
        '0x243f6a8885a308d313198a2e03707344'
    """
    rc = [
        0x243f6a8885a308d313198a2e03707344,
        0xa4093822299f31d0082efa98ec4e6c89,
        0x452821e638d01377be5466cf34e90c6c,
        0xc0ac29b7c97c50dd3f84d5b5b5470917,
        0x9216d5d98979fb1bd1310ba698dfb5ac,
        0x2ffd72dbd01adfb7b8e1afed6a267e96,
        0xba7c9045f12c7f9924a19947b3916cf7,
        0x0801f2e2858efc16636920d871574e69,
    ]
    rc_prime = [
        0xa458fea3f4933d7e0d95748f728eb658,
        0x718bcd5882154aee7b54a41dc25a59b5,
        0x9c30d5392af26013c5d1b023286085f0,
        0xca417918b8db38ef8e79dcb0603a180e,
        0x6c9e0e8bb01e8a3ed71577c1bd314b27,
        0x78af2fda55605c60e65525f3aa55ab94,
        0x5748986263e8144055ca396a2aab10b6,
        0xb4cc5c341141e8cea15486af7c72e993,
    ]
    return rc, rc_prime


def blink_k_prime(k, total_bits):
    r"""
    Compute the rearranged key :math:`k'` from the master key :math:`k`.

    The rearrangement follows the Blink key schedule (Section 5.4 of
    the THF paper):

    .. MATH::

        k'_i = k_{11 \cdot i \bmod N}, \qquad 0 \le i < N

    where :math:`N` is ``total_bits``.

    INPUT:

    - ``k`` -- integer; the master key.

    - ``total_bits`` -- integer; the length of the key in bits.

    OUTPUT:

    Integer representing the rearranged key :math:`k'`.

    EXAMPLES::

        sage: from civerly.cipher_implementations.blink import blink_k_prime
        sage: k = 0b101010
        sage: k_prime = blink_k_prime(k, 6)
        sage: bin(k_prime)
        '0b101010'
    """
    k_prime = 0
    for i in range(total_bits):
        src_idx = (11 * i) % total_bits
        if (k >> src_idx) & 1:
            k_prime |= (1 << i)
    return k_prime


def blink_key_schedule(k, n, a, b):
    r"""
    Parse a master key into the format used by the Blink THF mode.

    The master key of length ``(a + b + 2) * n`` bits is divided into
    ``a + b`` round keys ``rk_1 || ... || rk_{a+b}`` and two whitening
    keys ``w2 || w1`` (with ``w1`` as the least-significant `n` bits).
    The rearranged key ``k'`` is also derived, from which the Toeplitz
    hash keys ``k2`` and ``k1`` are taken.

    INPUT:

    - ``k`` -- integer; the master key.

    - ``n`` -- integer; the block size in bits (64 or 128).

    - ``a`` -- integer; THF parameter :math:`a`.

    - ``b`` -- integer; THF parameter :math:`b`.

    OUTPUT:

    A 5-tuple ``(rk, w1, w2, k1, k2)`` where ``rk`` is a list of round
    keys ``[rk_1, ..., rk_{a+b}]`` (least-significant block first),
    ``w1`` and ``w2`` are whitening keys, and ``k1``, ``k2`` are the
    hash keys for the Toeplitz hash.

    EXAMPLES::

        sage: from civerly.cipher_implementations.blink import blink_key_schedule
        sage: k = 0x00050004000300020001  # 5*16=80 bits, n=16, a=2, b=1
        sage: rk, w1, w2, k1, k2 = blink_key_schedule(k, 16, 2, 1)
        sage: [hex(x) for x in rk]
        ['0x3', '0x4', '0x5']
        sage: hex(w1)
        '0x1'
        sage: hex(w2)
        '0x2'
    """
    total_bits = (a + b + 2) * n
    key_bytes = total_bits // 8
    state_bytes = n // 8
    tweak_bytes = n // 8
    hk_len = state_bytes + tweak_bytes

    # Convert master key to little-endian byte list
    master_key = [(k >> (8 * i)) & 0xFF for i in range(key_bytes)]

    w1 = k & ((1 << n) - 1)
    w2 = (k >> n) & ((1 << n) - 1)

    rks = []
    for i in range(a + b):
        rk_val = (k >> (2 * n + i * n)) & ((1 << n) - 1)
        rks.append(rk_val)

    # Derive k' (bit permutation)
    k_prime = [0] * key_bytes
    for i in range(key_bytes):
        for j in range(8):
            bit_index = (11 * (8 * i + j)) % total_bits
            byte_idx = bit_index // 8
            bit_in_byte = bit_index % 8
            bit_val = (master_key[byte_idx] >> bit_in_byte) & 1
            k_prime[i] ^= (bit_val << j)
            k_prime[i] &= 0xFF

    # Derive hash keys (byte-level shift, matching the reference)
    hk0 = [0] * hk_len
    hk1 = [0] * hk_len
    for i in range(hk_len - 1, -1, -1):
        if i > 0:
            hk0[i] = ((k_prime[i] << 1) ^ (k_prime[i - 1] >> 7)) & 0xFF
            val = (k_prime[i + hk_len] << 2) & 0xFF
            val2 = (k_prime[i + hk_len - 1] >> 6) & 0xFF
            hk1[i] = (val ^ val2) & 0xFF
        else:
            hk0[i] = (k_prime[i] << 1) & 0xFF
            val = (k_prime[i + hk_len] << 2) & 0xFF
            val2 = (k_prime[i + hk_len - 1] >> 6) & 0xFF
            hk1[i] = ((val ^ val2) & 0xFE) & 0xFF

    k1 = sum(hk0[i] << (8 * i) for i in range(hk_len))
    k2 = sum(hk1[i] << (8 * i) for i in range(hk_len))

    return rks, w1, w2, k1, k2


# HW2 parity table used by the byte-level Toeplitz hash
_HW2 = [
    0, 1, 1, 0, 1, 0, 0, 1, 1, 0, 0, 1, 0, 1, 1, 0,
    1, 0, 0, 1, 0, 1, 1, 0, 0, 1, 1, 0, 1, 0, 0, 1,
    1, 0, 0, 1, 0, 1, 1, 0, 0, 1, 1, 0, 1, 0, 0, 1,
    0, 1, 1, 0, 1, 0, 0, 1, 1, 0, 0, 1, 0, 1, 1, 0,
    1, 0, 0, 1, 0, 1, 1, 0, 0, 1, 1, 0, 1, 0, 0, 1,
    0, 1, 1, 0, 1, 0, 0, 1, 1, 0, 0, 1, 0, 1, 1, 0,
    0, 1, 1, 0, 1, 0, 0, 1, 1, 0, 0, 1, 0, 1, 1, 0,
    1, 0, 0, 1, 0, 1, 1, 0, 0, 1, 1, 0, 1, 0, 0, 1,
    1, 0, 0, 1, 0, 1, 1, 0, 0, 1, 1, 0, 1, 0, 0, 1,
    0, 1, 1, 0, 1, 0, 0, 1, 1, 0, 0, 1, 0, 1, 1, 0,
    0, 1, 1, 0, 1, 0, 0, 1, 1, 0, 0, 1, 0, 1, 1, 0,
    1, 0, 0, 1, 0, 1, 1, 0, 0, 1, 1, 0, 1, 0, 0, 1,
    0, 1, 1, 0, 1, 0, 0, 1, 1, 0, 0, 1, 0, 1, 1, 0,
    1, 0, 0, 1, 0, 1, 1, 0, 0, 1, 1, 0, 1, 0, 0, 1,
    1, 0, 0, 1, 0, 1, 1, 0, 0, 1, 1, 0, 1, 0, 0, 1,
    0, 1, 1, 0, 1, 0, 0, 1, 1, 0, 0, 1, 0, 1, 1, 0,
]

# MixColumn matrix (nibble-level, same as Midori)
_M_MATRIX = [
    [0, 1, 1, 1],
    [1, 0, 1, 1],
    [1, 1, 0, 1],
    [1, 1, 1, 0],
]


def _int_to_bytes(val, num_bytes):
    """Convert an integer to a little-endian byte list."""
    return [(val >> (8 * i)) & 0xFF for i in range(num_bytes)]


def _bytes_to_int(byte_list):
    """Convert a little-endian byte list to an integer."""
    return sum((byte_list[i] & 0xFF) << (8 * i) for i in range(len(byte_list)))


def blink_toeplitz_hash(k_hash, t, n, tau):
    r"""
    Toeplitz hash function used in the Blink THF mode.

    This implementation follows the byte-level reference algorithm.

    INPUT:

    - ``k_hash`` -- integer; the hash key.

    - ``t`` -- integer; the tweak value.

    - ``n`` -- integer; the block size in bits.

    - ``tau`` -- integer; the tweak length in bits.

    OUTPUT:

    Integer of ``n`` bits representing the hash value :math:`h_T(t)`.

    EXAMPLES::

        sage: from civerly.cipher_implementations.blink import blink_toeplitz_hash
        sage: h = blink_toeplitz_hash(0x1234, 0x56, 8, 8)
        sage: h
        126
    """
    state_bytes = n // 8
    tweak_bytes = tau // 8
    hk_len = state_bytes + tweak_bytes
    k_hash_bytes = _int_to_bytes(k_hash, hk_len)
    t_bytes = _int_to_bytes(t, tweak_bytes)
    h = [0] * state_bytes
    for i in range(state_bytes - 1, -1, -1):
        h[state_bytes - 1 - i] = 0
        for l in range(8):
            temp = [0] * tweak_bytes
            for j in range(tweak_bytes):
                left = (k_hash_bytes[tweak_bytes + i - j] << l) & 0xFF
                right = (k_hash_bytes[tweak_bytes + i - j - 1] >> (8 - l)) & 0xFF
                temp[tweak_bytes - 1 - j] = left ^ right
            p = 0
            for j in range(tweak_bytes):
                p ^= (t_bytes[j] & temp[j])
                p &= 0xFF
            h[state_bytes - 1 - i] ^= (_HW2[p] << l)
            h[state_bytes - 1 - i] &= 0xFF
    return _bytes_to_int(h)


class _BlinkTHF_CVL(Component):
    r"""
    Internal component that evaluates the full Blink THF construction.

    Not intended for direct use; it is instantiated by `BLINK64_CVL` /
    `BLINK128_CVL` when ``k`` and ``t`` are supplied.
    """

    _VARIANTS = {
        "64a":  {"n": 64,  "state_bytes": 8,  "tweak_bytes": 8,  "key_bytes": 56,  "ra": 2, "rb": 3, "pbox": _BLINK_P_64},
        "64b":  {"n": 64,  "state_bytes": 8,  "tweak_bytes": 16, "key_bytes": 56,  "ra": 2, "rb": 3, "pbox": _BLINK_P_64},
        "128a": {"n": 128, "state_bytes": 16, "tweak_bytes": 16, "key_bytes": 128, "ra": 3, "rb": 3, "pbox": _BLINK_P_128},
        "128b": {"n": 128, "state_bytes": 16, "tweak_bytes": 32, "key_bytes": 128, "ra": 3, "rb": 3, "pbox": _BLINK_P_128},
        "128A": {"n": 128, "state_bytes": 16, "tweak_bytes": 16, "key_bytes": 160, "ra": 3, "rb": 5, "pbox": _BLINK_P_128},
        "128B": {"n": 128, "state_bytes": 16, "tweak_bytes": 32, "key_bytes": 160, "ra": 3, "rb": 5, "pbox": _BLINK_P_128},
    }

    def __init__(self, variant, k, t, name="BlinkTHF"):
        if variant not in self._VARIANTS:
            raise ValueError(f"unsupported variant {variant!r}")
        p = self._VARIANTS[variant]
        self.variant = variant
        self.n = p["n"]
        self.state_bytes = p["state_bytes"]
        self.tweak_bytes = p["tweak_bytes"]
        self.key_bytes = p["key_bytes"]
        self.ra = p["ra"]
        self.rb = p["rb"]
        self.pbox = p["pbox"]
        self.state_nibbles = self.state_bytes * 2

        if self.n == 64:
            self.rc, self.rc_prime = blink_round_constants_64()
        else:
            self.rc, self.rc_prime = blink_round_constants_128()

        # Key schedule and tweak hash
        master_key = [(k >> (8 * i)) & 0xFF for i in range(self.key_bytes)]
        t_bytes = [(t >> (8 * i)) & 0xFF for i in range(self.tweak_bytes)]
        total_bits = self.key_bytes * 8

        key_prime = [0] * self.key_bytes
        for i in range(self.key_bytes):
            for j in range(8):
                bit_index = (11 * (8 * i + j)) % total_bits
                byte_idx = bit_index // 8
                bit_in_byte = bit_index % 8
                bit_val = (master_key[byte_idx] >> bit_in_byte) & 1
                key_prime[i] ^= (bit_val << j)
                key_prime[i] &= 0xFF

        self.w0 = [master_key[i] for i in range(self.state_bytes)]
        self.w1 = [master_key[i + self.state_bytes] for i in range(self.state_bytes)]
        self.rk = []
        for j in range(self.ra + self.rb):
            self.rk.append([master_key[i + (j + 2) * self.state_bytes] for i in range(self.state_bytes)])

        hk_len = self.state_bytes + self.tweak_bytes
        hk0 = [0] * hk_len
        hk1 = [0] * hk_len
        for i in range(hk_len - 1, -1, -1):
            if i > 0:
                hk0[i] = ((key_prime[i] << 1) ^ (key_prime[i - 1] >> 7)) & 0xFF
                val = (key_prime[i + hk_len] << 2) & 0xFF
                val2 = (key_prime[i + hk_len - 1] >> 6) & 0xFF
                hk1[i] = (val ^ val2) & 0xFF
            else:
                hk0[i] = (key_prime[i] << 1) & 0xFF
                val = (key_prime[i + hk_len] << 2) & 0xFF
                val2 = (key_prime[i + hk_len - 1] >> 6) & 0xFF
                hk1[i] = ((val ^ val2) & 0xFE) & 0xFF

        self.h0 = self._hash_func(hk0, t_bytes, self.state_bytes, self.tweak_bytes)
        self.h1 = self._hash_func(hk1, t_bytes, self.state_bytes, self.tweak_bytes)
        self.h_xor = [self.h0[i] ^ self.h1[i] for i in range(self.state_bytes)]

        super().__init__(self.n, self.n, name=name)

    @staticmethod
    def _hash_func(key, t, state_bytes, tweak_bytes):
        h = [0] * state_bytes
        for i in range(state_bytes - 1, -1, -1):
            h[state_bytes - 1 - i] = 0
            for l in range(8):
                temp = [0] * tweak_bytes
                for j in range(tweak_bytes):
                    left = (key[tweak_bytes + i - j] << l) & 0xFF
                    right = (key[tweak_bytes + i - j - 1] >> (8 - l)) & 0xFF
                    temp[tweak_bytes - 1 - j] = left ^ right
                p = 0
                for j in range(tweak_bytes):
                    p ^= (t[j] & temp[j])
                    p &= 0xFF
                h[state_bytes - 1 - i] ^= (_HW2[p] << l)
                h[state_bytes - 1 - i] &= 0xFF
        return h

    def _sub_bytes(self, state):
        for i in range(self.state_bytes):
            hi = _BLINK_SBOX_VALUES[(state[i] >> 4) & 0xF]
            lo = _BLINK_SBOX_VALUES[state[i] & 0xF]
            state[i] = ((hi << 4) | lo) & 0xFF

    def _mix_columns(self, state):
        cols = self.state_nibbles // 4
        for col in range(cols):
            coldata = [0] * 4
            for r in range(4):
                idx = col + r * cols
                byte_index = idx // 2
                high_nibble = (idx % 2 == 1)
                nibble = (state[byte_index] >> 4) & 0xF if high_nibble else state[byte_index] & 0xF
                coldata[r] = nibble
            result = [0] * 4
            for r in range(4):
                for c in range(4):
                    if _M_MATRIX[r][c]:
                        result[r] ^= coldata[c]
            for r in range(4):
                idx = col + r * cols
                byte_index = idx // 2
                high_nibble = (idx % 2 == 1)
                if high_nibble:
                    state[byte_index] = ((result[r] << 4) | (state[byte_index] & 0xF)) & 0xFF
                else:
                    state[byte_index] = (state[byte_index] & 0xF0) | result[r]

    def _add_round_key(self, state, round_key):
        for i in range(self.state_bytes):
            state[i] ^= round_key[i]

    def _add_round_constant(self, state, constant):
        for i in range(self.state_bytes):
            state[i] ^= constant[i]

    def _permutation(self, state):
        temp = [0] * self.state_nibbles
        for i in range(self.state_nibbles):
            byte_index = i // 2
            high_nibble = (i % 2 == 1)
            temp[i] = (state[byte_index] >> 4) & 0xF if high_nibble else state[byte_index] & 0xF
        permuted = [0] * self.state_nibbles
        for i in range(self.state_nibbles):
            permuted[i] = temp[self.pbox[i]]
        for i in range(self.state_bytes):
            state[i] = ((permuted[2 * i + 1] << 4) | permuted[2 * i]) & 0xFF

    def _inv_permutation(self, state):
        temp = [0] * self.state_nibbles
        for i in range(self.state_nibbles):
            byte_index = i // 2
            high_nibble = (i % 2 == 1)
            temp[i] = (state[byte_index] >> 4) & 0xF if high_nibble else state[byte_index] & 0xF
        permuted = [0] * self.state_nibbles
        for i in range(self.state_nibbles):
            permuted[self.pbox[i]] = temp[i]
        for i in range(self.state_bytes):
            state[i] = ((permuted[2 * i + 1] << 4) | permuted[2 * i]) & 0xFF

    def _whitening(self, state, w):
        for i in range(self.state_bytes):
            state[i] ^= w[i]

    def _encrypt_bytes(self, state):
        self._whitening(state, self.w0)
        for r in range(self.ra):
            self._sub_bytes(state)
            self._mix_columns(state)
            self._add_round_key(state, self.rk[r])
            self._add_round_constant(state, _int_to_bytes(self.rc[r], self.state_bytes))
            self._permutation(state)
        self._sub_bytes(state)
        self._mix_columns(state)
        self._add_round_key(state, self.h0)
        self._permutation(state)
        for r in range(self.rb):
            self._sub_bytes(state)
            self._mix_columns(state)
            self._add_round_key(state, self.rk[r + self.ra])
            self._add_round_constant(state, _int_to_bytes(self.rc[r + self.ra], self.state_bytes))
            self._permutation(state)

        self._sub_bytes(state)
        self._mix_columns(state)
        self._add_round_key(state, self.h_xor)
        self._sub_bytes(state)

        for r in range(self.rb):
            self._inv_permutation(state)
            self._add_round_constant(state, _int_to_bytes(self.rc_prime[r], self.state_bytes))
            self._add_round_key(state, self.rk[r])
            self._mix_columns(state)
            self._sub_bytes(state)
        self._inv_permutation(state)
        self._add_round_key(state, self.h1)
        self._mix_columns(state)
        self._sub_bytes(state)
        for r in range(self.ra):
            self._inv_permutation(state)
            self._add_round_constant(state, _int_to_bytes(self.rc_prime[r + self.rb], self.state_bytes))
            self._add_round_key(state, self.rk[r + self.rb])
            self._mix_columns(state)
            self._sub_bytes(state)
        self._whitening(state, self.w1)

    def eval(self, x):
        m = vec_to_int(x)
        state = _int_to_bytes(m, self.state_bytes)
        self._encrypt_bytes(state)
        c = _bytes_to_int(state)
        return int_to_vec(c, self.n)

    def _model_milp(self, model_options):
        raise NotImplementedError("MILP modeling is not supported for the full Blink THF construction.")

    def _model_sat(self, model_options):
        raise NotImplementedError("SAT modeling is not supported for the full Blink THF construction.")


# ----------------------------------------------------------------------
# CiVerLy cipher classes
# ----------------------------------------------------------------------
class BLINK64_CVL:
    """Implementation of the 64-bit Blink cipher in CiVerLy."""

    def __init__(self, R=14, rks=None, round_constants=None, name=None,
                 variant="64a", k=None, t=None):
        r"""
        Implement the 64-bit variant of Blink in CiVerLy.

        INPUT:

            - ``R`` -- integer; Number of rounds for SPN mode (default: 14).

            - ``rks`` -- list (optional); Round key values for SPN mode.

            - ``round_constants`` -- list (optional); Round constant values
              for SPN mode (one per round).  Defaults to all zeros.

            - ``name`` -- string (optional); The name of the cipher.

            - ``variant`` -- string; ``"64a"`` or ``"64b"`` (default: ``"64a"``).

            - ``k`` -- integer (optional); Master key for THF mode.

            - ``t`` -- integer (optional); Tweak for THF mode.

        When ``k`` and ``t`` are provided the full THF construction is used.
        Otherwise the bare iterated SPN is built, exactly as before.

        This cipher is "plug-and-play" usable.

        TESTS:

        Basic SPN-mode instantiation::

            sage: from civerly.cipher_implementations.blink import BLINK64_CVL
            sage: from civerly.util import int_to_vec, vec_to_int
            sage: blink = BLINK64_CVL(R=2)
            sage: plaintext = int_to_vec(0x0, 64)
            sage: ciphertext = blink(plaintext)
            sage: len(ciphertext)
            64
            sage: blink = BLINK64_CVL(R=1, rks=[0x1, 0x2])
            sage: ciphertext = blink(int_to_vec(0x123456789abcdef, 64))
            sage: vec_to_int(ciphertext)  # random
            0x583d631749abdf1c
            sage: blink = BLINK64_CVL(R=14)
            sage: blink.is_valid
            True

        THF test vectors (Appendix F)::

            sage: k_64 = 0xd6a102d888a467e4d1d7dec33a246943e07c1dc6f302c57e762c2df9de6f0d216dd387874a0b52ce3022e0ad78c78a0697779021b38e7fa1

            Blink-64a::
            sage: blink = BLINK64_CVL(variant="64a", k=k_64, t=0x0123456789abcdef)
            sage: result = vec_to_int(blink(int_to_vec(0x0, 64)))
            sage: result == 0xa4a0d10502be846e
            True

            Blink-64b::
            sage: blink = BLINK64_CVL(variant="64b", k=k_64, t=0x0123456789abcdef0123456789abcdef)
            sage: result = vec_to_int(blink(int_to_vec(0x0, 64)))
            sage: result == 0x743e142f17caaae1
            True
        """
        if k is not None and t is not None:
            if name is None:
                name = f"BLINK64-{variant}"
            block_size_bits = 64
            thf = _BlinkTHF_CVL(variant, k, t, name=name)
            cipher = Cipher(block_size_bits, block_size_bits, name=name)
            node = cipher.add_subcipher(thf, [(cipher.IN, (i, i)) for i in range(block_size_bits)])
            cipher.add_output([(node, (i, i)) for i in range(block_size_bits)])
            self.blink_cipher = cipher
            return

        # SPN mode (backward compatible)
        if rks is None:
            rks = [0 for _ in range(R + 1)]
        if round_constants is None:
            round_constants = [0 for _ in range(R)]
        if name is None:
            name = "BLINK64"

        block_size_bits = 64
        block_size_words = 16
        wordsize = 4

        sbox_values = [0x1, 0x0, 0x9, 0x3, 0x8, 0x5, 0xe, 0x7,
                       0x4, 0x2, 0xc, 0xb, 0xa, 0xf, 0x6, 0xd]
        sbox = SBox_CVL(SBox(sbox_values), name="SBox")

        sboxlayer = WordSBoxCipher(wordsize, block_size_words, block_size_words,
                                   name="SBoxLayer")
        for j in range(block_size_words):
            node = sboxlayer.add_subcipher(sbox, [(sboxlayer.IN, (j, 0))])
            sboxlayer.add_output([(node, (0, j))])

        mixcolumn = LinearLayer_CVL(_create_blink_mixcolumn_matrix(block_size_bits),
                                    branch_number_differential=5,
                                    branch_number_linear=5, name="MixColumn")

        P = [0, 5, 11, 10, 1, 6, 4, 13, 2, 12, 9, 15, 3, 7, 14, 8]
        P_inv = [0] * 16
        for i in range(16):
            P_inv[P[i]] = i
        perm_internal = [15 - P_inv[15 - i] for i in range(16)]
        shuffle_perm = PermuteLayer_CVL(perm_internal,
                                        word_coarseness=wordsize, name="Shuffle")

        key_add = RoundkeyXOR_CVL(block_size_bits, 0x0, name="KeyAdd")
        rc_add = RoundkeyXOR_CVL(block_size_bits, 0x0, name="RoundConstant")

        blink_round = WordSBoxCipher(wordsize, block_size_words, block_size_words,
                                     name="blink_round")

        node = blink_round.add_subcipher(sboxlayer,
                                         [(blink_round.IN, (i, i)) for i in range(block_size_words)])
        node = blink_round.add_subcipher(mixcolumn,
                                         [(node, (i, i)) for i in range(block_size_words)])
        node_key = blink_round.add_subcipher(key_add,
                                             [(node, (i, i)) for i in range(block_size_words)])
        node_rc = blink_round.add_subcipher(rc_add,
                                            [(node_key, (i, i)) for i in range(block_size_words)])
        node = blink_round.add_subcipher(shuffle_perm,
                                         [(node_rc, (i, i)) for i in range(block_size_words)])
        blink_round.add_output([(node, (i, i)) for i in range(block_size_words)])

        blink_cipher = WordSBoxCipher(wordsize, block_size_words, block_size_words,
                                      name=name)

        cipher_node = blink_cipher.IN
        for r in range(R):
            blink_round.nodes[node_key].const = rks[r]
            blink_round.nodes[node_rc].const = round_constants[r]
            cipher_node = blink_cipher.add_subcipher(
                blink_round, [(cipher_node, (i, i)) for i in range(block_size_words)]
            )

        cipher_node = blink_cipher.add_subcipher(
            key_add, [(cipher_node, (i, i)) for i in range(block_size_words)]
        )
        blink_cipher.nodes[cipher_node].const = rks[R]

        blink_cipher.add_output([(cipher_node, (i, i)) for i in range(block_size_words)])

        self.blink_cipher = blink_cipher

    def __new__(cls, *args, **kwargs):
        """Instantiate the Blink64 cipher."""
        instance = super(BLINK64_CVL, cls).__new__(cls)
        instance.__init__(*args, **kwargs)
        return instance.blink_cipher


class BLINK128_CVL:
    """Implementation of the 128-bit Blink cipher in CiVerLy."""

    def __init__(self, R=14, rks=None, round_constants=None, name=None,
                 variant="128a", k=None, t=None):
        r"""
        Implement the 128-bit variant of Blink in CiVerLy.

        INPUT:

            - ``R`` -- integer; Number of rounds for SPN mode (default: 14).

            - ``rks`` -- list (optional); Round key values for SPN mode.

            - ``round_constants`` -- list (optional); Round constant values
              for SPN mode (one per round).  Defaults to all zeros.

            - ``name`` -- string (optional); The name of the cipher.

            - ``variant`` -- string; one of ``"128a"``, ``"128b"``,
              ``"128A"``, ``"128B"`` (default: ``"128a"``).

            - ``k`` -- integer (optional); Master key for THF mode.

            - ``t`` -- integer (optional); Tweak for THF mode.

        When ``k`` and ``t`` are provided the full THF construction is used.
        Otherwise the bare iterated SPN is built, exactly as before.

        This cipher is "plug-and-play" usable.

        TESTS:

        Basic SPN-mode instantiation::

            sage: from civerly.cipher_implementations.blink import BLINK128_CVL
            sage: from civerly.util import int_to_vec, vec_to_int
            sage: blink = BLINK128_CVL(R=2)
            sage: plaintext = int_to_vec(0x0, 128)
            sage: ciphertext = blink(plaintext)
            sage: len(ciphertext)
            128
            sage: blink = BLINK128_CVL(R=3, rks=[0, 0xffffffffffffffff, 0, 0])
            sage: ciphertext = blink(int_to_vec(0x123456789abcdef, 128))  # pad with zeros
            sage: len(ciphertext)
            128
            sage: blink = BLINK128_CVL(R=14)
            sage: blink.is_valid
            True

        THF test vectors (Appendix F)::

            sage: k_128 = 0xd6a102d888a467e4d1d7dec33a246943e07c1dc6f302c57e762c2df9de6f0d216dd387874a0b52ce3022e0ad78c78a0697779021b38e7fa15e2b66350517f80f2961c648d578bae174d70cb769c30a45cc40300fe8a342ca57a0bd0251ae39b621b8f104904374bbd6a102e234a664e421b8f104904374bbd6a102d888a666e4
            sage: k_128A = 0xd6a102d888a467e4d1d7dec33a246943e07c1dc6f302c57e762c2df9de6f0d216dd387874a0b52ce3022e0ad78c78a0697779021b38e7fa15e2b66350517f80f2961c648d578bae174d70cb769c30a45cc40300fe8a342ca57a0bd0251ae39b621b8f104904374bbd6a102e234a664e421b8f104904374bbd6a102d888a666e428962a4c96893eda752c17026a6395c2d6963be43b2fc10813d73f5a4a48d28d

            Blink-128a::
            sage: blink = BLINK128_CVL(variant="128a", k=k_128, t=0x0123456789abcdef0123456789abcdef)
            sage: result = vec_to_int(blink(int_to_vec(0x0, 128)))
            sage: result == 0xb722eef350bb182074a6ff13c967a593
            True

            Blink-128b::
            sage: blink = BLINK128_CVL(variant="128b", k=k_128, t=0x0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef)
            sage: result = vec_to_int(blink(int_to_vec(0x0, 128)))
            sage: result == 0x20705a38e00412165bdabcac1dcbdec2
            True

            Blink-128A::
            sage: blink = BLINK128_CVL(variant="128A", k=k_128A, t=0x0123456789abcdef0123456789abcdef)
            sage: result = vec_to_int(blink(int_to_vec(0x0, 128)))
            sage: result == 0x82449f141c183601195b5046eac2b026
            True

            Blink-128B::
            sage: blink = BLINK128_CVL(variant="128B", k=k_128A, t=0x0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef)
            sage: result = vec_to_int(blink(int_to_vec(0x0, 128)))
            sage: result == 0x8dc41b223bc8cd9923b1297dd27583fc
            True
        """
        if k is not None and t is not None:
            if name is None:
                name = f"BLINK128-{variant}"
            block_size_bits = 128
            thf = _BlinkTHF_CVL(variant, k, t, name=name)
            cipher = Cipher(block_size_bits, block_size_bits, name=name)
            node = cipher.add_subcipher(thf, [(cipher.IN, (i, i)) for i in range(block_size_bits)])
            cipher.add_output([(node, (i, i)) for i in range(block_size_bits)])
            self.blink_cipher = cipher
            return

        # SPN mode (backward compatible)
        if rks is None:
            rks = [0 for _ in range(R + 1)]
        if round_constants is None:
            round_constants = [0 for _ in range(R)]
        if name is None:
            name = "BLINK128"

        block_size_bits = 128
        block_size_words = 32
        wordsize = 4

        sbox_values = [0x1, 0x0, 0x9, 0x3, 0x8, 0x5, 0xe, 0x7,
                       0x4, 0x2, 0xc, 0xb, 0xa, 0xf, 0x6, 0xd]
        sbox = SBox_CVL(SBox(sbox_values), name="SBox")

        sboxlayer = WordSBoxCipher(wordsize, block_size_words, block_size_words,
                                   name="SBoxLayer")
        for j in range(block_size_words):
            node = sboxlayer.add_subcipher(sbox, [(sboxlayer.IN, (j, 0))])
            sboxlayer.add_output([(node, (0, j))])

        mixcolumn = LinearLayer_CVL(_create_blink_mixcolumn_matrix(block_size_bits),
                                    branch_number_differential=5,
                                    branch_number_linear=5, name="MixColumn")

        P = [5, 12, 4, 1, 17, 9, 10, 16, 28, 14, 21, 22, 11, 27, 8, 13,
             2, 25, 18, 3, 30, 6, 19, 20, 0, 23, 24, 31, 7, 15, 29, 26]
        P_inv = [0] * 32
        for i in range(32):
            P_inv[P[i]] = i
        perm_internal = [31 - P_inv[31 - i] for i in range(32)]
        shuffle_perm = PermuteLayer_CVL(perm_internal,
                                        word_coarseness=wordsize, name="Shuffle")

        key_add = RoundkeyXOR_CVL(block_size_bits, 0x0, name="KeyAdd")
        rc_add = RoundkeyXOR_CVL(block_size_bits, 0x0, name="RoundConstant")

        blink_round = WordSBoxCipher(wordsize, block_size_words, block_size_words,
                                     name="blink_round")

        node = blink_round.add_subcipher(sboxlayer,
                                         [(blink_round.IN, (i, i)) for i in range(block_size_words)])
        node = blink_round.add_subcipher(mixcolumn,
                                         [(node, (i, i)) for i in range(block_size_words)])
        node_key = blink_round.add_subcipher(key_add,
                                             [(node, (i, i)) for i in range(block_size_words)])
        node_rc = blink_round.add_subcipher(rc_add,
                                            [(node_key, (i, i)) for i in range(block_size_words)])
        node = blink_round.add_subcipher(shuffle_perm,
                                         [(node_rc, (i, i)) for i in range(block_size_words)])
        blink_round.add_output([(node, (i, i)) for i in range(block_size_words)])

        blink_cipher = WordSBoxCipher(wordsize, block_size_words, block_size_words,
                                      name=name)

        cipher_node = blink_cipher.IN
        for r in range(R):
            blink_round.nodes[node_key].const = rks[r]
            blink_round.nodes[node_rc].const = round_constants[r]
            cipher_node = blink_cipher.add_subcipher(
                blink_round, [(cipher_node, (i, i)) for i in range(block_size_words)]
            )

        cipher_node = blink_cipher.add_subcipher(
            key_add, [(cipher_node, (i, i)) for i in range(block_size_words)]
        )
        blink_cipher.nodes[cipher_node].const = rks[R]

        blink_cipher.add_output([(cipher_node, (i, i)) for i in range(block_size_words)])

        self.blink_cipher = blink_cipher

    def __new__(cls, *args, **kwargs):
        r"""
        Instantiate the Blink128 cipher.

        TESTS::

            sage: from civerly.cipher_implementations.blink import BLINK128_CVL
            sage: blink = BLINK128_CVL(R=2)  # default instantiation
            sage: blink.is_valid
            True
        """
        instance = super(BLINK128_CVL, cls).__new__(cls)
        instance.__init__(*args, **kwargs)
        return instance.blink_cipher
