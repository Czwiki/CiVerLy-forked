"""
Blink tweakable block cipher — reference implementation.
Translated faithfully from the C++ sources for all six variants.

Supported variants:
    Blink-64a   (64-bit block,  64-bit tweak,  56-bit key,  a=2, b=3)
    Blink-64b   (64-bit block,  128-bit tweak, 56-bit key,  a=2, b=3)
    Blink-128a  (128-bit block, 128-bit tweak, 128-bit key, a=3, b=3)
    Blink-128b  (128-bit block, 256-bit tweak, 128-bit key, a=3, b=3)
    Blink-128A  (128-bit block, 128-bit tweak, 160-bit key, a=3, b=5)
    Blink-128B  (128-bit block, 256-bit tweak, 160-bit key, a=3, b=5)
"""

from typing import List

# ---------------------------------------------------------------------------
# Shared tables
# ---------------------------------------------------------------------------

HW2 = [
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

SBOX = [
    0x1, 0x0, 0x9, 0x3,
    0x8, 0x5, 0xE, 0x7,
    0x4, 0x2, 0xC, 0xB,
    0xA, 0xF, 0x6, 0xD,
]

INV_SBOX = SBOX

M_MATRIX = [
    [0, 1, 1, 1],
    [1, 0, 1, 1],
    [1, 1, 0, 1],
    [1, 1, 1, 0],
]

# ---------------------------------------------------------------------------
# Variant-specific permutation boxes
# ---------------------------------------------------------------------------

PBOX_64 = [
    0, 5, 11, 10,
    1, 6, 4, 13,
    2, 12, 9, 15,
    3, 7, 14, 8,
]

PBOX_128 = [
    5, 12, 4, 1, 17, 9, 10, 16,
    28, 14, 21, 22, 11, 27, 8, 13,
    2, 25, 18, 3, 30, 6, 19, 20,
    0, 23, 24, 31, 7, 15, 29, 26,
]

# ---------------------------------------------------------------------------
# Variant-specific round constants
# ---------------------------------------------------------------------------

# 64-bit variants: RA+RB = 5 rows, STATE_BYTES = 8
ROUND_CONST_64 = [
    [0x44, 0x73, 0x70, 0x03, 0x2e, 0x8a, 0x19, 0x13],
    [0x89, 0x6c, 0x4e, 0xec, 0x98, 0xfa, 0x2e, 0x08],
    [0x6c, 0x0c, 0xe9, 0x34, 0xcf, 0x66, 0x54, 0xbe],
    [0x17, 0x09, 0x47, 0xb5, 0xb5, 0xd5, 0x84, 0x3f],
    [0xac, 0xb5, 0xdf, 0x98, 0xa6, 0x0b, 0x31, 0xd1],
]

ROUND_CONST_PRIME_64 = [
    [0x58, 0xb6, 0x8e, 0x72, 0x8f, 0x74, 0x95, 0x0d],
    [0xb5, 0x59, 0x5a, 0xc2, 0x1d, 0xa4, 0x54, 0x7b],
    [0xf0, 0x85, 0x60, 0x28, 0x23, 0xb0, 0xd1, 0xc5],
    [0x0e, 0x18, 0x3a, 0x60, 0xb0, 0xdc, 0x79, 0x8e],
    [0x27, 0x4b, 0x31, 0xbd, 0xc1, 0x77, 0x15, 0xd7],
]

# 128a / 128b: RA+RB = 6 rows, STATE_BYTES = 16
ROUND_CONST_128a = [
    [0x44, 0x73, 0x70, 0x03, 0x2e, 0x8a, 0x19, 0x13, 0xd3, 0x08, 0xa3, 0x85, 0x88, 0x6a, 0x3f, 0x24],
    [0x89, 0x6c, 0x4e, 0xec, 0x98, 0xfa, 0x2e, 0x08, 0xd0, 0x31, 0x9f, 0x29, 0x22, 0x38, 0x09, 0xa4],
    [0x6c, 0x0c, 0xe9, 0x34, 0xcf, 0x66, 0x54, 0xbe, 0x77, 0x13, 0xd0, 0x38, 0xe6, 0x21, 0x28, 0x45],
    [0x17, 0x09, 0x47, 0xb5, 0xb5, 0xd5, 0x84, 0x3f, 0xdd, 0x50, 0x7c, 0xc9, 0xb7, 0x29, 0xac, 0xc0],
    [0xac, 0xb5, 0xdf, 0x98, 0xa6, 0x0b, 0x31, 0xd1, 0x1b, 0xfb, 0x79, 0x89, 0xd9, 0xd5, 0x16, 0x92],
    [0x96, 0x7e, 0x26, 0x6a, 0xed, 0xaf, 0xe1, 0xb8, 0xb7, 0xdf, 0x1a, 0xd0, 0xdb, 0x72, 0xfd, 0x2f],
]

ROUND_CONST_PRIME_128a = [
    [0x58, 0xb6, 0x8e, 0x72, 0x8f, 0x74, 0x95, 0x0d, 0x7e, 0x3d, 0x93, 0xf4, 0xa3, 0xfe, 0x58, 0xa4],
    [0xb5, 0x59, 0x5a, 0xc2, 0x1d, 0xa4, 0x54, 0x7b, 0xee, 0x4a, 0x15, 0x82, 0x58, 0xcd, 0x8b, 0x71],
    [0xf0, 0x85, 0x60, 0x28, 0x23, 0xb0, 0xd1, 0xc5, 0x13, 0x60, 0xf2, 0x2a, 0x39, 0xd5, 0x30, 0x9c],
    [0x0e, 0x18, 0x3a, 0x60, 0xb0, 0xdc, 0x79, 0x8e, 0xef, 0x38, 0xdb, 0xb8, 0x18, 0x79, 0x41, 0xca],
    [0x27, 0x4b, 0x31, 0xbd, 0xc1, 0x77, 0x15, 0xd7, 0x3e, 0x8a, 0x1e, 0xb0, 0x8b, 0x0e, 0x9e, 0x6c],
    [0x94, 0xab, 0x55, 0xaa, 0xf3, 0x25, 0x55, 0xe6, 0x60, 0x5c, 0x60, 0x55, 0xda, 0x2f, 0xaf, 0x78],
]

# 128A / 128B: RA+RB = 8 rows, STATE_BYTES = 16
ROUND_CONST_128A = [
    [0x44, 0x73, 0x70, 0x03, 0x2e, 0x8a, 0x19, 0x13, 0xd3, 0x08, 0xa3, 0x85, 0x88, 0x6a, 0x3f, 0x24],
    [0x89, 0x6c, 0x4e, 0xec, 0x98, 0xfa, 0x2e, 0x08, 0xd0, 0x31, 0x9f, 0x29, 0x22, 0x38, 0x09, 0xa4],
    [0x6c, 0x0c, 0xe9, 0x34, 0xcf, 0x66, 0x54, 0xbe, 0x77, 0x13, 0xd0, 0x38, 0xe6, 0x21, 0x28, 0x45],
    [0x17, 0x09, 0x47, 0xb5, 0xb5, 0xd5, 0x84, 0x3f, 0xdd, 0x50, 0x7c, 0xc9, 0xb7, 0x29, 0xac, 0xc0],
    [0xac, 0xb5, 0xdf, 0x98, 0xa6, 0x0b, 0x31, 0xd1, 0x1b, 0xfb, 0x79, 0x89, 0xd9, 0xd5, 0x16, 0x92],
    [0x96, 0x7e, 0x26, 0x6a, 0xed, 0xaf, 0xe1, 0xb8, 0xb7, 0xdf, 0x1a, 0xd0, 0xdb, 0x72, 0xfd, 0x2f],
    [0xf7, 0x6c, 0x91, 0xb3, 0x47, 0x99, 0xa1, 0x24, 0x99, 0x7f, 0x2c, 0xf1, 0x45, 0x90, 0x7c, 0xba],
    [0x69, 0x4e, 0x57, 0x71, 0xd8, 0x20, 0x69, 0x63, 0x16, 0xfc, 0x8e, 0x85, 0xe2, 0xf2, 0x01, 0x08],
]

ROUND_CONST_PRIME_128A = [
    [0x58, 0xb6, 0x8e, 0x72, 0x8f, 0x74, 0x95, 0x0d, 0x7e, 0x3d, 0x93, 0xf4, 0xa3, 0xfe, 0x58, 0xa4],
    [0xb5, 0x59, 0x5a, 0xc2, 0x1d, 0xa4, 0x54, 0x7b, 0xee, 0x4a, 0x15, 0x82, 0x58, 0xcd, 0x8b, 0x71],
    [0xf0, 0x85, 0x60, 0x28, 0x23, 0xb0, 0xd1, 0xc5, 0x13, 0x60, 0xf2, 0x2a, 0x39, 0xd5, 0x30, 0x9c],
    [0x0e, 0x18, 0x3a, 0x60, 0xb0, 0xdc, 0x79, 0x8e, 0xef, 0x38, 0xdb, 0xb8, 0x18, 0x79, 0x41, 0xca],
    [0x27, 0x4b, 0x31, 0xbd, 0xc1, 0x77, 0x15, 0xd7, 0x3e, 0x8a, 0x1e, 0xb0, 0x8b, 0x0e, 0x9e, 0x6c],
    [0x94, 0xab, 0x55, 0xaa, 0xf3, 0x25, 0x55, 0xe6, 0x60, 0x5c, 0x60, 0x55, 0xda, 0x2f, 0xaf, 0x78],
    [0xb6, 0x10, 0xab, 0x2a, 0x6a, 0x39, 0xca, 0x55, 0x40, 0x14, 0xe8, 0x63, 0x62, 0x98, 0x48, 0x57],
    [0x93, 0xe9, 0x72, 0x7c, 0xaf, 0x86, 0x54, 0xa1, 0xce, 0xe8, 0x41, 0x11, 0x34, 0x5c, 0xcc, 0xb4],
]


# ---------------------------------------------------------------------------
# Core cipher class (parameterised by variant)
# ---------------------------------------------------------------------------

class BlinkCipher:
    def __init__(
        self,
        state_bytes: int,
        tweak_bytes: int,
        key_bytes: int,
        ra: int,
        rb: int,
        pbox: List[int],
        round_const: List[List[int]],
        round_const_prime: List[List[int]],
    ):
        self.state_bytes = state_bytes
        self.state_nibbles = state_bytes * 2
        self.tweak_bytes = tweak_bytes
        self.key_bytes = key_bytes
        self.ra = ra
        self.rb = rb
        self.pbox = pbox
        self.round_const = round_const
        self.round_const_prime = round_const_prime

    # --- Primitive operations ------------------------------------------------

    def sub_bytes(self, state: List[int]) -> None:
        for i in range(self.state_bytes):
            hi = SBOX[(state[i] >> 4) & 0xF]
            lo = SBOX[state[i] & 0xF]
            state[i] = ((hi << 4) | lo) & 0xFF

    def mix_columns(self, state: List[int]) -> None:
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
                    if M_MATRIX[r][c]:
                        result[r] ^= coldata[c]
            for r in range(4):
                idx = col + r * cols
                byte_index = idx // 2
                high_nibble = (idx % 2 == 1)
                if high_nibble:
                    state[byte_index] = ((result[r] << 4) | (state[byte_index] & 0xF)) & 0xFF
                else:
                    state[byte_index] = (state[byte_index] & 0xF0) | result[r]

    def add_round_key(self, state: List[int], round_key: List[int]) -> None:
        for i in range(self.state_bytes):
            state[i] ^= round_key[i]

    def add_round_constant(self, state: List[int], constant: List[int]) -> None:
        for i in range(self.state_bytes):
            state[i] ^= constant[i]

    def permutation(self, state: List[int]) -> None:
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

    def inv_permutation(self, state: List[int]) -> None:
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

    def whitening(self, state: List[int], w: List[int]) -> None:
        for i in range(self.state_bytes):
            state[i] ^= w[i]

    # --- Hash & Key schedule -------------------------------------------------

    def hash_func(self, key: List[int], t: List[int], h: List[int]) -> None:
        # key length = self.state_bytes + self.tweak_bytes
        # t length   = self.tweak_bytes
        # h length   = self.state_bytes
        for i in range(self.state_bytes - 1, -1, -1):
            h[self.state_bytes - 1 - i] = 0
            for l in range(8):
                temp = [0] * self.tweak_bytes
                for j in range(self.tweak_bytes):
                    left = (key[self.tweak_bytes + i - j] << l) & 0xFF
                    right = (key[self.tweak_bytes + i - j - 1] >> (8 - l)) & 0xFF
                    temp[self.tweak_bytes - 1 - j] = left ^ right
                p = 0
                for j in range(self.tweak_bytes):
                    p ^= (t[j] & temp[j])
                    p &= 0xFF
                h[self.state_bytes - 1 - i] ^= (HW2[p] << l)
                h[self.state_bytes - 1 - i] &= 0xFF

    def generate_round_key(
        self,
        master_key: List[int],
        t: List[int],
    ):
        key_prime = [0] * self.key_bytes
        for i in range(self.key_bytes):
            for j in range(8):
                bit_index = (11 * (8 * i + j)) % (self.key_bytes * 8)
                byte_idx = bit_index // 8
                bit_in_byte = bit_index % 8
                bit_val = (master_key[byte_idx] >> bit_in_byte) & 1
                key_prime[i] ^= (bit_val << j)
                key_prime[i] &= 0xFF

        rk = [[0] * self.state_bytes for _ in range(self.ra + self.rb)]
        w = [[0] * self.state_bytes for _ in range(2)]
        h = [[0] * self.state_bytes for _ in range(2)]

        for i in range(self.state_bytes):
            w[0][i] = master_key[i]
            w[1][i] = master_key[i + self.state_bytes]
            for j in range(self.ra + self.rb):
                rk[j][i] = master_key[i + (j + 2) * self.state_bytes]

        hk_len = self.state_bytes + self.tweak_bytes
        hk = [[0] * hk_len for _ in range(2)]
        for i in range(hk_len - 1, -1, -1):
            if i > 0:
                hk[0][i] = ((key_prime[i] << 1) ^ (key_prime[i - 1] >> 7)) & 0xFF
                val = (key_prime[i + hk_len] << 2) & 0xFF
                val2 = (key_prime[i + hk_len - 1] >> 6) & 0xFF
                hk[1][i] = (val ^ val2) & 0xFF
            else:
                hk[0][i] = (key_prime[i] << 1) & 0xFF
                val = (key_prime[i + hk_len] << 2) & 0xFF
                val2 = (key_prime[i + hk_len - 1] >> 6) & 0xFF
                hk[1][i] = ((val ^ val2) & 0xFE) & 0xFF

        self.hash_func(hk[0], t, h[0])
        self.hash_func(hk[1], t, h[1])
        return rk, w, h

    # --- Encrypt / Decrypt ---------------------------------------------------

    def encrypt(self, state: List[int], rk: List[List[int]], w: List[List[int]], h: List[List[int]]) -> None:
        self.whitening(state, w[0])
        for r in range(self.ra):
            self.sub_bytes(state)
            self.mix_columns(state)
            self.add_round_key(state, rk[r])
            self.add_round_constant(state, self.round_const[r])
            self.permutation(state)
        self.sub_bytes(state)
        self.mix_columns(state)
        self.add_round_key(state, h[0])
        self.permutation(state)
        for r in range(self.rb):
            self.sub_bytes(state)
            self.mix_columns(state)
            self.add_round_key(state, rk[r + self.ra])
            self.add_round_constant(state, self.round_const[r + self.ra])
            self.permutation(state)

        h_xor = [h[0][i] ^ h[1][i] for i in range(self.state_bytes)]
        self.sub_bytes(state)
        self.mix_columns(state)
        self.add_round_key(state, h_xor)
        self.sub_bytes(state)

        for r in range(self.rb):
            self.inv_permutation(state)
            self.add_round_constant(state, self.round_const_prime[r])
            self.add_round_key(state, rk[r])
            self.mix_columns(state)
            self.sub_bytes(state)
        self.inv_permutation(state)
        self.add_round_key(state, h[1])
        self.mix_columns(state)
        self.sub_bytes(state)
        for r in range(self.ra):
            self.inv_permutation(state)
            self.add_round_constant(state, self.round_const_prime[r + self.rb])
            self.add_round_key(state, rk[r + self.rb])
            self.mix_columns(state)
            self.sub_bytes(state)
        self.whitening(state, w[1])

    def decrypt(self, state: List[int], rk: List[List[int]], w: List[List[int]], h: List[List[int]]) -> None:
        self.whitening(state, w[1])
        for r in range(self.ra):
            self.sub_bytes(state)
            self.mix_columns(state)
            self.add_round_key(state, rk[self.ra + self.rb - r - 1])
            self.add_round_constant(state, self.round_const_prime[self.ra + self.rb - r - 1])
            self.permutation(state)
        self.sub_bytes(state)
        self.mix_columns(state)
        self.add_round_key(state, h[1])
        self.permutation(state)
        for r in range(self.rb):
            self.sub_bytes(state)
            self.mix_columns(state)
            self.add_round_key(state, rk[self.rb - r - 1])
            self.add_round_constant(state, self.round_const_prime[self.rb - r - 1])
            self.permutation(state)

        h_xor = [h[0][i] ^ h[1][i] for i in range(self.state_bytes)]
        self.sub_bytes(state)
        self.add_round_key(state, h_xor)
        self.mix_columns(state)
        self.sub_bytes(state)

        for r in range(self.rb):
            self.inv_permutation(state)
            self.add_round_constant(state, self.round_const[self.ra + self.rb - r - 1])
            self.add_round_key(state, rk[self.ra + self.rb - r - 1])
            self.mix_columns(state)
            self.sub_bytes(state)
        self.inv_permutation(state)
        self.add_round_key(state, h[0])
        self.mix_columns(state)
        self.sub_bytes(state)
        for r in range(self.ra):
            self.inv_permutation(state)
            self.add_round_constant(state, self.round_const[self.ra - r - 1])
            self.add_round_key(state, rk[self.ra - r - 1])
            self.mix_columns(state)
            self.sub_bytes(state)
        self.whitening(state, w[0])


# ---------------------------------------------------------------------------
# Pre-defined variant objects
# ---------------------------------------------------------------------------

Blink_64a = BlinkCipher(
    state_bytes=8,
    tweak_bytes=8,
    key_bytes=56,
    ra=2,
    rb=3,
    pbox=PBOX_64,
    round_const=ROUND_CONST_64,
    round_const_prime=ROUND_CONST_PRIME_64,
)

Blink_64b = BlinkCipher(
    state_bytes=8,
    tweak_bytes=16,
    key_bytes=56,
    ra=2,
    rb=3,
    pbox=PBOX_64,
    round_const=ROUND_CONST_64,
    round_const_prime=ROUND_CONST_PRIME_64,
)

Blink_128a = BlinkCipher(
    state_bytes=16,
    tweak_bytes=16,
    key_bytes=128,
    ra=3,
    rb=3,
    pbox=PBOX_128,
    round_const=ROUND_CONST_128a,
    round_const_prime=ROUND_CONST_PRIME_128a,
)

Blink_128b = BlinkCipher(
    state_bytes=16,
    tweak_bytes=32,
    key_bytes=128,
    ra=3,
    rb=3,
    pbox=PBOX_128,
    round_const=ROUND_CONST_128a,
    round_const_prime=ROUND_CONST_PRIME_128a,
)

Blink_128A = BlinkCipher(
    state_bytes=16,
    tweak_bytes=16,
    key_bytes=160,
    ra=3,
    rb=5,
    pbox=PBOX_128,
    round_const=ROUND_CONST_128A,
    round_const_prime=ROUND_CONST_PRIME_128A,
)

Blink_128B = BlinkCipher(
    state_bytes=16,
    tweak_bytes=32,
    key_bytes=160,
    ra=3,
    rb=5,
    pbox=PBOX_128,
    round_const=ROUND_CONST_128A,
    round_const_prime=ROUND_CONST_PRIME_128A,
)


# ---------------------------------------------------------------------------
# Convenience helpers
# ---------------------------------------------------------------------------

def hex_to_bytes(s: str) -> List[int]:
    s = s.replace(" ", "").replace("0x", "")
    return [int(s[i : i + 2], 16) for i in range(0, len(s), 2)]


def bytes_to_hex(b: List[int]) -> str:
    return "".join(f"{x:02x}" for x in b)


def encrypt_bytes(cipher: BlinkCipher, plaintext: bytes, tweak: bytes, key: bytes) -> bytes:
    """High-level encrypt: accepts big-endian bytes, returns big-endian bytes."""
    state = list(reversed(list(plaintext)))
    t = list(reversed(list(tweak)))
    master_key = list(reversed(list(key)))
    rk, w, h = cipher.generate_round_key(master_key, t)
    cipher.encrypt(state, rk, w, h)
    return bytes(reversed(state))


def decrypt_bytes(cipher: BlinkCipher, ciphertext: bytes, tweak: bytes, key: bytes) -> bytes:
    """High-level decrypt: accepts big-endian bytes, returns big-endian bytes."""
    state = list(reversed(list(ciphertext)))
    t = list(reversed(list(tweak)))
    master_key = list(reversed(list(key)))
    rk, w, h = cipher.generate_round_key(master_key, t)
    cipher.decrypt(state, rk, w, h)
    return bytes(reversed(state))


# ---------------------------------------------------------------------------
# Test vectors (big-endian hex notation, as in test vector.md)
# ---------------------------------------------------------------------------

TEST_VECTORS = [
    # (variant, name, plaintext_hex, key_hex, tweak_hex, ciphertext_hex)
    (
        Blink_128a,
        "Blink-128a",
        "00" * 16,
        (
            "d6a102d888a467e4d1d7dec33a246943"
            "e07c1dc6f302c57e762c2df9de6f0d21"
            "6dd387874a0b52ce3022e0ad78c78a06"
            "97779021b38e7fa15e2b66350517f80f"
            "2961c648d578bae174d70cb769c30a45"
            "cc40300fe8a342ca57a0bd0251ae39b6"
            "21b8f104904374bbd6a102e234a664e4"
            "21b8f104904374bbd6a102d888a666e4"
        ),
        "0123456789abcdef0123456789abcdef",
        "b722eef350bb182074a6ff13c967a593",
    ),
    (
        Blink_128A,
        "Blink-128A",
        "00" * 16,
        (
            "d6a102d888a467e4d1d7dec33a246943"
            "e07c1dc6f302c57e762c2df9de6f0d21"
            "6dd387874a0b52ce3022e0ad78c78a06"
            "97779021b38e7fa15e2b66350517f80f"
            "2961c648d578bae174d70cb769c30a45"
            "cc40300fe8a342ca57a0bd0251ae39b6"
            "21b8f104904374bbd6a102e234a664e4"
            "21b8f104904374bbd6a102d888a666e4"
            "28962a4c96893eda752c17026a6395c2"
            "d6963be43b2fc10813d73f5a4a48d28d"
        ),
        "0123456789abcdef0123456789abcdef",
        "82449f141c183601195b5046eac2b026",
    ),
    (
        Blink_128B,
        "Blink-128B",
        "00" * 16,
        (
            "d6a102d888a467e4d1d7dec33a246943"
            "e07c1dc6f302c57e762c2df9de6f0d21"
            "6dd387874a0b52ce3022e0ad78c78a06"
            "97779021b38e7fa15e2b66350517f80f"
            "2961c648d578bae174d70cb769c30a45"
            "cc40300fe8a342ca57a0bd0251ae39b6"
            "21b8f104904374bbd6a102e234a664e4"
            "21b8f104904374bbd6a102d888a666e4"
            "28962a4c96893eda752c17026a6395c2"
            "d6963be43b2fc10813d73f5a4a48d28d"
        ),
        "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
        "8dc41b223bc8cd9923b1297dd27583fc",
    ),
    (
        Blink_128b,
        "Blink-128b",
        "00" * 16,
        (
            "d6a102d888a467e4d1d7dec33a246943"
            "e07c1dc6f302c57e762c2df9de6f0d21"
            "6dd387874a0b52ce3022e0ad78c78a06"
            "97779021b38e7fa15e2b66350517f80f"
            "2961c648d578bae174d70cb769c30a45"
            "cc40300fe8a342ca57a0bd0251ae39b6"
            "21b8f104904374bbd6a102e234a664e4"
            "21b8f104904374bbd6a102d888a666e4"
        ),
        "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
        "20705a38e00412165bdabcac1dcbdec2",
    ),
    (
        Blink_64a,
        "Blink-64a",
        "00" * 8,
        (
            "d6a102d888a467e4d1d7dec33a246943"
            "e07c1dc6f302c57e762c2df9de6f0d21"
            "6dd387874a0b52ce3022e0ad78c78a06"
            "97779021b38e7fa1"
        ),
        "0123456789abcdef",
        "a4a0d10502be846e",
    ),
    (
        Blink_64b,
        "Blink-64b",
        "00" * 8,
        (
            "d6a102d888a467e4d1d7dec33a246943"
            "e07c1dc6f302c57e762c2df9de6f0d21"
            "6dd387874a0b52ce3022e0ad78c78a06"
            "97779021b38e7fa1"
        ),
        "0123456789abcdef0123456789abcdef",
        "743e142f17caaae1",
    ),
]


def run_tests():
    print("Running Blink test vectors...\n")
    for cipher, name, m_hex, k_hex, t_hex, c_hex in TEST_VECTORS:
        m = bytes.fromhex(m_hex)
        k = bytes.fromhex(k_hex)
        t = bytes.fromhex(t_hex)
        expected = bytes.fromhex(c_hex)

        c = encrypt_bytes(cipher, m, t, k)
        m_rec = decrypt_bytes(cipher, c, t, k)

        assert c == expected, (
            f"{name} encrypt mismatch!\n"
            f"  Expected: {expected.hex()}\n"
            f"  Got:      {c.hex()}"
        )
        assert m_rec == m, (
            f"{name} decrypt mismatch!\n"
            f"  Expected: {m.hex()}\n"
            f"  Got:      {m_rec.hex()}"
        )
        print(f"  {name}: OK  (c = {c.hex()})")

    # S-box involution check
    for x in range(16):
        assert SBOX[SBOX[x]] == x, f"S-box involution failed for x={x}"
    print("\nS-box involution: OK")

    print("\nAll tests passed!")


if __name__ == "__main__":
    run_tests()
