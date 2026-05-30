"""
KATAN implementation for CiVerLy.

Reference implementation and attribution:
- Original C reference by Orr Dunkelman: http://www.cs.technion.ac.il/~orrd/KATAN/katan.c
- Public gist fork used for verification: https://gist.github.com/raullenchai/2712516

This Python/Sage implementation was validated against the C reference
included in documentation/reference_implementation_katan.c. Consult the
original sources for licensing and full attribution.
"""

from sage.crypto.sbox import SBox

from civerly.component import I_CVL, SBox_CVL
from civerly.cipher import Cipher


PARAMS = {
    32: {
        "l1": 13,
        "l2": 19,
        "fa": (12, 7, 8, 5, 3),
        "fb": (18, 7, 12, 10, 8, 3),
        "steps": 1,
    },
    48: {
        "l1": 19,
        "l2": 29,
        "fa": (18, 12, 15, 7, 6),
        "fb": (28, 19, 21, 13, 15, 6),
        "steps": 2,
    },
    64: {
        "l1": 25,
        "l2": 39,
        "fa": (24, 15, 20, 11, 9),
        "fb": (38, 25, 33, 21, 14, 9),
        "steps": 3,
    },
}


def _key_bits(key, rounds):
    bits = [(int(key) >> i) & 1 for i in range(80)]
    for i in range(80, 2 * rounds):
        bits.append(bits[i - 80] ^ bits[i - 61] ^ bits[i - 50] ^ bits[i - 13])
    return bits


def _ir_bits(rounds):
    state = [1] * 8

    def clock(current):
        new_bit = current[7] ^ current[6] ^ current[4] ^ current[2]
        return [new_bit] + current[:7]

    state = clock(state)
    result = []
    for _ in range(rounds):
        result.append(state[0])
        state = clock(state)
    return result


def _fa_sbox(ir_bit, key_bit):
    table = []
    for value in range(1 << 5):
        bits = [(value >> (4 - i)) & 1 for i in range(5)]
        output = bits[0] ^ bits[1] ^ (bits[2] & bits[3])
        if ir_bit:
            output ^= bits[4]
        output ^= key_bit
        table.append(output)
    return SBox(table)


def _fb_sbox(key_bit):
    table = []
    for value in range(1 << 6):
        bits = [(value >> (5 - i)) & 1 for i in range(6)]
        output = bits[0] ^ bits[1] ^ (bits[2] & bits[3]) ^ (bits[4] & bits[5])
        output ^= key_bit
        table.append(output)
    return SBox(table)


def _register_bit_index(l1_len, l2_len, register, bit_position):
    if register == "l1":
        return l1_len - 1 - bit_position
    if register == "l2":
        return l1_len + l2_len - 1 - bit_position
    raise ValueError("Unknown register")


def _build_step_cipher(l1_len, l2_len, fa_bits, fb_bits, ir_bit, ka, kb, name):
    step = Cipher(l1_len + l2_len, l1_len + l2_len, name=name)

    fa = SBox_CVL(_fa_sbox(ir_bit, ka), name=f"{name}-fa")
    fb = SBox_CVL(_fb_sbox(kb), name=f"{name}-fb")

    fa_edges = [
        (step.IN, (_register_bit_index(l1_len, l2_len, "l1", bit), i))
        for i, bit in enumerate(fa_bits)
    ]
    fb_edges = [
        (step.IN, (_register_bit_index(l1_len, l2_len, "l2", bit), i))
        for i, bit in enumerate(fb_bits)
    ]

    fa_node = step.add_subcipher(fa, fa_edges)
    fb_node = step.add_subcipher(fb, fb_edges)

    for bit in range(1, l1_len):
        route = I_CVL(1, name=f"{name}-l1-{bit}")
        node = step.add_subcipher(
            route,
            [(step.IN, (_register_bit_index(l1_len, l2_len, "l1", bit - 1), 0))],
        )
        step.add_output([(node, (0, _register_bit_index(l1_len, l2_len, "l1", bit)))])

    for bit in range(1, l2_len):
        route = I_CVL(1, name=f"{name}-l2-{bit}")
        node = step.add_subcipher(
            route,
            [(step.IN, (_register_bit_index(l1_len, l2_len, "l2", bit - 1), 0))],
        )
        step.add_output([(node, (0, _register_bit_index(l1_len, l2_len, "l2", bit)))])

    step.add_output([(fa_node, (0, _register_bit_index(l1_len, l2_len, "l2", 0)))])
    step.add_output([(fb_node, (0, _register_bit_index(l1_len, l2_len, "l1", 0)))])
    return step


def _build_round_cipher(variant, round_index, ka, kb, ir_bit):
    params = PARAMS[variant]
    l1_len = params["l1"]
    l2_len = params["l2"]
    fa_bits = params["fa"]
    fb_bits = params["fb"]
    steps = params["steps"]

    round_cipher = Cipher(l1_len + l2_len, l1_len + l2_len, name=f"KATAN{variant}-r{round_index}")
    node = round_cipher.IN
    for step_idx in range(steps):
        step = _build_step_cipher(
            l1_len,
            l2_len,
            fa_bits,
            fb_bits,
            ir_bit,
            ka,
            kb,
            name=f"KATAN{variant}-r{round_index}-s{step_idx}",
        )
        node = round_cipher.add_subcipher(
            step,
            [(node, (i, i)) for i in range(l1_len + l2_len)],
        )
    round_cipher.add_output([(node, (i, i)) for i in range(l1_len + l2_len)])
    return round_cipher


def reference_katan_encrypt(variant, plaintext_int, key_int, rounds):
    r"""Reference Python implementation mirroring the C reference.

    Returns integer ciphertext. Used for doctests.

    Examples (small rounds):

    >>> from civerly.cipher_implementations.katan import KATAN_CVL, reference_katan_encrypt
    >>> from civerly.util import int_to_vec, vec_to_int
    >>> key = 0x0123456789abcdef0123  # 80-bit example key
    >>> pt32 = 0x12345678
    >>> c = KATAN_CVL(variant=32, R=10, key=key)
    >>> vec_to_int(c(int_to_vec(pt32, 32))) == reference_katan_encrypt(32, pt32, key, 10)
    True

    >>> pt48 = 0x123456789abc
    >>> c48 = KATAN_CVL(variant=48, R=8, key=key)
    >>> vec_to_int(c48(int_to_vec(pt48, 48))) == reference_katan_encrypt(48, pt48, key, 8)
    True

    >>> pt64 = 0x0123456789abcdef
    >>> c64 = KATAN_CVL(variant=64, R=6, key=key)
    >>> vec_to_int(c64(int_to_vec(pt64, 64))) == reference_katan_encrypt(64, pt64, key, 6)
    True
    """
    params = PARAMS[variant]
    l1 = params["l1"]
    l2 = params["l2"]
    fa_pos = params["fa"]
    fb_pos = params["fb"]
    steps = params["steps"]

    # initialize L1 and L2 as lists of bits, index 0 = least significant
    mask_l2 = (1 << l2) - 1
    L2 = [(plaintext_int >> i) & 1 for i in range(l2)]
    L1 = [((plaintext_int >> (l2 + i)) & 1) for i in range(l1)]

    # key bits
    k = [(int(key_int) >> i) & 1 for i in range(80)]
    for i in range(80, 2 * rounds):
        k.append(k[i - 80] ^ k[i - 61] ^ k[i - 50] ^ k[i - 13])

    # IR stream
    ir = _ir_bits(rounds)

    for r in range(rounds):
        if steps == 1:
            fa = L1[fa_pos[0]] ^ L1[fa_pos[1]] ^ (L1[fa_pos[2]] & L1[fa_pos[3]]) ^ ((L1[fa_pos[4]] & ir[r])) ^ k[2 * r]
            fb = L2[fb_pos[0]] ^ L2[fb_pos[1]] ^ (L2[fb_pos[2]] & L2[fb_pos[3]]) ^ ((L2[fb_pos[4]] & L2[fb_pos[5]])) ^ k[2 * r + 1]

            # shift left (towards higher index), dropping MSB (last element)
            L1 = [fb] + L1[:-1]
            L2 = [fa] + L2[:-1]

        elif steps == 2:
            fa_1 = L1[fa_pos[0]] ^ L1[fa_pos[1]] ^ (L1[fa_pos[2]] & L1[fa_pos[3]]) ^ ((L1[fa_pos[4]] & ir[r])) ^ k[2 * r]
            fa_0 = L1[fa_pos[0] - 1] ^ L1[fa_pos[1] - 1] ^ (L1[fa_pos[2] - 1] & L1[fa_pos[3] - 1]) ^ ((L1[fa_pos[4] - 1] & ir[r])) ^ k[2 * r]
            fb_1 = L2[fb_pos[0]] ^ L2[fb_pos[1]] ^ (L2[fb_pos[2]] & L2[fb_pos[3]]) ^ ((L2[fb_pos[4]] & L2[fb_pos[5]])) ^ k[2 * r + 1]
            fb_0 = L2[fb_pos[0] - 1] ^ L2[fb_pos[1] - 1] ^ (L2[fb_pos[2] - 1] & L2[fb_pos[3] - 1]) ^ ((L2[fb_pos[4] - 1] & L2[fb_pos[5] - 1])) ^ k[2 * r + 1]

            L1 = [fb_0, fb_1] + L1[:-2]
            L2 = [fa_0, fa_1] + L2[:-2]

        elif steps == 3:
            fa_2 = L1[fa_pos[0]] ^ L1[fa_pos[1]] ^ (L1[fa_pos[2]] & L1[fa_pos[3]]) ^ ((L1[fa_pos[4]] & ir[r])) ^ k[2 * r]
            fa_1 = L1[fa_pos[0] - 1] ^ L1[fa_pos[1] - 1] ^ (L1[fa_pos[2] - 1] & L1[fa_pos[3] - 1]) ^ ((L1[fa_pos[4] - 1] & ir[r])) ^ k[2 * r]
            fa_0 = L1[fa_pos[0] - 2] ^ L1[fa_pos[1] - 2] ^ (L1[fa_pos[2] - 2] & L1[fa_pos[3] - 2]) ^ ((L1[fa_pos[4] - 2] & ir[r])) ^ k[2 * r]
            fb_2 = L2[fb_pos[0]] ^ L2[fb_pos[1]] ^ (L2[fb_pos[2]] & L2[fb_pos[3]]) ^ ((L2[fb_pos[4]] & L2[fb_pos[5]])) ^ k[2 * r + 1]
            fb_1 = L2[fb_pos[0] - 1] ^ L2[fb_pos[1] - 1] ^ (L2[fb_pos[2] - 1] & L2[fb_pos[3] - 1]) ^ ((L2[fb_pos[4] - 1] & L2[fb_pos[5] - 1])) ^ k[2 * r + 1]
            fb_0 = L2[fb_pos[0] - 2] ^ L2[fb_pos[1] - 2] ^ (L2[fb_pos[2] - 2] & L2[fb_pos[3] - 2]) ^ ((L2[fb_pos[4] - 2] & L2[fb_pos[5] - 2])) ^ k[2 * r + 1]

            L1 = [fb_0, fb_1, fb_2] + L1[:-3]
            L2 = [fa_0, fa_1, fa_2] + L2[:-3]

        else:
            raise ValueError("Unsupported steps")

    # recombine
    out = 0
    for i in range(l1 - 1, -1, -1):
        out = (out << 1) | L1[i]
    for i in range(l2 - 1, -1, -1):
        out = (out << 1) | L2[i]
    return out


class KATAN_CVL:
    def __init__(self, variant=32, R=254, key=0, name=None):
        if variant not in PARAMS:
            raise ValueError("Unsupported KATAN variant")

        params = PARAMS[variant]
        l1_len = params["l1"]
        l2_len = params["l2"]
        block_size = l1_len + l2_len

        if name is None:
            name = f"KATAN{variant}"

        key_stream = _key_bits(key, R)
        ir_stream = _ir_bits(R)

        cipher = Cipher(block_size, block_size, name=name)
        node = cipher.IN
        for round_index in range(R):
            ka = key_stream[2 * round_index]
            kb = key_stream[2 * round_index + 1]
            round_cipher = _build_round_cipher(
                variant,
                round_index,
                ka,
                kb,
                ir_stream[round_index],
            )
            node = cipher.add_subcipher(
                round_cipher,
                [(node, (i, i)) for i in range(block_size)],
            )

        cipher.add_output([(node, (i, i)) for i in range(block_size)])
        self.cipher = cipher

    def __new__(cls, *args, **kwargs):
        instance = super(KATAN_CVL, cls).__new__(cls)
        instance.__init__(*args, **kwargs)
        return instance.cipher
