r"""
Implementation of ARADI.

Aradi is a 128-bit SPN with four 32-bit state words. This implementation
follows the specification in the project documentation:

- a 4-bit S-box applied in parallel across the 32 bit positions,
- a word-wise linear layer on each 32-bit word,
- and a 256-bit key schedule that expands to 16 round keys plus a post-add.
"""

from civerly.sboxcipher import SBoxCipher
from civerly.component import SBox_CVL, LinearLayer_CVL, RoundkeyXOR_CVL
from civerly.util import int_to_vec

from sage.crypto.sbox import SBox
from sage.matrix.constructor import Matrix as matrix
from sage.rings.finite_rings.finite_field_constructor import GF


_MASK16 = (1 << 16) - 1
_MASK32 = (1 << 32) - 1


class ARADI_CVL:
    @staticmethod
    def _rol32(value, shift):
        shift %= 32
        value &= _MASK32
        return ((value << shift) | (value >> (32 - shift))) & _MASK32

    @staticmethod
    def _rol16(value, shift):
        shift %= 16
        value &= _MASK16
        return ((value << shift) | (value >> (16 - shift))) & _MASK16

    @staticmethod
    def _aradi_sbox_table():
        table = []
        for nibble in range(16):
            w = (nibble >> 3) & 1
            x = (nibble >> 2) & 1
            y = (nibble >> 1) & 1
            z = nibble & 1

            x = x ^ (w & y)
            z = z ^ (x & y)
            y = y ^ (w & z)
            w = w ^ (x & z)

            table.append((w << 3) | (x << 2) | (y << 1) | z)
        return table

    @classmethod
    def _aradi_linear_word_eval(cls, word, a, b, c):
        upper = (word >> 16) & _MASK16
        lower = word & _MASK16

        first = upper ^ cls._rol16(upper, a) ^ cls._rol16(lower, c)
        second = lower ^ cls._rol16(lower, a) ^ cls._rol16(upper, b)

        return ((first & _MASK16) << 16) | (second & _MASK16)

    @classmethod
    def _aradi_linear_word_matrix(cls, a, b, c):
        rows = []
        for basis_index in range(32):
            basis = 1 << (31 - basis_index)
            rows.append(int_to_vec(cls._aradi_linear_word_eval(basis, a, b, c), 32))
        # LinearLayer_CVL expects a matrix where columns represent input bits.
        return matrix(GF(2), rows)

    @classmethod
    def _expand_aradi_round_keys(cls, key, rounds):
        if key < 0 or key >= (1 << 256):
            raise ValueError("ARADI key must fit into 256 bits")

        # Interpret the 256-bit key as a sequence of 32-bit words with the
        # most-significant word first. This follows the test-vector byte-order
        # convention (e.g. 0x03020100 for a 4-byte word).
        words = [(key >> (32 * (7 - i))) & _MASK32 for i in range(8)]
        round_keys = []

        def m0(x, y):
            new_x = cls._rol32(x, 1) ^ y
            new_y = cls._rol32(y, 3) ^ new_x
            return new_x & _MASK32, new_y & _MASK32

        def m1(x, y):
            new_x = cls._rol32(x, 9) ^ y
            new_y = cls._rol32(y, 28) ^ new_x
            return new_x & _MASK32, new_y & _MASK32

        for i in range(rounds):
            if i % 2 == 0:
                round_keys.append(
                    (words[0] << 96)
                    | (words[1] << 64)
                    | (words[2] << 32)
                    | words[3]
                )
            else:
                round_keys.append(
                    (words[4] << 96)
                    | (words[5] << 64)
                    | (words[6] << 32)
                    | words[7]
                )

            words[1], words[0] = m0(words[1], words[0])
            words[3], words[2] = m1(words[3], words[2])
            words[5], words[4] = m0(words[5], words[4])
            words[7], words[6] = m1(words[7], words[6])
            words[7] ^= i

            if i % 2 == 0:
                words[1], words[2] = words[2], words[1]
                words[5], words[6] = words[6], words[5]
            else:
                words[1], words[4] = words[4], words[1]
                words[3], words[6] = words[6], words[3]

        round_keys.append(
            (words[0] << 96)
            | (words[1] << 64)
            | (words[2] << 32)
            | words[3]
        )
        return round_keys

    def __init__(self, R=16, key=None, rks=[], name=None):
        r"""
        Implement ARADI in CiVerLy.

        INPUT:

            - ``R`` -- integer; Number of rounds.

            - ``key`` -- integer (optional); 256-bit master key used to derive
              round keys when ``rks`` is not provided. Defaults to the all-zero
              key.

            - ``rks`` -- list (optional); Explicit 128-bit round keys. If
              provided, it must have length ``R + 1`` and overrides ``key``.

            - ``name`` -- string (optional); The name of the cipher.

        EXAMPLES::

            sage: from civerly.cipher_implementations.aradi import ARADI_CVL
            sage: from civerly.util import int_to_vec, vec_to_int
            sage: # Test vector (full encryption) from reference
            sage: KEY = 0x1f1e1d1c1b1a191817161514131211100f0e0d0c0b0a09080706050403020100
            sage: # Round keys (precomputed for the given KEY)
            sage: rks = [
            ....:   0x3020100070605040b0a09080f0e0d0c,
            ....:   0xa5aeb3b8a69180b73d3e3b3827202126,
            ....:   0x92af7845c5f82f12adfcc796feaf94c5,
            ....:   0x39bf0583b7100baeeb4405aad5c2c9de,
            ....:   0xdd16c60d9a673ec7b25203e3c063f85b,
            ....:   0xf280e298478b8a40130fc1d51cb7f55c,
            ....:   0x9715fc36e990e2df822df6d12dd585f1,
            ....:   0x844355d2fc88a846674e4f666643af96,
            ....:   0x7a4c8e1c5f48abcb9c5e6e438665875c,
            ....:   0x90a43ad19a5ba4c66436454d2ada7613,
            ....:   0x7e5e81772132a5d0c93e9abc0699074c,
            ....:   0xdf2b7d7897e250f783b52c86d1b5648f,
            ....:   0xd7f61c3e09b437512ffd158c814761ed,
            ....:   0x4c1714b2b19b1e614057ae77a458f4ff,
            ....:   0x65d837954f998de3754a88f785bb2bd8,
            ....:   0x78b9a112e313cc0e2eefc24c5a10a33,
            ....:   0x9ded35d867b53319ff366690eed4746d,
            ....: ]
            sage: aradi = ARADI_CVL(rks=rks)
            sage: hex(vec_to_int(aradi(int_to_vec(0x0, 128))))
            '0xa52604bc87564e804d7a319f0a404aee'
        """
        if name is None:
            name = "ARADI"

        if rks == []:
            if key is None:
                key = 0
            rks = self._expand_aradi_round_keys(key, R)

        if len(rks) != R + 1:
            raise ValueError(
                f"ARADI requires exactly R+1 round keys, got {len(rks)} for R={R}"
            )

        cipher = SBoxCipher(128, 128, name=name)

        sbox = SBox_CVL(SBox(self._aradi_sbox_table()), name="SBox")
        sbox_layer = SBoxCipher(128, 128, name="SBoxLayer")
        for bit_index in range(32):
            # Use direct bit_index mapping (LSB-first within words). This
            # matches the test-vector wiring and previous working version.
            node = sbox_layer.add_subcipher(
                sbox,
                [(sbox_layer.IN, (bit_index + 32 * word_index, word_index)) for word_index in range(4)]
            )
            sbox_layer.add_output(
                [(node, (word_index, bit_index + 32 * word_index)) for word_index in range(4)]
            )

        a_values = [11, 10, 9, 8]
        b_values = [8, 9, 4, 9]
        c_values = [14, 11, 14, 7]

        linear_layer = SBoxCipher(128, 128, name="LinearLayer")
        for word_index in range(4):
            word_matrix = self._aradi_linear_word_matrix(
                a_values[word_index],
                b_values[word_index],
                c_values[word_index],
            )
            word_component = LinearLayer_CVL(
                word_matrix,
                name=f"L{word_index}"
            )
            # Connect the linear word component with direct bit ordering
            node = linear_layer.add_subcipher(
                word_component,
                [(linear_layer.IN, (32 * word_index + bit_index, bit_index)) for bit_index in range(32)]
            )
            linear_layer.add_output(
                [(node, (bit_index, 32 * word_index + bit_index)) for bit_index in range(32)]
            )

        round_cipher = SBoxCipher(128, 128, name="ARADI-round")
        rk = RoundkeyXOR_CVL(128, 0, name="RK")
        node_rk = round_cipher.add_subcipher(
            rk, [(round_cipher.IN, (bit_index, bit_index)) for bit_index in range(128)]
        )
        node_sbox = round_cipher.add_subcipher(
            sbox_layer, [(node_rk, (bit_index, bit_index)) for bit_index in range(128)]
        )
        node_linear = round_cipher.add_subcipher(
            linear_layer, [(node_sbox, (bit_index, bit_index)) for bit_index in range(128)]
        )
        round_cipher.add_output([(node_linear, (bit_index, bit_index)) for bit_index in range(128)])

        node = cipher.IN
        for round_index in range(R):
            round_cipher.nodes[1].const = rks[round_index]
            node = cipher.add_subcipher(
                round_cipher, [(node, (bit_index, bit_index)) for bit_index in range(128)]
            )

        post_rk = RoundkeyXOR_CVL(128, rks[R], name="PostRK")
        node = cipher.add_subcipher(
            post_rk, [(node, (bit_index, bit_index)) for bit_index in range(128)]
        )
        cipher.add_output([(node, (bit_index, bit_index)) for bit_index in range(128)])

        self.cipher = cipher

    def __new__(cls, *args, **kwargs):
        instance = super(ARADI_CVL, cls).__new__(cls)
        instance.__init__(*args, **kwargs)
        return instance.cipher


# Backwards-compatible thin wrappers (preferred: use ARADI_CVL methods).
# Note: helper functions are implemented as private methods on
# `ARADI_CVL` (e.g. `ARADI_CVL._expand_aradi_round_keys`).
# Module-level wrappers were removed to keep the public module API
# minimal and to match the style of other cipher implementations.