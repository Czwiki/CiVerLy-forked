r"""
Implementation of ARADI.

Aradi is a 128-bit SPN with four 32-bit state words. This implementation
follows the specification in the project documentation:

- a 4-bit S-box applied in parallel across the 32 bit positions,
- a word-wise linear layer on each 32-bit word,
- and explicit 128-bit round keys for each round plus a post-add.
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
        """Rotate a 32-bit word left by ``shift`` bits."""
        shift %= 32
        value &= _MASK32
        return ((value << shift) | (value >> (32 - shift))) & _MASK32

    @staticmethod
    def _rol16(value, shift):
        """Rotate a 16-bit half-word left by ``shift`` bits."""
        shift %= 16
        value &= _MASK16
        return ((value << shift) | (value >> (16 - shift))) & _MASK16

    @staticmethod
    def _aradi_sbox_table():
        """Build the 4-bit ARADI S-box truth table."""
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
        """Evaluate ARADI's linear layer on one 32-bit word."""
        upper = (word >> 16) & _MASK16
        lower = word & _MASK16

        first = upper ^ cls._rol16(upper, a) ^ cls._rol16(lower, c)
        second = lower ^ cls._rol16(lower, a) ^ cls._rol16(upper, b)

        return ((first & _MASK16) << 16) | (second & _MASK16)

    @classmethod
    def _aradi_linear_word_matrix(cls, a, b, c):
        """Return the binary matrix representation for one word transform."""
        rows = []
        for basis_index in range(32):
            basis = 1 << (31 - basis_index)
            rows.append(int_to_vec(cls._aradi_linear_word_eval(basis, a, b, c), 32))
        # LinearLayer_CVL expects a matrix where columns represent input bits.
        return matrix(GF(2), rows)

    def __init__(self, R=16, rks=[], name=None):
        r"""
        Implement ARADI in CiVerLy.

        INPUT:

            - ``R`` -- integer; Number of rounds.

            - ``rks`` -- list (optional); Explicit 128-bit round keys. If
              provided, it must have length ``R + 1``.

                            The first ``R`` entries are used as round keys for the SPN
                            rounds, and the final entry is applied as the post-round
                            whitening key.

            - ``name`` -- string (optional); The name of the cipher.

                IMPLEMENTATION NOTES:

                        - The 128-bit state is represented as four 32-bit words.
                        - The S-box layer applies the same 4-bit S-box to each bit slice
                            across the four words.
                        - The linear layer is built word by word from the ARADI
                            specification parameters ``(a, b, c)``.
                        - The cipher graph is assembled from reusable subciphers so the
                            round structure stays close to the specification.

        EXAMPLES::

            sage: from civerly.cipher_implementations.aradi import ARADI_CVL
            sage: from civerly.util import int_to_vec, vec_to_int
            sage: # Round keys from the reference test vector
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

        if len(rks) != R + 1:
            raise ValueError(
                f"ARADI requires exactly R+1 round keys, got {len(rks)} for R={R}"
            )

        cipher = SBoxCipher(128, 128, name=name)

        sbox = SBox_CVL(SBox(self._aradi_sbox_table()), name="SBox")
        sbox_layer = SBoxCipher(128, 128, name="SBoxLayer")
        for bit_index in range(32):
            # Each S-box instance consumes one bit from each 32-bit word,
            # which gives a 4-bit nibble at the same bit position.
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
            # Build one 32-bit linear transformation per state word.
            word_matrix = self._aradi_linear_word_matrix(
                a_values[word_index],
                b_values[word_index],
                c_values[word_index],
            )
            word_component = LinearLayer_CVL(
                word_matrix,
                name=f"L{word_index}"
            )
            # Wire the word component so its input and output bit positions
            # stay aligned with the surrounding 128-bit state layout.
            node = linear_layer.add_subcipher(
                word_component,
                [(linear_layer.IN, (32 * word_index + bit_index, bit_index)) for bit_index in range(32)]
            )
            linear_layer.add_output(
                [(node, (bit_index, 32 * word_index + bit_index)) for bit_index in range(32)]
            )

        # One ARADI round is: add round key -> S-box layer -> linear layer.
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
            # The round key component is reused; only its constant changes.
            round_cipher.nodes[1].const = rks[round_index]
            node = cipher.add_subcipher(
                round_cipher, [(node, (bit_index, bit_index)) for bit_index in range(128)]
            )

        # Final whitening step after the last round.
        post_rk = RoundkeyXOR_CVL(128, rks[R], name="PostRK")
        node = cipher.add_subcipher(
            post_rk, [(node, (bit_index, bit_index)) for bit_index in range(128)]
        )
        cipher.add_output([(node, (bit_index, bit_index)) for bit_index in range(128)])

        self.cipher = cipher

    def __new__(cls, *args, **kwargs):
        """Return the constructed cipher graph instance."""
        instance = super(ARADI_CVL, cls).__new__(cls)
        instance.__init__(*args, **kwargs)
        return instance.cipher


# ARADI is intentionally configured through explicit round keys.