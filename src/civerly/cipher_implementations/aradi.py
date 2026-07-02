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
        return matrix(GF(2), rows).transpose()

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
            ....:   0x313237342b2c2d2a89829f94eaddccfb,
            ....:   0x1918131249484342bfb2b5b8efe2e5e8,
            ....:   0x93d8dd9649bbf10212918d0e2caf0292,
            ....:   0x7c795e5b6e0a4a2f708952ab0fb51eb7,
            ....:   0x73be37f3b12de15c6d10261a63fa1fb1,
            ....:   0x30e1a56556518eba38a4dc7043b62b6b,
            ....:   0x6ff94bf4a1525d49960d690af40ac5e6,
            ....:   0x652b43fa7ea0caa18356eca6eed8d0ca,
            ....:   0x1e8816b8eaf40402bf1911dbd2ed83c3,
            ....:   0x2aed0767d7e429720ddcac43e0ce34bd,
            ....:   0xe587db6fd93a728ee7a7904354e47c4c,
            ....:   0x5deafddf1235c451b94205971bc4fb83,
            ....:   0xf95881fca9cbae8e266a00c264230546,
            ....:   0xcc0fab2e5b7aad7732495539b022810a,
            ....:   0x71c5c0468ab9aa02d8fb0856b7dfa119,
            ....:   0xa443053b69322a8ee8abfb4f41cf0ca8,
            ....: ]
            sage: aradi = ARADI_CVL(rks=rks)
            sage: hex(vec_to_int(aradi(int_to_vec(0x0, 128))))
            '0x3f09abf400e3bd7403260defb7c53912'
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

        linear_layers = []
        for round_index in range(4):
            a_values = [11, 10, 9, 8]
            b_values = [8, 9, 4, 9]
            c_values = [14, 11, 14, 7]

            linear_layer = SBoxCipher(128, 128, name=f"LinearLayer{round_index}")
            word_matrix = self._aradi_linear_word_matrix(
                a_values[round_index],
                b_values[round_index],
                c_values[round_index],
            )
            word_component = LinearLayer_CVL(
                word_matrix,
                name=f"L{round_index}"
            )
            for word_index in range(4):
                # Each round uses the same 32-bit linear transform on every word.
                node = linear_layer.add_subcipher(
                    word_component,
                    [(linear_layer.IN, (32 * word_index + bit_index, bit_index)) for bit_index in range(32)]
                )
                linear_layer.add_output(
                    [(node, (bit_index, 32 * word_index + bit_index)) for bit_index in range(32)]
                )
            linear_layers.append(linear_layer)

        # One ARADI round is: add round key -> S-box layer -> round-dependent linear layer.
        round_ciphers = []
        for round_index in range(4):
            round_cipher = SBoxCipher(128, 128, name=f"ARADI-round{round_index}")
            rk = RoundkeyXOR_CVL(128, 0, name="RK")
            node_rk = round_cipher.add_subcipher(
                rk, [(round_cipher.IN, (bit_index, bit_index)) for bit_index in range(128)]
            )
            node_sbox = round_cipher.add_subcipher(
                sbox_layer, [(node_rk, (bit_index, bit_index)) for bit_index in range(128)]
            )
            node_linear = round_cipher.add_subcipher(
                linear_layers[round_index], [(node_sbox, (bit_index, bit_index)) for bit_index in range(128)]
            )
            round_cipher.add_output([(node_linear, (bit_index, bit_index)) for bit_index in range(128)])
            round_ciphers.append(round_cipher)

        node = cipher.IN
        for round_index in range(R):
            round_cipher = round_ciphers[round_index % 4]
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
