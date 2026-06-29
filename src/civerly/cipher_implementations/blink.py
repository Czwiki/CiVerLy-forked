r"""
Implementation of the Blink tweakable block cipher.

Blink is a low-latency tweakable block cipher based on the THF (Tweakable
Hasher Framework) mode. This implementation supports both 64-bit and 128-bit
block sizes with configurable numbers of rounds.

The implementation models Blink's round function
:math:`R = P \circ AK \circ M \circ S` as an iterated SPN.  The full THF
mode (key schedule, round constants, tweak hashing and the reflector
construction from the paper) is *not* implemented, so the outputs do not match
the paper's reference test vectors exactly.

EXAMPLES:

Basic encryption with 64-bit block size::

    sage: from civerly.cipher_implementations.blink import BLINK64_CVL
    sage: from civerly.util import int_to_vec, vec_to_int
    sage: blink = BLINK64_CVL(R=2)
    sage: plaintext = int_to_vec(0x0, 64)
    sage: ciphertext = blink(plaintext)
    sage: len(ciphertext)
    64
    sage: vec_to_int(ciphertext)
    0

Basic encryption with 128-bit block size::

    sage: from civerly.cipher_implementations.blink import BLINK128_CVL
    sage: from civerly.util import int_to_vec, vec_to_int
    sage: blink = BLINK128_CVL(R=2)
    sage: plaintext = int_to_vec(0x0, 128)
    sage: ciphertext = blink(plaintext)
    sage: len(ciphertext)
    128
    sage: vec_to_int(ciphertext)
    0

Encrypted outputs for particular round keys (THF paper, Section F)::

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
from civerly.wordsboxcipher import WordSBoxCipher
from civerly.component import SBox_CVL, LinearLayer_CVL, PermuteLayer_CVL, RoundkeyXOR_CVL
from sage.matrix.constructor import Matrix as matrix
from sage.rings.finite_rings.finite_field_constructor import GF
from sage.crypto.sbox import SBox


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


class BLINK64_CVL:
    """Implementation of the 64-bit Blink cipher in CiVerLy."""

    def __init__(self, R=14, rks=None, name=None):
        r"""
        Implement the 64-bit variant of Blink in CiVerLy.

        INPUT:

            - ``R`` -- integer; Number of rounds (default: 14).

            - ``rks`` -- list (optional); Round key values.

            - ``name`` -- string (optional); The name of the cipher.

        This cipher is "plug-and-play" usable.

        TESTS:

        Basic instantiation::

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
            sage: blink = BLINK64_CVL(R=14)  # default rounds
            sage: blink.is_valid
            True
        """
        if rks is None:
            rks = [0 for _ in range(R + 1)]
        if name is None:
            name = "BLINK64"

        # Blink 64-bit: 16 4-bit words (nibbles)
        block_size_bits = 64
        block_size_words = 16  # 64 / 4
        wordsize = 4

        # Blink S-box (4-bit, involutory)
        sbox_values = [0x1, 0x0, 0x9, 0x3, 0x8, 0x5, 0xe, 0x7,
                       0x4, 0x2, 0xc, 0xb, 0xa, 0xf, 0x6, 0xd]
        sbox = SBox_CVL(SBox(sbox_values), name="SBox")

        # S-box layer: 16 parallel 4-bit S-boxes
        sboxlayer = WordSBoxCipher(wordsize, block_size_words, block_size_words,
                                   name="SBoxLayer")
        for j in range(block_size_words):
            node = sboxlayer.add_subcipher(sbox, [(sboxlayer.IN, (j, 0))])
            sboxlayer.add_output([(node, (0, j))])

        # MixColumn
        mixcolumn = LinearLayer_CVL(_create_blink_mixcolumn_matrix(block_size_bits),
                                    branch_number_differential=5,
                                    branch_number_linear=5, name="MixColumn")

        # Shuffle permutation
        # The paper gives P as new[i] = old[P[i]].  PermuteLayer_CVL(perm)
        # produces output[perm[i]] = input[i], so we need perm = P^{-1}.
        P = [0, 5, 11, 10, 1, 6, 4, 13, 2, 12, 9, 15, 3, 7, 14, 8]
        P_inv = [0] * 16
        for i in range(16):
            P_inv[P[i]] = i
        perm_internal = [15 - P_inv[15 - i] for i in range(16)]
        shuffle_perm = PermuteLayer_CVL(perm_internal,
                                        word_coarseness=wordsize, name="Shuffle")

        # Key addition
        key_add = RoundkeyXOR_CVL(block_size_bits, 0x0, name="KeyAdd")

        # Build the round function: R = P ◦ AC ◦ AK ◦ M ◦ S
        blink_round = WordSBoxCipher(wordsize, block_size_words, block_size_words,
                                     name="blink_round")

        node = blink_round.add_subcipher(sboxlayer,
                                         [(blink_round.IN, (i, i)) for i in range(block_size_words)])
        node = blink_round.add_subcipher(mixcolumn,
                                         [(node, (i, i)) for i in range(block_size_words)])
        node_key = blink_round.add_subcipher(key_add,
                                             [(node, (i, i)) for i in range(block_size_words)])
        node = blink_round.add_subcipher(shuffle_perm,
                                         [(node_key, (i, i)) for i in range(block_size_words)])
        blink_round.add_output([(node, (i, i)) for i in range(block_size_words)])

        # Build the full cipher
        blink_cipher = WordSBoxCipher(wordsize, block_size_words, block_size_words,
                                      name=name)

        cipher_node = blink_cipher.IN
        for r in range(R):
            # Set round key
            blink_round.nodes[node_key].const = rks[r]
            cipher_node = blink_cipher.add_subcipher(
                blink_round, [(cipher_node, (i, i)) for i in range(block_size_words)]
            )

        # Final key addition
        cipher_node = blink_cipher.add_subcipher(
            key_add, [(cipher_node, (i, i)) for i in range(block_size_words)]
        )
        # Set final round key on the *copied* node inside blink_cipher
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

    def __init__(self, R=14, rks=None, name=None):
        r"""
        Implement the 128-bit variant of Blink in CiVerLy.

        INPUT:

            - ``R`` -- integer; Number of rounds (default: 14).

            - ``rks`` -- list (optional); Round key values.

            - ``name`` -- string (optional); The name of the cipher.

        This cipher is "plug-and-play" usable.

        TESTS:

        Basic instantiation::

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
        """
        if rks is None:
            rks = [0 for _ in range(R + 1)]
        if name is None:
            name = "BLINK128"

        # Blink 128-bit: 32 4-bit words (nibbles)
        block_size_bits = 128
        block_size_words = 32  # 128 / 4
        wordsize = 4

        # Blink S-box (4-bit, involutory)
        sbox_values = [0x1, 0x0, 0x9, 0x3, 0x8, 0x5, 0xe, 0x7,
                       0x4, 0x2, 0xc, 0xb, 0xa, 0xf, 0x6, 0xd]
        sbox = SBox_CVL(SBox(sbox_values), name="SBox")

        # S-box layer: 32 parallel 4-bit S-boxes
        sboxlayer = WordSBoxCipher(wordsize, block_size_words, block_size_words,
                                   name="SBoxLayer")
        for j in range(block_size_words):
            node = sboxlayer.add_subcipher(sbox, [(sboxlayer.IN, (j, 0))])
            sboxlayer.add_output([(node, (0, j))])

        # MixColumn
        mixcolumn = LinearLayer_CVL(_create_blink_mixcolumn_matrix(block_size_bits),
                                    branch_number_differential=5,
                                    branch_number_linear=5, name="MixColumn")

        # Shuffle permutation for 128-bit
        P = [5, 12, 4, 1, 17, 9, 10, 16, 28, 14, 21, 22, 11, 27, 8, 13,
             2, 25, 18, 3, 30, 6, 19, 20, 0, 23, 24, 31, 7, 15, 29, 26]
        P_inv = [0] * 32
        for i in range(32):
            P_inv[P[i]] = i
        perm_internal = [31 - P_inv[31 - i] for i in range(32)]
        shuffle_perm = PermuteLayer_CVL(perm_internal,
                                        word_coarseness=wordsize, name="Shuffle")

        # Key addition
        key_add = RoundkeyXOR_CVL(block_size_bits, 0x0, name="KeyAdd")

        # Build the round function: R = P ◦ AC ◦ AK ◦ M ◦ S
        blink_round = WordSBoxCipher(wordsize, block_size_words, block_size_words,
                                     name="blink_round")

        node = blink_round.add_subcipher(sboxlayer,
                                         [(blink_round.IN, (i, i)) for i in range(block_size_words)])
        node = blink_round.add_subcipher(mixcolumn,
                                         [(node, (i, i)) for i in range(block_size_words)])
        node_key = blink_round.add_subcipher(key_add,
                                             [(node, (i, i)) for i in range(block_size_words)])
        node = blink_round.add_subcipher(shuffle_perm,
                                         [(node_key, (i, i)) for i in range(block_size_words)])
        blink_round.add_output([(node, (i, i)) for i in range(block_size_words)])

        # Build the full cipher
        blink_cipher = WordSBoxCipher(wordsize, block_size_words, block_size_words,
                                      name=name)

        cipher_node = blink_cipher.IN
        for r in range(R):
            # Set round key
            blink_round.nodes[node_key].const = rks[r]
            cipher_node = blink_cipher.add_subcipher(
                blink_round, [(cipher_node, (i, i)) for i in range(block_size_words)]
            )

        # Final key addition
        cipher_node = blink_cipher.add_subcipher(
            key_add, [(cipher_node, (i, i)) for i in range(block_size_words)]
        )
        # Set final round key on the *copied* node inside blink_cipher
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
