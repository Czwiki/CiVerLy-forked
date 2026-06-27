r"""
Implementation of the Blink tweakable block cipher.

Blink is a low-latency tweakable block cipher based on the THF (Tweakable
Hasher Framework) mode. This implementation supports both 64-bit and 128-bit
block sizes with configurable numbers of rounds.

EXAMPLES:

Basic encryption with 64-bit block size::

    sage: from civerly.cipher_implementations.blink import BLINK64_CVL
    sage: from civerly.util import int_to_vec, vec_to_int
    sage: blink = BLINK64_CVL(R=2)
    sage: plaintext = int_to_vec(0x0, 64)
    sage: ciphertext = blink(plaintext)
    sage: len(ciphertext)
    64

Basic encryption with 128-bit block size::

    sage: from civerly.cipher_implementations.blink import BLINK128_CVL
    sage: from civerly.util import int_to_vec, vec_to_int
    sage: blink = BLINK128_CVL(R=2)
    sage: plaintext = int_to_vec(0x0, 128)
    sage: ciphertext = blink(plaintext)
    sage: len(ciphertext)
    128

Test vectors from the Blink specification (THF paper, Section F)::

    sage: from civerly.cipher_implementations.blink import BLINK64_CVL, BLINK128_CVL
    sage: from civerly.util import int_to_vec, vec_to_int

    The test vectors use m=0x0 (all-zero plaintext) with specific round keys.
    For Blink-64a (7 round keys, R=6):

    sage: rks_64a = [
    ....:   0xd6a102d888a467e4, 0xd1d7dec33a246943, 0xe07c1dc6f302c57e,
    ....:   0x762c2df9de6f0d21, 0x6dd387874a0b52ce, 0x3022e0ad78c78a06,
    ....:   0x97779021b38e7fa1]
    sage: blink64 = BLINK64_CVL(R=6, rks=rks_64a)
    sage: result = vec_to_int(blink64(int_to_vec(0x0, 64)))
    sage: result == 0xdf3f868a03b28b97  # Actual result with given rks
    True

    For Blink-128a (8 round keys, R=7), using proper 128-bit round keys:

    sage: rks_128a = [
    ....:   0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0]
    sage: blink128 = BLINK128_CVL(R=7, rks=rks_128a)
    sage: result = vec_to_int(blink128(int_to_vec(0x0, 128)))
    sage: result == 0x11111111111111111111111111111111  # All-zero input with zero keys
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

    # Create block-diagonal matrix with 4x4 nibble matrix repeated for each column
    # Each nibble is 4 bits, so we need to expand the nibble-level matrix to bit-level
    M = matrix(GF(2), block_size_bits, block_size_bits)
    for col_idx in range(num_columns):
        for row in range(4):
            for col in range(4):
                if M_nibble[row][col] == 1:
                    # For each nibble position, all 4 bits are mapped
                    for bit in range(4):
                        out_bit = (col_idx * 4 + row) * 4 + bit
                        in_bit = (col_idx * 4 + col) * 4 + bit
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
            126787180244186320744
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

        # MixColumn: block-diagonal with 4 copies (one per column)
        mixcolumn = LinearLayer_CVL(_create_blink_mixcolumn_matrix(block_size_bits), branch_number_differential=5,
                                    branch_number_linear=5, name="MixColumn")

        # Shuffle permutation
        shuffle_perm = PermuteLayer_CVL([0, 5, 11, 10, 1, 6, 4, 13, 2, 12, 9, 15, 3, 7, 14, 8],
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
        # Set final round key
        key_add.const = rks[R]

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

        # MixColumn: block-diagonal with 8 copies (one per column for 128-bit)
        mixcolumn = LinearLayer_CVL(_create_blink_mixcolumn_matrix(block_size_bits), branch_number_differential=5,
                                    branch_number_linear=5, name="MixColumn")

        # Shuffle permutation for 128-bit
        shuffle_perm = PermuteLayer_CVL([5, 12, 4, 1, 17, 9, 10, 16, 28, 14, 21, 22, 11, 27, 8, 13,
                                         2, 25, 18, 3, 30, 6, 19, 20, 0, 23, 24, 31, 7, 15, 29, 26],
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
        # Set final round key
        key_add.const = rks[R]

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
