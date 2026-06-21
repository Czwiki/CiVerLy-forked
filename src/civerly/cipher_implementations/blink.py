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
"""
from civerly.wordsboxcipher import WordSBoxCipher
from civerly.component import SBox_CVL, LinearLayer_CVL, PermuteLayer_CVL, RoundkeyXOR_CVL
from sage.matrix.constructor import Matrix as matrix
from sage.rings.finite_rings.finite_field_constructor import GF
from sage.crypto.sbox import SBox


def _create_blink_mixcolumn_matrix():
    r"""
    Create the MixColumn matrix for Blink operating on a single column.
    
    The Blink MixColumn uses the Midori MixColumn matrix:
    M = [[0, 1, 1, 1],
         [1, 0, 1, 1],
         [1, 1, 0, 1],
         [1, 1, 1, 0]]
    
    This matrix is applied to each 4-nibble column independently.
    """
    M_nibble = [[0, 1, 1, 1],
                [1, 0, 1, 1],
                [1, 1, 0, 1],
                [1, 1, 1, 0]]
    
    # Create 16×16 block diagonal matrix with 4 copies for 4 columns
    M = matrix(GF(2), 16, 16)
    for col_idx in range(4):
        for row in range(4):
            for col in range(4):
                if M_nibble[row][col] == 1:
                    M[col_idx * 4 + row, col_idx * 4 + col] = 1
    
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
        M = _create_blink_mixcolumn_matrix()
        mixcolumn = LinearLayer_CVL(M, branch_number_differential=5,
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
        node = blink_round.add_subcipher(key_add,
                                         [(node, (i, i)) for i in range(block_size_words)])
        node = blink_round.add_subcipher(shuffle_perm,
                                         [(node, (i, i)) for i in range(block_size_words)])
        blink_round.add_output([(node, (i, i)) for i in range(block_size_words)])

        # Build the full cipher
        blink_cipher = WordSBoxCipher(wordsize, block_size_words, block_size_words,
                                      name=name)

        cipher_node = blink_cipher.IN
        for r in range(R):
            # Set round key
            for node in blink_round.nodes.values():
                if isinstance(node, RoundkeyXOR_CVL):
                    node.const = rks[r]
                    break
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
        M_nibble = [[0, 1, 1, 1],
                    [1, 0, 1, 1],
                    [1, 1, 0, 1],
                    [1, 1, 1, 0]]
        
        M = matrix(GF(2), 32, 32)
        for col_idx in range(8):  # 8 columns for 128-bit
            for row in range(4):
                for col in range(4):
                    if M_nibble[row][col] == 1:
                        M[col_idx * 4 + row, col_idx * 4 + col] = 1

        mixcolumn = LinearLayer_CVL(M, branch_number_differential=5,
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
        node = blink_round.add_subcipher(key_add,
                                         [(node, (i, i)) for i in range(block_size_words)])
        node = blink_round.add_subcipher(shuffle_perm,
                                         [(node, (i, i)) for i in range(block_size_words)])
        blink_round.add_output([(node, (i, i)) for i in range(block_size_words)])

        # Build the full cipher
        blink_cipher = WordSBoxCipher(wordsize, block_size_words, block_size_words,
                                      name=name)

        cipher_node = blink_cipher.IN
        for r in range(R):
            # Set round key
            for node in blink_round.nodes.values():
                if isinstance(node, RoundkeyXOR_CVL):
                    node.const = rks[r]
                    break
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
        """Instantiate the Blink128 cipher."""
        instance = super(BLINK128_CVL, cls).__new__(cls)
        instance.__init__(*args, **kwargs)
        return instance.blink_cipher
