r"""
Implementation of the Serpent block cipher.

Serpent is a 32-round SP-network operating on four 32-bit words,
giving a block size of 128 bits. It uses 8 different 4-bit S-boxes
applied in parallel 32 times per round.

EXAMPLES::

    sage: from civerly.cipher_implementations.serpent import SERPENT_CVL
    sage: from civerly.util import int_to_vec, vec_to_int
    sage: # With zero round keys and zero plaintext, the cipher is not zero
    sage: # due to non-trivial S-box outputs
    sage: serpent = SERPENT_CVL(R=1)
    sage: result = serpent(int_to_vec(0x0, 128))
    sage: vec_to_int(result) > 0
    True

"""

from sage.crypto.sbox import SBox as SBox_sage
from sage.rings.finite_rings.finite_field_constructor import GF
from sage.matrix.constructor import Matrix as matrix

from civerly.sboxcipher import SBoxCipher
from civerly.component import SBox_CVL, LinearLayer_CVL, RoundkeyXOR_CVL


# S-boxes definition from the Serpent specification
SERPENT_SBOXES = [
    SBox_sage([3, 8, 15, 1, 10, 6, 5, 11, 14, 13, 4, 2, 7, 0, 9, 12]),   # S0
    SBox_sage([15, 12, 2, 7, 9, 0, 5, 10, 1, 11, 14, 8, 6, 13, 3, 4]),  # S1
    SBox_sage([8, 6, 7, 9, 3, 12, 10, 15, 13, 1, 14, 4, 0, 11, 5, 2]), # S2
    SBox_sage([0, 15, 11, 8, 12, 9, 6, 3, 13, 1, 2, 4, 10, 7, 5, 14]),  # S3
    SBox_sage([1, 15, 8, 3, 12, 0, 11, 6, 2, 5, 4, 10, 9, 14, 7, 13]), # S4
    SBox_sage([15, 5, 2, 11, 4, 10, 9, 12, 0, 3, 14, 8, 13, 6, 7, 1]), # S5
    SBox_sage([7, 2, 12, 5, 8, 4, 6, 11, 14, 9, 1, 15, 13, 3, 10, 0]),  # S6
    SBox_sage([1, 13, 15, 0, 14, 8, 2, 11, 7, 4, 12, 10, 9, 3, 5, 6]),  # S7
]


def _build_serpent_linear_layer():
    r"""
    Build the LinearLayer_CVL for Serpent's linear transformation.

    The linear transformation is defined by the LTTable in the reference
    implementation. This function constructs the corresponding binary matrix.

    TESTS::

        sage: from civerly.cipher_implementations.serpent import _build_serpent_linear_layer
        sage: lt = _build_serpent_linear_layer()
        sage: lt  # returns LinearLayer_CVL
        LT

    """
    # LT table from serpent-tables.h (128 rows, each with input bit indices)
    # Output bit i = XOR of input bits in LT_TABLE[i]
    LT_TABLE = [
        [16, 52, 56, 70, 83, 94, 105],
        [72, 114, 125],
        [2, 9, 15, 30, 76, 84, 126],
        [36, 90, 103],
        [20, 56, 60, 74, 87, 98, 109],
        [1, 76, 118],
        [2, 6, 13, 19, 34, 80, 88],
        [40, 94, 107],
        [24, 60, 64, 78, 91, 102, 113],
        [5, 80, 122],
        [6, 10, 17, 23, 38, 84, 92],
        [44, 98, 111],
        [28, 64, 68, 82, 95, 106, 117],
        [9, 84, 126],
        [10, 14, 21, 27, 42, 88, 96],
        [48, 102, 115],
        [32, 68, 72, 86, 99, 110, 121],
        [2, 13, 88],
        [14, 18, 25, 31, 46, 92, 100],
        [52, 106, 119],
        [36, 72, 76, 90, 103, 114, 125],
        [6, 17, 92],
        [18, 22, 29, 35, 50, 96, 104],
        [56, 110, 123],
        [1, 40, 76, 80, 94, 107, 118],
        [10, 21, 96],
        [22, 26, 33, 39, 54, 100, 108],
        [60, 114, 127],
        [5, 44, 80, 84, 98, 111, 122],
        [14, 25, 100],
        [26, 30, 37, 43, 58, 104, 112],
        [3, 118],
        [9, 48, 84, 88, 102, 115, 126],
        [18, 29, 104],
        [30, 34, 41, 47, 62, 108, 116],
        [7, 122],
        [2, 13, 52, 88, 92, 106, 119],
        [22, 33, 108],
        [34, 38, 45, 51, 66, 112, 120],
        [11, 126],
        [6, 17, 56, 92, 96, 110, 123],
        [26, 37, 112],
        [38, 42, 49, 55, 70, 116, 124],
        [2, 15, 76],
        [10, 21, 60, 96, 100, 114, 127],
        [30, 41, 116],
        [0, 42, 46, 53, 59, 74, 120],
        [6, 19, 80],
        [3, 14, 25, 100, 104, 118],
        [34, 45, 120],
        [4, 46, 50, 57, 63, 78, 124],
        [10, 23, 84],
        [7, 18, 29, 104, 108, 122],
        [38, 49, 124],
        [0, 8, 50, 54, 61, 67, 82],
        [14, 27, 88],
        [11, 22, 33, 108, 112, 126],
        [0, 42, 53],
        [4, 12, 54, 58, 65, 71, 86],
        [18, 31, 92],
        [2, 15, 26, 37, 76, 112, 116],
        [4, 46, 57],
        [8, 16, 58, 62, 69, 75, 90],
        [22, 35, 96],
        [6, 19, 30, 41, 80, 116, 120],
        [8, 50, 61],
        [12, 20, 62, 66, 73, 79, 94],
        [26, 39, 100],
        [10, 23, 34, 45, 84, 120, 124],
        [12, 54, 65],
        [16, 24, 66, 70, 77, 83, 98],
        [30, 43, 104],
        [0, 14, 27, 38, 49, 88, 124],
        [16, 58, 69],
        [20, 28, 70, 74, 81, 87, 102],
        [34, 47, 108],
        [0, 4, 18, 31, 42, 53, 92],
        [20, 62, 73],
        [24, 32, 74, 78, 85, 91, 106],
        [38, 51, 112],
        [4, 8, 22, 35, 46, 57, 96],
        [24, 66, 77],
        [28, 36, 78, 82, 89, 95, 110],
        [42, 55, 116],
        [8, 12, 26, 39, 50, 61, 100],
        [28, 70, 81],
        [32, 40, 82, 86, 93, 99, 114],
        [46, 59, 120],
        [12, 16, 30, 43, 54, 65, 104],
        [32, 74, 85],
        [36, 90, 103, 118],
        [50, 63, 124],
        [16, 20, 34, 47, 58, 69, 108],
        [36, 78, 89],
        [40, 94, 107, 122],
        [0, 54, 67],
        [20, 24, 38, 51, 62, 73, 112],
        [40, 82, 93],
        [44, 98, 111, 126],
        [4, 58, 71],
        [24, 28, 42, 55, 66, 77, 116],
        [44, 86, 97],
        [2, 48, 102, 115],
        [8, 62, 75],
        [28, 32, 46, 59, 70, 81, 120],
        [48, 90, 101],
        [6, 52, 106, 119],
        [12, 66, 79],
        [32, 36, 50, 63, 74, 85, 124],
        [52, 94, 105],
        [10, 56, 110, 123],
        [16, 70, 83],
        [0, 36, 40, 54, 67, 78, 89],
        [56, 98, 109],
        [14, 60, 114, 127],
        [20, 74, 87],
        # Missing entries (116-127) added to complete LT table
        [4, 40, 44, 58, 71, 82, 93],
        [60, 102, 113],
        [3, 18, 72, 114, 118, 125],
        [24, 78, 91],
        [8, 44, 48, 62, 75, 86, 97],
        [64, 106, 117],
        [1, 7, 22, 76, 118, 122],
        [28, 82, 95],
        [12, 48, 52, 66, 79, 90, 101],
        [68, 110, 121],
        [5, 11, 26, 80, 122, 126],
        [32, 86, 99],
    ]

    # Build binary matrix: output bit i is XOR of input bits from LT_TABLE[i]
    m = [[0 for _ in range(128)] for _ in range(128)]
    for i, inputs in enumerate(LT_TABLE):
        for j in inputs:
            m[i][j] = 1

    return LinearLayer_CVL(matrix(GF(2), m), name="LT")


class SERPENT_CVL:
    r"""
    The CiVerLy implementation of the Serpent block cipher.

    Serpent is a 32-round SP-network operating on four 32-bit words,
    giving a block size of 128 bits. The cipher consists of:

    - An initial permutation (IP) - skipped for simplicity (identity)
    - 32 rounds, each applying: key mixing XOR, S-box layer, linear
      transformation (except last round which uses an extra key XOR instead)
    - A final permutation (FP) - skipped for simplicity (identity)

    Note: The IP/FP permutations are omitted in this implementation as they
    only serve to convert between bitslice and traditional representations.
    For cryptanalysis, they can be included as PermuteLayer_CVL if needed.

    INPUT::

        - ``R`` -- integer; Number of rounds (default: 32).

        - ``rks`` -- list (optional); Specifies the round key values.
          Must have length R+1 (33 keys for full-round Serpent).
          Defaults to all zeros.

        - ``name`` -- string (optional); The name of the cipher.

    EXAMPLES::

        Verify basic encryption functionality::

            sage: from civerly.cipher_implementations.serpent import SERPENT_CVL
            sage: from civerly.util import int_to_vec, vec_to_int
            sage: serpent = SERPENT_CVL(R=1)
            sage: result = serpent(int_to_vec(0x0, 128))
            sage: vec_to_int(result) > 0  # S-box output is non-zero even for zero input
            True

        Model the cipher with MILP::

            sage: from civerly.cipher_implementations.serpent import SERPENT_CVL
            sage: from civerly.model_options import *
            sage: import tempfile
            sage: with tempfile.TemporaryDirectory() as tmpdir:  # optional - scip
            ....:   serpent = SERPENT_CVL(R=4)
            ....:   model_options = MODEL_OPTIONS(
            ....:       cryptanalysis=CRYPTANALYSIS.DIFFERENTIAL,
            ....:       optimization=OPTIMIZATION.MILP,
            ....:       granularity=GRANULARITY.BITWISE,
            ....:       sbox_modeling=SBOX_MODELING.CONVEX_HULL,
            ....:       linear_layer_modeling=LINEAR_LAYER_MODELING.MORE_DUMMIES,
            ....:       milp_solver=SCIP_CVL(),
            ....:       path=Path(tmpdir))
            ....:   serpent.analyse(model_options)
            ....:   trail = str(serpent.get_trail(model_options))
            ....:   assert "Unnamed Component" not in trail

    """

    def __init__(self, R=32, rks=None, name=None):
        if name is None:
            name = "SERPENT"

        if rks is None:
            rks = [0 for _ in range(R + 1)]

        # Build linear layer (same for all rounds except last)
        lt = _build_serpent_linear_layer()

        # Build S-box layer: 32 parallel 4-bit S-boxes (for a specific S-box index)
        # Uses bitslice representation where S-box j takes bits j, j+32, j+64, j+96
        def make_sboxlayer(sbox_idx):
            sboxlayer = SBoxCipher(128, 128, name=f"SBoxLayer_{sbox_idx}")
            sbox = SBox_CVL(SERPENT_SBOXES[sbox_idx], name=f"S{sbox_idx}")
            output_edges = []
            for j in range(32):
                # Each S-box processes 4 bits at positions j, j+32, j+64, j+96
                # Input: bits (j, j+32, j+64, j+96) -> S-box input bits (0, 1, 2, 3)
                # Output: S-box output bits (0, 1, 2, 3) -> bits (j, j+32, j+64, j+96)
                node = sboxlayer.add_subcipher(sbox, [(sboxlayer.IN, (j + 32*i, i)) for i in range(4)])
                output_edges.extend([(node, (i, j + 32*i)) for i in range(4)])
            sboxlayer.add_output(output_edges)
            return sboxlayer

        # Build S-box layers for each round (round i uses S_i mod 8)
        sboxlayers = [make_sboxlayer(r % 8) for r in range(R)]

        # Key addition component
        key_add = RoundkeyXOR_CVL(128, 0x0, name="KeyAdd")

        # Build the full cipher
        cipher = SBoxCipher(128, 128, name=name)

        node = cipher.IN
        for r in range(R):
            # Key addition before S-box
            key_add.const = rks[r]
            node_key = cipher.add_subcipher(key_add, [(node, (i, i)) for i in range(128)])

            # S-box layer
            node_sbox = cipher.add_subcipher(sboxlayers[r], [(node_key, (i, i)) for i in range(128)])

            if r == R - 1:
                # Last round: skip LT, apply final key XOR
                key_add.const = rks[R]
                node_key = cipher.add_subcipher(key_add, [(node_sbox, (i, i)) for i in range(128)])
                cipher.add_output([(node_key, (i, i)) for i in range(128)])
            else:
                # Linear transformation
                node = cipher.add_subcipher(lt, [(node_sbox, (i, i)) for i in range(128)])

        self.cipher = cipher

    def __new__(cls, *args, **kwargs):
        instance = super(SERPENT_CVL, cls).__new__(cls)
        instance.__init__(*args, **kwargs)
        return instance.cipher