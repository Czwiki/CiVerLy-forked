from civerly.aeslike import AESlike
from civerly.component import SBox_CVL, PermuteLayer_CVL, LinearLayer_CVL
from civerly.component import RoundkeyXOR_CVL
from sage.crypto.sbox import SBox
from sage.rings.finite_rings.finite_field_constructor import GF
from sage.matrix.constructor import Matrix as matrix
from sage.matrix.special import identity_matrix, block_matrix


class BEANIE_CVL:
    def __init__(self, R=5, rks=None, name=None):
        r"""
        The CiVerLy implementation of BEANIE.

        BEANIE is a 32-bit block cipher with an AES-like structure operating on
        a :math:`4 \times 2` state of 4-bit nibbles.

        INPUT:

            - ``R`` -- integer (default: ``5``); Number of encryption rounds.

            - ``rks`` -- list (optional); The round key values. Must have
              length :math:`R+1`. Defaults to all zeros.

            - ``name`` -- string (optional); The name of the cipher.

        This cipher is "plug-and-play" usable.

        EXAMPLES:

        Encrypt a message (for verifying the implementation)::

            sage: from civerly.cipher_implementations.beanie import BEANIE_CVL
            sage: from civerly.util import int_to_vec, vec_to_int
            sage: beanie = BEANIE_CVL(R=5)
            sage: hex(vec_to_int(beanie(int_to_vec(0x12345678, 32))))
            '0x27a35219'

        Test with non-zero round keys::

            sage: from civerly.cipher_implementations.beanie import BEANIE_CVL
            sage: from civerly.util import int_to_vec, vec_to_int
            sage: rks = [
            ....:   0x01234567, 0x89abcdef, 0xfedcba98,
            ....:   0x76543210, 0x88888888, 0x88888888
            ....: ]
            sage: beanie = BEANIE_CVL(R=5, rks=rks)
            sage: hex(vec_to_int(beanie(int_to_vec(0x00000000, 32))))
            '0xf05a49f1'
            sage: hex(vec_to_int(beanie(int_to_vec(0xabcdef01, 32))))
            '0x8dd221be'

        TESTS:

        Verify with official test vectors (Table 15)::

            sage: from civerly.cipher_implementations.beanie import BEANIE_CVL
            sage: from civerly.util import int_to_vec, vec_to_int
            sage: rks1 = [
            ....:   0xbeedff0f, 0xf8a29afc, 0x9369ab08,
            ....:   0x7391f5d3, 0x464f65f3, 0xe0f85edb
            ....: ]
            sage: beanie = BEANIE_CVL(R=5, rks=rks1)
            sage: hex(vec_to_int(beanie(int_to_vec(0x00000000, 32))))
            '0xda46f4d3'
            sage: rks2 = [
            ....:   0x93061e07, 0x87607a4d, 0xd7d11b34,
            ....:   0xb1769b2e, 0x1466644a, 0x66a7801a
            ....: ]
            sage: beanie = BEANIE_CVL(R=5, rks=rks2)
            sage: hex(vec_to_int(beanie(int_to_vec(0x1841938a, 32))))
            '0x92c2fea'

        Single-round trace::

            sage: from civerly.cipher_implementations.beanie import BEANIE_CVL
            sage: from civerly.util import int_to_vec, vec_to_int
            sage: beanie = BEANIE_CVL(R=1)
            sage: hex(vec_to_int(beanie(int_to_vec(0x12345678, 32))))
            '0x49b5c28a'

        Model the cipher with MILP (differential, wordwise, branch number)::

            sage: from civerly.cipher_implementations.beanie import BEANIE_CVL
            sage: from civerly.model_options import *
            sage: import tempfile
            sage: beanie = BEANIE_CVL(R=3)
            sage: with tempfile.TemporaryDirectory() as tmpdir:  # optional - scip
            ....:   model_options = MODEL_OPTIONS(
            ....:     cryptanalysis=CRYPTANALYSIS.DIFFERENTIAL,
            ....:     optimization=OPTIMIZATION.MILP,
            ....:     granularity=GRANULARITY.WORDWISE,
            ....:     linear_layer_modeling=LINEAR_LAYER_MODELING.BRANCH_NUMBER,
            ....:     milp_solver=SCIP_CVL(),
            ....:     path=Path(tmpdir))
            ....:   beanie.analyse(model_options)
            2832 variables and 2889 constraints were written to '...'
            15

        Model the cipher with MILP (differential, bitwise)::

            sage: from civerly.cipher_implementations.beanie import BEANIE_CVL
            sage: from civerly.model_options import *
            sage: import tempfile
            sage: beanie = BEANIE_CVL(R=3)
            sage: with tempfile.TemporaryDirectory() as tmpdir:  # optional - scip
            ....:   model_options = MODEL_OPTIONS(
            ....:     cryptanalysis=CRYPTANALYSIS.DIFFERENTIAL,
            ....:     optimization=OPTIMIZATION.MILP,
            ....:     granularity=GRANULARITY.BITWISE,
            ....:     sbox_modeling=SBOX_MODELING.CONVEX_HULL,
            ....:     milp_solver=SCIP_CVL(),
            ....:     path=Path(tmpdir))
            ....:   beanie.analyse(model_options)
            6864 variables and 7841 constraints were written to '...'
            15

        Model the cipher with SAT (differential, bitwise)::

            sage: from civerly.cipher_implementations.beanie import BEANIE_CVL
            sage: from civerly.model_options import *
            sage: import tempfile
            sage: beanie = BEANIE_CVL(R=3)
            sage: with tempfile.TemporaryDirectory() as tmpdir:  # optional - cryptominisat  # optional - espresso
            ....:   model_options = MODEL_OPTIONS(
            ....:     cryptanalysis=CRYPTANALYSIS.DIFFERENTIAL,
            ....:     optimization=OPTIMIZATION.SAT,
            ....:     granularity=GRANULARITY.BITWISE,
            ....:     linear_layer_modeling=LINEAR_LAYER_MODELING.EXCLUDE_ODD,
            ....:     sbox_modeling=SBOX_MODELING.LOGICAL_COND_ESPRESSO,
            ....:     sat_solver=CRYPTOMINISAT_CVL(),
            ....:     logic_minimizer=ESPRESSO_CVL(),
            ....:     path=Path(tmpdir))
            ....:   beanie.analyse(model_options)
            ....:   trail = str(beanie.get_trail(model_options))
            ....:   assert "Unnamed Component" not in trail
            6864 variables and 15361 clauses were written to '...'
            [  0 ,100] (trying w =  50) : SAT
            [  0 , 50] (trying w =  25) : SAT
            [  0 , 25] (trying w =  12) : SAT
            [  0 , 12] (trying w =   6) : UNSAT
            [  7 , 12] (trying w =   9) : SAT
            [  7 ,  9] (trying w =   8) : UNSAT
            9
        """
        if name is None:
            name = "BEANIE"
        if rks is None:
            rks = [0] * (R + 1)
        if len(rks) != R + 1:
            raise ValueError(
                f"rks must have length R+1 = {R+1}, got {len(rks)}"
            )

        # BEANIE S-box
        sbox = SBox_CVL(
            SBox([0, 4, 2, 11, 10, 12, 9, 8, 5, 15, 13, 3, 7, 1, 6, 14]),
            name="SBox"
        )

        # S-box layer (8 S-boxes in parallel)
        sboxlayer = AESlike(4, 4, 2, name="SBoxLayer")
        for i in range(8):
            node = sboxlayer.add_subcipher(sbox, [(sboxlayer.IN, (i, 0))])
            sboxlayer.add_output([(node, (0, i))])

        # ShiftRows: rows 1 and 3 are rotated left by 1
        shiftrows = PermuteLayer_CVL(
            [0, 5, 2, 7, 4, 1, 6, 3],
            word_coarseness=4,
            name="ShiftRows"
        )

        # MixColumns: GF(2^4) MDS matrix with primitive polynomial x^4 + x + 1
        # Build per-nibble binary multiplication matrices
        mul2 = matrix(GF(2), [
            [0, 0, 0, 1],
            [1, 0, 0, 1],
            [0, 1, 0, 0],
            [0, 0, 1, 0],
        ])
        mul1 = identity_matrix(GF(2), 4)
        mul4 = mul2 * mul2
        mul8 = mul2 * mul2 * mul2
        mul9 = mul8 + mul1
        muld = mul8 + mul4 + mul1
        mulf = mul8 + mul4 + mul2 + mul1

        # The matrix below is constructed for LSB-first order, then conjugated
        # by a full bit-reversal to match the MSB-first convention of int_to_vec.
        mix_matrix_lsb = block_matrix(GF(2), [
            [mul2, mul1, muld, mul1],
            [mul1, mul4, mul9, muld],
            [mul1, mulf, mul4, mul1],
            [mul9, mul1, mul1, mul2],
        ], subdivide=False)

        P16 = matrix(GF(2), 16, 16)
        for i in range(16):
            P16[i, 15 - i] = 1
        mix_matrix = P16 * mix_matrix_lsb * P16

        mixcolumn = LinearLayer_CVL(
            mix_matrix,
            branch_number_differential=5,
            branch_number_linear=5,
            name="MixColumn"
        )

        # Full round: KeyAdd -> SBox -> ShiftRows -> MixColumns
        key_add = RoundkeyXOR_CVL(32, const=0x0, name="KeyAdd")
        beanie_round = AESlike(4, 4, 2, name="BEANIE-round")
        node_rk = beanie_round.add_subcipher(
            key_add, [(beanie_round.IN, (i, i)) for i in range(8)]
        )
        node_s = beanie_round.add_subcipher(
            sboxlayer, [(node_rk, (i, i)) for i in range(8)]
        )
        node_p = beanie_round.add_subcipher(
            shiftrows, [(node_s, (i, i)) for i in range(8)]
        )
        for j in range(2):
            node_mix = beanie_round.add_subcipher(
                mixcolumn, [(node_p, (i + 4*j, i)) for i in range(4)]
            )
            beanie_round.add_output(
                [(node_mix, (i, i + 4*j)) for i in range(4)]
            )

        # Last round: KeyAdd -> SBox -> ShiftRows (no MixColumns)
        key_add_last = RoundkeyXOR_CVL(32, const=0x0, name="KeyAdd")
        beanie_last = AESlike(4, 4, 2, name="BEANIE-last")
        node_rk_last = beanie_last.add_subcipher(
            key_add_last, [(beanie_last.IN, (i, i)) for i in range(8)]
        )
        node_s = beanie_last.add_subcipher(
            sboxlayer, [(node_rk_last, (i, i)) for i in range(8)]
        )
        node_p = beanie_last.add_subcipher(
            shiftrows, [(node_s, (i, i)) for i in range(8)]
        )
        beanie_last.add_output([(node_p, (i, i)) for i in range(8)])

        # Assemble the cipher
        beanie_cipher = AESlike(4, 4, 2, name=name)
        node = beanie_cipher.IN
        for r in range(R - 1):
            beanie_round.nodes[node_rk].const = rks[r]
            node = beanie_cipher.add_subcipher(
                beanie_round, [(node, (i, i)) for i in range(8)]
            )

        beanie_last.nodes[node_rk_last].const = rks[R - 1]
        node = beanie_cipher.add_subcipher(
            beanie_last, [(node, (i, i)) for i in range(8)]
        )

        key_add_final = RoundkeyXOR_CVL(32, const=rks[R], name="KeyAdd")
        node = beanie_cipher.add_subcipher(
            key_add_final, [(node, (i, i)) for i in range(8)]
        )
        beanie_cipher.add_output([(node, (i, i)) for i in range(8)])

        self.beanie_cipher = beanie_cipher

    def __new__(cls, *args, **kwargs):
        instance = super(BEANIE_CVL, cls).__new__(cls)
        instance.__init__(*args, **kwargs)
        return instance.beanie_cipher
