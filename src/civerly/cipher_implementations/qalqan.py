"""
CiVerLy implementation of the Qalqan block cipher.

Specification (reconstructed from the CPITS-II-2021 paper
"About Cryptographic Properties of the Qalqan Encryption Algorithm"
and the reference implementation in ``documentation/qalqan.py``):

    * Block size       : 128 bit
    * Key size         : 256 .. 1024 bit, in 128 bit steps
    * Number of rounds : N = 17 + floor((KLen - 256) / 128) * 2  (17 .. 29)

Structure of the round function (per the paper's XSL / LSX design):

    * ``S``  : byte-wise 8-bit S-box applied to all 16 bytes
    * ``L``  : byte-wise modular (mod 256) linear diffusion layer
    * ``K``  : round-key addition (mod 2^128) for the middle rounds,
               modulo-2 (XOR) key whitening for the first and last round

Encryption (matching ``documentation/qalqan.py::encrypt_block``)::

    state = K_start_xor(plaintext)                    # round key 0, XOR
    for rk in round_keys[1:-1]:
        state = S(state)
        state = L(state)
        state = state + rk   (mod 2**128)             # middle rounds
    state = S(state)
    state = L(state)
    state = K_fin_xor(state)                          # round key N-1, XOR

The round keys are taken from the reconstructed key schedule
(``documentation/qalqan.py::KeyScheduler``), which is the same source used
to generate the test vectors below.  Because no official test vectors for
Qalqan are publicly available, the doctests compare the CiVerLy model
against that reference implementation.

Modeling notes
--------------
Qalqan mixes an S-box with modular addition, so it does not fit
``SBoxCipher``/``WordSBoxCipher`` (which reject ``ModAdd_CVL``) nor
``AddRX`` (which rejects ``SBox_CVL``).  The general :class:`civerly.cipher.Cipher`
container is therefore used; it supports any component but only SAT modeling
(MILP is not available for ``Cipher``).

The diffusion layer ``L`` is *not* GF(2)-linear (it uses mod-256 addition),
so it is modeled as a dedicated subcipher built from ``ModAdd_CVL(8)``
components.  The 128-bit round-key addition is modeled with ``ModAdd_CVL(128)``
after reversing the bit order of the state (the reference uses little-endian
128-bit addition, while CiVerLy interprets a 128-bit vector big-endian).
"""

from sage.crypto.sbox import SBox

from civerly.cipher import Cipher
from civerly.component import (
    RK_CVL,
    ModAdd_CVL,
    PermuteLayer_CVL,
    RoundkeyXOR_CVL,
    SBox_CVL,
)

# ---------------------------------------------------------------------------
# Qalqan S-box (Figure 1 in the paper / ``documentation/qalqan.py::SBOX``)
# ---------------------------------------------------------------------------

SBOX = [
    0xEB,
    0x89,
    0xDB,
    0xCB,
    0xF3,
    0xF5,
    0xFB,
    0x90,
    0xE6,
    0x3D,
    0xE5,
    0x2E,
    0xE3,
    0x0B,
    0x56,
    0xE1,
    0x6C,
    0x12,
    0x80,
    0x28,
    0xED,
    0x22,
    0x09,
    0x4A,
    0xEE,
    0x27,
    0x9B,
    0x58,
    0x35,
    0x57,
    0xEF,
    0x94,
    0x29,
    0xC0,
    0x16,
    0x7C,
    0x5E,
    0x87,
    0x0A,
    0x7E,
    0xE8,
    0x11,
    0x0E,
    0xAF,
    0x9A,
    0x84,
    0x3A,
    0x1A,
    0x69,
    0x71,
    0x8C,
    0xBC,
    0xD2,
    0x55,
    0x33,
    0xD1,
    0x85,
    0x75,
    0xB5,
    0x83,
    0xE9,
    0x50,
    0x54,
    0xAC,
    0x8A,
    0xD6,
    0x7F,
    0x1F,
    0x14,
    0x4E,
    0x21,
    0x82,
    0x30,
    0x24,
    0xDD,
    0x9F,
    0x1B,
    0x32,
    0x20,
    0xA8,
    0x6A,
    0xB0,
    0x97,
    0x62,
    0x19,
    0xD8,
    0xC8,
    0x0C,
    0x52,
    0x02,
    0x5C,
    0x43,
    0x03,
    0x95,
    0x13,
    0x81,
    0xAB,
    0x77,
    0xA6,
    0xF2,
    0x59,
    0x67,
    0x41,
    0xEC,
    0x76,
    0x98,
    0xB4,
    0x73,
    0x86,
    0x9C,
    0xF7,
    0xCF,
    0xDC,
    0xBA,
    0xA4,
    0xFD,
    0xC4,
    0x99,
    0xDF,
    0xCE,
    0xEA,
    0x1C,
    0x36,
    0xBD,
    0x34,
    0xD7,
    0x49,
    0x64,
    0x5A,
    0x6F,
    0x74,
    0x01,
    0xA0,
    0x39,
    0x91,
    0x00,
    0x15,
    0x3F,
    0x38,
    0xB8,
    0x8F,
    0x26,
    0x5F,
    0xF8,
    0x07,
    0xA3,
    0x0D,
    0xDA,
    0xF0,
    0xE7,
    0xD0,
    0xD9,
    0x93,
    0xF6,
    0x06,
    0x47,
    0x0F,
    0xA1,
    0x4B,
    0xC5,
    0x2A,
    0xFF,
    0x46,
    0x60,
    0xD5,
    0x1D,
    0x2F,
    0xA9,
    0x92,
    0x17,
    0x72,
    0x8E,
    0x7A,
    0xAA,
    0x18,
    0x6E,
    0x37,
    0x08,
    0x1E,
    0x63,
    0x31,
    0xC2,
    0xBF,
    0xC6,
    0x9E,
    0x65,
    0xD4,
    0x3B,
    0x96,
    0x9D,
    0xDE,
    0x45,
    0xCA,
    0x2D,
    0xA5,
    0xFE,
    0x4D,
    0xB9,
    0x66,
    0xC3,
    0xB3,
    0xCC,
    0xAD,
    0x61,
    0xBE,
    0x7B,
    0x68,
    0x88,
    0x25,
    0x2B,
    0x53,
    0x5B,
    0x44,
    0x40,
    0xA7,
    0xA2,
    0x5D,
    0xC9,
    0x51,
    0xAE,
    0xE4,
    0xC7,
    0xF9,
    0x78,
    0x70,
    0xCD,
    0x42,
    0x4F,
    0x4C,
    0x3C,
    0xE0,
    0x3E,
    0x7D,
    0xB7,
    0xD3,
    0xB2,
    0xF1,
    0x8D,
    0x79,
    0x8B,
    0x6B,
    0xE2,
    0x10,
    0x23,
    0x04,
    0x6D,
    0xC1,
    0xFC,
    0x05,
    0xB6,
    0xF4,
    0x48,
    0xBB,
    0xB1,
    0x2C,
    0xFA,
]


def _byte_rev_int(x):
    r"""
    Reverse the *byte* order of a 128-bit integer.

    CiVerLy interprets a 128-bit vector as big-endian with the bytes in their
    natural order, whereas the Qalqan reference implementation performs the
    128-bit round-key addition as a little-endian addition (byte order
    reversed, within-byte bit order preserved).  Reversing the byte order
    before and after a ``ModAdd_CVL(128)`` therefore realizes the
    little-endian addition on the natural (byte-wise) state layout used by the
    S-box and ``L`` layers.
    """
    return int.from_bytes(x.to_bytes(16, "big"), "little")


def _rounds_for_key(key):
    r"""Return ``N = 17 + floor((KLen - 256) / 128) * 2`` for a ``key``."""
    bits = len(key) * 8
    return 17 + ((bits - 256) // 128) * 2


def _reference_round_keys(key):
    r"""
    Generate the Qalqan round keys from ``key`` using the reference
    implementation in ``documentation/qalqan.py``.

    This keeps the CiVerLy test vectors consistent with the only available
    reference implementation (no official test vectors exist for Qalqan).
    """
    import importlib.util
    from pathlib import Path

    path = (
        Path(__file__).parent.parent.parent.parent
        / "documentation"
        / "qalqan.py"
    )
    spec = importlib.util.spec_from_file_location("qalqan_reference", str(path))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module.KeyScheduler(key).expand()


class QALQAN_CVL:
    r"""
    The CiVerLy implementation of the Qalqan block cipher.

    INPUT:

        - ``R`` -- integer (optional); Number of rounds ``N``.  If omitted it
          is derived from the key length (``17 + floor((KLen-256)/128)*2``),
          or from the number of supplied round keys.

        - ``rks`` -- list (optional); The round keys, as a list of 128-bit
          integers (one per round, length ``R``).  If omitted, the round keys
          are generated from ``key`` via the reference key schedule.

        - ``key`` -- bytes (optional); The encryption key (256..1024 bit, in
          128-bit steps).  Used to generate the round keys when ``rks`` is not
          given.

        - ``name`` -- string (optional); Name of the cipher.

    OUTPUT: A ``Cipher`` object modeling Qalqan.

    .. NOTE::

        ``QALQAN_CVL(R, rks)`` mirrors the "plug-and-play" round-key interface
        of :class:`civerly.cipher_implementations.speck.SPECK_CVL`.  When only
        a ``key`` is supplied, the round keys are taken from the reconstructed
        key schedule of the reference implementation.

    EXAMPLES:

    Basic encryption, compared against the reference implementation
    (``documentation/qalqan.py``).  Because no official test vectors exist,
    this is the canonical correctness check::

        sage: from civerly.cipher_implementations.qalqan import QALQAN_CVL
        sage: from civerly.util import int_to_vec, vec_to_int
        sage: import sys, os
        sage: import civerly.cipher_implementations.qalqan as _qalqan_mod
        sage: sys.path.insert(0, os.path.join(os.path.dirname(_qalqan_mod.__file__), "..", "..", "..", "documentation"))
        sage: import qalqan
        sage: key = bytes(range(32))                          # 256-bit key
        sage: pt  = bytes(range(16))                          # plaintext
        sage: ct_ref = qalqan.encrypt_block(pt, key)
        sage: cipher = QALQAN_CVL(key=key)
        sage: ct_vec = cipher(int_to_vec(int.from_bytes(pt, "big"), 128))
        sage: ct = vec_to_int(ct_vec).to_bytes(16, "big")
        sage: ct == ct_ref
        True

    A second, longer key (384 bit) also matches the reference::

        sage: from civerly.cipher_implementations.qalqan import QALQAN_CVL
        sage: from civerly.util import int_to_vec, vec_to_int
        sage: import sys, os
        sage: import civerly.cipher_implementations.qalqan as _qalqan_mod
        sage: sys.path.insert(0, os.path.join(os.path.dirname(_qalqan_mod.__file__), "..", "..", "..", "documentation"))
        sage: import qalqan
        sage: key = bytes(range(48))
        sage: pt  = bytes(range(1, 17))
        sage: ct_ref = qalqan.encrypt_block(pt, key)
        sage: ct_vec = QALQAN_CVL(key=key)(int_to_vec(int.from_bytes(pt, "big"), 128))
        sage: vec_to_int(ct_vec).to_bytes(16, "big") == ct_ref
        True

    Providing round keys explicitly (as integers) gives the same result::

        sage: from civerly.cipher_implementations.qalqan import QALQAN_CVL
        sage: from civerly.util import int_to_vec, vec_to_int
        sage: import sys, os
        sage: import civerly.cipher_implementations.qalqan as _qalqan_mod
        sage: sys.path.insert(0, os.path.join(os.path.dirname(_qalqan_mod.__file__), "..", "..", "..", "documentation"))
        sage: import qalqan
        sage: key = bytes(range(32))
        sage: rks = [int.from_bytes(rk, "big") for rk in qalqan.KeyScheduler(key).expand()]
        sage: ct_ref = qalqan.encrypt_block(bytes(range(16)), key)
        sage: ct_vec = QALQAN_CVL(rks=rks)(int_to_vec(int.from_bytes(bytes(range(16)), "big"), 128))
        sage: vec_to_int(ct_vec).to_bytes(16, "big") == ct_ref
        True

    A random round-trip check against the reference implementation::

        sage: from civerly.cipher_implementations.qalqan import QALQAN_CVL
        sage: from civerly.util import int_to_vec, vec_to_int
        sage: import sys, os
        sage: import civerly.cipher_implementations.qalqan as _qalqan_mod
        sage: sys.path.insert(0, os.path.join(os.path.dirname(_qalqan_mod.__file__), "..", "..", "..", "documentation"))
        sage: import qalqan
        sage: ok = True
        sage: for _ in range(10):
        ....:     key = os.urandom(32)
        ....:     pt  = os.urandom(16)
        ....:     ct_ref = qalqan.encrypt_block(pt, key)
        ....:     ct = vec_to_int(QALQAN_CVL(key=key)(
        ....:         int_to_vec(int.from_bytes(pt, "big"), 128)
        ....:     )).to_bytes(16, "big")
        ....:     ok = ok and (ct == ct_ref)
        sage: ok
        True

    Differential trail search (requires an external SAT solver and the
    Espresso logic minimizer)::

        sage: # optional - cryptominisat
        sage: from civerly.cipher_implementations.qalqan import QALQAN_CVL
        sage: from civerly.util import int_to_vec, vec_to_int
        sage: from civerly.model_options import *
        sage: import tempfile
        sage: with tempfile.TemporaryDirectory() as tmpdir:               # optional - espresso
        ....:     cipher = QALQAN_CVL(R=4, rks=[0]*4)
        ....:     model_options = MODEL_OPTIONS(
        ....:         cryptanalysis=CRYPTANALYSIS.DIFFERENTIAL,
        ....:         optimization=OPTIMIZATION.SAT,
        ....:         granularity=GRANULARITY.BITWISE,
        ....:         sbox_modeling=SBOX_MODELING.LOGICAL_COND_ESPRESSO,
        ....:         sat_solver=CRYPTOMINISAT_CVL(),
        ....:         logic_minimizer=ESPRESSO_CVL(),
        ....:         path=Path(tmpdir))
        ....:     cipher.analyse(model_options=model_options)
        0

    The trail must not contain any unnamed components::

        sage: # optional - cryptominisat
        sage: from civerly.cipher_implementations.qalqan import QALQAN_CVL
        sage: from civerly.model_options import *
        sage: import tempfile
        sage: with tempfile.TemporaryDirectory() as tmpdir:               # optional - espresso
        ....:     cipher = QALQAN_CVL(R=3, rks=[0]*3)
        ....:     model_options = MODEL_OPTIONS(
        ....:         cryptanalysis=CRYPTANALYSIS.DIFFERENTIAL,
        ....:         optimization=OPTIMIZATION.SAT,
        ....:         granularity=GRANULARITY.BITWISE,
        ....:         sbox_modeling=SBOX_MODELING.LOGICAL_COND_ESPRESSO,
        ....:         sat_solver=CRYPTOMINISAT_CVL(),
        ....:         logic_minimizer=ESPRESSO_CVL(),
        ....:         number_of_solutions=1,
        ....:         path=Path(tmpdir))
        ....:     cipher.analyse(model_options=model_options)
        ....:     trail = cipher.get_trail(model_options)
        ....:     "Unnamed" not in str(trail)
        True
    """

    def __init__(self, R=None, rks=None, key=None, name=None):
        if name is None:
            name = "QALQAN"

        # ---- determine the round keys -----------------------------------
        if rks is None and key is not None:
            rks = [int.from_bytes(rk, "big") for rk in _reference_round_keys(key)]
        if rks is None:
            raise ValueError(
                "Either 'rks' (list of round-key integers) or 'key' "
                "(key bytes) must be provided."
            )

        if R is None:
            R = len(rks)
        else:
            assert len(rks) == R, f"len(rks)={len(rks)} must equal R={R}"

        assert R >= 2, "Qalqan needs at least 2 rounds."

        # ---- reusable S-box layer ---------------------------------------
        # One SBox_CVL(8) applied to each of the 16 bytes (byte j at bits
        # 8j .. 8j+7).  The same S-box instance is reused for all 16 bytes.
        sbox_cipher = Cipher(128, 128, name="SBoxLayer")
        sb = SBox_CVL(SBox(SBOX), name="SBox")
        for j in range(16):
            node_sb = sbox_cipher.add_subcipher(
                sb, [(sbox_cipher.IN, (8 * j + b, b)) for b in range(8)]
            )
            sbox_cipher.add_output([(node_sb, (b, 8 * j + b)) for b in range(8)])

        # ---- reusable diffusion layer L ---------------------------------
        # L is a fixed network of mod-256 byte additions (see the paper,
        # 3.3.2).  It is modeled with ModAdd_CVL(8) components.  Byte j of
        # the input/output lives at bit positions 8j .. 8j+7.
        l_cipher = Cipher(128, 128, name="L")

        def add8(a_node, a_off, b_node, b_off):
            # add the byte at ``a_off`` (of a_node) and ``b_off`` (of b_node)
            # modulo 256, returning the resulting ModAdd_CVL(8) node.
            return l_cipher.add_subcipher(
                ModAdd_CVL(8, name="Ladd"),
                [(a_node, (a_off + k, k)) for k in range(8)]
                + [(b_node, (b_off + k, 8 + k)) for k in range(8)],
            )

        IN = l_cipher.IN
        # diagonal sums
        sum01 = add8(IN, 0, IN, 8)
        sum23 = add8(IN, 16, IN, 24)
        r0 = add8(sum01, 0, sum23, 0)
        sum45 = add8(IN, 32, IN, 40)
        sum67 = add8(IN, 48, IN, 56)
        r5 = add8(sum45, 0, sum67, 0)
        sum89 = add8(IN, 64, IN, 72)
        sum1011 = add8(IN, 80, IN, 88)
        r10 = add8(sum89, 0, sum1011, 0)
        sum1213 = add8(IN, 96, IN, 104)
        sum1415 = add8(IN, 112, IN, 120)
        r15 = add8(sum1213, 0, sum1415, 0)

        # R0 .. R15 (output byte j at bits 8j .. 8j+7)
        R0 = r0
        R4 = add8(IN, 32, r0, 0)
        R8 = add8(IN, 64, r0, 0)
        R12 = add8(IN, 96, r0, 0)
        R5 = r5
        R1 = add8(IN, 8, r5, 0)
        R9 = add8(IN, 72, r5, 0)
        R13 = add8(IN, 104, r5, 0)
        R10 = r10
        R2 = add8(IN, 16, r10, 0)
        R6 = add8(IN, 48, r10, 0)
        R14 = add8(IN, 112, r10, 0)
        R15 = r15
        R3 = add8(IN, 24, r15, 0)
        R7 = add8(IN, 56, r15, 0)
        R11 = add8(IN, 88, r15, 0)

        for node, j in [
            (R0, 0),
            (R1, 1),
            (R2, 2),
            (R3, 3),
            (R4, 4),
            (R5, 5),
            (R6, 6),
            (R7, 7),
            (R8, 8),
            (R9, 9),
            (R10, 10),
            (R11, 11),
            (R12, 12),
            (R13, 13),
            (R14, 14),
            (R15, 15),
        ]:
            l_cipher.add_output([(node, (b, 8 * j + b)) for b in range(8)])

        # ---- reusable 128-bit round-key addition (mod 2^128) -----------
        # Implemented as byte-order reversal, ModAdd_CVL(128), byte-order
        # reversal, so the big-endian CiVerLy representation matches the
        # reference's little-endian 128-bit addition (the within-byte bit
        # order is preserved).  The (constant) round key is fed via an
        # RK_CVL node whose value is set per round.
        add128_cipher = Cipher(128, 128, name="Add128")
        rev_perm = [15 - c for c in range(16)]
        rev_in = add128_cipher.add_subcipher(
            PermuteLayer_CVL(rev_perm, word_coarseness=8, name="rev_in"),
            [(add128_cipher.IN, (i, i)) for i in range(128)],
        )
        rk_node = add128_cipher.add_subcipher(RK_CVL(128, const=0, name="rk"), [])
        modadd_node = add128_cipher.add_subcipher(
            ModAdd_CVL(128, name="ModAdd128"),
            [(rev_in, (i, i)) for i in range(128)]
            + [(rk_node, (i, 128 + i)) for i in range(128)],
        )
        rev_out = add128_cipher.add_subcipher(
            PermuteLayer_CVL(rev_perm, word_coarseness=8, name="rev_out"),
            [(modadd_node, (i, i)) for i in range(128)],
        )
        add128_cipher.add_output([(rev_out, (i, i)) for i in range(128)])

        # ---- middle round function (S, L, Add128) -----------------------
        round_fn = Cipher(128, 128, name="QalqanRound")
        n_s = round_fn.add_subcipher(
            sbox_cipher, [(round_fn.IN, (i, i)) for i in range(128)]
        )
        n_l = round_fn.add_subcipher(l_cipher, [(n_s, (i, i)) for i in range(128)])
        n_a = round_fn.add_subcipher(add128_cipher, [(n_l, (i, i)) for i in range(128)])
        round_fn.add_output([(n_a, (i, i)) for i in range(128)])
        # ``add128_cipher`` is deep-copied into ``round_fn`` at build time, so
        # the per-round round key must be set on the *copy* held by
        # ``round_fn`` (mirroring the SPECK_CVL key-schedule pattern).
        add128_in_round = round_fn.nodes[n_a]

        # ---- assemble the full cipher -----------------------------------
        cipher = Cipher(128, 128, name=name)

        node = cipher.IN
        # initial key whitening (XOR)
        kw_start = RoundkeyXOR_CVL(128, rks[0], name="KeyAdd_start")
        node = cipher.add_subcipher(kw_start, [(node, (i, i)) for i in range(128)])

        # middle rounds: S, L, Add128 (with round keys 1 .. R-2)
        for r in range(1, R - 1):
            add128_in_round.nodes[rk_node].const = _byte_rev_int(rks[r])
            node = cipher.add_subcipher(round_fn, [(node, (i, i)) for i in range(128)])

        # final round: S, L (no key addition)
        node = cipher.add_subcipher(sbox_cipher, [(node, (i, i)) for i in range(128)])
        node = cipher.add_subcipher(l_cipher, [(node, (i, i)) for i in range(128)])

        # final key whitening (XOR)
        kw_fin = RoundkeyXOR_CVL(128, rks[R - 1], name="KeyAdd_fin")
        node = cipher.add_subcipher(kw_fin, [(node, (i, i)) for i in range(128)])

        cipher.add_output([(node, (i, i)) for i in range(128)])

        self.cipher = cipher

    def __new__(cls, *args, **kwargs):
        instance = super(QALQAN_CVL, cls).__new__(cls)
        instance.__init__(*args, **kwargs)
        return instance.cipher
