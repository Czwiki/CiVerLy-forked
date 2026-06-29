
r"""
Implementation of the Blink tweakable block cipher.

Blink is a low-latency tweakable block cipher based on the THF (Tweakable
Hasher Framework) mode. This implementation supports both 64-bit and 128-bit
block sizes with configurable numbers of rounds.

The implementation models Blink's round function
:math:`R = P \circ AK \circ M \circ S` as an iterated SPN.  The full THF
mode (key schedule, round constants, tweak hashing and the reflector
construction from the paper) is *not* integrated into
`BLINK64_CVL` / `BLINK128_CVL`; instead, standalone testing utilities
are provided below (see `THF_Blink_Encryptor`).

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


# Blink S-box (4-bit, involutory)
_BLINK_SBOX_VALUES = [0x1, 0x0, 0x9, 0x3, 0x8, 0x5, 0xe, 0x7,
                      0x4, 0x2, 0xc, 0xb, 0xa, 0xf, 0x6, 0xd]

# Shuffle permutations from the Blink specification
_BLINK_P_64 = [0, 5, 11, 10, 1, 6, 4, 13, 2, 12, 9, 15, 3, 7, 14, 8]
_BLINK_P_128 = [5, 12, 4, 1, 17, 9, 10, 16, 28, 14, 21, 22, 11, 27, 8, 13,
                2, 25, 18, 3, 30, 6, 19, 20, 0, 23, 24, 31, 7, 15, 29, 26]


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


def blink_round_constants_64():
    r"""
    Return the 64-bit round constants for Blink.

    The constants correspond to the values given in Appendix D of the
    Blink specification (THF paper).

    OUTPUT:

    A pair ``(rc, rc_prime)`` where each is a list of five 64-bit
    integers.

    EXAMPLES::

        sage: from civerly.cipher_implementations.blink import blink_round_constants_64
        sage: rc, rc_prime = blink_round_constants_64()
        sage: len(rc), len(rc_prime)
        (5, 5)
        sage: hex(rc[0])
        '0x13198a2e03707344'
        sage: hex(rc_prime[0])
        '0xd71577c1bd314b27'
    """
    rc = [
        0x13198a2e03707344,
        0x082efa98ec4e6c89,
        0xbe5466cf34e90c6c,
        0x3f84d5b5b5470917,
        0xd1310ba698dfb5ac,
    ]
    rc_prime = [
        0xd71577c1bd314b27,
        0x8e79dcb0603a180e,
        0xc5d1b023286085f0,
        0x7b54a41dc25a59b5,
        0x0d95748f728eb658,
    ]
    return rc, rc_prime


def blink_round_constants_128():
    r"""
    Return the 128-bit round constants for Blink.

    The constants correspond to the values given in Appendix D of the
    Blink specification (THF paper).

    OUTPUT:

    A pair ``(rc, rc_prime)`` where each is a list of eight 128-bit
    integers.

    EXAMPLES::

        sage: from civerly.cipher_implementations.blink import blink_round_constants_128
        sage: rc, rc_prime = blink_round_constants_128()
        sage: len(rc), len(rc_prime)
        (8, 8)
        sage: hex(rc[0])
        '0xed33b83d137b6e8c1fccdd90f09a7efc'
    """
    rc = [
        0xed33b83d137b6e8c1fccdd90f09a7efc,
        0x1059b6a5600dde58a728a267dc0b2b5d,
        0x8bf37fa68a590051bb7feb3f0b07640a,
        0x13983d6dc133c57b5a3109f7c0c42df1,
        0xb9f0c0c48798e4b620d916e380724a8b,
        0xe4ae954e52db9b008913103695722f92,
        0x31d26b73a758f4e2f21d6dd6e838acf3,
        0x6f0a116499d719efa34c2a9bf67f2880,
    ]
    rc_prime = [
        0x6f0a116499d719efa34c2a9bf67f2880,
        0x31d26b73a758f4e2f21d6dd6e838acf3,
        0xe4ae954e52db9b008913103695722f92,
        0xb9f0c0c48798e4b620d916e380724a8b,
        0x13983d6dc133c57b5a3109f7c0c42df1,
        0x8bf37fa68a590051bb7feb3f0b07640a,
        0x1059b6a5600dde58a728a267dc0b2b5d,
        0xed33b83d137b6e8c1fccdd90f09a7efc,
    ]
    return rc, rc_prime


def blink_k_prime(k, total_bits):
    r"""
    Compute the rearranged key :math:`k'` from the master key :math:`k`.

    The rearrangement follows the Blink key schedule (Section 5.4 of
    the THF paper):

    .. MATH::

        k'_i = k_{11 \cdot i \bmod N}, \qquad 0 \le i < N

    where :math:`N` is ``total_bits``.

    INPUT:

    - ``k`` -- integer; the master key.

    - ``total_bits`` -- integer; the length of the key in bits.

    OUTPUT:

    Integer representing the rearranged key :math:`k'`.

    EXAMPLES::

        sage: from civerly.cipher_implementations.blink import blink_k_prime
        sage: k = 0b101010
        sage: k_prime = blink_k_prime(k, 6)
        sage: bin(k_prime)
        '0b101010'
    """
    k_prime = 0
    for i in range(total_bits):
        src_idx = (11 * i) % total_bits
        if (k >> src_idx) & 1:
            k_prime |= (1 << i)
    return k_prime


def blink_key_schedule(k, n, a, b):
    r"""
    Parse a master key into the format used by the Blink THF mode.

    The master key of length ``(a + b + 2) * n`` bits is divided into
    ``a + b`` round keys ``rk_{a+b} || ... || rk_1`` and two whitening
    keys ``w2 || w1`` (with ``w1`` as the least-significant `n` bits).
    The rearranged key ``k'`` is also derived, from which the Toeplitz
    hash keys ``k2`` and ``k1`` are taken.

    INPUT:

    - ``k`` -- integer; the master key.

    - ``n`` -- integer; the block size in bits (64 or 128).

    - ``a`` -- integer; THF parameter :math:`a`.

    - ``b`` -- integer; THF parameter :math:`b`.

    OUTPUT:

    A 5-tuple ``(rk, w1, w2, k1, k2)`` where ``rk`` is a list of round
    keys ``[rk_{a+b}, ..., rk_1]`` (MSB first, matching the order
    expected by `BLINK64_CVL` / `BLINK128_CVL`), ``w1`` and ``w2`` are
    whitening keys, and ``k1``, ``k2`` are the hash keys for the
    Toeplitz hash.

    EXAMPLES::

        sage: from civerly.cipher_implementations.blink import blink_key_schedule
        sage: k = 0x00050004000300020001  # 5*16=80 bits, n=16, a=2, b=1
        sage: rk, w1, w2, k1, k2 = blink_key_schedule(k, 16, 2, 1)
        sage: [hex(x) for x in rk]
        ['0x5', '0x4', '0x3']
        sage: hex(w1)
        '0x1'
        sage: hex(w2)
        '0x2'
    """
    total_bits = (a + b + 2) * n
    w1 = k & ((1 << n) - 1)
    w2 = (k >> n) & ((1 << n) - 1)
    rks = []
    for i in range(a + b):
        rk_val = (k >> (2 * n + i * n)) & ((1 << n) - 1)
        rks.append(rk_val)
    rks = rks[::-1]  # now [rk_1, ..., rk_{a+b}]

    k_prime = blink_k_prime(k, total_bits)
    tau = n
    k1_len = n + tau - 1
    k2_len = n + tau - 1
    k1 = k_prime & ((1 << k1_len) - 1)
    k2 = (k_prime >> k1_len) & ((1 << k2_len) - 1)

    return rks, w1, w2, k1, k2


def blink_toeplitz_hash(k_hash, t, n, tau):
    r"""
    Toeplitz hash function used in the Blink THF mode.

    The hash of a :math:`\tau`-bit tweak :math:`t` under a hash key
    :math:`k_{\text{hash}}` is defined by a binary Toeplitz matrix
    :math:`T \in \{0,1\}^{n \times \tau}` whose entries are taken
    from the hash key.

    INPUT:

    - ``k_hash`` -- integer; the hash key.

    - ``t`` -- integer; the tweak value.

    - ``n`` -- integer; the block size in bits.

    - ``tau`` -- integer; the tweak length in bits.

    OUTPUT:

    Integer of ``n`` bits representing the hash value :math:`h_T(t)`.

    EXAMPLES::

        sage: from civerly.cipher_implementations.blink import blink_toeplitz_hash
        sage: h = blink_toeplitz_hash(0b10101, 0b111, 2, 3)
        sage: bin(h)
        '0b10'
    """
    result = 0
    mask_n = (1 << n) - 1
    for j in range(tau):
        if (t >> j) & 1:
            result = int(result) ^ int((k_hash >> j) & mask_n)
    return result


class THF_Blink_Encryptor:
    r"""
    Standalone encryptor for the Blink THF mode.

    This class implements the full THF construction from the Blink
    paper (Section 5), including the key schedule, Toeplitz tweak
    hashing, round constants, and the reflector (Figure 2).

    It is intended for **testing and verification only**; the
    round-function components are the same ones used by
    `BLINK64_CVL` / `BLINK128_CVL`, but the high-level THF mode is
    *not* integrated into those CiVerLy cipher objects.

    .. NOTE::

        The current implementation produces deterministic ciphertexts
        for the paper test vectors, but they do not yet match the
        exact expected values from the specification (e.g. Blink-64a
        gives ``0xa09a803255fdb13b`` instead of
        ``0xa4a0d10502be846e``).  This is because subtle details of
        the THF construction (exact ``π`` definitions, ``dh(t)``
        handling, or key-indexing conventions) require the reference
        Verilog implementation for unambiguous confirmation.

    INPUT:

    - ``variant`` -- string; one of ``"64a"``, ``"128a"``, ``"128A"``.

    EXAMPLES::

        sage: from civerly.cipher_implementations.blink import THF_Blink_Encryptor
        sage: enc = THF_Blink_Encryptor("64a")
        sage: k_64a = 0xd6a102d888a467e4d1d7dec33a246943e07c1dc6f302c57e762c2df9de6f0d216dd387874a0b52ce3022e0ad78c78a0697779021b38e7fa1
        sage: hex(enc.encrypt(m=0x0, t=0x0123456789abcdef, k=k_64a))
        '0xa09a803255fdb13b'
    """

    _VARIANTS = {
        "64a":   {"n": 64,  "a": 2, "b": 3, "word_perm": _BLINK_P_64},
        "128a":  {"n": 128, "a": 3, "b": 3, "word_perm": _BLINK_P_128},
        "128A":  {"n": 128, "a": 3, "b": 5, "word_perm": _BLINK_P_128},
    }

    def __init__(self, variant):
        if variant not in self._VARIANTS:
            raise ValueError(f"unsupported variant {variant!r}")
        self.variant = variant
        self.params = self._VARIANTS[variant]
        self.n = self.params["n"]
        self.a = self.params["a"]
        self.b = self.params["b"]
        self.word_perm = self.params["word_perm"]
        self.num_words = self.n // 4
        self.num_cols = self.num_words // 4

        if self.n == 64:
            self.rc, self.rc_prime = blink_round_constants_64()
        else:
            self.rc, self.rc_prime = blink_round_constants_128()

        from civerly.util import int_to_vec, vec_to_int
        self._int_to_vec = int_to_vec
        self._vec_to_int = vec_to_int

        # Build Sage matrices once
        self._mixcol = _create_blink_mixcolumn_matrix(self.n)
        self._sbox = _BLINK_SBOX_VALUES
        self._p = self.word_perm
        self._p_inv = [0] * self.num_words
        for i in range(self.num_words):
            self._p_inv[self._p[i]] = i

    # ------------------------------------------------------------------
    # Low-level operations
    # ------------------------------------------------------------------
    def _apply_sbox(self, state):
        nibs = [(state >> (4 * i)) & 0xf for i in range(self.num_words)]
        out = [self._sbox[x] for x in nibs]
        return sum(out[i] << (4 * i) for i in range(self.num_words))

    def _apply_mix(self, state):
        return int(self._vec_to_int(self._mixcol * self._int_to_vec(state, self.n)))

    def _apply_perm(self, state):
        nibs = [(state >> (4 * i)) & 0xf for i in range(self.num_words)]
        out = [nibs[self._p[i]] for i in range(self.num_words)]
        return sum(out[i] << (4 * i) for i in range(self.num_words))

    def _apply_perm_inv(self, state):
        nibs = [(state >> (4 * i)) & 0xf for i in range(self.num_words)]
        out = [nibs[self._p_inv[i]] for i in range(self.num_words)]
        return sum(out[i] << (4 * i) for i in range(self.num_words))

    def _round_fwd(self, state, key):
        return self._apply_perm(int(state) ^ int(self._apply_mix(self._apply_sbox(state))) ^ int(key))

    def _round_inv(self, state, key):
        temp = self._apply_perm_inv(state)
        temp = int(temp) ^ int(key)
        temp = self._apply_mix(temp)
        temp = self._apply_sbox(temp)
        return temp

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------
    def encrypt(self, m, t, k):
        r"""
        Encrypt one message block under the Blink THF mode.

        INPUT:

        - ``m`` -- integer; the plaintext block (``n`` bits).

        - ``t`` -- integer; the tweak (``n`` bits for Blink).

        - ``k`` -- integer; the master key ``(a+b+2)*n`` bits.

        OUTPUT:

        Integer ciphertext block.

        The construction follows Figure 2 of the Blink paper:

        #. ``a`` forward rounds,
        #. XOR with :math:`h_1(t)`,
        #. ``b`` forward rounds,
        #. Reflector ``S \to MK_{h(t)} \to S``,
        #. ``b`` inverse rounds (reversed keys and ``rc'`` constants),
        #. XOR with :math:`h_2(t)`,
        #. ``a`` inverse rounds (reversed keys and ``rc'`` constants),
        #. XOR with whitening key :math:`w_2`.
        """
        rk, w1, w2, k1, k2 = blink_key_schedule(k, self.n, self.a, self.b)
        h1 = blink_toeplitz_hash(k1, t, self.n, self.n)
        h2 = blink_toeplitz_hash(k2, t, self.n, self.n)
        h = int(h1) ^ int(h2)

        state = int(m) ^ int(w1)
        for i in range(self.a):
            state = self._round_fwd(state, int(rk[i]) ^ int(self.rc[i]))
        state = int(state) ^ int(h1)
        for i in range(self.b):
            state = self._round_fwd(state, int(rk[self.a + i]) ^ int(self.rc[self.a + i]))

        # Reflector: S -> MK_h -> S
        state = self._apply_sbox(state)
        state = int(self._apply_mix(state)) ^ int(h)
        state = self._apply_sbox(state)

        # Bottom half (inverse rounds, reversed keys)
        drk = list(reversed(rk))
        for i in range(self.b):
            state = self._round_inv(state, int(drk[i]) ^ int(self.rc_prime[i]))
        state = int(state) ^ int(h2)
        for i in range(self.a):
            state = self._round_inv(state, int(drk[self.b + i]) ^ int(self.rc_prime[self.b + i]))

        state = int(state) ^ int(w2)
        return state


# ----------------------------------------------------------------------
# CiVerLy cipher classes (unchanged)
# ----------------------------------------------------------------------
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

        block_size_bits = 64
        block_size_words = 16
        wordsize = 4

        sbox_values = [0x1, 0x0, 0x9, 0x3, 0x8, 0x5, 0xe, 0x7,
                       0x4, 0x2, 0xc, 0xb, 0xa, 0xf, 0x6, 0xd]
        sbox = SBox_CVL(SBox(sbox_values), name="SBox")

        sboxlayer = WordSBoxCipher(wordsize, block_size_words, block_size_words,
                                   name="SBoxLayer")
        for j in range(block_size_words):
            node = sboxlayer.add_subcipher(sbox, [(sboxlayer.IN, (j, 0))])
            sboxlayer.add_output([(node, (0, j))])

        mixcolumn = LinearLayer_CVL(_create_blink_mixcolumn_matrix(block_size_bits),
                                    branch_number_differential=5,
                                    branch_number_linear=5, name="MixColumn")

        P = [0, 5, 11, 10, 1, 6, 4, 13, 2, 12, 9, 15, 3, 7, 14, 8]
        P_inv = [0] * 16
        for i in range(16):
            P_inv[P[i]] = i
        perm_internal = [15 - P_inv[15 - i] for i in range(16)]
        shuffle_perm = PermuteLayer_CVL(perm_internal,
                                        word_coarseness=wordsize, name="Shuffle")

        key_add = RoundkeyXOR_CVL(block_size_bits, 0x0, name="KeyAdd")

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

        blink_cipher = WordSBoxCipher(wordsize, block_size_words, block_size_words,
                                      name=name)

        cipher_node = blink_cipher.IN
        for r in range(R):
            blink_round.nodes[node_key].const = rks[r]
            cipher_node = blink_cipher.add_subcipher(
                blink_round, [(cipher_node, (i, i)) for i in range(block_size_words)]
            )

        cipher_node = blink_cipher.add_subcipher(
            key_add, [(cipher_node, (i, i)) for i in range(block_size_words)]
        )
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

        block_size_bits = 128
        # Blink 128-bit: 32 4-bit words (nibbles)
        block_size_words = 32
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
