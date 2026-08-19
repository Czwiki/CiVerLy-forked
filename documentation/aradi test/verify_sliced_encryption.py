"""
Manual verification of sliced ARADI encryption against the reference
implementation in this directory.

Usage:
    python3 "documentation/aradi test/verify_sliced_encryption.py"

The script:
1. Builds the 17 round keys with the reference key schedule.
2. Encrypts the all-zero block with the reference full-block routine.
3. Re-implements the same slice "by hand" using the reference round
   functions.
4. Compares the hand-computed slices with the output of CiVerLy's
   ``ARADI_CVL`` for the same slice parameters.
"""

import os
import sys

# Make the reference implementation importable from this directory.
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
# Make the CiVerLy source tree importable.
sys.path.insert(
    0,
    os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "..", "src"),
)

import aradi_core
from civerly.cipher_implementations.aradi import ARADI_CVL
from civerly.util import int_to_vec, vec_to_int

_MASK32 = (1 << 32) - 1


def words_to_int(words):
    """Convert four 32-bit words [w,x,y,z] to one 128-bit big-endian integer."""
    return (
        (words[0] & _MASK32) << 96
        | (words[1] & _MASK32) << 64
        | (words[2] & _MASK32) << 32
        | (words[3] & _MASK32)
    )


def int_to_words(value):
    """Convert one 128-bit big-endian integer to four 32-bit words [w,x,y,z]."""
    return [
        (value >> 96) & _MASK32,
        (value >> 64) & _MASK32,
        (value >> 32) & _MASK32,
        value & _MASK32,
    ]


def reference_slice_encrypt(state_words, key, round_start, round_end):
    """
    Manually encrypt ``state_words`` for rounds ``round_start`` through
    ``round_end`` (inclusive), using the reference round functions and the
    reference key schedule.  Post-whitening is applied only when the slice
    ends at the cipher's final round (round 15 of a 16-round ARADI).
    """
    assert 0 <= round_start <= round_end <= 15, "invalid slice bounds"
    rks = aradi_core.roundkeys(key)

    w, x, y, z = state_words
    for i in range(round_start, round_end + 1):
        w ^= rks[i][0]
        x ^= rks[i][1]
        y ^= rks[i][2]
        z ^= rks[i][3]

        w, x, y, z = aradi_core.sbox(w, x, y, z)

        j = i % 4
        w = aradi_core.linear(j, w)
        x = aradi_core.linear(j, x)
        y = aradi_core.linear(j, y)
        z = aradi_core.linear(j, z)

    if round_end == 15:
        w ^= rks[16][0]
        x ^= rks[16][1]
        y ^= rks[16][2]
        z ^= rks[16][3]

    return [w, x, y, z]


def main():
    # Master key from the ARADI reference test vectors.
    key = [
        0x03020100,
        0x07060504,
        0x0B0A0908,
        0x0F0E0D0C,
        0x13121110,
        0x17161514,
        0x1B1A1918,
        0x1F1E1D1C,
    ]
    pt_words = [0x00000000, 0x00000000, 0x00000000, 0x00000000]
    pt_int = words_to_int(pt_words)
    pt_vec = int_to_vec(pt_int, 128)

    # Full cipher sanity check.
    full_cvl = ARADI_CVL(key=key)
    full_cvl_words = int_to_words(vec_to_int(full_cvl(pt_vec)))
    full_ref_words = aradi_core.aradi_encryption_block(pt_words, key)
    assert full_cvl_words == full_ref_words, "full encryption mismatch"
    print("Full encryption:")
    print(f"  CiVerLy: {[hex(w) for w in full_cvl_words]}")
    print(f"  Ref:     {[hex(w) for w in full_ref_words]}")
    print()

    # Sliced encryption checks.
    slices = [
        # mid-cipher slice: no post-whitening
        (2, 5),
        # final slice: includes post-whitening
        (14, 15),
    ]

    for start, end in slices:
        cvl_cipher = ARADI_CVL(key=key, round_start=start, round_end=end, R=16)
        cvl_out_words = int_to_words(vec_to_int(cvl_cipher(pt_vec)))
        ref_out_words = reference_slice_encrypt(pt_words, key, start, end)

        assert cvl_out_words == ref_out_words, (
            f"slice {start}..{end} mismatch:\n"
            f"  CiVerLy: {[hex(w) for w in cvl_out_words]}\n"
            f"  Ref:     {[hex(w) for w in ref_out_words]}"
        )

        print(f"Slice rounds {start}..{end}:")
        print(f"  CiVerLy: {[hex(w) for w in cvl_out_words]}")
        print(f"  Ref:     {[hex(w) for w in ref_out_words]}")
        print()

    print("All sliced encryption checks passed.")


if __name__ == "__main__":
    main()
