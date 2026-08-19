#!/usr/bin/env sage
# -*- coding: utf-8 -*-
r"""
verify_blink_trail.py
=====================

Validate CiVerLy MILP trails for sliced Blink instances against empirical
reference encryption and structural weight checks.

Run from the repo root::

    sage verify_blink_trail.py [start] [end]

Examples::

    sage verify_blink_trail.py 1 2   # Superbox 1 (rounds 1-2 + h0)
    sage verify_blink_trail.py 3 4   # Superbox 2 (rounds 3-4)
    sage verify_blink_trail.py 5 6   # Transition across reflection
"""
from __future__ import print_function
import sys
from pathlib import Path
from math import isclose

# Ensure repo packages are importable
_repo = Path(__file__).resolve().parent
sys.path.insert(0, str(_repo / "src"))
sys.path.insert(0, str(_repo / "documentation"))

# ---------------------------------------------------------------------------
# Imports
# ---------------------------------------------------------------------------
try:
    from civerly.cipher_implementations.blink import BLINK_CVL
    from civerly.model_options import (
        MODEL_OPTIONS,
        CRYPTANALYSIS,
        OPTIMIZATION,
        GRANULARITY,
        LINEAR_LAYER_MODELING,
        SBOX_MODELING,
        SCIP_CVL,
    )
except ImportError as exc:
    print("ERROR: Could not import CiVerLy modules.", exc)
    sys.exit(1)

# Reference implementation (for structural comparison)
try:
    from blink import Blink_64a, encrypt_bytes
    HAVE_REF = True
except Exception:
    HAVE_REF = False

# ---------------------------------------------------------------------------
# Pretty-print helpers
# ---------------------------------------------------------------------------

def _format_state(vals, total_bits=64):
    """Pretty-print a flat state list into a 4x4 row-major nibble grid."""
    if vals is None or len(vals) == 0:
        return "None"
    if len(vals) == total_bits:
        # bitwise: pack into nibbles (LSB-first)
        nibbles = []
        for i in range(0, total_bits, 4):
            n = sum(int(vals[i + b]) << b for b in range(4))
            nibbles.append(n)
    elif len(vals) == total_bits // 4:
        # wordwise (nibbles)
        nibbles = [int(v) for v in vals]
    else:
        return str(vals[:16]) + "..."
    rows = [nibbles[i:i + 4] for i in range(0, 16, 4)]
    return " | ".join(
        " ".join(f"{n:01x}" if n != 0 else "·" for n in row)
        for row in rows
    )


def _count_active(vals):
    return sum(1 for v in vals if v != 0) if vals else 0


def walk_trail(node, depth=0, out=sys.stdout):
    """Recursively print a TrailNode tree."""
    prefix = "  " * depth
    name = getattr(node, "name", "?")
    weight = getattr(node, "weight", 0)
    in_str = _format_state(getattr(node, "input", None))
    out_str = _format_state(getattr(node, "output", None))
    print(f"{prefix}[{name}] weight={weight}", file=out)
    print(f"{prefix}  IN : {in_str}", file=out)
    print(f"{prefix}  OUT: {out_str}", file=out)
    for child in getattr(node, "children", []):
        walk_trail(child, depth + 1, out=out)


def sum_leaf_weights(node, keyword="SBox"):
    """Recursively sum weights of leaf nodes whose name contains ``keyword``."""
    children = getattr(node, "children", [])
    if not children:
        if keyword in (getattr(node, "name", "")):
            return float(getattr(node, "weight", 0))
        return 0.0
    return float(sum(sum_leaf_weights(c, keyword) for c in children))


def sum_subcells_weights(node):
    """Sum weights of all S-box layers (SubCells or leaf SBox nodes)."""
    children = getattr(node, "children", [])
    name = getattr(node, "name", "")
    if "SubCells" in name and not children:
        # This shouldn't happen because SubCells is composite, but be safe
        return float(getattr(node, "weight", 0))
    if not children:
        if "SBox" in name:
            return float(getattr(node, "weight", 0))
        return 0.0
    return float(sum(sum_subcells_weights(c) for c in children))


# ---------------------------------------------------------------------------
# Empirical reference check
# ---------------------------------------------------------------------------

def empirical_full_cipher_check(input_diff_int, key_int=0, tweak_int=0):
    """
    Encrypt a random plaintext and plaintext ^ input_diff under the
    *full* reference Blink-64a cipher.  Prints the ciphertext difference.

    This is mostly illustrative: it confirms that for *any* fixed key the
    difference propagates deterministically through the linear layers, while
    the S-box transitions depend on concrete values.
    """
    if not HAVE_REF:
        print("  (reference cipher unavailable; skipping empirical check)")
        return

    import random
    pt = random.getrandbits(64)
    pt2 = pt ^ input_diff_int

    plain = pt.to_bytes(8, "big")
    plain2 = pt2.to_bytes(8, "big")
    key = key_int.to_bytes(56, "big")
    tweak = tweak_int.to_bytes(8, "big")

    ct = encrypt_bytes(Blink_64a, plain, tweak, key)
    ct2 = encrypt_bytes(Blink_64a, plain2, tweak, key)

    out_diff = int.from_bytes(ct, "big") ^ int.from_bytes(ct2, "big")
    print(f"  Empirical full-cipher output diff: {out_diff:016x}")
    print(f"  Hamming weight of output diff    : {bin(out_diff).count('1')}")


# ---------------------------------------------------------------------------
# Main analysis
# ---------------------------------------------------------------------------

def analyze_slice(start, end, key_int=0, tweak_int=0):
    print("=" * 72)
    print(f"Blink-64 slice  Rounds {start}–{end}")
    print(f"Master key = 0x{key_int:0144x}" if key_int else "Master key = 0 (all-zero)")
    print(f"Tweak      = 0x{tweak_int:016x}" if tweak_int else "Tweak      = 0 (weak-key regime)")
    print("=" * 72)

    cipher = BLINK_CVL(
        64, 64,
        key=key_int,
        tweak=tweak_int,
        start=start,
        end=end,
        name=f"blink_R{start}-{end}",
    )
    print(f"\nCipher graph valid: {cipher.is_valid}")

    import tempfile
    with tempfile.TemporaryDirectory() as tmpdir:
        model_path = Path(tmpdir)
        opts = MODEL_OPTIONS(
            cryptanalysis=CRYPTANALYSIS.DIFFERENTIAL,
            optimization=OPTIMIZATION.MILP,
            granularity=GRANULARITY.BITWISE,
            linear_layer_modeling=LINEAR_LAYER_MODELING.MORE_DUMMIES,
            sbox_modeling=SBOX_MODELING.CONVEX_HULL,
            milp_solver=SCIP_CVL(),
            path=model_path,
        )

        print("\nBuilding / solving MILP …")
        try:
            cipher.analyse(opts)
        except Exception as exc:
            print(f"\nERROR: {exc}")
            print("Hint: SCIP (PySCIPOpt) must be installed and on the Sage Python path.")
            print("      If SCIP is unavailable, install it in the Nix environment")
            print("      or change milp_solver to another backend.")
            return

        print("Retrieving trail …")
        trail = cipher.get_trail(opts)

        print("\n" + "=" * 72)
        print("TRAIL TREE")
        print("=" * 72)
        walk_trail(trail)

        total_weight = float(getattr(trail, "weight", 0))
        sbox_weight = sum_subcells_weights(trail)
        leaf_sbox_weight = sum_leaf_weights(trail, keyword="SBox")

        print("\n" + "=" * 72)
        print("WEIGHT SANITY CHECK")
        print("=" * 72)
        print(f"Top-level trail weight                 : {total_weight}")
        print(f"Sum of SubCells / composite S-box weights: {sbox_weight}")
        print(f"Sum of leaf SBox_CVL weights             : {leaf_sbox_weight}")

        if total_weight:
            active_sb = int(round(total_weight / 2))
            print(f"\n=> Active S-box count (weight / 2)      : {active_sb}")
            print(f"=> Expected raw probability              : 2^{{-{int(total_weight)}}}")

        print("\n" + "=" * 72)
        print("ACTIVE-NIBBLE SUMMARY")
        print("=" * 72)
        print(f"Input  active nibbles: {_count_active(trail.input)}")
        print(f"Output active nibbles: {_count_active(trail.output)}")

        # Empirical check
        print("\n" + "=" * 72)
        print("EMPIRICAL FULL-CIPHER CHECK (illustrative)")
        print("=" * 72)
        if trail.input:
            # Reconstruct input difference integer from the trail state
            if len(trail.input) == 16:
                input_diff = sum(int(v) << (4 * i) for i, v in enumerate(trail.input))
            else:
                input_diff = sum(int(v) << i for i, v in enumerate(trail.input))
            empirical_full_cipher_check(input_diff, key_int, tweak_int)

        print("\n" + "=" * 72)
        print("NOTES")
        print("=" * 72)
        print("""
* The MILP computes a SINGLE optimal differential characteristic.
Its exponent (weight / 2) counts every active S-box at 2^-2.

* The paper's quoted probabilities (e.g. 2^-12, 2^-18.415) are
CLUSTERED differentials: they sum many characteristics that share
the same truncated mask, valid only under weak-key conditions.
Hence the paper's exponents are usually SMALLER than the MILP's.

* CiVerLy's result is sensible if:
    – top-level weight matches the sum of leaf S-box weights.
    – the active-nibble pattern matches the structural shape from
    Figure 3 (same positions active, ignoring exact values).
""")
        print("Done.\n")


if __name__ == "__main__":
    first = int(sys.argv[1]) if len(sys.argv) > 1 else 1
    last = int(sys.argv[2]) if len(sys.argv) > 2 else 2
    analyze_slice(first, last, key_int=0, tweak_int=0)
