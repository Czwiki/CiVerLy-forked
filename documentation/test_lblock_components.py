#!/usr/bin/env python3
r"""Verify LBlock components in CiVerLy against reference implementation."""

from sage.crypto.sbox import SBox
import sys
sys.path.insert(0, 'src')

from civerly.util import int_to_vec, vec_to_int
from civerly.component import SBox_CVL, PermuteLayer_CVL, RotateLayer_CVL
from civerly.component import RoundkeyXOR_CVL, XOR_CVL
from civerly.sboxcipher import SBoxCipher

# S-boxes from spec
S_BOXES = [
    [14, 9, 15, 0, 13, 4, 10, 11, 1, 2, 8, 3, 7, 6, 12, 5],
    [4, 11, 14, 9, 15, 13, 0, 10, 7, 12, 5, 6, 2, 8, 1, 3],
    [1, 14, 7, 12, 15, 13, 0, 6, 11, 5, 9, 3, 2, 4, 8, 10],
    [7, 6, 8, 11, 0, 15, 3, 14, 9, 10, 12, 13, 5, 2, 4, 1],
    [14, 5, 15, 0, 7, 2, 12, 13, 1, 8, 4, 9, 11, 10, 6, 3],
    [2, 13, 11, 12, 15, 14, 0, 9, 7, 10, 6, 3, 1, 8, 4, 5],
    [11, 9, 4, 14, 0, 15, 10, 13, 6, 12, 5, 7, 3, 8, 1, 2],
    [13, 10, 15, 0, 14, 4, 9, 11, 2, 1, 8, 3, 7, 5, 12, 6],
]

# Build S-box layer
sbox_layer = SBoxCipher(32, 32, name="SBoxLayer")
for i in range(8):
    src_start = 28 - 4 * i
    sbox = SBox_CVL(SBox(S_BOXES[i]), name=f"s{i}")
    node = sbox_layer.add_subcipher(
        sbox, [(sbox_layer.IN, (src_start + j, j)) for j in range(4)]
    )
    sbox_layer.add_output([(node, (j, src_start + j)) for j in range(4)])

# Build P permutation
P_perm = PermuteLayer_CVL(
    [2, 0, 3, 1, 6, 4, 7, 5], word_coarseness=4, name="P"
)

# Test S-box layer + P on a sample 32-bit value
x32 = 0x12345678
v = int_to_vec(x32, 32)

sbox_out = sbox_layer(v)
print("S-box input:", hex(x32))
print("S-box output:", hex(vec_to_int(sbox_out)))

perm_out = P_perm(sbox_out)
print("P output:", hex(vec_to_int(perm_out)))

# Verify against manual reference
from documentation.lblock_ref import sbox_layer as ref_sbox, perm_layer as ref_perm
ref_s = ref_sbox(x32)
ref_p = ref_perm(ref_s)
print("Ref S-box output:", hex(ref_s))
print("Ref P output:", hex(ref_p))

print("S-box match:", vec_to_int(sbox_out) == ref_s)
print("P match:", vec_to_int(perm_out) == ref_p)

# Test rotation on right half
rot = RotateLayer_CVL(32, 8, word_coarseness=1, name="rot")
r32 = 0x89abcdef
v_rot = int_to_vec(r32, 32)
rot_out = rot(v_rot)
print("\nRot input:", hex(r32))
print("Rot output:", hex(vec_to_int(rot_out)))
print("Ref rot:", hex(((r32 << 8) & 0xFFFFFFFF) | (r32 >> 24)))
print("Rot match:", vec_to_int(rot_out) == (((r32 << 8) & 0xFFFFFFFF) | (r32 >> 24)))

# Test full round function on simple input
# left = 0x12345678, right = 0x89abcdef, key = 0x00000000
lblock_round = SBoxCipher(64, 64, name="LBlock_round")
rk = RoundkeyXOR_CVL(32, 0x0, name="rk")
node_rk = lblock_round.add_subcipher(rk, [(lblock_round.IN, (i, i)) for i in range(32)])

node_s = lblock_round.add_subcipher(
    sbox_layer, [(node_rk, (i, i)) for i in range(32)]
)
node_p = lblock_round.add_subcipher(
    P_perm, [(node_s, (i, i)) for i in range(32)]
)

node_rot = lblock_round.add_subcipher(
    rot, [(lblock_round.IN, (i + 32, i)) for i in range(32)]
)

xor = XOR_CVL(32, name="xor")
node_xor = lblock_round.add_subcipher(
    xor,
    [(node_p, (i, i)) for i in range(32)]
    + [(node_rot, (i, i + 32)) for i in range(32)]
)

lblock_round.add_output([(node_xor, (i, i)) for i in range(32)])
lblock_round.add_output([(lblock_round.IN, (i, i + 32)) for i in range(32)])

left = 0x12345678
right = 0x89abcdef
inp = int_to_vec((left << 32) | right, 64)
round_out = lblock_round(inp)
out_left = vec_to_int(round_out[:32])
out_right = vec_to_int(round_out[32:64])
print("\nRound input: left=", hex(left), "right=", hex(right))
print("Round output: left=", hex(out_left), "right=", hex(out_right))

# Reference round
from documentation.lblock_ref import f as ref_f
ref_left = ref_f(left, 0) ^ (((right << 8) & 0xFFFFFFFF) | (right >> 24))
ref_right = left
print("Ref output: left=", hex(ref_left), "right=", hex(ref_right))
print("Round match:", out_left == ref_left and out_right == ref_right)
