#!/usr/bin/env python3
"""Compute Qalqan variant test vectors using the documentation reference."""
import sys
sys.path.insert(0, '/Users/Uni/Documents/GitHub/CiVerLy-forked-new/documentation')
from qalqan import (
    S, L, xor_bytes, add128, KeyScheduler, rounds_for_key, check_key,
    MIN_KEY_SIZE, KEY_STEP, BLOCK_SIZE,
)

def byteadd(a, b):
    """Byte-wise modulo 256 addition of two 16-byte blocks."""
    return bytes((x + y) & 0xff for x, y in zip(a, b))

def encrypt_block_variant(block, key, variant):
    check_key(key)
    scheduler = KeyScheduler(key)
    round_keys = scheduler.expand()
    state = bytes(block)
    first_add = xor_bytes if variant in ('original', 'xor_byteadd') else byteadd
    middle_add = add128 if variant == 'original' else byteadd
    last_add = xor_bytes if variant in ('original', 'xor_byteadd') else byteadd

    state = first_add(state, round_keys[0])
    state = S(state)
    state = L(state)

    for rk in round_keys[1:-1]:
        state = middle_add(state, rk)
        state = S(state)
        state = L(state)

    state = last_add(state, round_keys[-1])
    return state

def compute_tv(key_hex, pt_hex, variant, label):
    key = bytes.fromhex(key_hex)
    pt = bytes.fromhex(pt_hex)
    ct = encrypt_block_variant(pt, key, variant)
    print(f"{label} {variant}: {ct.hex()}")

# Same vectors as in the current qalqan.py doctests
# 256-bit key, pt = bytes(range(16))
compute_tv(''.join(f'{b:02x}' for b in range(32)),
           ''.join(f'{b:02x}' for b in range(16)),
           'original', '256-bit key')
compute_tv(''.join(f'{b:02x}' for b in range(32)),
           ''.join(f'{b:02x}' for b in range(16)),
           'xor_byteadd', '256-bit key')
compute_tv(''.join(f'{b:02x}' for b in range(32)),
           ''.join(f'{b:02x}' for b in range(16)),
           'byteadd_byteadd', '256-bit key')

# 384-bit key, pt = bytes(range(1, 17))
compute_tv(''.join(f'{b:02x}' for b in range(48)),
           ''.join(f'{b:02x}' for b in range(1, 17)),
           'original', '384-bit key')
compute_tv(''.join(f'{b:02x}' for b in range(48)),
           ''.join(f'{b:02x}' for b in range(1, 17)),
           'xor_byteadd', '384-bit key')
compute_tv(''.join(f'{b:02x}' for b in range(48)),
           ''.join(f'{b:02x}' for b in range(1, 17)),
           'byteadd_byteadd', '384-bit key')

# 512-bit key, pt = bytes(range(16))
compute_tv(''.join(f'{b:02x}' for b in range(64)),
           ''.join(f'{b:02x}' for b in range(16)),
           'original', '512-bit key')
compute_tv(''.join(f'{b:02x}' for b in range(64)),
           ''.join(f'{b:02x}' for b in range(16)),
           'xor_byteadd', '512-bit key')
compute_tv(''.join(f'{b:02x}' for b in range(64)),
           ''.join(f'{b:02x}' for b in range(16)),
           'byteadd_byteadd', '512-bit key')

# 1024-bit key, pt = bytes(range(16))
compute_tv(''.join(f'{b:02x}' for b in range(128)),
           ''.join(f'{b:02x}' for b in range(16)),
           'original', '1024-bit key')
compute_tv(''.join(f'{b:02x}' for b in range(128)),
           ''.join(f'{b:02x}' for b in range(16)),
           'xor_byteadd', '1024-bit key')
compute_tv(''.join(f'{b:02x}' for b in range(128)),
           ''.join(f'{b:02x}' for b in range(16)),
           'byteadd_byteadd', '1024-bit key')
