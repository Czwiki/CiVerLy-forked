#!/usr/bin/env python3
# implementation from AI based on Java implementation
"""Quick reference implementation of LBlock to verify test vectors."""

LBLOCK_SBOXES = [
    [14, 9, 15, 0, 13, 4, 10, 11, 1, 2, 8, 3, 7, 6, 12, 5],
    [4, 11, 14, 9, 15, 13, 0, 10, 7, 12, 5, 6, 2, 8, 1, 3],
    [1, 14, 7, 12, 15, 13, 0, 6, 11, 5, 9, 3, 2, 4, 8, 10],
    [7, 6, 8, 11, 0, 15, 3, 14, 9, 10, 12, 13, 5, 2, 4, 1],
    [14, 5, 15, 0, 7, 2, 12, 13, 1, 8, 4, 9, 11, 10, 6, 3],
    [2, 13, 11, 12, 15, 14, 0, 9, 7, 10, 6, 3, 1, 8, 4, 5],
    [11, 9, 4, 14, 0, 15, 10, 13, 6, 12, 5, 7, 3, 8, 1, 2],
    [13, 10, 15, 0, 14, 4, 9, 11, 2, 1, 8, 3, 7, 5, 12, 6],
    [8, 7, 14, 5, 15, 13, 0, 6, 11, 12, 9, 10, 2, 4, 1, 3],
    [11, 5, 15, 0, 7, 2, 9, 13, 4, 8, 1, 12, 14, 10, 3, 6],
]

def rotl8(x):
    """8-bit left rotation of a 32-bit value x."""
    return ((x << 8) & 0xFFFFFFFF) | (x >> 24)

def sbox_layer(x):
    """Apply 8 parallel 4-bit S-boxes to 32-bit x."""
    y = 0
    for i in range(8):
        nibble = (x >> (4 * i)) & 0xF
        y |= LBLOCK_SBOXES[i][nibble] << (4 * i)
    return y

def perm_layer(z):
    """Permutation P on 32-bit input (8 nibbles)."""
    # Extract nibbles: n[i] is nibble at position i (0 = LSB)
    n = [(z >> (4 * i)) & 0xF for i in range(8)]
    # P: U7=Z6, U6=Z4, U5=Z7, U4=Z5, U3=Z2, U2=Z0, U1=Z3, U0=Z1
    u = [0] * 8
    u[7] = n[6]
    u[6] = n[4]
    u[5] = n[7]
    u[4] = n[5]
    u[3] = n[2]
    u[2] = n[0]
    u[1] = n[3]
    u[0] = n[1]
    result = 0
    for i in range(8):
        result |= u[i] << (4 * i)
    return result

def f(x, k):
    """Round function F(X, Ki) = P(S(X XOR Ki))."""
    return perm_layer(sbox_layer(x ^ k))

def lblock_encrypt(plaintext, key, rounds=32):
    """Encrypt 64-bit plaintext with 80-bit key."""
    x = [0] * 34
    x[1] = (plaintext >> 32) & 0xFFFFFFFF
    x[0] = plaintext & 0xFFFFFFFF
    
    # Key schedule
    rks = lblock_key_schedule(key, rounds)
    
    for i in range(2, rounds + 2):
        x[i] = f(x[i-1], rks[i-2]) ^ rotl8(x[i-2])
    
    return (x[rounds] << 32) | x[rounds + 1]

def lblock_key_schedule(key, rounds=32):
    """Generate round keys for LBlock."""
    K = key & ((1 << 80) - 1)
    rks = []
    for i in range(rounds):
        rks.append((K >> 48) & 0xFFFFFFFF)  # leftmost 32 bits
        # Update key register
        # (a) K <<< 29
        K = ((K << 29) & ((1 << 80) - 1)) | (K >> (80 - 29))
        # (b) [k79 k78 k77 k76] = s9[k79 k78 k77 k76]
        #     [k75 k74 k73 k72] = s8[k75 k74 k73 k72]
        nibble9 = (K >> 76) & 0xF
        nibble8 = (K >> 72) & 0xF
        K = (K & ~((0xF << 76) | (0xF << 72))) | (LBLOCK_SBOXES[9][nibble9] << 76) | (LBLOCK_SBOXES[8][nibble8] << 72)
        # (c) [k50 k49 k48 k47 k46] XOR [i+1]_2
        # i goes from 1 to 31 (round index in 1-based), here i is 0-based round number
        counter = (i + 1) & 0x1F  # 5-bit counter
        k_bits = (K >> 46) & 0x1F
        k_bits ^= counter
        K = (K & ~(0x1F << 46)) | (k_bits << 46)
    return rks

if __name__ == "__main__":
    # Test vectors
    pt1 = 0x0000000000000000
    key1 = 0x00000000000000000000
    ct1_expected = 0xc218185308e75bcd
    
    pt2 = 0x0123456789abcdef
    key2 = 0x0123456789abcdeffedc
    ct2_expected = 0x4b7179d8ebee0c26
    
    ct1 = lblock_encrypt(pt1, key1)
    ct2 = lblock_encrypt(pt2, key2)
    
    print(f"Test 1: {ct1:016x} (expected {ct1_expected:016x}) {'OK' if ct1 == ct1_expected else 'FAIL'}")
    print(f"Test 2: {ct2:016x} (expected {ct2_expected:016x}) {'OK' if ct2 == ct2_expected else 'FAIL'}")
