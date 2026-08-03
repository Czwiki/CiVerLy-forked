#!/usr/bin/env python3
"""
Reference implementation of the Qalqan block cipher.

Specification:
    "About Cryptographic Properties of the Qalqan Encryption Algorithm"
    CPITS-II-2021

This implementation follows the paper as closely as possible and favors
readability over performance.
"""

from __future__ import annotations

from math import log2
import os
from typing import List


BLOCK_SIZE = 16          # bytes
MIN_KEY_SIZE = 32        # 256 bit
MAX_KEY_SIZE = 128       # 1024 bit
KEY_STEP = 16            # 128 bit


###########################################################################
# Qalqan S-Box
###########################################################################

SBOX = [

0xEB,0x89,0xDB,0xCB,0xF3,0xF5,0xFB,0x90,
0xE6,0x3D,0xE5,0x2E,0xE3,0x0B,0x56,0xE1,

0x6C,0x12,0x80,0x28,0xED,0x22,0x09,0x4A,
0xEE,0x27,0x9B,0x58,0x35,0x57,0xEF,0x94,

0x29,0xC0,0x16,0x7C,0x5E,0x87,0x0A,0x7E,
0xE8,0x11,0x0E,0xAF,0x9A,0x84,0x3A,0x1A,

0x69,0x71,0x8C,0xBC,0xD2,0x55,0x33,0xD1,
0x85,0x75,0xB5,0x83,0xE9,0x50,0x54,0xAC,

0x8A,0xD6,0x7F,0x1F,0x14,0x4E,0x21,0x82,
0x30,0x24,0xDD,0x9F,0x1B,0x32,0x20,0xA8,

0x6A,0xB0,0x97,0x62,0x19,0xD8,0xC8,0x0C,
0x52,0x02,0x5C,0x43,0x03,0x95,0x13,0x81,

0xAB,0x77,0xA6,0xF2,0x59,0x67,0x41,0xEC,
0x76,0x98,0xB4,0x73,0x86,0x9C,0xF7,0xCF,

0xDC,0xBA,0xA4,0xFD,0xC4,0x99,0xDF,0xCE,
0xEA,0x1C,0x36,0xBD,0x34,0xD7,0x49,0x64,

0x5A,0x6F,0x74,0x01,0xA0,0x39,0x91,0x00,
0x15,0x3F,0x38,0xB8,0x8F,0x26,0x5F,0xF8,

0x07,0xA3,0x0D,0xDA,0xF0,0xE7,0xD0,0xD9,
0x93,0xF6,0x06,0x47,0x0F,0xA1,0x4B,0xC5,

0x2A,0xFF,0x46,0x60,0xD5,0x1D,0x2F,0xA9,
0x92,0x17,0x72,0x8E,0x7A,0xAA,0x18,0x6E,

0x37,0x08,0x1E,0x63,0x31,0xC2,0xBF,0xC6,
0x9E,0x65,0xD4,0x3B,0x96,0x9D,0xDE,0x45,

0xCA,0x2D,0xA5,0xFE,0x4D,0xB9,0x66,0xC3,
0xB3,0xCC,0xAD,0x61,0xBE,0x7B,0x68,0x88,

0x25,0x2B,0x53,0x5B,0x44,0x40,0xA7,0xA2,
0x5D,0xC9,0x51,0xAE,0xE4,0xC7,0xF9,0x78,

0x70,0xCD,0x42,0x4F,0x4C,0x3C,0xE0,0x3E,
0x7D,0xB7,0xD3,0xB2,0xF1,0x8D,0x79,0x8B,

0x6B,0xE2,0x10,0x23,0x04,0x6D,0xC1,0xFC,
0x05,0xB6,0xF4,0x48,0xBB,0xB1,0x2C,0xFA

]

###########################################################################
# inverse S-box
###########################################################################

INV_SBOX = [0] * 256

for i, x in enumerate(SBOX):
    INV_SBOX[x] = i


###########################################################################
# basic arithmetic
###########################################################################

def add8(a: int, b: int) -> int:
    return (a + b) & 0xff


def sub8(a: int, b: int) -> int:
    return (a - b) & 0xff


def xor128(a: bytes, b: bytes) -> bytes:
    return bytes(x ^ y for x, y in zip(a, b))

def add128(a: bytes, b: bytes) -> bytes:
    ai = int.from_bytes(a, "little")
    bi = int.from_bytes(b, "little")
    ci = (ai + bi) & ((1 << 128) - 1)
    return ci.to_bytes(16, "little")


def sub128(a: bytes, b: bytes) -> bytes:
    ai = int.from_bytes(a, "little")
    bi = int.from_bytes(b, "little")
    ci = (ai - bi) & ((1 << 128) - 1)
    return ci.to_bytes(16, "little")

def xor_bytes(a: bytes, b: bytes) -> bytes:
    check_block(a)
    check_block(b)

    return bytes(x ^ y for x, y in zip(a, b))

###########################################################################
# nonlinear transformation
###########################################################################

def S(block: bytes) -> bytes:
    return bytes(SBOX[b] for b in block)


def InvS(block: bytes) -> bytes:
    return bytes(INV_SBOX[b] for b in block)

###########################################################################
# helpers
###########################################################################

def check_block(block: bytes):

    if len(block) != 16:
        raise ValueError("Block must contain exactly 16 bytes.")


def check_key(key: bytes):

    if len(key) < MIN_KEY_SIZE:
        raise ValueError("Key too short.")

    if len(key) > MAX_KEY_SIZE:
        raise ValueError("Key too long.")

    if (len(key) - MIN_KEY_SIZE) % KEY_STEP:
        raise ValueError("Key length must increase in 128-bit steps.")


def rounds_for_key(key: bytes) -> int:
    """
    N = 17 + floor((KLen-256)/128)*2
    """

    bits = len(key) * 8

    return 17 + ((bits - 256) // 128) * 2

###########################################################################
# Linear transformation
###########################################################################

def L(block: bytes) -> bytes:
    """
    Linear transformation from the paper.
    Addition is modulo 256.
    """

    check_block(block)

    B = list(block)
    R = [0] * 16

    # Diagonal bytes
    r0  = (B[0]  + B[1]  + B[2]  + B[3])  & 0xff
    r5  = (B[4]  + B[5]  + B[6]  + B[7])  & 0xff
    r10 = (B[8]  + B[9]  + B[10] + B[11]) & 0xff
    r15 = (B[12] + B[13] + B[14] + B[15]) & 0xff

    R[0] = r0
    R[5] = r5
    R[10] = r10
    R[15] = r15

    # column propagation

    R[4]  = (B[4]  + r0)  & 0xff
    R[8]  = (B[8]  + r0)  & 0xff
    R[12] = (B[12] + r0)  & 0xff

    R[1]  = (B[1]  + r5)  & 0xff
    R[9]  = (B[9]  + r5)  & 0xff
    R[13] = (B[13] + r5)  & 0xff

    R[2]  = (B[2]  + r10) & 0xff
    R[6]  = (B[6]  + r10) & 0xff
    R[14] = (B[14] + r10) & 0xff

    R[3]  = (B[3]  + r15) & 0xff
    R[7]  = (B[7]  + r15) & 0xff
    R[11] = (B[11] + r15) & 0xff

    return bytes(R)

###########################################################################
# inverse linear transformation
###########################################################################

def InvL(block: bytes) -> bytes:
    """
    Mathematical inverse of L().

    The paper contains a typo in the inverse equations.
    This implementation is derived directly from L().
    """

    check_block(block)

    R = list(block)
    B = [0] * 16

    #
    # Recover bytes that are directly obtainable
    #

    B[4]  = (R[4]  - R[0])  & 0xff
    B[8]  = (R[8]  - R[0])  & 0xff
    B[12] = (R[12] - R[0])  & 0xff

    B[1]  = (R[1]  - R[5])  & 0xff
    B[9]  = (R[9]  - R[5])  & 0xff
    B[13] = (R[13] - R[5])  & 0xff

    B[2]  = (R[2]  - R[10]) & 0xff
    B[6]  = (R[6]  - R[10]) & 0xff
    B[14] = (R[14] - R[10]) & 0xff

    B[3]  = (R[3]  - R[15]) & 0xff
    B[7]  = (R[7]  - R[15]) & 0xff
    B[11] = (R[11] - R[15]) & 0xff

    #
    # Recover diagonal bytes
    #

    B[0] = (R[0] - B[1] - B[2] - B[3]) & 0xff

    B[5] = (R[5] - B[4] - B[6] - B[7]) & 0xff

    B[10] = (R[10] - B[8] - B[9] - B[11]) & 0xff

    B[15] = (R[15] - B[12] - B[13] - B[14]) & 0xff

    return bytes(B)

def _test_L():

    import os

    for _ in range(10000):

        b = os.urandom(16)

        if InvL(L(b)) != b:
            raise RuntimeError("L inverse failed")

    print("L/InvL OK")

# -----------------------------------------------------------------
# NOTE
#
# The original Qalqan key schedule is not completely specified in any
# publicly available English publication.
#
# This implementation reconstructs the key schedule from
#
#  • CEUR paper
#  • RusCrypto slides
#  • Differential attack paper
#  • Bachelor's thesis
#
# Every assumption is explicitly marked.
# -----------------------------------------------------------------

###########################################################################
# Reconstructed Key Scheduler
###########################################################################

class KeyScheduler:

    def __init__(self, key: bytes, emit_after_clock=True):
        self.emit_after_clock = emit_after_clock

        check_key(key)

        self.rounds = rounds_for_key(key)

        #
        # Register A (17 bytes)
        #

        self.A = list(key[0:32:2])
        self.A.append(0)

        #
        # Register B (16 bytes)
        #

        self.B = list(key[1:32:2])

        #
        # Remaining key bytes (384..1024 bit keys)
        #

        self.extra = list(key[32:])
        self.extra_index = 0

    def _next_extra(self):

        if not self.extra:
            return 0

        x = self.extra[self.extra_index]

        self.extra_index += 1

        if self.extra_index == len(self.extra):
            self.extra_index = 0

        return x

    def _feedback_A(self):

        f = 0

        #
        # S-box taps
        #

        f += SBOX[self.A[0]]
        f += SBOX[self.A[3]]
        f += self.A[7]
        f += SBOX[self.A[12]]
        f += self.A[16]

        #
        # extra key byte
        #

        f += self._next_extra()

        return f & 0xff

    def _feedback_B(self):

        f = 0

        f += SBOX[self.B[0]]
        f += self.B[7]
        f += SBOX[self.B[11]]
        f += self.B[14]
        f += SBOX[self.B[15]]

        f += self._next_extra()

        return f & 0xff
    
    def _clock(self):

        fa = self._feedback_A()
        fb = self._feedback_B()

        #
        # Shift
        #

        self.A = self.A[1:] + [fa]
        self.B = self.B[1:] + [fb]

    def next_round_key(self):

        if self.emit_after_clock:

            for _ in range(17):
                self._clock()

        rk = bytes(
            ((self.A[i] + self.B[i]) & 0xff)
            for i in range(16)
        )

        if not self.emit_after_clock:

            for _ in range(17):
                self._clock()

        return rk

    def expand(self):
        """
        Generate all round keys.

        The encryption function (§3.4.1) requires one additional key
        on top of the nominal round count *N*:

            * ``rk[0]``   – start whitening (XOR)
            * ``rk[1..N-1]`` – N-1 middle rounds (mod 2^128 addition)
            * ``rk[N]``   – final whitening (XOR)

        Therefore ``expand()`` yields **N + 1** keys.
        """

        keys = []

        for _ in range(self.rounds + 1):
            keys.append(self.next_round_key())

        return keys

    
###########################################################################
# Encryption
###########################################################################

def encrypt_block(block: bytes, key: bytes) -> bytes:
    """
    Reconstructed Qalqan encryption.

    NOTE
    ----
    The public papers do not completely specify the round ordering.
    This implementation follows the most plausible interpretation
    reconstructed from

      * CEUR paper
      * RusCrypto slides
      * Differential attack paper
      * Bachelor's thesis
    """

    check_block(block)
    check_key(key)

    #
    # Generate round keys
    #

    scheduler = KeyScheduler(key)
    round_keys = scheduler.expand()

    state = bytes(block)

    #
    # first round
    #

    state = xor_bytes(state, round_keys[0])
    state = S(state)
    state = L(state)

    #
    # Middle rounds
    #

    for rk in round_keys[1:-1]:

        #
        # Round-key addition (mod 2^128)
        #

        state = add128(state, rk)

        #
        # Non-linear layer
        #

        state = S(state)

        #
        # Linear layer
        #

        state = L(state)

    #
    # Final whitening
    #

    state = xor_bytes(state, round_keys[-1])

    return state

def encrypt(data: bytes, key: bytes) -> bytes:
    """
    ECB encryption without padding.

    Length must be a multiple of 16 bytes.
    """

    if len(data) % 16:
        raise ValueError("Length must be multiple of 16 bytes.")

    out = bytearray()

    for i in range(0, len(data), 16):

        out.extend(
            encrypt_block(data[i:i+16], key)
        )

    return bytes(out)

def pkcs7_pad(data: bytes) -> bytes:

    pad = 16 - (len(data) % 16)

    return data + bytes([pad]) * pad


###########################################################################
# 2-round differential analysis
###########################################################################

if __name__ == "__main__":
    pass
#    # from report over two rounds including initial whitening
#    INPUT_DIFF  = bytes([0x06]*2 + [0x00] * 14 )
#    OUTPUT_DIFF = bytes([0x08]*2 + [0x00] * 2+[0x08]+[0x00] * 3+[0x08]+[0x00] * 3+[0x08]+[0x00] * 3)
#
#    NUM_KEYS    = 20
#    NUM_SAMPLES = 100000000        # adjust for accuracy / runtime
#
#    total_hits  = 0
#    total_tests = 0
#
#    for _ in range(NUM_KEYS):
#        #key = (0).to_bytes(32, "big")       # 256-bit key
#        key = os.urandom(32)               # 256-bit key
#        scheduler = KeyScheduler(key)
#        round_keys = scheduler.expand()
#
#        # For 2 rounds we need whitening (rk0) plus two middle rounds (rk1, rk2).
#        # round_keys[:4] makes round_keys[1:-1] contain exactly [rk1, rk2].
#        rk0, rk1, rk2 = round_keys[0], round_keys[1], round_keys[2]
#
#        local_hits = 0
#
#        for _ in range(NUM_SAMPLES):            
#            p1 = os.urandom(16)
#            p2 = xor_bytes(p1, INPUT_DIFF)
#
#            # --- whitening ---
#            s1 = xor_bytes(p1, rk0) ; s1= S(s1);  s1 = L(s1)
#            s2 = xor_bytes(p2, rk0) ; s2= S(s2);  s2 = L(s2)
#
#            # --- round 1 ---
#            s1 = S(s1);  s1 = L(s1);  s1 = add128(s1, rk1)
#            s2 = S(s2);  s2 = L(s2);  s2 = add128(s2, rk1)
#
#            # --- round 2 ---
#            s1 = S(s1);  s1 = L(s1);  s1 = add128(s1, rk2)
#            s2 = S(s2);  s2 = L(s2);  s2 = add128(s2, rk2)
#
#            if xor_bytes(s1, s2) == OUTPUT_DIFF:
#                local_hits += 1
#            total_tests += 1
#
#        result = local_hits / NUM_SAMPLES
#        total_hits += local_hits
#        
#        print("Key:", key.hex())
#        print("Pairs tested :", NUM_SAMPLES)
#        print("Hits         :", local_hits)
#        print("Probability  :", result)
#        if result > 0:
#            print("Weight (log2):", log2(result))
#        else:
#            print("Weight       : -inf")
#
#    result = total_hits / total_tests
#    print("Pairs tested :", total_tests)
#    print("Hits         :", total_hits)
#    print("Probability  :", result)
#    if result > 0:
#        print("Weight (log2):", log2(result))
#    else:
#        print("Weight       : -inf")