# Chapter 3 – Differential Attack on 7- and 8-Round Serpent (Detailed Summary)

This summary closely follows Chapter 3 of the paper while compressing repetitive discussion. It is intended to contain enough technical detail that, given a correct Serpent implementation, the attack can be implemented.

## Scope

The attacks target reduced-round Serpent covering rounds 4–10 (7 rounds) and rounds 4–11 (8 rounds). The authors retain the original Serpent round numbering rather than renumbering the reduced cipher.

The attack relies on the 6-round differential characteristic from Appendix D:

- Rounds: 4–9
- Probability: 2^-93
- 2^14 equivalent characteristics exist.
- All characteristics share exactly the same output difference.
- They differ only in the first round, where different input differences lead to the same state after round 4.
- Every characteristic has identical probability.

This property allows many possible plaintext differences to be tested simultaneously.

## Differential Characteristics

The attack uses:

- 13 active S-boxes in the first round.
- 19 inactive S-boxes in the first round.
- After six rounds the output difference activates only 19 S-boxes in the last attacked round.

Because only the first round differs between the 2^14 characteristics, all later-round processing is identical.

## Chosen-Plaintext Structures

Generate 2^32 structures.

Each structure contains 2^52 chosen plaintexts.

Construction:

- Fix the inputs of the 19 inactive S-boxes in the first attacked round.
- Enumerate all 52 input bits entering the 13 active S-boxes.

Thus every possible input difference required by every one of the 2^14 characteristics occurs inside each structure.

Each structure contains:

- 2^51 plaintext pairs for every possible characteristic.

Across all structures:

- 2^83 candidate pairs per characteristic.

Expected right pairs:

2^83 × 2^14 × 2^-93 = 2^4 = 16 right pairs.

## Ciphertext Filtering

Initially each structure contains approximately

2^103

pairs.

The expected characteristic activates only 19 S-boxes in the final attacked round.

Therefore:

- Any pair having non-zero difference inside any of the remaining 13 S-boxes is discarded.

Only

2^51

pairs remain.

### Differential-output filtering

The remaining active S-boxes cannot produce arbitrary differences.

Allowed output differences:

- 3 S-boxes: only 4 differences
- 6 S-boxes: only 6 differences
- 9 S-boxes: only 7 differences
- 1 S-box: 8 differences

This rejects another factor

(4/16)^3 (6/16)^6 (7/16)^9 (8/16) ≈ 2^-26.22

leaving

2^24.78

pairs per structure.

### Characteristic lookup

The remaining pairs are checked against the 2^14 legal plaintext differences.

Since approximately 2^52 differences exist overall, only

2^-38

survive.

Across all structures this leaves

2^18.78

candidate pairs.

## Recovering the Last-Round Subkey

For every surviving pair:

- Analyse the 19 active S-boxes in the final attacked round.
- Each active S-box suggests at most four possible subkey values.

If counting over m active S-boxes:

candidate hits ≤ 2^(18.78+2m)

For incorrect keys the expected counter value is

2^(18.78+2m)/2^(4m),

which falls below one once m ≥ 10.

The correct key is suggested by every right pair (~16 times), making it stand out clearly.

The attack therefore:

1. Count over any 10 active S-boxes.
2. Keep only subkeys receiving many hits.
3. Complete the remaining 9 S-boxes using only surviving pairs.

The attack recovers:

- 76 bits from the last attacked round.

## Recovering the First-Round Subkey

Exactly the same right pairs reveal information about the first attacked round.

An additional

52 subkey bits

are obtained.

Therefore:

76 + 52 = 128 recovered subkey bits.

For the 128-bit version these determine the master key by solving the linear key schedule equations.

## Extension to Longer Keys

192-bit and 256-bit keys require additional information.

The authors reuse the same characteristics rotated:

- one bit left
- two bits left

Rotation by three bits no longer yields useful characteristics.

The rotated attacks recover:

- 36 extra bits from round 4
- 32 extra bits from round 10

giving another 68 bits.

This suffices for 192-bit keys.

For 256-bit keys, another family of equivalent probability-2^-94 characteristics recovers the remaining unknown bits.

## Efficient Implementation

Rather than comparing all ciphertext pairs directly:

For each structure:

1. Hash ciphertexts using the 52 ciphertext bits belonging to inactive last-round S-boxes.
2. Every collision corresponds to a possible pair.
3. Check whether the plaintext difference equals one of the 2^14 characteristic inputs.
4. Verify whether the observed 76 output bits are compatible with the characteristic output.
5. Update counters indexed by 40 guessed subkey bits (10 active S-boxes).

After all structures:

- Keep counters with at least 10 hits.
- Complete remaining round-10 subkey bits.
- Recover round-4 subkey bits by intersecting candidate sets from all surviving right pairs.

## Complexity

### 7-round attack

Data:

- 2^84 chosen plaintexts

Time:

- approximately 2^85 memory accesses

Memory:

- 2^40 four-bit counters
- hash table with 2^52 entries

Expected right pairs:

- approximately 16

### 8-round (256-bit)

Guess the entire round-11 subkey.

For every candidate:

- decrypt one round,
- perform the 7-round attack.

Complexities:

Data:

- 2^84 chosen plaintexts

Time:

- 2^128 × 2^85 = 2^213 memory accesses

Memory:

- 2^40 counters

The key observation is that guessing the last-round subkey removes the need for the additional rotated differential attacks otherwise required to reconstruct the full 256-bit key.
