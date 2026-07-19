2 Specification of TWINE
Notations. A bitwise exclusive-OR is denoted by ⊕. For binary strings, x and
y, x‖y denotes their concatenation. Let |x| denote the bit length of x. If |x| = m,
1 In a double-block encryption. See Section 5.2.
TWINE: A Lightweight Block Cipher for Multiple Platforms 341
we may write x(m) to emphasize its bit length. If |x| = 4c for a positive integer
c, we write x → (x0‖x1‖ . . . ‖xc−1), where |xi| = 4, is the partition operation
into the 4-bit sub-blocks. The opposite operation, (x0‖x1‖ . . . ‖xc−1) → x, is
similarly defined. The partition operation may be implicit, i.e., we may simply
write xi to denote the i-th 4-bit subsequence for any 4c-bit string x.
Data Processing Part. TWINE is a 64-bit block cipher with 80 or 128-bit
key. We write TWINE-80 or TWINE-128 to denote the key length. The global
structure of TWINE is a variant of Type-2 GFS [41,45] with 16 4-bit sub-blocks.
A round function of TWINE consists of a nonlinear layer using 4-bit S-boxes
and a diffusion layer, which permutes the 16 blocks. Unlike original Type-2 GFS,
the diffusion layer is not a cyclic shift and is chosen to provide a better diffusion
than the cyclic shift from the result of [42]. This round function is iterated for 36
times for both key lengths, where the diffusion layer of the last round is omitted.
For i = 1, . . . , 36, i-th round uses a 32-bit round key, RKi, which is derived from
the secret key, K(n) with n ∈ {80, 128}, using the key schedule. The encryption
process is written as Algorithm 2.1.
The data processing part essentially consists of a 4-bit S-box, denoted by S,
and a permutation of block indexes, π : {0, . . . , 15} → {0, . . . , 15}, where j-th
sub-block is mapped to π[j]-th sub-block. The figure of the round function is in
Fig. 1. The decryption of TWINE uses the same S-box and key schedule as used
in the encryption, with the inverse block shuffle. See Algorithm 2.2.
Key Schedule Part. The key schedule produces RK(32×36) from the secret
key, K(n), for n ∈ {80, 128}. It is a variant of GFS with few S-boxes (the same
as one used at the data processing). The 80-bit key schedule uses 6-bit round
constants, CONi(6) = CONiH(3)‖CONiL(3) for i = 1 to 35, and Rotz(x) means z-
bit left cyclic shift of x. Its pseudocode is in Algorithm 2.3. For 128-bit key, see
Appendix A. We remark that CONi corresponds to 2i in GF(26) with primitive
polynomial z6 + z + 1.