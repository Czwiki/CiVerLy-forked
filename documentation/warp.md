2 Specification
WARP is a 128-bit block cipher with a 128-bit key. The general structure of
WARP is a variant of the 32-branch Type-2 GFN. A 128-bit plaintext M and
a ciphertext C are loaded into a 128-bit internal state in encryption and de-
cryption processes, respectively. The internal state is expressed as 32 nibbles,
X= X0 ∥X1 ∥... ∥X31, where Xi ∈{0,1}4. A 128-bit secret key K is denoted
as two 64-bit keys K0 and K1, i.e. K= K0||K1, where Ki ∈{0,1}64
. K0 and K1
are also expressed as 16 nibbles, K0 = K0
0 ∥K0
1 ∥... ∥K0
15, where K0
i ∈{0,1}4
,
and K1 = K1
0 ∥K1
1 ∥... ∥K1
15, where K1
i ∈{0,1}4, respectively.
Round Function. The round function of WARP consists of a 4-bit S-box S :
{0,1}4 →{0,1}4, a nibble XOR : {0,1}4 ×{0,1}4 →{0,1}4, and a shuﬄe
operation π: {0,...,31}→{0,...,31}applied to 32 nibbles. The round function
applies a non-linear unit transformation involving a single S evaluation and
round-key addition for each of two consecutive nibbles, adds a round constant,
and applies π to all 32 nibbles. See Fig. 1. The S-box S is described in Table 1.
The shuﬄe π and its inverse π−1 are described in Table 2.
Encryption and Decryption. The number of rounds of WARP is 41, where the
nibble shuﬄe operation π in the last round is omitted. For i= 1,...,41, the i-th
round uses a 64-bit (16 nibbles) round key RKi. Then, an i-th round key RKi
is given as RKi = K(i−1) mod 2
.
The encryption algorithm of WARP is given in Fig. 2. The decryption algorithm
is omitted here. It is obtained by just changing π to its inverse π−1
.
WARP uses LFSR-based round constants. A state of 6-bit LFSR is written as
(ℓ5,ℓ4,ℓ3,ℓ2,ℓ1,ℓ0) and is initialized to 000001. It is updated in each round as
(ℓ5,ℓ4,ℓ3,ℓ2,ℓ1,ℓ0) ←(ℓ4,ℓ3,ℓ2,ℓ1,ℓ0,ℓ0 ⊕ℓ5).
Using this LFSR, we define two nibbles RC0 = (ℓ5,ℓ4,ℓ3,ℓ2) and RC1 =
(ℓ1,ℓ0,0,0). RC0 and RC1 are xored to the first and third nibbles of the state
(note that the numbering of the nibbles is from 0 to 31) after the X2i+1 ←
S(X2i) ⊕K(r−1) mod 2
i ⊕X2i+1 operation. Let RCr
0 and RCr
1 be the r-th round
constants. For completeness, we list (RCr
0 ,RCr
1 ) for all r= 1,...,41 in Table 3.
Claimed Security. WARP claims single-key security, and does not claim any security
in related-key and known/chosen-key settings.
