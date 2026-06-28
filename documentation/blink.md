5 Instantiation: Blink
In this section, we instantiate the THF mode by proposing a concrete tweakable block
cipher family named Blink. The Blink family supports multiple configurations, including
block sizes of 64 and 128 bits, and tweak lengths equal to one or two times the block size.
For simplicity, in the following discussion we denote the block size by n and assume that
the length of tweak t is fixed to τ .
14 THF: Designing Low-Latency Tweakable Block Ciphers
Table 1: Comparison of three constructions across security and performance aspects.
Metric ETHF E4-LRW1 E2-LRW2
MT differential analysis – ↓ –
MT linear analysis D ↓ ↑
MT algebraic attack D ↓ ↑
#Rounds requirement a+b+c+d ≥ rS ˜a+˜b+˜c+ ˜d > rS ˆb+ˆc = rS
b, c ≥ rC ˜a, ˜b, ˜c, ˜d ≥ rC ˆb, ˆc ≥ rC
Encryption latency ≥ rS ·T (R)+∆a > rS · T (R) rS ·T (R)+T (h1)
Decryption latency ≥ rS ·T (R)+∆d > rS · T (R) rS ·T (R)+T (h2)
Legend: ↓: MT security is typically weaker than ST; ↑: stronger; –: secure in this setting;
D: the security depends on the property of hash functions.
∆a = max{0, T (h1) − a · T (R)}, ∆d = max{0, T (h2) − d · T (R)}.
5.1 The Construction
Blink’s overall structure is illustrated in Figure 2. While based on the THF construction,
Blink introduces several modifications compared to the instantiation ETHF in Section 4,
to better support hardware efficiency. In particular, Blink adopts a reflector construc-
tion [BCG+12], which reduces the hardware footprint by exploiting structural symmetry.
We next explain the notations used in Figure 2.
Each round function consists of five operations: an S-box layer (S), a MixColumn layer
(M), round key addition (AK), round constant addition (AC), and a shuffle layer (P). The
round function is:
R = P ◦ AC ◦ AK ◦ M ◦ S.
We denote MKk(x) = M(x) ⊕ k, and̂ z = M(z). Inverses are marked with overlines, e.g., P.
Since S and M are involutive, the inverse of round function is thus:
R = S ◦ MK ˆrk⊕ ˆrc ◦ P.
This shows that the structure depicted in Figure 2 supports a reflection property.
Blink corresponds to the four permutations in THF as:
• π1: M ◦ S ◦ Ra(• ⊕ w1),
• π2: M ◦ S ◦ Rb ◦ P,
• π3: P ◦ Rb ◦ S,
• π4: Ra ◦ S ◦ M(•) ⊕ w2.m
w1
S MK P
rk1 ⊕ rc1
· · · S MK P
rka ⊕ rca
S MK P
h1(t)
S MK P
rka+1 ⊕ rca+1
· · · S MK P
rka+b ⊕ rca+b
S
MK h(t)
SS MK P
drk1 ⊕ d
rc′
1
· · ·S MK P
drkb ⊕ d
rc′
b
S MK P
dh2(t)
S MK P
drkb+1 ⊕ d
rc′
b+1
· · ·S MK P
drka+b ⊕ d
rc′
a+b
w2
c
Figure 2: The overview of Blink
Jianhua Wang, Tao Huang, Guang Zeng, Tianyou Ding, Shuang Wu and Siwei Sun 15
5.2 The Round Function
The internal state of Blink is organized as a two-dimensional array, consisting of 4 rows
and n/16 columns, where each cell represents a nibble (4 bits). The state sn/4−1∥ · · · ∥s1
∥s0 can be visualized as follows:




s0 s1 · · · sn/16−1
sn/16 sn/16+1 · · · sn/8−1
sn/8 sn/8+1 · · · s3n/16−1
s3n/16 s3n/16+1 · · · sn/4−1



 ,
Each operation in round function R updates internal states as follows.
- S: The 4-bit S-box S is applied to each cell in parallel. Its specification in hex-
adecimal is shown in the following table. Additionally, the S-box is an involution,
meaning that its inverse is equal to itself.
x 0 1 2 3 4 5 6 7 8 9 a b c d e f
S(x) 1 0 9 3 8 5 e 7 4 2 c b a f 6 d
- M: A diffusion matrix M is multiplied to each column. Namely,
[sj , sj+n/16, sj+n/8, sj+3n/16
]T ← M [sj , sj+n/16, sj+n/8, sj+3n/16
]T ,
where 0 ≤ j < n/16, and M is the involutory matrix in Midori:
M =




0 1 1 1
1 0 1 1
1 1 0 1
1 1 1 0



 .
- AK: The round key is XORed to the state.
- AC: The round constant is XORed to the state. The specific values for the round
constants rci and rc′
i are provided in Appendix D.
- P: Each cell in the state is shuffled according to the permutation P . Namely,
[s0, s1, · · · , sn/4−1
] ← [sP [0], sP [1], · · · , sP [n/4−1]
] .
Specifically, for 64-bit block
P = [0, 5, 11, 10, 1, 6, 4, 13, 2, 12, 9, 15, 3, 7, 14, 8],
and for 128-bit block,
P = [5, 12, 4, 1, 17, 9, 10, 16, 28, 14, 21, 22, 11, 27, 8, 13,
2, 25, 18, 3, 30, 6, 19, 20, 0, 23, 24, 31, 7, 15, 29, 26].
5.3 The Hash Function
We define the map
hT : {0, 1}τ → {0, 1}n, hT (t) = T · t,
16 THF: Designing Low-Latency Tweakable Block Ciphers
where T ∈ {0, 1}n×τ and t = (t0, t1, . . . , tτ −1)⊤ ∈ {0, 1}τ . Here t0 denotes the least
significant bit of t. The hash family based on Toeplitz matrices is then defined as:
H = {hT | T is an keyed n × τ Toeplitz matrix}.
A Toeplitz matrix is a matrix in which each element on the same diagonal is identical,
meaning it is uniquely determined by the values of n + τ − 1 diagonals. Specifically, the
Toeplitz matrix T with k = (k0, k1, . . . , kn+τ −2) is defined as
T =





kn−1 kn · · · kn+τ −2
kn−2 kn−1 · · · kn+τ −3
... ... . . . ...
k0 k1 · · · kτ −1




 . (11)
In the Blink, h1 and h2 are randomly selected from the hash family H, and they
are independently determined by the (n + τ − 1)-bit keys k1 and k2, respectively. The
function h is defined as the sum of h1 and h2, i.e.,
h(t) = h1(t) ⊕ h2(t).
5.4 The Key Schedule
The master key k is the concatenation of whitening keys w1, w2, and round keys rki:
k = rka+b∥ · · · ∥rk1∥w2∥w1,
with a total length of (a + b + 2)n bits.
Let k′ be a rearrangement of k, where each bit k′
i = k11·i mod (a+b+2)n. The key k2∥k1,
used for generating the hash functions h1 and h2, is derived from the least significant
2n + 2τ − 2 bits of k′.
5.5 Security Claims
According to different security requirements, the number of rounds for each version is
summarized in Table 2. Similarly to QARMAv2 [ABD+23], we restrict the data volume per
master key to at most 256 blocks for the 64-bit variant and 280 blocks for the 128-bit
variant. This setting is consistent with existing recommendations, such as those from the
NIST call for lightweight cryptographic algorithms. We also believe that these limits are
ample for real-world applications.
In addition, we require that the tweak value t is non-zero. When t = 0, the derived
values h1(t), h2(t), and h(t) all degenerate to 0, which will significantly reduce the security
margin [CGZ25]. This constraint is trivial to satisfy in practice: one may reserve a single
bit (e.g., the MSB) to 1 and combine the remaining bits with a nonce or physical address.
When a counter is used as the tweak, counting simply starts from 1 instead of 0.
Remark. We do not claim the security of Blink against related-key attacks
