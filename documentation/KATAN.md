Following the design of KeeLoq [17], we decided to adopt a cipher whose structure re-
sembles a stream cipher. To this extent we have chosen a structure which resembles
trivium [6], or more precisely, its two register variant bivium as the base for the block
cipher. While the internal state of trivium was 288 bits to overcome the fact that each
round, one bit of internal state is revealed, in the block cipher this extra security measure
is unnecessary. Hence, we select the block size and the internal state of the cipher to be
equal.
The structure of the KATAN and the KTANTAN ciphers is very simple — the plain-
text is loaded into two registers (whose lengths depend on the block size). Each round,
several bits are taken from the registers and enter two nonlinear Boolean functions. The
output of the Boolean functions is loaded to the least significant bits of the registers (after
4
they were shifted). Of course, this is done in an invertible manner. To ensure sufficient
mixing, 254 rounds of the cipher are executed.
We have devised several mechanisms used to ensure the security of the cipher, while
maintaining a small foot print. The first one is the use of an LFSR instead of a counter
for counting the rounds and to stop the encryption after 254 rounds. As there are 254
rounds, an 8-bit LFSR with as sparse polynomial feedback can be used. The LFSR is
initialized with some state, and the cipher has to stop running the moment the LFSR
arrives to some predetermined state.
We have implemented the 8-bit LFSR counter, and the result fits a gate equivalent of
60 gates, while using an 8-bit counter (the standard alternative) took 80 gate equivalents.
Moreover, the expected speed of the LFSR (i.e. the critical path) is shorter than the one
for the 8-bit counter.
Another advantage for using LFSR is the fact that when considering one of the bits
taken from it, we expect a sequence which keeps on alternating between 0’s and 1’s in
a more irregular manner than in a counter (of course the change is linear). We use this
feature to enhance the security of our block ciphers as we describe later.
One of the problems that may arise in such a simple construction is related to self-
similarity attacks such as the slide attacks. For example, in KeeLoq [17] the key is used
again and again. This made KeeLoq susceptible to several slide attacks (see for exam-
ple [5, 13]). A simple solution to the problem is to have the key loaded into an LFSR
with a primitive feedback polynomial (thus, altering the subkeys used in the cipher).
This solution helps the KATAN family to achieve security against the slide attack.
While the above building block is suitable when the key is loaded into memory, in the
KTANTAN family, it is less favorable (as the key is hardcoded in the device). Thus, the
only means to prevent a slide attack is by generating a simple, non-repetitive sequence
of bits from the key. To do so, we use the “round counter” LFSR, which produces easily
computed bits, that at the same time follow a non-repetitive sequence.
The third building block which we use prevents the self-similarity attacks and in-
creases the diffusion of the cipher. The cipher actually has two (very similar but distinct)
round functions. The choice of the round function is made according to the most signifi-
cant bit of the round-counting LFSR. This irregular update also increases the diffusion of
the cipher, as the nonlinear update affects both the differential and the linear properties
of the cipher.
Finally, both KATAN and KTANTAN were constructed such that an implementation
of the 64-bit variants can support the 32-bit and the 48-bit variants at the cost of small
extra controlling hardware. Moreover, given the fact that the only difference between
a KATANn cipher and KTANTANn is the way the key is stored and the subkeys are
derived, it is possible to design a very compact circuit that support all six ciphers.

The KATAN ciphers compose of three variants: KATAN32, KATAN48 and KATAN64.
All the ciphers in the KATAN family share the key schedule which accepts an 80-bit key
and 254 rounds as well as the use of the same nonlinear functions.
We start by describing KATAN32, and describe the differences for KATAN48 and
KATAN64 later. KATAN32, the smallest of this family has a plaintext and ciphertext
size of 32 bits. The plaintext is loaded into two registers L1, and L2 (of respective lengths
of 13 and 19 bits) where the least significant bit of the plaintext is loaded to bit 0 of L2,
while the most significant bit of the plaintext is loaded to bit 12 of L1. Each round, L1
and L2 are shifted to the left (bit i is shifted to position i + 1), where the new computed
5
bits are loaded in the least significant bits of L1 and L2. After 254 rounds of the cipher,
the contents of the registers are then exported as the ciphertext (where bit 0 of L2 is the
least significant of the ciphertext).
KATAN32 uses two nonlinear function fa(·) and fb(·) in each round. The nonlinear
function fa and fb are defined as follows:
fa(L1) = L1[x1] ⊕ L1[x2] ⊕ (L1[x3] · L1[x4]) ⊕ (L1[x5] · IR) ⊕ ka
fb(L2) = L2[y1] ⊕ L2[y2] ⊕ (L2[y3] · L2[y4]) ⊕ (L2[y5] · L2[y6]) ⊕ kb
where IR is irregular update rule (i.e., L1[x5] is XORed in the rounds where the irregular
update is used), and ka and kb are the two subkey bits. For round i, ka is defined to
be k2i, whereas kb is k2i+1. The selection of the bits {xi} and {yj } are defined for each
variant independently, and listed in Table 2.
After the computation of the nonlinear functions, the registers L1 and L2 are shifted,
where the MSB falls off (into the corresponding nonlinear function), and the LSB is
loaded with the output of the second nonlinear function, i.e., after the round the LSB of
L1 is the output of fb, and the LSB of L2 is the output of fa.
The key schedule of the KATAN32 cipher (and the other two variants KATAN48
and KATAN64) loads the 80-bit key into an LFSR (the least significant bit of the key
is loaded to position 0 of the LFSR). Each round, positions 0 and 1 of the LFSR are
generated as the round’s subkey k2i and k2i+1, and the LFSR is clocked twice. The
feedback polynomial that was chosen is a primitive polynomial with minimal hamming
weight of 5 (there are no primitive polynomials of degree 80 with only 3 monomials):
x80 + x61 + x50 + x13 + 1.
We note that these locations compose a full difference set, and thus, are less likely to
lead to a guess and determine attacks faster than exhaustive key search.
In other words, let the key be K, then the subkey of round i is ka||kb = k2·i||k2·i+1
where
ki =
{ Ki for i = 0 . . . 79
ki−80 ⊕ ki−61 ⊕ ki−50 ⊕ ki−13 Otherwise
The differences between the various KATAN ciphers are:
– The plaintext/ciphertext size,
– The lengths of L1 and L2,
– The position of the bits which enter the nonlinear functions,
– The number of times the nonlinear functions are used in each round.
While the first difference is obvious, we define in Table 2 the lengths of the registers and
the positions of the bits which enter the nonlinear functions used in the ciphers. The
selection of the bits {xi} and {yj } are defined for each variant independently, and are
listed in Table 2.
For KATAN48, in one round of the cipher the functions fa and fb are applied twice.
The first pair of fa and fb is applied, and then after the update of the registers, they
are applied again, using the same subkeys. Of course, an efficient implementation can
implement these two steps in parallel. In KATAN64, each round applies fa and fb three
times (again, with the same key bits).
We outline the structure of KATAN32 (which is similar to the round function of any
of the KATAN variants or the KTANTAN variants) in Figure 1.
Finally, specification-wise, we define the counter which counts the number of rounds.
The round-counter LFSR is initialized to the all 1’s state, and clocked once using the
6
Cipher |L1| |L2| x1 x2 x3 x4 x5
KATAN32/KTANTAN32 13 19 12 7 8 5 3
KATAN48/KTANTAN48 19 29 18 12 15 7 6
KATAN64/KTANTAN64 25 39 24 15 20 11 9
Cipher y1 y2 y3 y4 y5 y6
KATAN32/KTANTAN32 18 7 12 10 8 3
KATAN48/KTANTAN48 28 19 21 13 15 6
KATAN64/KTANTAN64 38 25 33 21 14 9
Table 2. Parameters defined for the KATAN family of ciphers
L2
←−−−
L1
−−−→
?L
?L? -∧-
?-IR ∧ - ?L -  ka
?
6
L
6
L
6
 ∧  6
∧
6
L
-kb
6
Fig. 1. The Outline of a round of the KATAN/KTANTAN ciphers
feedback polynomial x8 + x7 + x5 + x3 + 1. Then, the encryption process starts, and ends
after 254 additional clocks when the LFSR returns to the all 1’s state. As mentioned
earlier, we use the most significant bit of the LFSR to control the irregular update (i.e.,
as the IR signal). For sake of completeness, in Table 3 in the Appendix we give the
sequence of irregular rounds.
We note that due to the way the irregular update rule is chosen, there are no sequences
of more than 7 rounds that share the pattern of the regular/irregular updates, this ensures
that any self-similarity attack cannot utilize more than 7 rounds of the same function
(even if the attacker chooses keys that suggest the same subkeys). Thus, it is easy to see
that such attacks are expected to fail when applied to the KATAN family.
We implemented KATAN32 using Synopsys Design Compiler version Y-2006.06 and
the fsc0l d sc tc 0.13μm CMOS library. Our implementation requires 802 GE, of which
742 are used for the sequential logic, and 60 GE are used for the combinational logic.
The power consumption at 100 KHz, and throughput of 12.5 Kbps is only 381 nW. This
is a gate level power estimation obtained using Synopsys Design Compiler3.
For KATAN48 the implementation size is 927 GE (of which 842 are for the sequential
logic) and the total power consumption is estimated to 439 nW. For the 64-bit variant,
KATAN64, the total area is 1054 GE (of which 935 are for the sequential logic) and the
power consumption 555 nW.
Here we would like to note that the further area reduction for KATAN48 and KATAN64
is possible by utilizing a clock gating technique. As explained above, the only difference
3 Although the gate level power estimation gives a rough estimate, it is useful for comparison
with related work reported in the literature.
7
between KATAN32 on one hand and KATAN48 and KATAN64 on the other, is the
number of nonlinear functions fa and fb applied with the same subkeys per single round.
Therefore, we can clock the key register and the counter such that they are updated once
in every two (three) cycles for KATAN48 (KATAN64). However, this approach reduces
the throughput two (three) times respectively, and is useful only when the compact im-
plementation is an ultimate goal. An area of 916 GE with the throughput of 9.4 Kb/s
(at 100 KHz) is obtained for KATAN48 and 1027 GE with the throughput of 8.4 Kb/s
(at 100 KHz) for KATAN64.
At the cost of little hardware overhead, a throughput of the KATAN family of block
ciphers can be doubled or even tripled. To increase the speed of the cipher, we double
(triple) the logic for the nonlinear functions fa and fb as well as the logic for the feedback
coefficients of the counter and the key register. The implementation results are given in
Appendix B

Reference implementation
------------------------
A C reference implementation was used to validate the CiVerLy implementation and
to generate test vectors. The original reference code is available from Orr Dunkelman
(Technion) at http://www.cs.technion.ac.il/~orrd/KATAN/katan.c and a public fork
was taken from https://gist.github.com/raullenchai/2712516. A copy of the
reference C code is included in this repository at documentation/reference_implementation_katan.c.

Please consult the original sources for licensing and attribution details.