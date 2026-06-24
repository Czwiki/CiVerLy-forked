2 The Cipher
Serpent is a 32-round SP-network operating on four 32-bit words, thus giving
a block size of 128 bits. All values used in the cipher are represented as bit-
streams. The indices of the bits are counted from 0 to bit 31 in one 32-bit
word, 0 to bit 127 in 128-bit blocks, 0 to bit 255 in 256-bit keys, and so on.
For internal computation, all values are represented in little-endian, where the
first word (word 0) is the least significant word, and the last word is the most
significant, and where bit 0 is the least significant bit of word 0. Externally, we
write each block as a plain 128-bit hex number.
Serpent encrypts a 128-bit plaintext P to a 128-bit ciphertext C in 32 rounds
ˆ
ˆ
under the control of 33 128-bit subkeys
K0,...,
K32. The user key length is
variable, but for the purposes of this submission we fix it at 128, 192 or 256
bits; short keys with less than 256 bits are mapped to full-length keys of 256
bits by appending one “1” bit to the MSB end, followed by as many “0” bits
as required to make up 256 bits. This mapping is designed to map every short
key to a full-length key, with no two short keys being equivalent. (We do not
propose, for example, the use of 40-bit keys, but if they are required in some
applications, then our padding method can cope with them.) There are no other
restrictions on the keyspace.
The cipher itself consists of:
– an initial permutation IP;
2
– 32 rounds, each consisting of a key mixing operation, a pass through S-boxes,
and (in all but the last round) a linear transformation. In the last round,
this linear transformation is replaced by an additional key mixing operation;
– a final permutation FP.
The initial and final permutations do not have any cryptographic significance.
They are used to simplify an optimized implementation of the cipher, which
is described in the next section, and to improve its computational eﬃciency.
Both these two permutations and the linear transformation are specified in the
appendix; their design principles will be made clear in the next section.
We use the following notation. The initial permutation IP is applied to the
ˆ
plaintext P giving
B0, which is the input to the first round. The rounds are
numbered from 0 to 31, where the first round is round 0 and the last is round 31.
ˆ
The output of the first round (round 0) is
B1, the output of the second round
ˆ
ˆ
(round 1) is
B2, the output of round iis
Bi+1, and so on, until the output of the
last round (in which the linear transformation is replaced by an additional key
ˆ
mixing) is denoted by
B32. The final permutation FP is now applied to give the
ciphertext C.
Each round function Ri (i∈{0,...,31}uses only a single replicated S-box.
For example, R0 uses S0, 32 copies of which are applied in parallel. Thus the first
ˆ
copy of S0 takes bits 0, 1, 2 and 3 of
B0 ⊕ˆ
K0 as its input and returns as output
the first four bits of an intermediate vector; the next copy of S0 inputs bits 4–7 of
ˆ
B0 ⊕ˆ
K0 and returns the next four bits of the intermediate vector, and so on. The
intermediate vector is then transformed using the linear transformation, giving
ˆ
ˆ
B1. Similarly, R1 uses 32 copies of S1 in parallel on
B1 ⊕ˆ
K1 and transforms
ˆ
their output using the linear transformation, giving
B2.
The set of eight S-boxes is used four times. Thus after using S7 in round 7,
we use S0 again in round 8, then S1 in round 9, and so on. The last round R31
ˆ
is slightly diﬀerent from the others: we apply S7 on
B31 ⊕ˆ
K31, and XOR the
ˆ
ˆ
result with
K32 rather than applying the linear transformation. The result
B32
is then permuted by FP, giving the ciphertext.
Thus the 32 rounds use 8 diﬀerent S-boxes each of which maps four input
bits to four output bits. Each S-box is used in precisely four rounds, and in each
of these it is used 32 times in parallel. The S-box design is discussed below.
As with DES, the final permutation is the inverse of the initial permutation.
Thus the cipher may be formally described by the following equations:
where
ˆ
B0 := IP(P)
ˆ
ˆ
Bi+1 := Ri(
Bi)
ˆ
C := FP(
B32)
ˆ
Ri(X) = L(
Si(X⊕ˆ
Ki)) i= 0,...,30
ˆ
Ri(X) =
Si(X⊕ˆ
Ki) ⊕ˆ
K32 i= 31
3
ˆ
where
Si is the application of the S-box Simod 8 32 times in parallel, and L
is the linear transformation.
Although each round of the proposed cipher might seem weaker than a round
of DES, this is not the case. For example, the probability of the best six-round
characteristic of DES is about 2−20, while for Serpent the corresponding figure
is less than 2−58. 16-round Serpent would be as secure as triple-DES, and twice
as fast as DES. However, AES may persist for 25 years as a standard and a
further 25 years in legacy systems, and will have to withstand advances in both
engineering and cryptanalysis during that time. We therefore propose 32 rounds
to put the algorithm’s security beyond question. This gives us a cipher that is
about as fast as DES but very more secure than 3DES.
2.1 The S-boxes
The S-boxes of Serpent are 4-bit permutations with the following properties:
– each diﬀerential characteristic has a probability of at most 1/4, and a one-bit
input diﬀerence will never lead to a one-bit output diﬀerence;
– each linear characteristic has a probability in the range 1/2 ±1/4, and a
linear relation between one single bit in the input and one single bit in the
output has a probability in the range 1/2 ±1/8;
– the nonlinear order of the output bits as a function of the input bits is the
maximum, namely 3.
The S-boxes were generated in the following manner, which was inspired by
RC4. We used a matrix with 32 arrays each with 16 entries. The matrix was
initialised with the 32 rows of the DES S-boxes and transformed by swapping
the entries in the rth array depending on the value of the entries in the (r+ 1)st
array and on an initial string representing a key. If the resulting array has the
desired (diﬀerential and linear) properties, save the array as a Serpent S-box.
Repeat the procedure until 8 S-boxes have been generated.
More formally, let serpent[·] be an array containing the least significant four
bits of each of the 16 ASCII characters in the expression “sboxesforserpent”.
Let sbox[·][·] be a (32 ×16)-array containing the 32 rows of the 8 DES S-
boxes, where sbox[r][·] denotes the rth row. The function swapentries(·
,·) is
self-explanatory. The following pseudo-code generates the Serpent S-boxes.
index := 0
repeat
currentsbox := index modulo 32;
for i:=0 to 15 do
j := sbox[(currentsbox+1) modulo 32][serpent[i]];
swapentries (sbox[currentsbox][i],sbox[currentsbox][j]);
if sbox[currentsbox][.] has the desired properties, save it;
index := index + 1;
until 8 S-boxes have been generated
4
In Serpent-0, we used the DES S-boxes in order to inspire a high level of public
confidence that we had not inserted any trapdoor in them. A similar assurance
for Serpent-1 comes from the fact that the S-boxes have been generated in this
simple deterministic manner.
2.2 Decryption
Decryption is diﬀerent from encryption in that the inverse of the S-boxes must
be used in the reverse order, as well as the inverse linear transformation and
reverse order of the subkeys.
3 An Eﬃcient Implementation
Much of the motivation for the above design will become clear as we consider
how to implement the algorithm eﬃciently. We do this in bitslice mode. For a
full description of a bitslice implementation of DES, see [6]; the basic idea is that
just as one can use a 1-bit processor to implement an algorithm such as DES
by executing a hardware description of it, using a logical instruction to emulate
each gate, so one can also use a 32-bit processor to compute 32 diﬀerent DES
blocks in parallel — in eﬀect, using the CPU as a 32-way SIMD machine.
This is much more eﬃcient than the conventional implementation, in which
a 32-bit processor is mostly idle as it computes operations on 6 bits, 4 bits, or
even single bits. The bitslice approach was used in the recent successful DES
key search [28], in which spare CPU cycles from thousands of machines were
volunteered to solve a challenge cryptogram. However the problem with using
bitslice techniques for DES encryption (as opposed to keysearch) is that one has
to process many blocks in parallel, and although special modes of operation can
be designed for this, they are not the modes in common use.
Our cipher has therefore been designed so that all operations can be executed
using 32-fold parallelism during the encryption or decryption of a single block.
Indeed the bitslice description of the algorithm is much simpler than its con-
ventional description. No initial and final permutations are required, since the
initial and final permutations described in the standard implementation above
are just those needed to convert the data from and to the bitslice representa-
tion. We will now present an equivalent description of the algorithm for bitslice
implementation.
The cipher consists simply of 32 rounds. The plaintext becomes the first
intermediate data B0 = P, after which the 32 rounds are applied, where each
round i∈{0,...,31}consists of three operations:
1. Key Mixing: At each round, a 128-bit subkey Ki is exclusive or’ed with the
current intermediate data Bi
2. S-Boxes: The 128-bit combination of input and key is considered as four
32-bit words. The S-box, which is implemented as a sequence of logical op-
erations (as it would be in hardware) is applied to these four words, and the
5
result is four output words. The CPU is thus employed to execute the 32
copies of the S-box simultaneously, resulting with Si(Bi ⊕Ki)
3. Linear Transformation: The 32 bits in each of the output words are linearly
mixed, by
X0,X1,X2,X3 := Si(Bi ⊕Ki)
X0 := X0 <<<13
X2 := X2 <<<3
X1 := X1 ⊕X0 ⊕X2
X3 := X3 ⊕X2 ⊕(X0 <<3)
X1 := X1 <<<1
X3 := X3 <<<7
X0 := X0 ⊕X1 ⊕X3
X2 := X2 ⊕X3 ⊕(X1 <<7)
X0 := X0 <<<5
X2 := X2 <<<22
Bi+1 := X0,X1,X2,X3
where <<<denotes rotation, and <<denotes shift. In the last round, this linear
transformation is replaced by an additional key mixing: B32 := S7(B31 ⊕K31)⊕
ˆ
ˆ
K32. Note that at each stage IP(Bi) =
Bi, and IP(Ki) =
Ki.
The first reason for the choice of linear transformation is to maximize the
avalanche eﬀect. The S-boxes have the property that a single input bit change
will cause two output bits to change; as the diﬀerence sets of {0, 1, 3, 5, 7, 13,
22}modulo 32 have no common member (except one), it follows that a single
input bit change will cause a maximal number of bit changes after two and more
rounds. The eﬀect is that each plaintext bit aﬀects all the data bits after three
rounds, as does each round key bit. Even if an opponent chooses some subkeys
and works backwards, it is still guaranteed that each key bit aﬀects each data
bit over six rounds. (Some historical information on the design of the linear
transformation is given in the appendix.)
The second reason is that it is simple, and can be used in a modern processor
with a minimum number of pipeline stalls. The third reason is that it was an-
alyzed by programs we developed for investigating block ciphers, and we found
bounds on the probabilities of the diﬀerential and linear characteristics. These
bounds show that this choice suits our needs.
4 The Key Schedule
As with the description of the cipher, we can describe the key schedule in either
standard or bitslice mode. We will give the substantive description for the latter
case.
6
Our cipher requires 132 32-bit words of key material. We first pad the user
supplied key to 256 bits, if necessary, as described in section 2. We then expand
it to 33 128-bit subkeys K0, . . . , K32, in the following way. We write the key K
as eight 32-bit words w−8, . . . , w−1 and expand these to an intermediate key
(which we call prekey) w0, . . . , w131 by the following aﬃne recurrence:
wi := (wi−8 ⊕wi−5 ⊕wi−3 ⊕wi−1 ⊕φ⊕i) <<<11
where φ is the fractional part of the golden ratio (√5 + 1)/2 or 0x9e3779b9
in hexadecimal. The underlying polynomial x8 + x7 + x5 + x3 + 1 is primitive,
which together with the addition of the round index is chosen to ensure an even
distribution of key bits throughout the rounds, and to eliminate weak keys and
related keys.
The round keys are now calculated from the prekeys using the S-boxes, again
in bitslice mode. We use the S-boxes to transform the prekeys wi into words ki
of round key in the following way:
{k0,k1,k2,k3}:= S3(w0,w1,w2,w3)
{k4,k5,k6,k7}:= S2(w4,w5,w6,w7)
{k8,k9,k10,k11}:= S1(w8,w9,w10,w11)
{k12,k13,k14,k15}:= S0(w12,w13,w14,w15)
{k16,k17,k18,k19}:= S7(w16,w17,w18,w19)
...
{k124,k125,k126,k127}:= S4(w124,w125,w126,w127)
{k128,k129,k130,k131}:= S3(w128,w129,w130,w131)
We then renumber the 32-bit values kj as 128-bit subkeys Ki (for i ∈{0, . . . ,
r}) as follows:
Ki := {k4i,k4i+1,k4i+2,k4i+3} (1)
Where we are implementing the algorithm in the form initially described in
section 2 above rather than using bitslice operations, we now apply IP to the
ˆ
round key in order to place the key bits in the correct column, i.e.,
Ki = IP(Ki).