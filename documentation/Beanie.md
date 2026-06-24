3 Specification
The cipher consists of a datapath and a tweak-key schedule. We display the relation
between these two building blocks in Figure 2.
T
K RC0
ϕ
K RC1
ϕ
K RC2
ϕ
K RC3
ϕ
K RC4
ϕ
K RC5
k0
k1
k2
k3
k4
k5
P
R
R
R
R
R′
C
Figure 2: Tweak-key schedule and data path of 5-round BEANIE. ϕ, R, R′are the round
functions φ, R, R′omitting the key and constant addition.
Gerhalter et al. 7
3.1 Data Path
As shown in Figure 2, the data path consists of r= 5 rounds given as R′◦R4. The round
Ri, with i= 0,...,r−2, consists of a AddRoundTweakeyi operation ARTi, a SubCells layer
SC, a ShiftRows transformation SR, and MixColumns operation MC. In the final round R′
the MC layer is omitted due to the weak impact against many attacks and an additional
whitening key is appended with an ARTr operation. In short:
Ri = MC ◦SR ◦SC ◦ARTi, R′
= ARTr ◦SR ◦SC ◦ARTr−1.
Each operation is performed on a 32 bit state. We view this state as a 4 ×2 array of
cells, each cell having the size of a nibble. The indexing of the cells (starting at 0) goes
from top to bottom and from left to right and is shown at state Xi in Figure 3. We refer
to X[i] as the nibble located in the i mod 4 row and the i
4 column. Note that if the
32-bit state is given as a concatenation of bits X = (x0,x1,...,x32), then the nibble with
the index i∈{0,1,....,7}contains the bits (x4i+0,x4i+1,x4i+2,x4i+3).
Xi Ki
0 4
Yi
Zi
0 4
Wi
0 4
2 1 1 9
Xi+1
1 4 f 1
d 9 4 1
1 d 1 2
1 5
1 5
≪1
5 1
SC
2 6
2 6
2 6
3 7
≪1
3 7
7 3
[0,4,2,b,a,c,9,8,5,f,d,3,7,1,6,e]
Figure 3: One round of BEANIE.
AddRoundTweakeyi. A 32-bit round tweak-key ki is XORed to the state. This round
tweak-key is derived from the tweak and the key by the tweak-key schedule.
SubCells. On each cell of the state we apply the S-Box S. The mapping performed by S
is shown in Figure 3 and in Table 12a in the appendix.
ShiftRows. The cells of the second and fourth row are rotated by one position to the left.
We can describe this rotation SR in terms of cell indices by
(0,1,2,...,7) SR
−→(0,5,2,7,4,1,6,3).
MixColumns. For the MixColumns operation we view the nibble of each cell as an element
in GF(24)/0x13 (the polynomial used is p(x) = x4 + x+ 1). Each column of the state
can therefore be viewed as a polynomial with a term for each row. These polynomials get
multiplied with an involuntary 4×4 MDS matrix M [JPST17a], which in hex representation
is shown in Figure 3. When multiplying a column of our state with M from the left side,
we therefore need to take the result modulo p(x).
3.2 Tweak-key Schedule (T KS)
A suitable key schedule of the cipher has to accommodate a tweak with 128 bits and
a 128-bit main key. The tweak itself includes 32 address bits, as well as other memory
related parameters mentioned in Section 2.1, while the size of the main key comes from
the cryptanalytic perspective. We realize the TKS by an alternating block cipher. This
cipher takes a 128-bit main key K and maps the 128-bit tweak T to a set of intermediate
round keys S= k0||k1||k2||k3, where ki are 32-bit blocks.
8 BEANIE – A 32-bit Cipher
0 4 8 12
0 4 8 12
0 4 8 12
1 5 9 13
M′
2 6 10 14
SCT′
≪1
1 5 9 13
9 13 17 21
≪2
≪3
2 6 10 14
18 22 26 30
3 7 16 20 11 24 15
28
3 7 11 15
16 20 24 28
SRMT
27 16 31 20 3 7
24 28
17 21 25 29
M′
18 22 26 30
SCT′
≪1
17 21 25 29
25 29 1 5
19 23 27 31
≪2
≪3
18 22 26 30
2 6 10 14
19 23 27 31
11 15 19 23
Figure 4: One round of the tweak-key schedule of BEANIE without AddKey.
Table 1: The round constants of BEANIE in hex.
RC 0 00000000000000000000000000000000 RC 1 000000000000000013198a2e03707344 RC 2 0000000000000000a4093822299f31d0 RC 3 0000000000000000082efa98ec4e6c89 RC 4 0000000000000000452821e638d01377 RC 5 0000000000000000be5466cf34e90c6c
RC 6 00000000000000007ef84f78fd955cb1
RC 7 000000000000000085840851f1ac43aa
RC 8 0000000000000000c882d32f25323c54
RC 9 000000000000000064a51195e0e3610d
Our approach for the TKS construction is based on the idea used in QARMA128
[ABD+23], where we use two copies of the 64-bit PRINCE [BCG+12] round function and
then mix the states after every round. The mixing is done by a Feistel Type-2 and AES
rotation over the 128-bit state (shifts by 2 cells row-wise). To reflect the composition
of two PRINCE rounds, we view the state as two 64-bit blocks. Each of these blocks
can be segmented into a 4 by 4 matrix of cells. The indices for each cell over the whole
128-bit state are shown in the first state of Figure 4. Note that if the 128-bit state is
given as a concatenation of bits X = (x0,x1,...,x127), then the nibble with the index
i∈{0,1,....,31}contains the bits (x4i+0,x4i+1,x4i+2,x4i+3).
As shown in Figure 2, the tweak-key schedule consists of r = 5 applications of the
round function φ. The round φi, with i= 0,...,r−1, consists of a AddKeyi operation
AKi, a SubCellsT layer SCT, a MixColumnsT operation MCT, a ShiftRowsT transformation
SRT and the mixing operations FeistelMixT (FMT) and ShiftRowsMixT (SRMT).
In short (see also Figure 4):
φi = SRMT ◦FMT ◦SRT ◦MCT ◦SCT ◦AKi.
After the last round, an additional AKr operations is applied. Here, SRT ◦MCT ◦SCT
implements two copies of PRINCE round function (with non-PRINCE 4-bit S-Box), while
SRMT ◦FMT mixes the states.
AddKeyi. The main key K is XORed to the state. To prevent weak key attacks, an
additional round constant RCi is added together with the key. The round constants are
the same used for PRINCE and displayed in Table 1.
SubCellsT. To both blocks of the state, a non-linear layer SCT′is applied. Concretely,
we apply to each nibble the 4-bit S-Box used in the data path (given in Table 12a).
MixColumnsT. To the two blocks of the state, the M′matrix of PRINCE [BCG+12] is
applied. When working with the whole state, we can view this as an application of the
extended block diagonal matrix of PRINCE, given as
M128 = diag(M′,M′) = diag(
ˆ
M(0)
ˆ
M(1)
ˆ
M(1)
ˆ
M(0)
ˆ
M(0)
ˆ
M(1)
ˆ
M(1)
,
,
,
,
,
,
,
ˆ
M(0)).
Gerhalter et al. 9
Here, we use the matrices
M0 =
   
0 0 0 0
0 1 0 0
0 0 1 0
0 0 0 1
   
, M1 =
   
1 0 0 0
0 0 0 0
0 0 1 0
0 0 0 1
   
, M2 =
   
1 0 0 0
0 1 0 0
0 0 0 0
0 0 0 1
   
, M3 =
   
1 0 0 0
0 1 0 0
0 0 1 0
0 0 0 0
   
to compose the matricesˆ
M(i)
, i= 0,1, by
ˆ
M(0) =
   
M0 M1 M2 M3
M1 M2 M3 M0
M2 M3 M0 M1
M3 M0 M1 M2
   ,
ˆ
M(1) =
   
M1 M2 M3 M0
M2 M3 M0 M1
M3 M0 M1 M2
M0 M1 M2 M3
   .
For an input state X (viewed as a 128-bit vector), the application of M128 can be done
either as X×M128 or M128 ×XT, since it is a symmetric matrix.
ShiftRowsT. This operation applies two PRINCE rotation layers in parallel (operating
within the two blocks of the state). Each operation is actually the AES rotation SRT over
the 4 ×4 block which is described as
(0,1,...,15) SRT
−−→(0,5,10,15,4,9,14,3,8,13,2,7,12,1,6,11).
FeistelMixT. on 32-bit branches, i.e.
We apply a Type-2 round function with the identity inner functions defined
Feistel Type-2 : (X0,X1,X2,X3) →(X1 ⊕X0,X2,X3 ⊕X2,X0),
where Xk = (x32·k+0,...,x32·k+31), k = 0,1,2,3. Note that X0 represents the first two
columns (cells 0,...,7), X1 represents the next two columns, etc.
ShiftRowsMixT. When viewing the state as an 8 ×4 matrix of cells, we apply the AES
rotation by grouping two cells. More specifically, by applying ≪ [0,2,4,6], we rotate the
cells of the four rows by 0, 2, 4, and 6 cells, respectively.
Relation to the datapath. The 128-bit output TKSK(T) = (k0,k1,k2,k3) supplies the
5-round datapath with the round keys ki, i= 0,...,5. We derive round keys k4 and k5, as
well as k6,k7,k8,k9 for extended versions of the cipher, with (see Figure 2)
k4 = k0 ⊕k1, k5 = k2 ⊕k3, k6 = k0 ⊕k2, k7 = k1 ⊕k3, k8 = k0 ⊕k3, k9 = k1 ⊕k2.
We provide test vectors in Appendix C.
3.3 Security Claims
Stemming from the real-world application described in Subsection 2.1, we define a practical
security claim limiting the attacker to 280 time and 240 data in the U-shape attack setting.
For this security claim, the cipher has a 5-round data path and a 5-round tweak-key
schedule. In case the latency requirements are less stringent, we recommend a 7-round
data path and a 7-round tweak-key schedule, leading to 128-bit security. As outlined
in Subsection 5.6, the cipher provides insufficient security guarantees in the non–U-shape
attack setting for both the 5 round and the 7 round version of the cipher. Therefore, we
do not claim any security in this attack setting.