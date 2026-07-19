2 Specification of LBlock
The block length of LBlock is 64-bit, and the key length is 80-bit. It employs a
variant Feistel structure and consists of 32 rounds. The specification of LBlock
consists of three parts: encryption algorithm, decryption algorithm and key
scheduling.
2.1 Notations
In the specification of LBlock, we use the following notations:
− M : 64-bit plaintext
− C: 64-bit ciphertext
− K: 80-bit master key
− Ki: 32-bit round subkey
− F : Round function
− s: 4 × 4 S-box
− S: S-box layer consists of eight s in parallel
− P, P1: Permutations operate on 32-bit
− ⊕: Bitwise exclusive-OR operation
− <<< 8: 8-bit left cyclic shift operation
− >>> 8: 8-bit right cyclic shift operation
− ||: Concatenation of two binary strings
− [i]2: Binary form of an integer i
2.2 Encryption Algorithm
The encryption algorithm of LBlock consists of a 32-round iterative structure
which is a variant of Feistel network. The encryption procedure is illustrated in
Fig. 1. Let M= X1||X0 denote a 64-bit plaintext, and then the data processing
procedure can be expressed as follows.
1. For i = 2, 3, . . . , 33, do
Xi = F (Xi−1, Ki−1) ⊕ (Xi−2 <<< 8)
2. Output C= X32||X33 as the 64-bit ciphertext

Specifically, the components used in each round are defined as follows.
(1) Round function F
The round function F is defined as follows, where S and P denote the con-
fusion and diﬀusion functions which will be defined later.
F : {0, 1}32 × {0, 1}32 −→ {0, 1}32
(X, Ki) −→ U= P(S(X ⊕ Ki))
Fig. 2 illustrates the structure of round function F in detail.
(2) Confusion function S

Confusion function S denotes the non-linear layer of round function F , and
it consists of eight 4-bit S-boxes si in parallel.
S : {0, 1}32 −→ {0, 1}32
Y= Y7||Y6||Y5||Y4||Y3||Y2||Y1||Y0 −→ Z= Z7||Z6||Z5||Z4||Z3||Z2||Z1||Z0
Z7 = s7(Y7), Z6 = s6(Y6), Z5 = s5(Y5), Z4 = s4(Y4),
Z3 = s3(Y3), Z2 = s2(Y2), Z1 = s1(Y1), Z0 = s0(Y0).
The contents of eight 4-bit S-boxes are listed in Table 1.
(3) Diﬀusion function P
Diﬀusion function P is defined as a permutation of eight 4-bit words, and it
can be expressed as the following equations.
P : {0, 1}32 −→ {0, 1}32
Z= Z7||Z6||Z5||Z4||Z3||Z2||Z1||Z0 −→ U= U7||U6||U5||U4||U3||U2||U1||U0
U7 = Z6, U6 = Z4, U5 = Z7, U4 = Z5,
U3 = Z2, U2 = Z0, U1 = Z3, U0 = Z1.

2.3 Decryption Algorithm
The decryption algorithm of LBlock is the inverse of encryption procedure, and it
consists of a 32-round variant Feistel structure too. Let C= X32||X33 denotes a
64-bit ciphertext, and then the decryption procedure can be expressed as follows.
1. For j = 31, 30, . . . , 0, do
Xj = (F (Xj+1, Kj+1) ⊕ Xj+2) >>> 8
2. Output M= X1||X0 as the 64-bit plaintext.

2.4 Key Scheduling
The 80-bit master key K is stored in a key register and denoted as K=
k79 k78 k77 k76 ...... k1k0. Output the leftmost 32 bits of current content of register
K as round subkey K1, and then operate as follows:
1. For i = 1, 2, . . . , 31, update the key register K as follows:
(a) K <<< 29
(b) [k79 k78 k77 k76] = s9[k79 k78 k77 k76]
[k75 k74 k73 k72] = s8[k75 k74 k73 k72]
(c) [k50k49k48k47k46] ⊕ [i]2
(d) Output the leftmost 32 bits of current content of register K as round
subkey Ki+1.
where s8 and s9 are two 4-bit S-boxes, and they are defined in Table 1.1

