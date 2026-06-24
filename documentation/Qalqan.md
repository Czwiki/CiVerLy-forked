3. Qalqan Block Symmetric Encryption Algorithm
3.1. Conventions
𝑉 𝑠 is the set of all binary strings of length s, where s is a natural number; numbering of substrings
and string components is carried out from left to right, starting from zero;
𝐵𝑙𝑒𝑛 is inlet and outlet block length;
𝐾𝐿𝑒𝑛 is original encryption key length;
𝑁 is number of rounds of encryption algorithm;
𝐾 is source encryption key;
⨁ is modulo 2 addition;
⊞ is modulo 2128 addition;
⊟ is modulo 2128;
∔ is modulo 256 addition;
∸ is modulo 256 subtraction.
3.2. General Information about the Algorithm
Algorithm architecture: LSX.
Block length: 𝐵𝑙𝑒𝑛 = 128 bit.
Key length: 𝐾𝐿𝑒𝑛 = 256. .1024 bit with 128 bit step.
Number of rounds: 𝑁 = 17 + ⌊𝐾𝐿𝑒𝑛−256
128 ⌋ ∗ 2 (from 17 to 29 rounds).
3.3. Parameter Value
3.3.1. Nonlinear Bijective Transformation
Nonlinear bijective transformation 𝑆: 𝑉 128 → 𝑉 128 is specified by substitution 𝑆𝑏𝑜𝑥: 𝑉 8 → 𝑉 8 (in the
following order 𝑆(0), . . , 𝑆(255)):
Figure 1: Qalqan S-box
0 1 2 3 4 5 6 7 8 9 a b c d e f
0 eb 89 db cb f3 f5 fb 90 e6 3d e5 2e e3 0b 56 e1
1 6c 12 80 28 ed 22 9 4a ee 27 9b 58 35 57 ef 94
2 29 c0 16 7c 5e 87 0a 7e e8 11 0e af 9a 84 3a 1a
3 69 71 8c bc d2 55 33 d1 85 75 b5 83 e9 50 54 ac
4 8a d6 7f 1f 14 4e 21 82 30 24 dd 9f 1b 32 20 a8
5 6a b0 97 62 19 d8 c8 0c 52 2 5c 43 3 95 13 81
6 ab 77 a6 f2 59 67 41 ec 76 98 b4 73 86 9c f7 cf
7 dc ba a4 fd c4 99 df ce ea 1c 36 bd 34 d7 49 64
8 5a 6f 74 1 a0 39 91 0 15 3f 38 b8 8f 26 5f f8
9 7 a3 0d da f0 e7 d0 d9 93 f6 6 47 0f a1 4b c5
a 2a ff 46 60 d5 1d 2f a9 92 17 72 8e 7a aa 18 6e
b 37 8 1e 63 31 c2 bf c6 9e 65 d4 3b 96 9d de 45
c ca 2d a5 fe 4d b9 66 c3 b3 cc ad 61 be 7b 68 88
d 25 2b 53 5b 44 40 a7 a2 5d c9 51 ae e4 c7 f9 78
e 70 cd 42 4f 4c 3c e0 3e 7d b7 d3 b2 f1 8d 79 8b
f 6b e2 10 23 4 6d c1 fc 5 b6 f4 48 bb b1 2c fa
207
Byte 00 is replaced with eb, 01 with 89, ff with fa (values are in hexadecimal). Substitution is applied
to all bytes of the processed block
3.3.2. Linear Transformation
Linear function 𝐿: 𝑉 128 → 𝑉 128 converts an 16 byte input block B into an output block R of the same
size as follows (bytes are numbered from high to low):
𝑅0 = 𝐵0 ∔ 𝐵1 ∔ 𝐵2 ∔ 𝐵3
𝑅4 = 𝐵4 ∔ 𝑅0
𝑅8 = 𝐵8 ∔ 𝑅0
𝑅12 = 𝐵12 ∔ 𝑅0
𝑅5 = 𝐵4 ∔ 𝐵5 ∔ 𝐵6 ∔ 𝐵7
𝑅1 = 𝐵1 ∔ 𝑅5
𝑅9 = 𝐵9 ∔ 𝑅5
𝑅13 = 𝐵13 ∔ 𝑅5
𝑅10 = 𝐵8 ∔ 𝐵9 ∔ 𝐵10 ∔ 𝐵11
𝑅2 = 𝐵2 ∔ 𝑅10
𝑅6 = 𝐵6 ∔ 𝑅10
𝑅14 = 𝐵14 ∔ 𝑅10
𝑅15 = 𝐵12 ∔ 𝐵13 ∔ 𝐵14 ∔ 𝐵15
𝑅3 = 𝐵3 ∔ 𝑅15
𝑅7 = 𝐵7 ∔ 𝑅15
𝑅11 = 𝐵11 ∔ 𝑅15
3.3.3. Key Addition
𝑖
Round keys are superimposed by modulo 2128adding with the processed data block (operation 𝐾⊞
,
where i – round number).
The keys of the first and last rounds are superimposed modulo 2 (operation 𝐾⨁
𝑠𝑡𝑎𝑟𝑡 in the first round
and 𝐾⨁
𝑓𝑖𝑛 in the last).
3.3.4. Round Transformation
Each round of the 𝑋𝑆𝐿 algorithm except for the last one, includes sequentially key addition,
nonlinear transformation and linear transformation, thus 𝑋𝑖𝑆𝐿(𝑇𝑒𝑥𝑡) = 𝐿 (𝑆 (𝐾⊞
𝑖 (𝑇𝑒𝑥𝑡))).
The last round contains only a modulo 2 key overlay operation.
3.3.5. Key Expansion
The bytes of the key (starting with the least significant one) are fed in turn to the byte shift registers
L0 and L1, starting from L0. Register L0 is 17 bytes long, L1 is 15 bytes long. Thus, a 256-bit key
consisting of bytes {𝐾0. . 𝐾31} fills the registers as follows:
𝐿0 = {𝐾0, 𝐾2, 𝐾4, 𝐾6, 𝐾8, 𝐾10, 𝐾12, 𝐾14, 𝐾16, 𝐾18, 𝐾20, 𝐾22, 𝐾24, 𝐾26, 𝐾28, 𝐾30, 𝐾31}
𝐿1 = {𝐾1, 𝐾3, 𝐾5, 𝐾7, 𝐾9, 𝐾11, 𝐾13, 𝐾15, 𝐾17, 𝐾19, 𝐾21, 𝐾23, 𝐾25, 𝐾27, 𝐾29}
The feedback of the shift registers is set as follows:
𝐿0 = {𝐿01. . 𝐿016, 𝑆(𝐿00) ∔ 𝐿01 ∔ 𝑆(𝐿03) ∔ 𝐿07 ∔ 𝑆(𝐿012) ∔ 𝐿016}
𝐿1 = {𝐿11. . 𝐿113, 𝑆(𝐿10) ∔ 𝐿13 ∔ 𝑆(𝐿19) ∔ 𝐿112 ∔ 𝑆(𝐿114)}
The registers move uniformly, after the 17th step each value 𝐿015 ∔ 𝐿14 is filled into the byte of the
next round key starting from the least significant.
208
For keys consisting of more than 256 bits, subsequent bytes in order from least significant to most
significant are loaded into shift registers after the 17th step of operation by adding registers modulo 256
to the feedback function starting from register L1. Thus, at each even step of the registers, starting from
the 18th, the value of the next byte of the key is superimposed on the feedback value of the L1 register,
and at odd steps starting from the 19th - on the feedback value of the L0 register.
Figure 2: Key expansion node.
3.4. Encryption Algorithm
3.4.1. Encryption
The encryption function consists of three parts and has the form:
𝐸1(𝑇𝑒𝑥𝑡) = 𝐿 (𝑆 (𝐾⨁
𝑠𝑡𝑎𝑟𝑡(𝑇𝑒𝑥𝑡)))
𝐸2(𝑇𝑒𝑥𝑡) = 𝑋𝑁−1𝑆𝐿(… 𝑋2𝑆𝐿(𝑋1𝑆𝐿(𝐸1(𝑇𝑒𝑥𝑡))))
𝐸(𝑇𝑒𝑥𝑡) = 𝐾⨁
𝑓𝑖𝑛(𝐸2(𝑇𝑒𝑥𝑡))
The encryption algorithm schematically represented as follows:
Figure 3: General view of the transformation
209
0 1 2 3 4 5 6 7 8 9 a b c d e f
0 87 83 59 5c f4 f8 9a 90 b1 16 26 0d 57 92 2a 9c
1 f2 29 11 5e 44 88 22 a9 ae 54 2f 4c 79 a5 b2 43
2 4e 46 15 f3 49 d0 8d 19 13 20 a0 d1 fe c1 0b a6
3 48 b4 4d 36 7c 1c 7a b0 8a 85 2e bb e5 9 e7 89
4 d5 66 e2 5b d4 bf a2 9b fb 7e 17 9e e4 c4 45 e3
5 3d da 58 d2 3e 35 0e 1d 1b 64 80 d3 5a d8 24 8e
6 a3 cb 53 b3 7f b9 c6 65 ce 30 50 f0 10 f5 af 81
7 e0 31 aa 6b 82 39 68 61 df ee ac cd 23 e8 27 42
8 12 5f 47 3b 2d 38 6c 25 cf 1 40 ef 32 ed ab 8c
9 7 86 a8 98 1f 5d bc 52 69 75 2c 1a 6d bd b8 4b
a 84 9d d7 91 72 c2 62 d6 4f a7 ad 60 3f ca db 2b
b 51 fd eb c8 6a 3a f9 e9 8b c5 71 fc 33 7b cc b6
c 21 f6 b5 c7 74 9f b7 dd 56 d9 c0 3 c9 e1 77 6f
d 96 37 34 ea ba a4 41 7d 55 97 93 2 70 4a be 76
e e6 0f f1 0c dc 0a 8 95 28 3c 78 0 67 14 18 1e
f 94 ec 63 4 fa 5 99 6e 8f de ff 6 f7 73 c3 a1
3.4.2. Decryption
For decryption, functions opposite to those described above are used.
Non-linear function InvS is defined by substitution 𝐼𝑛𝑣𝑆𝑏𝑜𝑥: 𝑉 8 → 𝑉 8 of the following kind (in the
following order 𝐼𝑛𝑣𝑆(0), . . , 𝐼𝑛𝑣𝑆(255)):
Figure 4: Qalqan inverted S-box
Inverse linear operation 𝐼𝑛𝑣𝐿: 𝑉 128 → 𝑉 128 converts 16 byte input block B to output block R of the
same size as follows (bytes are numbered in ascending order):
𝑅1 = 𝐵1
∸ 𝐵5
𝑅2 = 𝐵2 ∸ 𝐵10
𝑅3 = 𝐵3 ∸ 𝐵15
𝑅4 = 𝐵4
∸ 𝐵0
𝑅6 = 𝐵6 ∸ 𝐵10
𝑅7 = 𝐵7
∸ 𝐵15
𝑅8 = 𝐵8 ∸ 𝐵0
𝑅9 = 𝐵9 ∸ 𝐵5
𝑅11 = 𝐵11
∸ 𝐵15
𝑅12 = 𝐵12 ∸ 𝐵0
𝑅14 = 𝐵14
∸ 𝐵0
𝑅0 = 𝐵0 ∸ 𝑅1
∸ 𝑅2 ∸ 𝑅3
𝑅5 = 𝐵5 ∸ 𝑅4
∸ 𝑅6 ∸ 𝑅7
𝑅10 = 𝐵10 ∸ 𝑅8 ∸ 𝑅9 ∸ 𝑅11
𝑅15 = 𝐵15 ∸ 𝑅12 ∸ 𝑅13 ∸ 𝑅14
The round keys 𝐾⊟ are superimposed by modulo 2128subtraction. The keys of the first and last
rounds are superimposed by modulo 2 operation.
One round of the 𝑆𝐿𝑋 decryption algorithm includes sequentially linear, non-linear transformations
and key addition, thus 𝑆𝐿𝑋𝑖(𝐶𝑖𝑝ℎ𝑒𝑟) = 𝐾⊟
𝑖 (𝐼𝑛𝑣𝐿(𝐼𝑛𝑣𝑆(𝐶𝑖𝑝ℎ𝑒𝑟)).
The decrypting operation of the Cipher ciphertext on round keys Key is represented as follows:
𝐷1(𝐶𝑖𝑝ℎ𝑒𝑟) = 𝐾⨁
𝑓𝑖𝑛(𝐶𝑖𝑝ℎ𝑒𝑟)
210
𝐷2(𝐶𝑖𝑝ℎ𝑒𝑟) = 𝑆𝐿𝑋1(… 𝑆𝐿𝑋𝑁−2(𝑆𝐿𝑋𝑁−1(𝐷1(𝐶𝑖𝑝ℎ𝑒𝑟))))
𝐷(𝐶𝑖𝑝ℎ𝑒𝑟) = 𝐾⨁
𝑠𝑡𝑎𝑟𝑡 (𝐼𝑛𝑣𝐿 (𝐼𝑛𝑣𝑆(𝐷2(𝐶𝑖𝑝ℎ𝑒𝑟))))