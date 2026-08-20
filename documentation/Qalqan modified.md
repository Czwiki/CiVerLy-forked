Qalqan𝑣1 Cipher and Its Modifications
The block cipher Qalqan [1] has an SP-network-
based structure with a block size of 128 bits. The
cipher key length is 256-1024 bits, with 17-23 en-
cryption rounds. The number of rounds depends
on the key length. Cipher has a byte-oriented struc-
ture: all operations, but adding round keys, are
done over bytes (8-bit sequences) or sets of bytes.
Input texts and encryption states are represented
as 128-bit vectors, arrays of 16 bytes, and byte
matrix4×4 atthe sametime, dependingon applied
transformation.
Oneencryptionround𝐹𝑘(𝑥) = 𝐿(𝑆(𝐾∘
𝑘 (𝑥))) con-
sists of three sequential layers:
1) round key addition 𝐾∘
𝑘 with operation ∘;
2) non-linear substitution 𝑆;
3) linear transformation 𝐿, which consists of a
series of state byte additions (details further).
At the end of encryption, extra whitening is
applied with a separate round key.
Addition with the round key on the first round
and at the end of the encryption is performed
with the bit-wise operation (𝐾⊕
𝑘 (𝑥) = 𝑥 ⊕𝑘).
All other rounds use addition modulo 2128
(𝐾+
𝑘 (𝑥) = (𝑥+ 𝑘) mod 2128) and encryption state
is represented as 128-bit non-negative integer in
Little-Endian format. In our work, we denote these
functions as 𝐹⊕
𝑘 and 𝐹+
𝑘 for round functions. They
use 𝐾⊕
𝑘 and 𝐾+
𝑘 keys respectively.
Non-linear substitution 𝑆 is applied to all bytes
in state matrix with fixed S-Box 𝑠: 𝑎𝑖,𝑗= 𝑠[𝑎𝑖,𝑗 ].
Qalqan𝑣1 S-Box is claimed to be constructed us-
ing Nyberg scheme [9], similarly to AES S-Box;
however, its algebraic form had not be published.
Linearlayer𝐿ofQalqan𝑣1 cipherisbasedonbyte
addition (modulo 28) and consists of two phases:
a) on the first phase («absorption») diagonal ele-
ments from the matrix are added with all elements from the corresponding row:
∀𝑖∈{0,1,2,3}: 𝑎𝑖,𝑖= 𝑎𝑖,0 + 𝑎𝑖,1 + 𝑎𝑖,2 + 𝑎𝑖,3;
b) on the second phase («distribution») updated
diagonal matrix elements are added to all elements
of corresponding columns:
∀𝑗,𝑖∈{0,1,2,3},𝑖̸= 𝑗: 𝑎𝑖,𝑗= 𝑎𝑖,𝑗 + 𝑎𝑗,𝑗.
The scheme of the linear layer 𝐿 is presented in
fig. 1.
It’s worth mentioning that the linear layer of
Qalqan𝑣1 cipher has no analogs among other linear
mappings used in known block ciphers.
A detailed description of the Qalqan𝑣1 cipher,
its components and key schedule are presented
in [1, 2].
Further in our work, alongside with original ci-
pher, we consider its modification, where byte-wise
vectoraddition⊞modulo28 isused. Thefirstmodi-
fication has all its round key additions 𝐾+
𝑘 modulo
2128 substituted with additions 𝐾⊞
𝑘 (𝑥) = 𝑥⊞𝑘.
The modified round function we denote as 𝐹⊞
𝑘.
The essence of this modification is a removal of
carry bits between state bytes. This modification
transforms cipher into Markov cipher w.r.t. the
sequence of operations (⊕,⊞,⊞,...,⊞,⊕). The
second modification uses byte-wise addition for
first and last addition with key as well. This modi-
fication transforms the cipher into Markov cipher
w.r.t. ⊞operation and can be considered as a ci-
pher model without first round and final whitening.
We denote these modifications as Qalqan𝑣1
⊕⊞ and
Qalqan𝑣1
⊞⊞ respectively.