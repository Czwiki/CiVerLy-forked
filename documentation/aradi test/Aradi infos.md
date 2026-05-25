Aradi is a substitution-permutation network (SPN) with round function act-
ing on a state consisting of four 32-bit words (w, x, y, z)∗. In this representa-
tion, the s-box layer consists of 32 identical 4-bit s-boxes, with the i-th s-box
acting on the i-th bit level of the words of state. The s-box is a composition
of four Toffoli gates, i.e. 3-bit to 3-bit gates of the form (a, b, c) 7 → (a, b, c ⊕ ab)
(see Figure 3.1 for a diagram).
This s-box has optimal statistical properties for its size. Namely, the largest
entry in the Difference Distribution Table is 1/4 and the largest magnitude of
any entry in the Linear Approximation Table is 1/2. It is easy to see that any
4-bit s-box that is a composition of Toffoli gates requires at least four such
gates if we want acceptable linear/differential properties.
∗Here w is the most significant 32-bit word of the 128-bit state, and z is the least
significant.
3
w x y z
w x y z
&
&
&
&
Figure 3.1: Aradi s-box layer
The linear maps for Aradi vary on a cycle of four, which makes it possible
to improve resistance to linear and differential cryptanalysis. By acting in-
dependently on the words w, x, y, and z, the linear maps operate in a way
complementary to the s-box layer, which operates independently on the dif-
ferent bit levels. So, we can write the Aradi linear maps in the form
(w, x, y, z) 7 → (Li(w), Li(x), Li(y), Li(z)),
where Li is a linear map on 32-bit words.
The Li are involutions constructed from 16-bit circular shifts and XORs. If the
32-bit input is composed of two 16-bit halves u, l, then Li has the form
(u, l) 7 → (u ⊕ Sai
16(u) ⊕ Sci
16(l), l ⊕ Sai
16(l) ⊕ Sbi
16(u))
(see Figure 3.2 for a diagram). As a matrix each Li has row density three, so
that each output bit requires two XORs (or one 3-input XOR). This, along with
the fact that Li is an involution, allows for an efficient implementation of both
the encrypt and decrypt cipher.
4
u l
u l
Sbi
16 Sci
16
Sai
16 Sai
16
Figure 3.2: Aradi linear map applied to a 32-bit word w =
u || l (u and l represent the upper and lower 16 bits of w. S16 is
a left circular shift on a 16-bit word).
The sequence of shift amounts for the Aradi linear maps is
i mod 4 ai bi ci
0 11 8 14
1 10 9 11
2 9 4 14
3 8 9 7
These parameters were chosen by a limited search over the possible values. No
attempt was made to select shift values close to multiples of eight, so we antic-
ipate Aradi is more well suited to 16-bit rather than 8-bit microprocessors.
Let π be the Aradi s-box layer and Λi the i-th linear map. If we denote
translation by the 128-bit value v by τv, then the Aradi encryption function
has the form (reading from right to left)
τk16 ◦ (Λ15πτk15 ) ◦ · · · ◦ (Λ2πτk2 ) ◦ (Λ1πτk1 ) ◦ (Λ0πτk0 ),
where the indices of the Λi are reduced modulo four, and the ki are the ex-
panded keys (16 round keys plus a post add). The method for generating the
ki from the 256-bit base key is described in the next subsection.
5
3.2. The ARADI Key Schedule
The Aradi key schedule operates on an array of eight 32-bit words Kj . It
makes use of two invertible linear maps M0, M1 operating on pairs of 32-bit
words. These maps have the form
M0(x, y) = (S1
32(x) ⊕ y, S3
32(y) ⊕ S1
32(x) ⊕ y)
M1(x, y) = (S9
32(x) ⊕ y, S28
32 (y) ⊕ S9
32(x) ⊕ y)
where S32 is a left circular shift on a 32-bit word. The key schedule update
varies on a period of two. Two steps (starting on an even index round) are
illustrated in Figure 3.3.
Ki
0 Ki
1 Ki
2 Ki
3 Ki
4 Ki
5 Ki
6 Ki
7
M0 M1 M0 M1
Ki+1
0 Ki+1
1 Ki+1
2 Ki+1
3 Ki+1
4 Ki+1
5 Ki+1
6 Ki+1
7
i
M0 M1 M0 M1
Ki+2
0 Ki+2
1 Ki+2
2 Ki+2
3 Ki+2
4 Ki+2
5 Ki+2
6 Ki+2
7
i + 1
Figure 3.3: Aradi key schedule. Two consecutive rounds
shown. Round keys are drawn from the boxed regions.
6
If we denote the register values at step i by (Ki
0, Ki
1, Ki
2, Ki
3, Ki
4, Ki
5, Ki
6, Ki
7),
then the i-th round key is the concatenation Ki
0||Ki
1||Ki
2||Ki
3 for even index
rounds and Ki
4||Ki
5||Ki
6||Ki
7 otherwise. At each step, the four pairs of consecu-
tive words are mixed by applying either M0 or M1. Then a word permutation
Pj is applied, where P0 = (12)(56) and P1 = (14)(36) (j is the round modulo
2). The register is initially loaded with the eight 32-bit words of key K0, . . . K7,
and a counter is XORed into K7 at each step in order to block slide/rotational
attacks [1].
