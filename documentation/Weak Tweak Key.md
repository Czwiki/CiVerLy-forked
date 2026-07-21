3.2 Concrete Examples in Blink
We identify a special type of diﬀerential for a Blink S-box: 0x8 → α with probability 2−2
,
where α ∈ {0x2, 0x5, 0x8, 0xa}. To simplify the notations, in this subsection, we use Vα to
denote the output value space 0x8 → α. We have that Vα is an aﬃne subspace of Dα with
oﬀset cα. The details are given in Table 2. We noticed that there are only two possible
Dα, thus we define D1 = D0x2 = D0xa = {0x0, 0x2, 0x8, 0xa} and D2 = D0x5 = D0x8 =
{0x0, 0x8, 0x5, 0xd}. We note that D1 + D2 = {0x0, 0x2, 0x5, 0x7, 0x8, 0xa, 0xd, 0xf} and
D1 ∩ D2 = {0x0, 0x8}. We now give example analyses regarding relevant active patterns
for Superbox diﬀerentials with fixed input and output diﬀerence 0x8· a → 0x8· b, where
a, b ∈ {0, 1}4 are the active masks as defined above.

Example 1: 1-to-3 active. In this case, without loss of generality, let a = {0, 0, 1, 0} and
b= {1, 1, 0, 1}. The diﬀerential pattern must satisfy
{0x0, 0x0, 0x8, 0x0} → {0x0, 0x0, α, 0x0} → {α, α, 0x0, α} → {0x8, 0x8, 0x0, 0x8},
where α ∈ {0x2, 0x5, 0x8, 0xa}. Thus
X= Fn
2 × Vα × Fn
2 × Fn
2 , Y= Vα × Fn
2 × Vα × Vα
are cosets of
U= Fn
2 × Fn
2 × Dα × Fn
2 , V= Dα × Dα × Fn
2 × Dα,
with oﬀsets
u = [0, 0, cα, 0], v = [cα, cα, 0, cα].
As M= M−1 and u = M v, shifting away the oﬀsets reduces the weak key condition to
L(k) = M k ∈ W, W := U + M V.
To analyze W rigorously, we work in the dual. We have
U ⊥
= {0} × {0} × D⊥
α × {0}, V ⊥
= D⊥
α × D⊥
α × {0} × D⊥
α ,
and since M is invertible and symmetric in Blink, we have
W ⊥
= U ⊥ ∩ (M V )⊥
= U ⊥ ∩ M V ⊥
= U ⊥
.
Shiyao Chen, Jian Guo and Tianyu Zhang 9
Thus, we have dim(W ⊥) = dim(U ⊥) = 2 and dim(W ) = 4n− dim(W ⊥) = 16− 2 = 14.
We have the weak key condition simply as
(M k)2 = k0 + k1 + k3 ∈ Dα.
We then proceed to compute the probability of Q holding given a weak key, Pr(Q | k). As
dim(S) = dim(U )+dim(V )−dim(W ), and we have dim(V ) = 10, dim(U ) = dim(W ) = 14,
we have
Pr(Q | k) = 214+10−14−4·4 = 2−6
.
From the simplified weak key condition k0 + k1 + k3 ∈ Dα, we see that when k0 + k1 + k3 ∈
D1 ∩ D2 = {0x0, 0x8}, all 4 diﬀerentials are valid. Otherwise, when k0 + k1 + k3 ∈
(D1 ∪ D2) \ (D1 ∩ D2) = {0x2, 0xa, 0x5, 0xd}, exactly 2 diﬀerentials are valid. Thus, we
have a weak key distribution:
Pr(Q | k) =
    
2−4 k0 + k1 + k3 ∈ {0x0, 0x8},
2−5 k0 + k1 + k3 ∈ {0x2, 0xa, 0x5, 0xd},
0 otherwise.
Example 2: 3-to-3 active. Let a = {1, 1, 1, 0} and b= {1, 1, 1, 0} without loss of
generality. The diﬀerential pattern must satisfy
{0x8, 0x8, 0x8, 0x0} → {α, β, γ, 0x0} → {α, β, γ, 0x0} → {0x8, 0x8, 0x8, 0x0},
where α ̸= β ̸= γ ∈ {0x2, 0x8, 0xa}. Similar to above, we have U, V, u, v defined as
U= V= Dα × Dβ × Dγ × Fn
2 , u= v = [cα, cβ , cγ , 0].
As in Blink we have M= M−1 and M= J− I, where J is the all-one matrix. Shifting
away the oﬀsets again yields the weak key condition
L(k) = J u + M k ∈ W, W := U + M V.
We now derive W via its dual. We have
U ⊥
= D⊥
α × D⊥
β × D⊥
γ × {0}= V ⊥
.
We can express U ⊥ and (M V )⊥ = M V ⊥ as follows
U ⊥
M V ⊥
= (p, q, r, 0) : p ∈ D⊥
α , q ∈ D⊥
β , r ∈ D⊥
γ.}
= (q + r, p + r, p + q, p + q + r) : p ∈ D⊥
α , q ∈ D⊥
β , r ∈ D⊥
γ.
It is easy to see W ⊥ = U ⊥ ∩ (M V )⊥ can be expressed as
W ⊥
= (p, q, p + q, 0) : p ∈ D⊥
α , q ∈ D⊥
β , p + q ∈ D⊥
γ.
As two of Dα, Dβ , Dγ equal D1 and one equals D2, we can easily check dim(W ⊥) = 3 and
dim(W ) = 4n− dim(W ⊥) = 16− 3 = 13.
We notice that w ∈ W if and only if w0 + w1 ∈ Dα + Dβ and w0 + w2 ∈ Dα + Dγ.
Substituting w = L(k) = J u + M k, as we have (J u + M k)0 + (J u + M k)1 = k0 + k1 and
(J u + M k)0 + (J u + M k)2 = k0 + k2, we obtain straightforward weak key conditions as:
k0 + k1 ∈ Dα + Dβ , k0 + k2 ∈ Dα + Dγ.
As two of Dα, Dα, Dγ equals D1 and one equals D2, w0 + w1 ∈ Dα + Dβ and w0 + w2 ∈
Dα + Dγ results in dim(W ) = 13. Under a weak key, the diﬀerential holds with probability
Pr(Q | k) = 210+10−13−4·4 = 2−9
.
10 Weak Tweak-Key Analysis Of Blink Via Superbox
We next discuss the clustering of diﬀerentials. We see that when k0 + k1, k0 + k2 ∈ D1,
all 6 diﬀerentials are valid. When (k0 + k1, k0 + k2) ∈ (D1, 0x5 + D1) or (0x5 + D1, D1)
or (0x5 + D1, 0x5 + D1), exactly 2 diﬀerentials are valid. Thus, we have a weak key
distribution:
Pr(Q | k) =
    
3· 2−8 (ki0 + ki1 , ki0 + ki2 ) ∈ (D1)2
2−8 (ki0 , ki1 ) ∈ (D1 + D2)2 \ (D1)2
0 otherwise
Summary of Clusters and Respective Weak Key Distribution. We have summarized
the clustering eﬀect for selected active pattern in forward direction and the corresponding
weak key distribution in Table 3.

3.3 Superbox Patterns and Chain-like Trails for Blink
As mentioned in Section 2.2, we focus on Superboxes whose active input and output cells
are all fixed to the diﬀerence 0x8, however, we also tested the other three candidates
{0x2, 0x5, 0xa}, but they both have lower probabilities, and the gap will widen rapidly as
the trail propagates through additional rounds, making them non-competitive compared
to the 0x8 based patterns. This observation is further confirmed by our later experiments
on the Blink-64 distinguisher, which also show that 0x8 based patterns dominate the
multi-round diﬀerential behavior. Thanks to the swap between the S and P operations,
each Superbox can be analyzed column-wise and independently, and therefore we only
need to consider the propagation patterns listed in Table 3. One exception is the 4-to-4
pattern: we exclude it because P and P split the four active cells of an input column into
four diﬀerent output columns, thereby activating more columns and significantly reducing
the overall trail probability. Now, considering the maximum probabilities of the Superbox
patterns in Table 3, for each active S-box, it has an average probability 2−1
, e.g., 1-to-3,
3-to-1, and 2-to-2 patterns all with probability 2−4 for 4 active S-boxes; 3-to-3, 4-to-2, and
2-to-4 patterns all with probability 3· 2−8 for 6 active S-boxes.
With the above Superbox analysis, the core non-linear behavior of Blink can be well
captured. We then naturally connect these Superboxes through the surrounding linear
layer: P (or P) first splits the four cells of each column into four diﬀerent columns, after
which M mixes the nibbles within each column, and finally another P (or P) is applied. This
structure ensures strong diﬀusion between the input and output of adjacent Superboxes.
Moreover, since we restrict ourselves to Superbox patterns whose active input and output
cells are always fixed to the diﬀerence 0x8, the propagation through the linear layer
becomes deterministic, which greatly simplifies the search model. As a result, the overall
multi-round diﬀerential trail constructed from these Superboxes forms a clean chain-like
structure, each Superbox accounts for the non-linear transitions and weak-key conditions,
while the linear layers deterministically connect their diﬀerences across rounds.
4 Weak Tweak-Key Diﬀerential Distinguishers of Blink
In this section, with the analysis of Superbox propagation in the previous section, we
will simply provide the Superbox based automatic model to search the weak tweak-key
diﬀerential distinguisher for Blink ciphers. With this, for Blink-64, we find a 10-round
weak tweak-key diﬀerential trail with a maximum probability of 2−50.42 by setting 6-bit
conditions on key space. For Blink-128, we find a 10-round weak tweak-key diﬀerential
trail with a maximum probability of 2−68.48, which can be extended two more rounds to a
12-round multiple diﬀerential distinguisher with probability 2−96.84 (the corresponding
random probability are 2−100). As the designers of Blink [WHZ+25, Section 7.1] claim,
“we conclude that when the data does not exceed 256, it is highly unlikely to distinguish
10 rounds of Blink-64”, our two identified 10-round distinguishers remain within the data
limitations claimed by the designers, i.e., 256 for Blink-64 and 280 for Blink-128, and even
a 12-round multiple diﬀerential distinguisher is mounted for Blink-128.
4.1 Simple Superbox Pattern based Diﬀerential Search Model
According to analyses in Section 3.2 and Section 3.3, it can be observed that there are
not too many choices when considering the Superbox based propagation of the diﬀerential
trail for Blink. Thus, we can simply model these Superbox patterns into the search model
by using the mature MILP or SAT/SMT automatic search methods. For example, we
can directly follow Mouha et al. ’s [MWGP11] automatic search model of the diﬀerential
pattern, i.e., we consider truncated diﬀerences with every nibble in our search model,
which has either a zero or a non-zero diﬀerence as described in Definition 1. Considering
that how to search for the distinguisher is not a diﬃcult task for our cryptanalysis on Blink
ciphers, in the following, we just briefly provide the diﬀerence vector propagations through
diﬀerent operations to capture this pattern-based searching. To avoid distractions, the
detailed MILP or SAT/SMT model constraints will not be discussed here.
Diﬀerence Vector Propagation through Superbox. Let δx = (δx0, δx1, δx2, δx3) and
δy = (δy0, δy1, δy2, δy3) be one-column diﬀerence vectors of input and output of the
Superbox respectively. Then, according to Table 3, we only have several possible patterns
to propagate through the Superbox, which are given in Table 4 below. Based on these
patterns of Superbox, we can model the corresponding propagation rules by using the
convex hull representation for MILP [SHW+14] or Product-of-Sum representation for both
MILP and SAT/SMT [AST+17].

Diﬀerence Vector Propagation through MixColumn. As we have discussed in Section 2.2,
we fix the diﬀerence to 0x8 for each active nibble of the input and output states of the
Superbox, that is, the propagations of diﬀerence vectors through MixColumn will be
deterministic, which is given in Table 5. Thus, the propagation rules of MixColumn can
be easily modeled by the XOR operation using its MILP or SAT/SMT constraints. For
nibble-based permutation layers of Blink, the propagation of diﬀerence vectors through
permutations P and P can be directly modeled by wiring the corresponding variables.
Objective Function. With the above diﬀerential patterns through diﬀerent operations of
Blink and the discussion in Section 3.3, the objective function of this Superbox pattern
based search model can be approximately evaluated by summing the Hamming weights
of the diﬀerence vectors of the input and output for all Superboxes, that is, count the
number of active S-boxes as the objective function.
Next, we will present distinguishers of Blink-64 and Blink-128, which are obtained by
simply applying our search model provided above.
Remark. As mentioned in Section 2.2 and Section 3.3, we have tested three other candi-
dates {0x2, 0x5, 0xa}, they both have lower probabilities (2−4.68
, e.g., 0x0002 → 0x2220
and 0x0220 → 0x0220), and probabilities will drop faster across chained Superboxes. Be-
sides, {0x2, 0x5, 0xa} do not allow 3-to-3, 4-to-2 and 2-to-4 patterns, which makes it
diﬃcult to follow the optimal truncated diﬀerential. Hence, other potential diﬀerences are
less competitive compared to the 0x8-based patterns. This could be partially confirmed by
our experiments in Section 4.2, where we fixed the input/output diﬀerences of two tested
4-round trails (both with 2 Superboxes), the experiment results show that the diﬀerential
probabilities of those trails are dominated by the 0x8-based ones.

As given in Figure 3, the obtained 10-round diﬀerential distinguisher of Blink-64 can be
divided into five Superboxes, i.e., Round 1-2, Round 3-4, Round 5-6, Round 7-8 and Round
9-10. To reach the maximum probability of this distinguisher, we set tweak t = 0 and let
rk4, rk2 in Superboxes of Round 3-4 and Round 7-8 to satisfy the key conditions of 3-to-1
and 1-to-3 patterns both with probability 2−4 in Table 3, then this 10-round distinguisher
has a probability of 2−(12+4+18.415+4+12) ≈ 2−50.42 with 6-bit key conditions on the key
space. Thus, under the weak tweak-key setting, we can significantly increase the probability
of the 10-round distinguisher from 2−100 (the optimal characteristic evaluated by Blink
designers [WHZ+25, Section 7.1]) to 2−50.42. Some experiments are also performed on
this 10-round weak tweak-key diﬀerential trail as below, which could partially verify our
analysis on this weak tweak-key distinguisher.
Verifications and Experiments. We firstly perform experiments on two Superboxes of
Round 3-4 and Round 5-6, which are connected by P ◦ MK ◦ P. For each of 512 randomly
chosen keys, we then evaluate the diﬀerential from Round 3 to Round 6 with 229 pairs,
among which 329 keys (ratio 329/512 ≈ 0.643) are with zero probability and the rest keys
are distributed in two clusters as shown in Figure 4, which corresponds to two kinds of
key conditions with probabilities 2−4 and 2−5 for the 1-to-3 Superbox pattern of Round
3-4, i.e., expecting 229−18.415−4 ≈ 96 and 230−18.415−5 ≈ 48 right pairs respectively.
Secondly, we perform experiments on two Superboxes of Round 1-2 and Round 3-4,
which are also connected by P ◦ MK ◦ P. For each of 512 randomly chosen keys, we similarly
evaluate the diﬀerential from Round 1 to Round 4 with 223 pairs, among which 319 keys
(ratio 319/512 ≈ 0.623) are with zero probability and the rest keys are distributed in two
clusters as shown in Figure 5, which also corresponds to two kinds of key conditions with
probabilities 2−4 and 2−5 for the 1-to-3 Superbox pattern from Round 3-4, i.e., expecting
223−12−4 = 128 and 223−12−5 = 64 right pairs respectively.

