7.1 Differential Analysis
We employed the MILP approach for differential analysis [BS91]. The obtained results,
including bounds on the active S-boxes numbers, are summarized in Table 3, where ”full
cipher” refers to the full reflective construction. Each round containing an S-box layer is
counted as a single round in the overall round count.
For Blink-64, since the maximum differential probability of the S-box in Blink is 2−2
,
the maximum differential probability of 10-round ”full cipher” differential characteristic
is at most 2−100. Hence, we conclude that when the data does not exceed 256, it is highly
unlikely to distinguish 10 rounds of Blink-64 without any key constraints.
Furthermore, due to the fact that after applying R or its inverses three times, each
output cell is influenced by all input cells and any three consecutive rounds keys are
independent, the output of the third encryption or decryption round is affected by (16 +
9 + 3) ×4 = 112 bits of the key, while the second encryption or decryption round is
affected by (9 + 3) ×4 = 48 bits of the key. Consequently, for the 14-round Blink-64,
only a 10-round distinguisher could potentially be useful to recover the full key. Thus, we
think Blink-64 is secure against differential attacks.
Similarly, for Blink-128, when the data does not exceed 280, it is highly unlikely
to distinguish 10 rounds of Blink-128 without any key constraints. The output of the
third / fourth encryption or decryption round is affected by (23 + 9 + 3) ×4 = 140 /
(31 + 23 + 9 + 3) ×4 = 264 bits of the key, respectively. Thus, we think Blink-128 is also
secure against differential attacks.
Weak-key Differential Attacks. Recent work [CGZ25] analyzes the special case where
the tweak is fixed to zero and constructs superboxes exploiting this degenerate condition.
Under this assumption, for Blink-64a/b with a 448-bit key, they obtain a 10-round differ-
ential distinguisher for up to 2442 weak keys with probability 2−50.42. For Blink-128a/b
with a 1024-bit key, they derive a 10-round distinguisher for up to 21010 weak keys with
probability 2−68.83, which can be extended to a 12-round multiple-differential distinguisher
with probability 2−96.83. Based on the weak tweak-key distinguisher, they further mount
a 13-round key-recovery attack on Blink-64, recovering the full 448-bit master key with
time complexity 2112.15 and requiring 256 chosen plaintexts.
These results crucially rely on the degenerate tweak value t= 0, for which the hash
functions h1, h2, h collapse to zero and lose their intended key/tweak mixing properties.
The Blink specification excludes this corner case by design: as described in Section 5.5,
the tweak space is restricted to non-zero values, and standard padding or counter-offset
conventions make this requirement trivial to satisfy in practice.
When t ̸= 0, the values of the hash functions are key dependent and cannot be
predetermined, preventing the structural collapses exploited in [CGZ25]. Consequently,
extending their weak-tweak analysis to the full tweak domain would require substantially
stronger assumptions and distinguishers far beyond the allowable data limits.
We therefore conclude that, under the specified tweak space Fτ
2 \{0}, Blink remains
secure against differential attacks, including weak-key scenarios.

7.1.1 MT Differential Attacks
For Blink-64 / Blink-128, h1 and h2 both belong to 2−64-AXUHF / 2−128-AXUHF,
respectively. Therefore, under the data limitations of 256 / 280
, Blink-64 and Blink-128
are suﬀiciently resistant to MT differential attacks.
7.2 Impossible Differential Attacks
We explored the impossible differential trails for the center structure, considering r1-
rounds of the upper half and r2-rounds of the lower half. Inspired by [ST17], we con-
strained the differential model such that the input and output have only one active cell.
By determining the feasibility of the model, we verify whether the input-output differ-
ential pair is valid. The final results are summarized in Table 4, where ‘✓’ indicates
the existence of an r1 + r2 impossible differential trail, and ‘blank’ denotes that for any
difference pair with a single active cell in the input and output, a valid trail exists.
For Blink-64, the longest impossible differential trail spans 7 rounds, while it spans 9
rounds for Blink-128. Since we have employed multiple different round keys, similar to
differential analysis, these distinguishers are insuﬀicient to pose a threat to the security
of Blink.

7.2.1 MT Impossible Differential Attacks
Since h1 and h2 are 2−n-AXUHF, when the difference of tweak is non-zero, the value of
output difference is diﬀicult to be determined. Therefore, we believe that Blink is secure
against MT impossible differential attacks.

7.3 Linear Analysis
Since the diffusion matrix M is symmetric and involutory, and the shuffle layer is cell-
based, Table 3 also presents the lower bounds on the number of active S-boxes for linear
characteristics. Given that the linearity of the S-box is 8, its maximum squared correlation
is 2−2. Similar to differential analysis, we conclude that Blink-64 and Blink-128 are
secure against linear attacks.
7.3.1 MT Linear Attacks
Given that for variable tweaks and non-zero λt, we have ch = 2−n, as defined in Equation 7,
and by the linear analysis of ETHF, we conclude that Blink achieves security against MT
linear attacks.