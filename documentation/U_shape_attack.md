Under the assumption that the ciphertext is not available to the attacker (Section 2.1), we
use the U-shape attack scenario. For a cipher EK,T(P) = C with tweak-key pair (K,T)
and non-available C, this means that the attacker queries the MMU to decrypt C with
a different tweak T′. The tweak-key schedule will produce round keys different from the
correct one (for the correct tweak), and thus the information flow will look as follows:
P →EK,T(P) = C → E−1K,T′ (C) = C,

where the secret main key K can not be changed/affected by the attacker and T′̸= T. In
this context, we view U= E−1
K,T′ ◦EK,T as an encryption scheme that produces (P,C) pairs U(P) = E−1 K,T′ (EK,T(P)) = C, where the round tweak-keys used in EK,T and EK,T′ are independent due to the strong tweak-key schedule. The parts EK,T and E−1
K,T′ will be called branches of the U-shape (left l and right r branches). Stemming from the attack
setting, in a round-reduced version of the cipher, both branches get shortened by the same
number of rounds. However, the reduced round R′is always applied in the last round.
The cipher achieves full diffusion after 2 rounds, except when the last round R′ is
involved. In this case, we need 3 rounds for full diffusion. It may take up to 5 rounds
to achieve full diffusion when the bottom layers of the U-shape are considered, since the
transitions from left to right branches annuls parts of the diffusion of the linear layers.
Note that the round key recovery attacks will target the initial rounds of the left branch
EK,T (thus from the plaintext side) or the last round keys of the right branch E−1
K,T′ (from the ciphertext side). Therefore, the inferior diffusion properties towards the last rounds of
the cipher have little impact on the key recovery. Distinguishers used in attacks can always be mirrored due to the U-shape. Thus, a (rl + rr)-round distinguisher stretching over rl-rounds of EK,T and rr-rounds of E−1
K,T′(connected at the bottom of U-shape), imply the existence of a (rr+rl)-round distinguisher.
Once we recovered the subkeys k belonging to a (K,T) pair, it is straightforward to
gather additional subkeys derived from another tweak T′. This is because we then know
the encrypted value EK,T and therefore only need to attack E−1
K,T′ . Thus, we can obtain an arbitrary number of data to attack the tweak-key schedule. Furthermore, the tweak-key
schedule is easier to attack than the data path. We therefore assume that a valid attack
on the data path leads to a valid attack on the cipher in the U-shape attack setting.
We assume that the first 4 round keys are independent (due to the strength of the TKS)
and thus we do not consider the existence of exploits that come from the tweak-key schedule.
In particular, choosing a pair of tweaks that lead to the same round keys in the last round
is prevented by the differential properties of the TKS. However, even in the generic case,
we on average get a collision in the last round keys of EK,T and E−1
K,T′ after trying 232 different tweaks for T′. If this is the case, the last round of EK,T and the first round of
E−1 K,T′ cancel each other. Thus, by increasing the time and data complexities by a factor
of 232 we can extend each attack by one round in the left and right branch. Note that it is
also possible to exploit a partial collision in the last round key (see Subsubsection 5.3.1).
In Table 7 we provide a quick overview of the best attacks with the U-shape attack
setting we found. We also include extensions we get from generic last-round key collisions.
We believe that the attack breaking the full round SCARF [FGLL+25] is not applicable to
our cipher, since we use a more traditional approach of adding the round keys to the state.

rl \ rr 0 1 2 3 4 5
1 2 4 12 22 32 34
2 10 12 20 26 40
3 16 22 26 32
4 30 32 40
5 32 34
6 40