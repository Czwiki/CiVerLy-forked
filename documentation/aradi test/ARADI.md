# Block Cipher Pseudocode

---

## Definitions

- `w, x, y, z` = plaintext words  
- `K[7] ... K[0]` = key words  
- `k[i][0..3]` = round key words

### Functions

- **M(i, j, X, Y):**
  ```
  (S_i^32 Y) ⊕ (S_j^32 X) ⊕ X,  S_i^32 Y ⊕ X
  ```
- **L(a, b, c, x‖y):**
  ```
  first = x ⊕ S_a^16 x ⊕ S_c^16 y
  second = y ⊕ S_a^16 y ⊕ S_b^16 x
  return first‖second
  ```

- Arrays:  
  `a = [11,10,9,8]`  
  `b = [8,9,4,9]`  
  `c = [14,11,14,7]`  

## Encryption

```
for i = 0..15:
    z := z ⊕ k[i][3]
    y := y ⊕ k[i][2]
    x := x ⊕ k[i][1]
    w := w ⊕ k[i][0]

    x := x ⊕ (w & y)
    z := z ⊕ (x & y)
    y := y ⊕ (w & z)
    w := w ⊕ (x & z)

    j := i mod 4
    z := L(a[j], b[j], c[j], z)
    y := L(a[j], b[j], c[j], y)
    x := L(a[j], b[j], c[j], x)
    w := L(a[j], b[j], c[j], w)
end for

z := z ⊕ k[16][3]
y := y ⊕ k[16][2]
x := x ⊕ k[16][1]
w := w ⊕ k[16][0]
```
## key expansion (just for reference)
for i = 0..15
j ← i mod 2
k[i][3] ← K[4j+3], k[i][2] ← K[4j+2], k[i][1] ← K[4j+1], k[i][0] ← K[4j+0]
(K[1], K[0]) ← M(1, 3,K[1],K[0])
(K[3], K[2]) ← M(9,28,K[3],K[2])
(K[5], K[4]) ← M(1, 3,K[5],K[4])
(K[7], K[6]) ← M(9,28,K[7],K[6]), K[7] ← K[7] ⊕ i
if (j = 0)
T ← K[1], K[1] ← K[2], K[2] ← T
T ← K[5], K[5] ← K[6], K[6] ← T
else
T ← K[1], K[1] ← K[4], K[4] ← T
T ← K[3], K[3] ← K[6], K[6] ← T
end if
end for
k[16][3] ← K[3], k[16][2] ← K[2], k[16][1] ← K[1], k[16][0] ← K[0]

---

## Notation

- `S_x^n X` means rotate word X left by n bits, then right by n bits, as per the S operation defined in the algorithm.
- `⊕` is bitwise XOR.
- `&` is bitwise AND.
- `‖` is concatenation (if used in context of two values; for 32-bit values, treat accordingly).
- Indices and ranges are zero-based.

---

**End of specification**
