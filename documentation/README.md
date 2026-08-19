# Implementing New Ciphers in CiVerLy

This directory contains reference implementations of ciphers built from CiVerLy components. Follow the procedure below to add a new cipher in the same style and compatible with the existing modeling pipeline. The checklist is intentionally concrete so a new cipher can be dropped in with minimal guesswork.

## 1) Choose the right base class

Pick the lowest class in the cipher hierarchy that matches your design. This maximizes supported modeling options.

Common entry points live in these modules:

- `civerly.cipher.Cipher`: the general DAG container.
- `civerly.sboxcipher.SBoxCipher`: S-box-oriented ciphers with MILP support.
- `civerly.wordbasedcipher.WordBasedCipher`: word-indexed wiring helper.
- `civerly.wordsboxcipher.WordSBoxCipher`: word-based S-box ciphers with wordwise MILP support.
- `civerly.aeslike.AESlike`: rectangular-state ciphers with AES-style column layout.
- `civerly.component`: component classes such as `SBox_CVL`, `LinearLayer_CVL`, `PermuteLayer_CVL`, `RotateLayer_CVL`, `RoundkeyXOR_CVL`, `XOR_CVL`, `I_CVL`, `ModAdd_CVL`, and `AND_CVL`.

- `Cipher`: most general, allows any components, but MILP is not supported.
- `SBoxCipher`: only S-box nonlinearity; supports SAT and MILP (bitwise).
- `WordBasedCipher`: enforces word sizes; SAT only.
- `WordSBoxCipher`: word-based + S-boxes; supports SAT and MILP (bitwise and wordwise).
- `AddRX` / `AndRX`: word-based with modular add / AND nonlinearity; SAT only.
- `AESlike`: rectangular state, word-based S-boxes, and column-wise MixColumn-style linear layers; supports SAT and MILP (bitwise and wordwise).

Pitfall: if you add `ModAdd_CVL` or `AND_CVL` to an `SBoxCipher` or `WordSBoxCipher`, `add_subcipher` will raise a `TypeError`.

Rule of thumb: if the cipher can be described as only S-boxes + linear layers + permutations, use `SBoxCipher` or `WordSBoxCipher`. If it needs modular addition or AND, use `AddRX` / `AndRX` (SAT only). If it uses a rectangular state matrix with MixColumn-like diffusion, use `AESlike` to unlock wordwise MILP.

If you are matching an existing implementation, the usual patterns are:

- `aes.py` for `AESlike`.
- `present.py` for `WordSBoxCipher`.
- `abc.py` for `SBoxCipher` with explicit round constants and layered subciphers.
- `skinny.py` for key-schedule subciphers and word-oriented state layouts.

## 2) Pick a file name and public class name

- Use `snake_case.py` for the file (e.g., `toy_cipher.py`).
- Use `CIPHERNAME_CVL` for the public class (e.g., `TOYCIPHER_CVL`).
- Implement `__new__` to return the underlying cipher object, matching existing implementations.

Recommended layout inside the file:

1. Imports (components and Sage helpers).
2. Public class (for example `PRESENT_CVL`).
3. Helper subciphers or functions as class methods (if needed).
4. Doctests inside the class docstring.

## 3) Build the cipher as a DAG

CiVerLy ciphers are constructed by adding subciphers/components to a directed acyclic graph (DAG). The typical flow is:

1. Initialize the cipher instance (from the chosen class).
2. Build reusable layers (S-box layers, linear layers, permutations, key schedule rounds) as their own ciphers.
3. Compose a round function from those layers.
4. Apply the round function in a loop for `R` rounds.
5. Call `add_output` on the final node(s).

Edge mapping details:

- An edge is a tuple `(node, (src_index, dst_index))`.
- `src_index` and `dst_index` are bit positions (or word positions if you work in a word-based cipher). For word-based ciphers, positions are word indices, not bit indices.
- The input node is always `cipher.IN` and outputs must be wired explicitly.

Pitfall: overlapping or missing edges often produce silently wrong behavior or `is_valid == False`. Use a quick encrypt test vector to catch indexing mistakes.

Pitfall: if you do not call `add_output` for all outputs, `is_valid` remains false and evaluation/modeling fails.

## 4) Sliceable round construction

Design the cipher so that individual rounds or round ranges can be extracted for isolated analysis. This is essential for analyzing truncated differentials, bounding probabilities over specific round intervals, or comparing trails across partial cipher variants.

Slicing parameters:

- The constructor may keep an `R` parameter that sets the total number of rounds.
- It must also be possible to specify a round range through a `start` and an `end` parameter. These two parameters must always be accepted together; a constructor that accepts only one of them is not allowed.
- `R` and the pair `(start, end)` are mutually exclusive: if `start` and `end` are provided, `R` must not be used to override the range, and vice versa. The constructor should raise an error when both are given together.
- The cipher must be sliceable. Preferably this is achieved directly through the `start` and `end` constructor parameters. Depending on the cipher structure, an equivalent technique (for example a dedicated slicing helper or explicit round-indexed DAG construction) may be more suitable, but the user-facing API must still allow extraction of a contiguous round range without manual DAG rewiring.

Guidelines:

- Build each round as a named subcipher so that round boundaries are explicit in the DAG. Avoid flattening multiple rounds into a single anonymous subcipher.
- If the round function is uniform, construct it once and add it repeatedly with `add_subcipher`, but ensure each instantiation is wired independently so tools can slice between any two round nodes.
- Provide an `R` parameter (total number of rounds) and document whether the constructor accepts `start`/`end` or if slicing is done through another mechanism.
- When adding outputs, ensure intermediate round states can be exposed if the analysis tool supports it. At minimum, the final round must terminate with `add_output`.
- If round constants or keys vary per round, store them in a list indexed by round number so that a slice from round `r_start` to round `r_end` can retrieve the correct constants without recomputing the full schedule.

Round slicing in practice:

- Some modeling pipelines expect a contiguous subgraph from round `a` to round `b`. Keeping the DAG layered by round makes this extraction straightforward.
- If the cipher has an initial or final whitening layer, model these as separate subciphers (or as round 0 and round `R+1`) so they do not interfere with round-indexed slicing.
- Test slicing by extracting a sub-cipher for rounds 2–9 (or 1–10) and verifying that `is_valid` remains true and that test vectors for the full cipher can be reproduced by composing the slices.

## 5) Model-friendly component choices

Use CiVerLy components whenever possible to keep compatibility with modeling:

- `SBox_CVL` from `civerly.component` for S-boxes; this is the safest choice if you want MILP support.
- `LinearLayer_CVL` for binary diffusion matrices over GF(2).
- `PermuteLayer_CVL` for permutations and ShiftRows-like layers; set `word_coarseness` when the permutation acts on words instead of bits.
- `RotateLayer_CVL` and `I_CVL` for word-level operations and simple byte/word reshuffling.
- `RoundkeyXOR_CVL` or `XOR_CVL` for key mixing and Feistel-style combine steps.
- `ModAdd_CVL` and `AND_CVL` only when you intentionally target `AddRX` / `AndRX`.

Pitfalls:

- `LinearLayer_CVL` expects a binary matrix over GF(2). Do not pass an integer matrix or a list of rows without converting to GF(2).
- Word-based ciphers require input/output sizes that are multiples of the word size.
- `SBoxCipher` and `WordSBoxCipher` reject `ModAdd_CVL` and `AND_CVL` subciphers.
- AES-like ciphers require MixColumn-like layers to operate per column.
- `PermuteLayer_CVL` can act on words or bits. Always set `word_coarseness` to match the cipher word size if you expect word-level permutations.
- Reusing the same mutable component object across unrelated layers can lead to confusing names or shared state; prefer building dedicated layer ciphers for repeated structures.

## 5) AES-like indexing and layout

`AESlike` uses column-wise indexing of the state (AES convention). If the reference cipher uses row-wise indexing (common in some designs), you must transpose before and after ShiftRows-like steps. If you skip this, trails and test vectors will not match.

The manual also makes one important distinction explicit: `LinearLayer_CVL` objects in an `AESlike` cipher must act on a full column, but `PermuteLayer_CVL` may act on the whole state, which is why ShiftRows-style layers stay separate from MixColumn-style layers.

Suggested practice:

- Document the chosen indexing scheme in the class docstring.
- Keep a small helper permutation for transpose operations, so it is visible and easy to review.

## 6) Key schedule strategy

Decide whether the key schedule is modeled explicitly. If you only need fixed-round testing or do not analyze related-key behavior, use constants in `RoundkeyXOR_CVL` and pass `rks` to the constructor. If the key schedule matters to your analysis, model it as a dedicated subcipher instead of hard-coding the constants in the round function.

Key schedule encapsulation:

- Implement the key schedule as a class method. This method should only be usable from the constructor or from other internal helper functions; it is not part of the public cipher API.
- The constructor should accept a master key (`master_key`), from which the round keys are derived using the internal key-schedule method.
- Providing a master key and providing explicit round keys (`rks`) are mutually exclusive. The constructor must raise an error when both are supplied.

Practical rule: if the examples in `skinny.py` or `abc.py` set round constants on a node before each round, follow that pattern; if the round key is fixed and externally known, a constant XOR is usually enough.

## 7) Provide tests and examples

Follow the existing pattern in `aes.py`, `present.py`, and `abc.py`:

- Add doctests in the class docstring for:
  - basic encryption (test vectors),
  - modeling options (if relevant),
  - sanity checks (e.g., `Unnamed Component` should not appear in trails).

- Include at least one example that imports the public class from `civerly.cipher_implementations.<cipher_name>` and one example that uses `civerly.util.int_to_vec` / `vec_to_int` for round-trip verification.
- If the cipher supports modeling, show the relevant `MODEL_OPTIONS` settings from `civerly.model_options` and use `analyse`, `model`, or `generate_report` as appropriate.

Keep doctests short and scoped. Use `# optional - solver` tags where external solvers are required.

Recommended minimum test set:

- One encryption test with a known test vector.
- One test that runs `analyse` or `model` with a supported solver (optional tag).
- One test that calls `get_trail` and asserts that no unnamed components appear.

## 8) Minimal template

Below is a minimal structure showing the expected style:

```python
from civerly.sboxcipher import SBoxCipher
from civerly.component import SBox_CVL, PermuteLayer_CVL
from sage.crypto.sbox import SBox

class TOYCIPHER_CVL:
    def __init__(self, R=4, start=1, end=None, master_key=None, rks=None, name=None):
        if end is None:
            end = R
        if start is not None and end is not None and R != end - start + 1:
            raise ValueError("R cannot be combined with an explicit (start, end) range")
        if master_key is not None and rks is not None:
            raise ValueError("master_key and rks are mutually exclusive")
        if rks is None:
            rks = [0x0 for _ in range(R)]
        if name is None:
            name = "TOYCIPHER"

        cipher = SBoxCipher(64, 64, name=name)

        # Build layers
        sbox = SBox_CVL(SBox([0x0, 0x1, 0x2, 0x3, 0x4, 0x5, 0x6, 0x7,
                              0x8, 0x9, 0xa, 0xb, 0xc, 0xd, 0xe, 0xf]))
        perm = PermuteLayer_CVL(list(range(16)))

        round_fn = SBoxCipher(64, 64, name="round")
        node_s = round_fn.add_subcipher(sbox, [(round_fn.IN, (i, i)) for i in range(4)])
        node_p = round_fn.add_subcipher(perm, [(node_s, (i, i)) for i in range(16)])
        round_fn.add_output([(node_p, (i, i)) for i in range(64)])

        node = cipher.IN
        for r in range(R):
            node = cipher.add_subcipher(round_fn, [(node, (i, i)) for i in range(64)])
        cipher.add_output([(node, (i, i)) for i in range(64)])

        self.cipher = cipher

    def __new__(cls, *args, **kwargs):
        instance = super(TOYCIPHER_CVL, cls).__new__(cls)
        instance.__init__(*args, **kwargs)
        return instance.cipher
```

Adjust word sizes, state layout, and components as required by the design.

When you add multiple parallel instances of a component, prefer building a dedicated layer cipher (S-box layer, linear layer, etc.). This keeps naming consistent and makes trails readable.

## 9) Modeling options and performance notes

- Wordwise MILP is much faster than bitwise MILP, but only available for `WordSBoxCipher` and `AESlike`.
- `LINEAR_LAYER_MODELING.GENERALIZED_WORDWISE` may require external solving of an auxiliary MILP. Provide a solver or prepare for a two-stage run as shown in `aes.py`.
- If the linear layer is a word permutation, `LINEAR_LAYER_MODELING.BRANCH_NUMBER` may be too loose. Consider bitwise modeling for precise trails.
- For SAT-based analyses with S-boxes, use `SBOX_MODELING.LOGICAL_COND_ESPRESSO` for accurate constraints, but expect longer preprocessing.

The generated reports also follow the same distinction: AESlike models are rendered on a rectangular state, while general `WordSBoxCipher` reports show a flat word state. That difference is useful to keep in mind when you choose the base class and the state layout.

## 10) Common pitfalls checklist

- Wrong cipher class (MILP suddenly unavailable).
- Missing or incomplete `add_output` calls.
- State indexing mismatch (AESlike row/column order).
- Word size not matching component input/output sizes.
- Reusing mutable component instances across different layers incorrectly.
- Round constants set on the wrong node or not reset per round.
- Using bit indices where word indices are expected (and vice versa).
- Forgetting to set `word_coarseness` for permutations in word-based ciphers.
- Accidentally wiring round keys to state words in the wrong order.
- Leaving default names for subciphers, which makes trails harder to interpret.
- Using `WordBasedCipher.add_subcipher()` edges like bit edges instead of word edges; the method expands them internally.
- Assuming SAT supports wordwise modeling; wordwise MILP is the supported word-level path.
- Passing a non-binary matrix into `LinearLayer_CVL` or a linear layer whose dimensions do not match the state layout.
- Forgetting that AES-like linear layers must be column-aligned and sized to one state column.
- Treating `get_trail()` output as trustworthy when `Unnamed Component` still appears; that usually means a naming or wiring problem remains.
- Combining `R` with `start`/`end` in the constructor instead of making them mutually exclusive.
- Supplying both `master_key` and `rks` to the constructor instead of choosing one key input path.

## 11) Where to look for examples

- `aes.py`: `AESlike` construction, MixColumn modeling, and column-wise indexing.
- `present.py`: `WordSBoxCipher`, permutation layers, and wordwise modeling tradeoffs.
- `skinny.py`: key schedule subciphers, LFSR modeling, and round-constant wiring.
- `abc.py`: layered `SBoxCipher` construction, round constants, and repeated subcipher naming.

## 12) Related docs pages

The docs tree already contains focused reference pages for the same topics this guide covers:

- `docs/source/user_manual/implement_cipher.rst` explains the class hierarchy, allowed components, and the AESlike column-wise rules.
- `docs/source/user_manual/model_cipher.rst` covers the modeling workflow and solver choices.
- `docs/source/user_manual/generate_report.rst` shows how report output differs for bitwise, wordwise, and AESlike models.
- `docs/source/documentation/component.rst` is the component reference for `SBox_CVL`, `LinearLayer_CVL`, `PermuteLayer_CVL`, `RotateLayer_CVL`, `RoundkeyXOR_CVL`, `XOR_CVL`, `ModAdd_CVL`, and `AND_CVL`.
- `docs/source/documentation/sboxcipher.rst`, `docs/source/documentation/wordsboxcipher.rst`, and `docs/source/documentation/aeslike.rst` document the main cipher classes.
