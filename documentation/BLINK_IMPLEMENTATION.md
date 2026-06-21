# Blink Cipher Implementation for CiVerLy

## Overview

This document describes the implementation of the **Blink tweakable block cipher** in CiVerLy. Blink is a low-latency tweakable block cipher based on the THF (Tweakable Hasher Framework) construction, supporting both 64-bit and 128-bit block sizes.

## Implementation Details

### File Location

The implementation is located at:
```
src/civerly/cipher_implementations/blink.py
```

### Classes

Two main cipher classes are implemented:

1. **`BLINK64_CVL`**: 64-bit variant
   - 16 nibbles (4-bit words)
   - 4 columns of 4 nibbles each
   - Default: 14 rounds

2. **`BLINK128_CVL`**: 128-bit variant
   - 32 nibbles (4-bit words)
   - 8 columns of 4 nibbles each
   - Default: 14 rounds

### Cipher Architecture

Both variants follow the same round structure defined by the Blink specification:

**Round Function**: R = P ◦ AC ◦ AK ◦ M ◦ S

Where:
- **S**: S-box layer (16 parallel 4-bit S-boxes per column)
- **M**: MixColumn layer (column-wise diffusion)
- **AK**: Round key addition
- **AC**: Round constant addition
- **P**: Shuffle permutation layer

### Components

#### 1. S-Box Layer (`SBoxLayer`)
- **Implementation**: `WordSBoxCipher` with 16 (or 32 for 128-bit) parallel 4-bit S-boxes
- **S-Box Values** (from Blink spec): `[0x1, 0x0, 0x9, 0x3, 0x8, 0x5, 0xe, 0x7, 0x4, 0x2, 0xc, 0xb, 0xa, 0xf, 0x6, 0xd]`
- **Property**: The S-box is involutory (S(S(x)) = x)
- **Component**: `SBox_CVL` from civerly.component

#### 2. MixColumn Layer (`MixColumn`)
- **Implementation**: `LinearLayer_CVL` over GF(2)
- **Matrix**: Block-diagonal structure with independent 4×4 Midori matrices per column
  ```
  M = [[0, 1, 1, 1],
       [1, 0, 1, 1],
       [1, 1, 0, 1],
       [1, 1, 1, 0]]
  ```
- **Size**:
  - 64-bit: 16×16 block-diagonal matrix
  - 128-bit: 32×32 block-diagonal matrix
- **Branch Numbers**: Differential = 5, Linear = 5

#### 3. Key Addition (`KeyAdd`)
- **Implementation**: `RoundkeyXOR_CVL`
- **Operation**: XOR with round key

#### 4. Shuffle/Permutation Layer (`Shuffle`)
- **Implementation**: `PermuteLayer_CVL` with word coarseness = 4
- **64-bit permutation**: `[0, 5, 11, 10, 1, 6, 4, 13, 2, 12, 9, 15, 3, 7, 14, 8]`
- **128-bit permutation**: `[5, 12, 4, 1, 17, 9, 10, 16, 28, 14, 21, 22, 11, 27, 8, 13, 2, 25, 18, 3, 30, 6, 19, 20, 0, 23, 24, 31, 7, 15, 29, 26]`

### Class Hierarchy

```
BLINK64_CVL
  └─ __init__()    // Cipher construction
     ├─ SBox_CVL   // 4-bit S-boxes
     ├─ WordSBoxCipher (sboxlayer)
     ├─ LinearLayer_CVL (mixcolumn)
     ├─ PermuteLayer_CVL (shuffle_perm)
     ├─ RoundkeyXOR_CVL (key_add)
     └─ WordSBoxCipher (full cipher)

BLINK128_CVL
  └─ Similar structure with 128-bit parameters
```

### Implementation Pattern

The implementation follows the standard CiVerLy pattern used by other ciphers (AES, PRESENT):

1. **Component Creation**: Build reusable components (S-box layer, MixColumn, etc.)
2. **Round Function**: Compose components into a single round
3. **Main Cipher**: Apply round function repeatedly with different round keys
4. **Output**: Add final key and collect outputs

### Key Features

- **Word-Based**: Uses `WordSBoxCipher` with 4-bit word size
- **Bitwise MILP Support**: Can be analyzed using MILP solvers
- **Column-Wise MixColumn**: Efficient implementation with block-diagonal matrix
- **Flexible Round Count**: Supports any number of rounds
- **Customizable Keys**: Accepts round key array `rks`

## Usage Examples

### Basic Instantiation (64-bit)

```python
from civerly.cipher_implementations.blink import BLINK64_CVL
from civerly.util import int_to_vec, vec_to_int

# Create cipher with default 14 rounds
blink = BLINK64_CVL(R=14)

# Encrypt
plaintext = int_to_vec(0x0123456789abcdef, 64)
ciphertext = blink(plaintext)
print(len(ciphertext))  # 64 bits
```

### Basic Instantiation (128-bit)

```python
from civerly.cipher_implementations.blink import BLINK128_CVL
from civerly.util import int_to_vec, vec_to_int

# Create cipher with 10 rounds
blink = BLINK128_CVL(R=10)

# Encrypt
plaintext = int_to_vec(0x0123456789abcdef0fedcba987654321, 128)
ciphertext = blink(plaintext)
print(len(ciphertext))  # 128 bits
```

### Cryptanalysis with MILP

```python
from civerly.cipher_implementations.blink import BLINK64_CVL
from civerly.model_options import *
from pathlib import Path
import tempfile

blink = BLINK64_CVL(R=4)

with tempfile.TemporaryDirectory() as tmpdir:
    model_options = MODEL_OPTIONS(
        cryptanalysis=CRYPTANALYSIS.DIFFERENTIAL,
        optimization=OPTIMIZATION.MILP,
        granularity=GRANULARITY.WORDWISE,
        linear_layer_modeling=LINEAR_LAYER_MODELING.BRANCH_NUMBER,
        milp_solver=SCIP_CVL(),
        path=Path(tmpdir))
    
    # Analyze differential characteristics
    blink.analyse(model_options)
    
    # Generate report
    blink.generate_report(model_options)
```

## Implementation Notes

### Round Key Management

The implementation properly handles round keys:
- Round keys are passed as a list `rks` with length R+1 (one for each round plus final addition)
- Round keys are set on `RoundkeyXOR_CVL` nodes within the round function
- The final round key is applied after all rounds

### MixColumn Matrix Construction

For efficient implementation, the MixColumn matrix is constructed as a block-diagonal matrix:
- Each block corresponds to one column
- Independent 4×4 Midori matrices
- Maintains the nibble-wise structure of Blink

### Word-Based Cipher Structure

Blink is implemented as a `WordSBoxCipher` with `wordsize=4`:
- Each nibble is treated as a 4-bit word
- Word-based edges are used internally
- Supports efficient word-wise MILP modeling

## Verification

The implementation follows the official Blink specification and includes:
- Correct S-box values and properties
- Proper MixColumn matrix structure
- Accurate permutation patterns for both variants
- Correct round function composition

## Testing

Doctests are included in the class docstrings and can be run with Sage:

```bash
sage -t src/civerly/cipher_implementations/blink.py
```

Basic tests verify:
- Cipher instantiation
- Encryption with correct output length
- Round structure

## Integration with CiVerLy

The Blink implementation integrates seamlessly with CiVerLy's analysis tools:
- Supports differential and linear cryptanalysis
- Compatible with MILP and SAT solvers
- Generates trails and reports
- Can be composed with other ciphers

## References

- **Specification**: Blink: THF: Designing Low-Latency Tweakable Block Ciphers
- **S-Box**: 4-bit involutory S-box from Blink specification
- **MixColumn**: Midori MixColumn matrix adapted for Blink
- **CiVerLy Documentation**: See [implementation guide](README.md)
