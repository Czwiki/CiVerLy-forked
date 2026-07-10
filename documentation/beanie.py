"""Simple Python port of the BEANIE reference implementation.

The functions mirror the C test vectors in documentation/testcases.c.
All state values are represented as plain Python integers.
"""

from __future__ import annotations


SBOX = (0, 4, 2, 11, 10, 12, 9, 8, 5, 15, 13, 3, 7, 1, 6, 14)
SBOX_INV = (0, 13, 2, 11, 1, 8, 14, 12, 7, 6, 4, 3, 5, 10, 15, 9)

ROUND_CONSTANTS = (
    (0x0, 0x0000000000000000),
    (0x0, 0x13198A2E03707344),
    (0x0, 0xA4093822299F31D0),
    (0x0, 0x082EFA98EC4E6C89),
    (0x0, 0x452821E638D01377),
    (0x0, 0xBE5466CF34E90C6C),
    (0x0, 0x7EF84F78FD955CB1),
    (0x0, 0x85840851F1AC43AA),
    (0x0, 0xC882D32F25323C54),
    (0x0, 0x64A51195E0E3610D),
)


def _sbox32(state: int) -> int:
    output = 0
    for column_index in range(2):
        column = (state >> (16 * column_index)) & 0xFFFF
        transformed = 0
        for shift in (12, 8, 4, 0):
            transformed |= SBOX[(column >> shift) & 0xF] << shift
        output |= transformed << (16 * column_index)
    return output


def _sbox32_inv(state: int) -> int:
    output = 0
    for column_index in range(2):
        column = (state >> (16 * column_index)) & 0xFFFF
        transformed = 0
        for shift in (12, 8, 4, 0):
            transformed |= SBOX_INV[(column >> shift) & 0xF] << shift
        output |= transformed << (16 * column_index)
    return output


def _shift32(state: int) -> int:
    shifted = state & 0xF0F0F0F0
    shifted |= (state & 0x0F0F0000) >> 16
    shifted |= (state & 0x00000F0F) << 16
    return shifted & 0xFFFFFFFF


def _xtime(value: int) -> int:
    return (0xF) & ((value << 1) ^ (((value >> 3) & 1) * 0x3))


def _multiply(value: int, factor: int) -> int:
    return (
        ((factor & 1) * value)
        ^ (((factor >> 1) & 1) * _xtime(value))
        ^ (((factor >> 2) & 1) * _xtime(_xtime(value)))
        ^ (((factor >> 3) & 1) * _xtime(_xtime(_xtime(value))))
    )


def _mix_columns(state: int) -> int:
    output = 0
    for column_index in range(2):
        column = (state >> (16 * column_index)) & 0xFFFF
        c0 = (column >> 12) & 0xF
        c1 = (column >> 8) & 0xF
        c2 = (column >> 4) & 0xF
        c3 = column & 0xF

        mixed = (
            ((_multiply(c0, 0x2) ^ _multiply(c1, 0x1) ^ _multiply(c2, 0x1) ^ _multiply(c3, 0x9)) << 12)
            | ((_multiply(c0, 0x1) ^ _multiply(c1, 0x4) ^ _multiply(c2, 0xF) ^ _multiply(c3, 0x1)) << 8)
            | ((_multiply(c0, 0xD) ^ _multiply(c1, 0x9) ^ _multiply(c2, 0x4) ^ _multiply(c3, 0x1)) << 4)
            | ((_multiply(c0, 0x1) ^ _multiply(c1, 0xD) ^ _multiply(c2, 0x1) ^ _multiply(c3, 0x2)) << 0)
        )
        output |= (mixed & 0xFFFF) << (16 * column_index)
    return output & 0xFFFFFFFF


def enc(state: int, round_keys: list[int] | tuple[int, ...], rounds: int) -> int:
    if rounds == 0:
        return state & 0xFFFFFFFF

    for round_index in range(rounds - 1):
        state ^= round_keys[round_index]
        state = _sbox32(state)
        state = _shift32(state)
        state = _mix_columns(state)

    state ^= round_keys[rounds - 1]
    state = _sbox32(state)
    state = _shift32(state)
    state ^= round_keys[rounds]
    return state & 0xFFFFFFFF


def dec(state: int, round_keys: list[int] | tuple[int, ...], rounds: int) -> int:
    if rounds == 0:
        return state & 0xFFFFFFFF

    state ^= round_keys[rounds]
    state = _shift32(state)
    state = _sbox32_inv(state)
    state ^= round_keys[rounds - 1]

    for round_index in range(rounds - 2, -1, -1):
        state = _mix_columns(state)
        state = _shift32(state)
        state = _sbox32_inv(state)
        state ^= round_keys[round_index]

    return state & 0xFFFFFFFF


def _sbox64(state: int) -> int:
    output = 0
    for shift in range(0, 64, 4):
        output |= SBOX[(state >> shift) & 0xF] << shift
    return output & 0xFFFFFFFFFFFFFFFF


def _prince_m_0(column: int) -> int:
    c0 = (column >> 12) & 0xF
    c1 = (column >> 8) & 0xF
    c2 = (column >> 4) & 0xF
    c3 = column & 0xF
    return (
        (((c0 & 0x7) ^ (c1 & 0xB) ^ (c2 & 0xD) ^ (c3 & 0xE)) << 12)
        | (((c0 & 0xB) ^ (c1 & 0xD) ^ (c2 & 0xE) ^ (c3 & 0x7)) << 8)
        | (((c0 & 0xD) ^ (c1 & 0xE) ^ (c2 & 0x7) ^ (c3 & 0xB)) << 4)
        | (((c0 & 0xE) ^ (c1 & 0x7) ^ (c2 & 0xB) ^ (c3 & 0xD)) << 0)
    ) & 0xFFFF


def _prince_m_1(column: int) -> int:
    c0 = (column >> 12) & 0xF
    c1 = (column >> 8) & 0xF
    c2 = (column >> 4) & 0xF
    c3 = column & 0xF
    return (
        (((c0 & 0xB) ^ (c1 & 0xD) ^ (c2 & 0xE) ^ (c3 & 0x7)) << 12)
        | (((c0 & 0xD) ^ (c1 & 0xE) ^ (c2 & 0x7) ^ (c3 & 0xB)) << 8)
        | (((c0 & 0xE) ^ (c1 & 0x7) ^ (c2 & 0xB) ^ (c3 & 0xD)) << 4)
        | (((c0 & 0x7) ^ (c1 & 0xB) ^ (c2 & 0xD) ^ (c3 & 0xE)) << 0)
    ) & 0xFFFF


def _prince_m(state: tuple[int, int]) -> tuple[int, int]:
    left, right = state

    left_columns = [
        left & 0xFFFF,
        (left >> 16) & 0xFFFF,
        (left >> 32) & 0xFFFF,
        (left >> 48) & 0xFFFF,
    ]
    right_columns = [
        right & 0xFFFF,
        (right >> 16) & 0xFFFF,
        (right >> 32) & 0xFFFF,
        (right >> 48) & 0xFFFF,
    ]

    left_columns = [
        _prince_m_0(left_columns[0]),
        _prince_m_1(left_columns[1]),
        _prince_m_1(left_columns[2]),
        _prince_m_0(left_columns[3]),
    ]
    right_columns = [
        _prince_m_0(right_columns[0]),
        _prince_m_1(right_columns[1]),
        _prince_m_1(right_columns[2]),
        _prince_m_0(right_columns[3]),
    ]

    left_out = 0
    right_out = 0
    for index, column in enumerate(left_columns):
        left_out |= column << (16 * index)
    for index, column in enumerate(right_columns):
        right_out |= column << (16 * index)
    return left_out, right_out


def _prince_shift(state: int) -> int:
    shifted = state & 0xF000F000F000F000
    for index in range(1, 4):
        row = state & (0xF000F000F000F000 >> (4 * index))
        shifted |= (row << (index * 16)) | (row >> (64 - index * 16))
    return shifted & 0xFFFFFFFFFFFFFFFF


def _feistel(state: tuple[int, int]) -> tuple[int, int]:
    left, right = state
    words = [
        left & 0xFFFFFFFF,
        (left >> 32) & 0xFFFFFFFF,
        right & 0xFFFFFFFF,
        (right >> 32) & 0xFFFFFFFF,
    ]
    new_words = [0, 0, 0, 0]
    new_words[0] = words[3]
    new_words[1] = words[1] ^ words[0]
    new_words[2] = words[1]
    new_words[3] = words[3] ^ words[2]
    return (
        ((new_words[1] & 0xFFFFFFFF) << 32) | (new_words[0] & 0xFFFFFFFF),
        ((new_words[3] & 0xFFFFFFFF) << 32) | (new_words[2] & 0xFFFFFFFF),
    )


def _tks_shift(state: tuple[int, int]) -> tuple[int, int]:
    left, right = state
    new_left = 0
    new_right = 0

    new_left |= left & 0xF000F000F000F000
    new_right |= right & 0xF000F000F000F000

    new_left |= ((left & 0x000000000F000F00) << 32) | ((right & 0x0F000F0000000000) >> 32)
    new_right |= ((right & 0x000000000F000F00) << 32) | ((left & 0x0F000F0000000000) >> 32)

    new_left |= right & 0x00F000F000F000F0
    new_right |= left & 0x00F000F000F000F0

    new_left |= ((left & 0x000F000F00000000) >> 32) | ((right & 0x00000000000F000F) << 32)
    new_right |= ((right & 0x000F000F00000000) >> 32) | ((left & 0x00000000000F000F) << 32)

    return new_left & 0xFFFFFFFFFFFFFFFF, new_right & 0xFFFFFFFFFFFFFFFF


def tweak_key_schedule(key: tuple[int, int], tweak: tuple[int, int], rounds: int) -> tuple[int, int]:
    if rounds == 0:
        return tweak

    tweak_left, tweak_right = tweak
    key_left, key_right = key

    for round_index in range(rounds):
        tweak_left ^= key_left
        tweak_right ^= key_right

        rc_left, rc_right = ROUND_CONSTANTS[round_index]
        tweak_left ^= rc_left
        tweak_right ^= rc_right

        tweak_left, tweak_right = _prince_m((tweak_left, tweak_right))
        tweak_left = _prince_shift(tweak_left)
        tweak_right = _prince_shift(tweak_right)
        tweak_left, tweak_right = _feistel((tweak_left, tweak_right))
        tweak_left, tweak_right = _tks_shift((tweak_left, tweak_right))

    tweak_left ^= key_left
    tweak_right ^= key_right

    rc_left, rc_right = ROUND_CONSTANTS[rounds]
    tweak_left ^= rc_left
    tweak_right ^= rc_right
    return tweak_left & 0xFFFFFFFFFFFFFFFF, tweak_right & 0xFFFFFFFFFFFFFFFF


def key_expansion(key: tuple[int, int], nr_keys: int) -> list[int]:
    if nr_keys <= 3:
        raise AssertionError

    left, right = key
    key_words = [
        (left >> 32) & 0xFFFFFFFF,
        left & 0xFFFFFFFF,
        (right >> 32) & 0xFFFFFFFF,
        right & 0xFFFFFFFF,
    ]

    round_keys = [0] * nr_keys
    round_keys[0] = key_words[0]
    round_keys[1] = key_words[1]
    round_keys[2] = key_words[2]
    round_keys[3] = key_words[3]

    if nr_keys > 4:
        round_keys[4] = round_keys[0] ^ round_keys[1]
    if nr_keys > 5:
        round_keys[5] = round_keys[2] ^ round_keys[3]
    if nr_keys > 6:
        round_keys[6] = round_keys[0] ^ round_keys[2]
    if nr_keys > 7:
        round_keys[7] = round_keys[1] ^ round_keys[3]
    if nr_keys > 8:
        round_keys[8] = round_keys[0] ^ round_keys[3]
    if nr_keys > 9:
        round_keys[9] = round_keys[1] ^ round_keys[2]

    return round_keys


def tests() -> None:
    state = 0x12345678
    assert _sbox32(state) == 0x42BAC985
    assert _sbox32_inv(state) == 0xD2B18EC7
    assert _shift32(state) == 0x16385274
    assert _mix_columns(state) == 0x1F43FD89

    tweak = (0x0123456789ABCDEF, 0xFEDCBA9876543210)
    assert _sbox64(tweak[0]) == 0x042BAC985FD3716E
    assert _sbox64(tweak[1]) == 0xE6173DF589CAB240

    prince_m_out = _prince_m(tweak)
    assert prince_m_out[0] == 0x3012456789ABFCDE
    assert prince_m_out[1] == 0xCFEDBA9876540321

    assert _prince_shift(tweak[0]) == 0x05AF49E38D27C16B

    feistel_out = _feistel(tweak)
    assert feistel_out[0] == 0x88888888FEDCBA98
    assert feistel_out[1] == 0x8888888801234567

    tks_shift_out = _tks_shift(tweak)
    assert tks_shift_out[0] == 0x09D44D908E53CA17
    assert tks_shift_out[1] == 0xF62BB26F71AC35E8

    round_keys = key_expansion(tweak, 10)
    assert round_keys[0] == 0x01234567
    assert round_keys[1] == 0x89ABCDEF
    assert round_keys[2] == 0xFEDCBA98
    assert round_keys[3] == 0x76543210
    assert round_keys[4] == 0x88888888
    assert round_keys[5] == 0x88888888
    assert round_keys[6] == 0xFFFFFFFF
    assert round_keys[7] == 0xFFFFFFFF
    assert round_keys[8] == 0x77777777
    assert round_keys[9] == 0x77777777

    print("All tests passed!")

tests()