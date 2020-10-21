from fastecdsa.curve import Curve
from fastecdsa.point import Point

from starkware.crypto.signature import (
    ALPHA, BETA, CONSTANT_POINTS, EC_ORDER, FIELD_PRIME, N_ELEMENT_BITS_HASH, SHIFT_POINT)

curve = Curve(
    'Curve0',
    FIELD_PRIME,
    ALPHA,
    BETA,
    EC_ORDER,
    *SHIFT_POINT)

LOW_PART_BITS = 248
LOW_PART_MASK = 2**248 - 1
HASH_SHIFT_POINT = Point(*SHIFT_POINT, curve=curve)
P_0 = Point(*CONSTANT_POINTS[2], curve=curve)
P_1 = Point(*CONSTANT_POINTS[2 + LOW_PART_BITS], curve=curve)
P_2 = Point(*CONSTANT_POINTS[2 + N_ELEMENT_BITS_HASH], curve=curve)
P_3 = Point(*CONSTANT_POINTS[2 + N_ELEMENT_BITS_HASH + LOW_PART_BITS], curve=curve)


def process_single_element(element: bytes, p1, p2) -> Point:
    assert len(element) == 32, 'Unexpected element length'

    val = int.from_bytes(element, 'big', signed=False)
    assert val < EC_ORDER, 'Element int value >= EC_ORDER'

    high_nibble = val >> LOW_PART_BITS
    low_part = val & LOW_PART_MASK

    return low_part * p1 + high_nibble * p2


def pedersen_hash_func(x: bytes, y: bytes) -> bytes:
    """
    Computes the Starkware version of the Pedersen hash of x and y.
    The hash is defined by:
        shift_point + x_low * P_0 + x_high * P1 + y_low * P2  + y_high * P3
    where x_low is the 248 low bits of x, x_high is the 4 high bits of x and similarly for y.
    shift_point, P_0, P_1, P_2, P_3 are constant points generated from the digits of pi.
    """
    return (HASH_SHIFT_POINT + process_single_element(x, P_0, P_1) +
            process_single_element(y, P_2, P_3)).x.to_bytes(32, 'big')


async def async_pedersen_hash_func(x: bytes, y: bytes) -> bytes:
    """
    Async variant of pedersen_hash_func.
    """

    return pedersen_hash_func(x, y)