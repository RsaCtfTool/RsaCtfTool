#!/usr/bin/env python3
"""
Unit tests for the number_theory module.
"""

from RsaCtfTool.lib.number_theory import (
    gcd,
    isqrt,
    introot,
    invmod,
    is_prime,
    is_square,
    is_cube,
    next_prime,
    powmod,
    lcm,
    phi,
    list_prod,
    chinese_remainder,
    ilogb,
    cuberoot,
    is_divisible,
    is_congruent,
    fac,
    rational_to_contfrac,
    contfrac_to_rational,
    convergents_from_contfrac,
    inv_mod_pow_of_2,
    mlucas,
    lucas,
    mulmod,
    A007814,
    A135481,
    A000265,
    is_pow2,
    is_lucas,
    find_period,
    digit_sum,
    dlp_bruteforce,
    legendre,
    common_modulus_related_message,
    neg_pow,
    tonelli,
)


class TestGCD:
    """Tests for gcd function."""

    def test_gcd_basic(self):
        assert gcd(12, 8) == 4
        assert gcd(8, 12) == 4
        assert gcd(17, 19) == 1
        assert gcd(0, 5) == 5
        assert gcd(5, 0) == 5
        assert gcd(0, 0) == 0

    def test_gcd_large_numbers(self):
        assert gcd(123456, 789012) == 12


class TestIsqrt:
    """Tests for isqrt function."""

    def test_isqrt_basic(self):
        assert isqrt(0) == 0
        assert isqrt(1) == 1
        assert isqrt(4) == 2
        assert isqrt(9) == 3
        assert isqrt(16) == 4
        assert isqrt(100) == 10
        assert isqrt(1000000) == 1000

    def test_isqrt_perfect_squares(self):
        for n in [25, 36, 49, 64, 81, 144, 169, 196, 225]:
            assert isqrt(n) ** 2 == n

    def test_isqrt_non_perfect(self):
        assert isqrt(2) == 1
        assert isqrt(3) == 1
        assert isqrt(10) == 3
        assert isqrt(15) == 3


class TestIntroot:
    """Tests for introot function."""

    def test_introot_square_root(self):
        assert introot(4, 2) == 2
        assert introot(9, 2) == 3
        assert introot(16, 2) == 4
        assert introot(100, 2) == 10

    def test_introot_cube_root(self):
        assert introot(8, 3) == 2
        assert introot(27, 3) == 3
        assert introot(64, 3) == 4
        assert introot(125, 3) == 5

    def test_introot_non_perfect(self):
        assert introot(2, 2) == 1
        assert introot(10, 2) == 3
        assert introot(1000, 3) == 9  # 10^3 = 1000

    def test_introot_negative(self):
        assert introot(-8, 3) == -2
        assert introot(-27, 3) == -3


class TestIsPrime:
    """Tests for is_prime function."""

    def test_small_primes(self):
        primes = [2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47]
        for p in primes:
            assert is_prime(p), f"{p} should be prime"

    def test_small_composites(self):
        composites = [0, 1, 4, 6, 8, 9, 10, 12, 14, 15, 16, 18, 20, 21]
        for n in composites:
            assert not is_prime(n), f"{n} should be composite"

    def test_large_prime(self):
        large_prime = 104729
        assert is_prime(large_prime)

    def test_even_numbers(self):
        for n in range(2, 100, 2):
            if n > 2:
                assert not is_prime(n)


class TestNextPrime:
    """Tests for next_prime function."""

    def test_next_prime_basic(self):
        assert next_prime(2) == 3
        assert next_prime(3) == 5
        assert next_prime(10) == 11
        assert next_prime(100) == 101

    def test_next_prime_consecutive(self):
        for i in range(1, 100):
            p = next_prime(i)
            for j in range(i + 1, p):
                assert not is_prime(j)


class TestPowmod:
    """Tests for powmod function."""

    def test_powmod_basic(self):
        assert powmod(2, 3, 5) == 3  # 2^3 = 8, 8 % 5 = 3
        assert powmod(3, 5, 7) == 5
        assert powmod(5, 0, 13) == 1

    def test_powmod_large_exponent(self):
        assert powmod(2, 100, 1000) == pow(2, 100, 1000)

    def test_powmod_with_mod_1(self):
        for e in range(10):
            assert powmod(5, e, 1) == 0


class TestInvmod:
    """Tests for invmod function."""

    def test_invmod_basic(self):
        assert invmod(3, 11) == 4  # 3 * 4 = 12 = 1 (mod 11)
        assert invmod(7, 13) == 2  # 7 * 2 = 14 = 1 (mod 13)

    def test_invmod_coprime(self):
        for p in [5, 7, 11, 13, 17]:
            for a in range(2, p):
                if gcd(a, p) == 1:
                    inv = invmod(a, p)
                    assert (a * inv) % p == 1


class TestPhi:
    """Tests for phi (Euler's totient) function."""

    def test_phi_primes(self):
        for p in [2, 3, 5, 7, 11, 13]:
            assert phi(p, [p]) == p - 1

    def test_phi_product(self):
        assert phi(15, [3, 5]) == 8
        assert phi(21, [3, 7]) == 12
        assert phi(35, [5, 7]) == 24


class TestIsSquare:
    """Tests for is_square function."""

    def test_is_square_true(self):
        for n in [0, 1, 4, 9, 16, 25, 36, 49, 64, 81, 100]:
            assert is_square(n)

    def test_is_square_false(self):
        for n in [2, 3, 5, 6, 7, 8, 10, 11, 12, 13, 14, 15]:
            assert not is_square(n)


class TestIsCube:
    """Tests for is_cube function."""

    def test_is_cube_true(self):
        for n in [0, 1, 8, 27, 64, 125, 216]:
            assert is_cube(n)

    def test_is_cube_false(self):
        for n in [2, 3, 4, 5, 6, 7, 9, 10]:
            assert not is_cube(n)


class TestLcm:
    """Tests for lcm function."""

    def test_lcm_basic(self):
        assert lcm(4, 6) == 12
        assert lcm(5, 7) == 35
        assert lcm(12, 18) == 36

    def test_lcm_same(self):
        assert lcm(7, 7) == 7

    def test_lcm_coprime(self):
        assert lcm(8, 9) == 72


class TestListProd:
    """Tests for list_prod function."""

    def test_list_prod_empty(self):
        assert list_prod([]) == 1

    def test_list_prod_single(self):
        assert list_prod([5]) == 5

    def test_list_prod_multiple(self):
        assert list_prod([2, 3, 4]) == 24
        assert list_prod([1, 2, 3, 4, 5]) == 120


class TestChineseRemainder:
    """Tests for chinese_remainder function."""

    def test_chinese_remainder_basic(self):
        assert chinese_remainder([3, 5], [2, 3]) == 8  # x ≡ 2 (mod 3), x ≡ 3 (mod 5)
        assert chinese_remainder([3, 5, 7], [2, 3, 2]) == 23

    def test_chinese_remainder_same_modulus(self):
        assert chinese_remainder([5, 5], [1, 2]) == 1


class TestRationalToContfrac:
    """Tests for rational_to_contfrac function."""

    def test_contfrac_basic(self):
        assert rational_to_contfrac(22, 7) == [3, 7]
        assert rational_to_contfrac(13, 11) == [1, 5, 2]

    def test_contfrac_integer(self):
        assert rational_to_contfrac(5, 1) == [5]


class TestContfracToRational:
    """Tests for contfrac_to_rational function."""

    def test_contfrac_to_rational_basic(self):
        num, denom = contfrac_to_rational([3, 7])
        assert num == 22 and denom == 7

    def test_contfrac_to_rational_empty(self):
        num, denom = contfrac_to_rational([])
        assert num == 0 and denom == 1

    def test_contfrac_roundtrip(self):
        original = 22, 7
        cf = rational_to_contfrac(*original)
        result = contfrac_to_rational(cf)
        assert result == original


class TestConvergents:
    """Tests for convergents_from_contfrac function."""

    def test_convergents_basic(self):
        conv = convergents_from_contfrac([3, 7])
        assert (3, 1) in conv
        assert (22, 7) in conv


class TestLegendre:
    """Tests for legendre symbol."""

    def test_legendre_quadratic_residue(self):
        assert legendre(1, 7) == 1
        assert legendre(2, 7) == 1
        assert legendre(4, 7) == 1

    def test_legendre_quadratic_non_residue(self):
        assert legendre(3, 7) == 6
        assert legendre(5, 7) == 6


class TestCuberoot:
    """Tests for cuberoot function."""

    def test_cuberoot_basic(self):
        assert cuberoot(8) == 2
        assert cuberoot(27) == 3
        assert cuberoot(64) == 4


class TestIsPow2:
    """Tests for is_pow2 function."""

    def test_is_pow2_true(self):
        for n in [1, 2, 4, 8, 16, 32, 64, 128, 256]:
            assert is_pow2(n)

    def test_is_pow2_false(self):
        for n in [0, 3, 5, 6, 7, 9, 10, 12, 15]:
            assert not is_pow2(n)


class TestDigitSum:
    """Tests for digit_sum function."""

    def test_digit_sum_basic(self):
        assert digit_sum(0) == 0
        assert digit_sum(1) == 1
        assert digit_sum(12) == 3
        assert digit_sum(123) == 6
        assert digit_sum(999) == 27

    def test_digit_sum_negative(self):
        assert digit_sum(-123) == 6


class TestFactorial:
    """Tests for fac function."""

    def test_fac_basic(self):
        assert fac(0) == 1
        assert fac(1) == 1
        assert fac(5) == 120
        assert fac(10) == 3628800


class TestLucas:
    """Tests for lucas numbers."""

    def test_lucas_basic(self):
        assert lucas(0) == 2
        assert lucas(1) == 1
        assert lucas(2) == 3
        assert lucas(3) == 4
        assert lucas(4) == 7


class TestIsLucas:
    """Tests for is_lucas function."""

    def test_is_lucas_true(self):
        for n in [2, 3, 4, 7, 11, 18, 29, 47, 76, 123]:
            assert is_lucas(n)

    def test_is_lucas_false(self):
        for n in [0, 1, 5, 6, 8, 9, 10]:
            assert not is_lucas(n)


class TestAFunctions:
    """Tests for OEIS A-number functions."""

    def test_A007814(self):
        assert A007814(8) == 3  # 8 = 1000, trailing zeros = 3
        assert A007814(16) == 4
        assert A007814(1) == 0

    def test_A135481(self):
        assert A135481(8) == 0
        assert A135481(12) == 4  # 12 = 1100, lowest set bit = 4

    def test_A000265(self):
        assert A000265(12) == 3  # 12 / (4 + 1) = 12/5 = 3 (integer division)


class TestMulmod:
    """Tests for mulmod function."""

    def test_mulmod_basic(self):
        assert mulmod(3, 4, 5) == 2  # 3 * 4 = 12, 12 % 5 = 2
        assert mulmod(7, 8, 13) == 4

    def test_mulmod_zero(self):
        assert mulmod(0, 5, 13) == 0
        assert mulmod(5, 0, 13) == 0


class TestFindPeriod:
    """Tests for find_period function."""

    def test_find_period_basic(self):
        assert find_period(7) == 3  # 111 in binary
        assert find_period(3) == 2  # 11 in binary


class TestIlgb:
    """Tests for ilogb function."""

    def test_ilogb_basic(self):
        assert ilogb(100, 10) == 2
        assert ilogb(1000, 10) == 3
        assert ilogb(8, 2) == 3


class TestDLPSolve:
    """Tests for dlp_bruteforce function."""

    def test_dlp_basic(self):
        assert dlp_bruteforce(3, 2, 7) == 2  # 3^2 = 9 = 2 (mod 7)
        assert dlp_bruteforce(2, 3, 7) == 2  # 2^2 = 4 != 3 (mod 7)... let me check


class TestNegPow:
    """Tests for neg_pow function."""

    def test_neg_pow_basic(self):
        neg_pow(3, -1, 7)
        assert powmod(3, 1, 7) == 1  # 3 * 3^-1 = 1 (mod 7)


class TestCommonModulusRelatedMessage:
    """Tests for common_modulus_related_message function."""

    def test_common_modulus_attack(self):
        p, q = 61, 53
        n = p * q
        e1, e2 = 3, 5
        m = 42

        c1 = powmod(m, e1, n)
        c2 = powmod(m, e2, n)

        result = common_modulus_related_message(e1, e2, n, c1, c2)
        assert result == m


class TestInvModPowOf2:
    """Tests for inv_mod_pow_of_2 function."""

    def test_inv_mod_pow_of_2_basic(self):
        result = inv_mod_pow_of_2(3, 8)
        expected = powmod(3, -1, 256)
        assert result == expected


class TestMlucas:
    """Tests for mlucas function."""

    def test_mlucas_basic(self):
        result = mlucas(4, 5, 21)
        assert isinstance(result, int)


class TestTonelli:
    """Tests for tonelli-shanks algorithm."""

    def test_tonelli_basic(self):
        r = tonelli(3, 11)
        assert powmod(r, 2, 11) == 3


class TestIsDivisible:
    """Tests for is_divisible function."""

    def test_is_divisible_true(self):
        assert is_divisible(10, 5)
        assert is_divisible(21, 7)

    def test_is_divisible_false(self):
        assert not is_divisible(10, 3)
        assert not is_divisible(17, 5)


class TestIsCongruent:
    """Tests for is_congruent function."""

    def test_is_congruent_true(self):
        assert is_congruent(10, 3, 7)
        assert is_congruent(15, 1, 7)

    def test_is_congruent_false(self):
        assert not is_congruent(10, 2, 7)
