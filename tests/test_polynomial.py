#!/usr/bin/env python3
"""
Unit tests for the polynomial module.
"""

import pytest

from RsaCtfTool.lib.polynomial import Polynomial, PolynomialDivisionError


MODULUS = 17


class TestPolynomialConstruction:
    """Tests for Polynomial construction and normalization."""

    def test_coefficients_are_reduced_modulo_modulus(self):
        polynomial = Polynomial([-1, 18, 34], MODULUS)

        assert polynomial == Polynomial([16, 1], MODULUS)

    def test_trailing_zeroes_are_removed(self):
        polynomial = Polynomial([1, 2, 0, 0], MODULUS)

        assert polynomial == Polynomial([1, 2], MODULUS)

    def test_zero_polynomial_is_canonical(self):
        polynomial = Polynomial([0, 0, 0], MODULUS)

        assert polynomial.is_zero()
        assert polynomial.degree == -1
        assert polynomial.leading_coefficient == 0
        assert polynomial == Polynomial([0], MODULUS)

    def test_modulus_is_required(self):
        with pytest.raises(TypeError):
            Polynomial([1])

    def test_invalid_modulus_fails(self):
        with pytest.raises(ValueError):
            Polynomial([1, 2], 0)

        with pytest.raises(ValueError):
            Polynomial([1, 2], -17)


class TestPolynomialEquality:
    """Tests for Polynomial equality."""

    def test_equal_polynomials(self):
        assert Polynomial([1, 2, 3], MODULUS) == Polynomial([1, 2, 3], MODULUS)

    def test_different_coefficients_are_not_equal(self):
        assert Polynomial([1, 2], MODULUS) != Polynomial([1, 3], MODULUS)

    def test_different_moduli_are_not_equal(self):
        assert Polynomial([1, 2], 17) != Polynomial([1, 2], 19)


class TestPolynomialProperties:
    """Tests for Polynomial properties."""

    def test_degree(self):
        polynomial = Polynomial([3, 5, 0, 7], MODULUS)

        assert polynomial.degree == 3

    def test_leading_coefficient(self):
        polynomial = Polynomial([3, 5, 0, 7], MODULUS)

        assert polynomial.leading_coefficient == 7


class TestPolynomialAddition:
    """Tests for polynomial addition."""

    def test_addition(self):
        p = Polynomial([1, 2, 3], MODULUS)
        q = Polynomial([4, 5], MODULUS)

        assert p + q == Polynomial([5, 7, 3], MODULUS)

    def test_addition_is_modular(self):
        p = Polynomial([16, 16], MODULUS)
        q = Polynomial([2, 3], MODULUS)

        assert p + q == Polynomial([1, 2], MODULUS)

    def test_addition_with_scalar(self):
        polynomial = Polynomial([1, 2], MODULUS)

        assert polynomial + 3 == Polynomial([4, 2], MODULUS)
        assert 3 + polynomial == Polynomial([4, 2], MODULUS)

    def test_addition_with_different_moduli_fails(self):
        p = Polynomial([1, 2], 17)
        q = Polynomial([3, 4], 19)

        with pytest.raises(ValueError):
            p + q

    def test_addition_with_invalid_operand_fails(self):
        polynomial = Polynomial([1, 2], MODULUS)

        with pytest.raises(TypeError):
            polynomial + "x"


class TestPolynomialSubtraction:
    """Tests for polynomial subtraction."""

    def test_subtraction(self):
        p = Polynomial([5, 7, 3], MODULUS)
        q = Polynomial([4, 5], MODULUS)

        assert p - q == Polynomial([1, 2, 3], MODULUS)

    def test_subtraction_is_modular(self):
        p = Polynomial([1, 1], MODULUS)
        q = Polynomial([3, 4], MODULUS)

        assert p - q == Polynomial([15, 14], MODULUS)

    def test_subtraction_with_scalar(self):
        polynomial = Polynomial([5, 2], MODULUS)

        assert polynomial - 3 == Polynomial([2, 2], MODULUS)
        assert 3 - polynomial == Polynomial([15, 15], MODULUS)

    def test_subtraction_with_different_moduli_fails(self):
        p = Polynomial([1, 2], 17)
        q = Polynomial([3, 4], 19)

        with pytest.raises(ValueError):
            p - q

    def test_subtraction_with_invalid_operand_fails(self):
        polynomial = Polynomial([1, 2], MODULUS)

        with pytest.raises(TypeError):
            polynomial - "x"


class TestPolynomialMultiplication:
    """Tests for polynomial multiplication."""

    def test_multiplication(self):
        p = Polynomial([1, 2], MODULUS)
        q = Polynomial([3, 4], MODULUS)

        assert p * q == Polynomial([3, 10, 8], MODULUS)

    def test_multiplication_with_scalar(self):
        polynomial = Polynomial([1, 2, 3], MODULUS)

        assert polynomial * 5 == Polynomial([5, 10, 15], MODULUS)
        assert 5 * polynomial == Polynomial([5, 10, 15], MODULUS)

    def test_multiplication_is_modular(self):
        p = Polynomial([10, 10], MODULUS)
        q = Polynomial([10, 10], MODULUS)

        assert p * q == Polynomial([15, 13, 15], MODULUS)

    def test_multiplication_with_different_moduli_fails(self):
        p = Polynomial([1, 2], 17)
        q = Polynomial([3, 4], 19)

        with pytest.raises(ValueError):
            p * q

    def test_multiplication_with_invalid_operand_fails(self):
        polynomial = Polynomial([1, 2], MODULUS)

        with pytest.raises(TypeError):
            polynomial * "x"


class TestPolynomialPower:
    """Tests for polynomial exponentiation."""

    def test_power_zero(self):
        polynomial = Polynomial([3, 2], MODULUS)

        assert polynomial**0 == Polynomial([1], MODULUS)

    def test_power_one(self):
        polynomial = Polynomial([3, 2], MODULUS)

        assert polynomial**1 == polynomial

    def test_power(self):
        polynomial = Polynomial([1, 1], MODULUS)

        assert polynomial**3 == Polynomial([1, 3, 3, 1], MODULUS)

    def test_power_large_exponent(self):
        polynomial = Polynomial([1, 1], MODULUS)

        assert polynomial**10 == Polynomial(
            [1, 10, 11, 1, 6, 14, 6, 1, 11, 10, 1],
            MODULUS,
        )

    def test_negative_power_fails(self):
        polynomial = Polynomial([1, 1], MODULUS)

        with pytest.raises(ValueError):
            polynomial**-1


class TestPolynomialDivision:
    """Tests for polynomial division."""

    def test_exact_division(self):
        divisor = Polynomial([2, 1], MODULUS)
        quotient = Polynomial([1, 16, 1], MODULUS)
        dividend = quotient * divisor

        actual_quotient, remainder = divmod(dividend, divisor)

        assert actual_quotient == quotient
        assert remainder == Polynomial([0], MODULUS)

    def test_division_with_remainder(self):
        quotient = Polynomial([1, 1, 1], MODULUS)
        divisor = Polynomial([2, 1], MODULUS)
        remainder = Polynomial([1], MODULUS)

        dividend = quotient * divisor + remainder

        actual_quotient, actual_remainder = divmod(dividend, divisor)

        assert actual_quotient == quotient
        assert actual_remainder == remainder

    def test_floor_division_returns_quotient(self):
        quotient = Polynomial([1, 1, 1], MODULUS)
        divisor = Polynomial([2, 1], MODULUS)
        remainder = Polynomial([1], MODULUS)

        dividend = quotient * divisor + remainder

        assert dividend // divisor == quotient

    def test_modulo_returns_remainder(self):
        quotient = Polynomial([1, 1, 1], MODULUS)
        divisor = Polynomial([2, 1], MODULUS)
        remainder = Polynomial([1], MODULUS)

        dividend = quotient * divisor + remainder

        assert dividend % divisor == remainder

    def test_division_by_zero_fails(self):
        polynomial = Polynomial([1, 2], MODULUS)

        with pytest.raises(ZeroDivisionError):
            divmod(polynomial, Polynomial([0], MODULUS))

    def test_noninvertible_leading_coefficient_fails(self):
        modulus = 15
        dividend = Polynomial([1, 0, 1], modulus)
        divisor = Polynomial([1, 3], modulus)

        with pytest.raises(PolynomialDivisionError):
            divmod(dividend, divisor)


class TestPolynomialMonic:
    """Tests for monic normalization."""

    def test_monic(self):
        polynomial = Polynomial([-9, 3], MODULUS)

        assert polynomial.monic() == Polynomial([14, 1], MODULUS)

    def test_monic_zero_polynomial(self):
        polynomial = Polynomial([0], MODULUS)

        assert polynomial.monic() == Polynomial([0], MODULUS)


class TestPolynomialGCD:
    """Tests for polynomial GCD."""

    def test_gcd(self):
        # Both polynomials have x - 3 as their monic common factor.
        p = Polynomial([2, 2, 1], MODULUS)
        q = Polynomial([11, 16, 1], MODULUS)

        assert p.gcd(q) == Polynomial([14, 1], MODULUS)

    def test_gcd_is_monic(self):
        p = Polynomial([8, 3], MODULUS)
        q = Polynomial([8, 3], MODULUS)

        assert p.gcd(q) == Polynomial([14, 1], MODULUS)

    def test_gcd_with_zero(self):
        p = Polynomial([14, 1], MODULUS)

        assert p.gcd(Polynomial([0], MODULUS)) == p.monic()
        assert Polynomial([0], MODULUS).gcd(p) == p.monic()

    def test_gcd_of_coprime_polynomials(self):
        p = Polynomial([1, 1], MODULUS)
        q = Polynomial([1, 2], MODULUS)

        assert p.gcd(q) == Polynomial([1], MODULUS)


class TestPolynomialEvaluation:
    """Tests for polynomial evaluation."""

    def test_evaluation(self):
        polynomial = Polynomial([3, 2, 1], MODULUS)

        assert polynomial.evaluate(4) == 27 % MODULUS
        assert polynomial.evaluate(4) == 10

    def test_evaluation_is_modular(self):
        polynomial = Polynomial([1, 2, 3], MODULUS)

        assert polynomial.evaluate(20) == polynomial.evaluate(3)


class TestPolynomialOperations:
    """Tests for algebraic identities used by the FR attack."""

    def test_additive_identity(self):
        p = Polynomial([3, 2, 1], MODULUS)
        zero = Polynomial([0], MODULUS)

        assert p + zero == p
        assert p - zero == p

    def test_multiplicative_identity(self):
        p = Polynomial([3, 2, 1], MODULUS)
        one = Polynomial([1], MODULUS)

        assert p * one == p

    def test_division_reconstruction(self):
        quotient = Polynomial([1, 1, 1], MODULUS)
        divisor = Polynomial([2, 1], MODULUS)
        remainder = Polynomial([1], MODULUS)

        dividend = quotient * divisor + remainder

        actual_quotient, actual_remainder = divmod(dividend, divisor)

        assert actual_quotient * divisor + actual_remainder == dividend

    def test_affine_polynomial_construction(self):
        x = Polynomial([0, 1], MODULUS)
        a = 5
        b = 7

        affine = a * x + b

        assert affine == Polynomial([7, 5], MODULUS)
        assert affine.evaluate(3) == (a * 3 + b) % MODULUS

    def test_affine_power(self):
        x = Polynomial([0, 1], MODULUS)

        a = 5
        b = 7

        affine = a * x + b
        result = affine**3

        assert result == Polynomial([3, 4, 15, 6], MODULUS)
