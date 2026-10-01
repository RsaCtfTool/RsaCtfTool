#!/usr/bin/env python3
"""
Polynomial arithmetic over Z_modulus[x].

Coefficients are stored in ascending degree order:
    Polynomial([c0, c1, c2], n) == c0 + c1*x + c2*x^2
"""

from math import gcd


__all__ = ["Polynomial", "PolynomialDivisionError"]


class PolynomialDivisionError(Exception):
    """Raised when polynomial division cannot be performed over Z_n."""


class Polynomial:
    """Polynomial over the ring Z_n[x]."""

    def __init__(self, coefficients, modulus):
        if modulus <= 1:
            raise ValueError("modulus must be greater than 1")

        self.modulus = modulus

        coefficients = [coefficient % modulus for coefficient in coefficients]

        while len(coefficients) > 1 and coefficients[-1] == 0:
            coefficients.pop()

        if not coefficients:
            coefficients = [0]

        self.coefficients = tuple(coefficients)

    @property
    def degree(self):
        """Return the degree of the polynomial, or -1 for zero."""
        if self.is_zero():
            return -1
        return len(self.coefficients) - 1

    @property
    def leading_coefficient(self):
        """Return the leading coefficient, or 0 for zero."""
        if self.is_zero():
            return 0
        return self.coefficients[-1]

    def is_zero(self):
        """Return whether the polynomial is zero."""
        return len(self.coefficients) == 1 and self.coefficients[0] == 0

    def _check_modulus(self, other):
        if self.modulus != other.modulus:
            raise ValueError("polynomials must have the same modulus")

    def _coerce(self, other):
        if isinstance(other, Polynomial):
            self._check_modulus(other)
            return other

        if isinstance(other, int):
            return Polynomial([other], self.modulus)

        raise TypeError(
            f"unsupported operand type: {type(other).__name__}"
        )

    def __eq__(self, other):
        if not isinstance(other, Polynomial):
            return False

        return (
            self.modulus == other.modulus
            and self.coefficients == other.coefficients
        )

    def __add__(self, other):
        other = self._coerce(other)

        size = max(len(self.coefficients), len(other.coefficients))
        coefficients = [0] * size

        for i in range(size):
            left = self.coefficients[i] if i < len(self.coefficients) else 0
            right = other.coefficients[i] if i < len(other.coefficients) else 0
            coefficients[i] = left + right

        return Polynomial(coefficients, self.modulus)

    def __radd__(self, other):
        return self + other

    def __sub__(self, other):
        other = self._coerce(other)

        size = max(len(self.coefficients), len(other.coefficients))
        coefficients = [0] * size

        for i in range(size):
            left = self.coefficients[i] if i < len(self.coefficients) else 0
            right = other.coefficients[i] if i < len(other.coefficients) else 0
            coefficients[i] = left - right

        return Polynomial(coefficients, self.modulus)

    def __rsub__(self, other):
        return -self + other

    def __neg__(self):
        return Polynomial(
            [-coefficient for coefficient in self.coefficients],
            self.modulus,
        )

    def __mul__(self, other):
        other = self._coerce(other)

        coefficients = [0] * (
            len(self.coefficients) + len(other.coefficients) - 1
        )

        for i, left in enumerate(self.coefficients):
            for j, right in enumerate(other.coefficients):
                coefficients[i + j] += left * right

        return Polynomial(coefficients, self.modulus)

    def __rmul__(self, other):
        return self * other

    def __pow__(self, exponent):
        if not isinstance(exponent, int):
            raise TypeError("polynomial exponent must be an integer")

        if exponent < 0:
            raise ValueError("polynomial exponent must be non-negative")

        result = Polynomial([1], self.modulus)
        base = self

        while exponent:
            if exponent & 1:
                result = result * base

            base = base * base
            exponent >>= 1

        return result

    def __divmod__(self, divisor):
        divisor = self._coerce(divisor)

        if divisor.is_zero():
            raise ZeroDivisionError("polynomial division by zero")

        if self.is_zero() or self.degree < divisor.degree:
            return (
                Polynomial([0], self.modulus),
                Polynomial(self.coefficients, self.modulus),
            )

        remainder = Polynomial(self.coefficients, self.modulus)
        quotient_coefficients = [0] * (
            self.degree - divisor.degree + 1
        )

        leading_coefficient = divisor.leading_coefficient

        if gcd(leading_coefficient, self.modulus) != 1:
            raise PolynomialDivisionError(
                "divisor leading coefficient is not invertible modulo modulus"
            )

        inverse = pow(leading_coefficient, -1, self.modulus)

        while not remainder.is_zero() and remainder.degree >= divisor.degree:
            degree_difference = remainder.degree - divisor.degree

            coefficient = (
                remainder.leading_coefficient * inverse
            ) % self.modulus

            quotient_coefficients[degree_difference] = coefficient

            term = Polynomial(
                [0] * degree_difference + [coefficient],
                self.modulus,
            )

            remainder = remainder - term * divisor

        quotient = Polynomial(quotient_coefficients, self.modulus)

        return quotient, remainder

    def __floordiv__(self, divisor):
        quotient, _ = divmod(self, divisor)
        return quotient

    def __mod__(self, divisor):
        _, remainder = divmod(self, divisor)
        return remainder

    def monic(self):
        """Return the monic form of the polynomial."""
        if self.is_zero():
            return Polynomial([0], self.modulus)

        leading_coefficient = self.leading_coefficient

        if gcd(leading_coefficient, self.modulus) != 1:
            raise PolynomialDivisionError(
                "leading coefficient is not invertible modulo modulus"
            )

        inverse = pow(leading_coefficient, -1, self.modulus)

        return self * inverse

    def gcd(self, other):
        """Return the monic polynomial GCD."""
        other = self._coerce(other)

        left = self
        right = other

        while not right.is_zero():
            _, remainder = divmod(left, right)
            left, right = right, remainder

        return left.monic()

    def evaluate(self, x):
        """Evaluate the polynomial at x modulo the polynomial modulus."""
        x %= self.modulus

        result = 0

        for coefficient in reversed(self.coefficients):
            result = (result * x + coefficient) % self.modulus

        return result

    def __repr__(self):
        return (
            f"Polynomial({list(self.coefficients)!r}, "
            f"{self.modulus!r})"
        )
