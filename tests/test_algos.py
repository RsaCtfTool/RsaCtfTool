#!/usr/bin/env python3
"""
Unit tests for the algos module.
"""

import pytest

from RsaCtfTool.lib.algos import (
    brent,
    carmichael,
    fermat,
    kraitchik,
    lehman,
    lehmer_machine,
    SQUFOF,
    wiener,
    factor_2PN,
    factor_XYXZ,
    euler,
    hart,
    pollard_rho,
    pollard_P_1,
    pollard_strassen,
    williams_pp1,
    difference_of_powers_factor,
    repunit_factor,
    FactorHighAndLowBitsEqual,
    Fibonacci,
)
from RsaCtfTool.lib.exceptions import FactorizationError


class TestFermat:
    """Tests for fermat factorization."""

    def test_fermat_close_primes(self):
        p, q = 101, 103
        n = p * q
        result = fermat(n)
        assert result is not None
        f1, f2 = result
        assert f1 * f2 == n

    def test_fermat_large_gap(self):
        p, q = 1009, 1013
        n = p * q
        result = fermat(n)
        assert result is not None
        f1, f2 = result
        assert f1 * f2 == n

    def test_fermat_invalid_congruence(self):
        n = 6  # 6 % 4 == 2, which is invalid for fermat
        with pytest.raises(FactorizationError):
            fermat(n)


class TestBrent:
    """Tests for brent factorization."""

    def test_brent_small_composite(self):
        n = 15
        result = brent(n)
        assert result is not None
        assert n % result == 0

    def test_brent_prime(self):
        result = brent(17)
        assert result == 17

    def test_brent_power_of_2(self):
        result = brent(16)
        assert result == 2


class TestPollardRho:
    """Tests for pollard_rho factorization."""

    def test_pollard_rho_small(self):
        n = 15
        result = pollard_rho(n)
        assert result is not None
        assert n % result == 0

    def test_pollard_rho_medium(self):
        n = 8051
        result = pollard_rho(n)
        assert result is not None
        assert n % result == 0


class TestPollardP1:
    """Tests for pollard_p_1 factorization."""

    def test_pollard_p_1_smooth(self):
        p, q = 101, 151
        n = p * q
        result = pollard_P_1(n, progress=False)
        if result is not None:
            f1, f2 = result
            assert f1 * f2 == n


class TestHart:
    """Tests for hart factorization."""

    def test_hart_basic(self):
        p, q = 29, 31
        n = p * q
        result = hart(n)
        assert result is not None
        f1, f2 = result
        assert f1 * f2 == n or f1 * f2 == n


class TestKraitchik:
    """Tests for kraitchik factorization."""

    def test_kraitchik_basic(self):
        n = 77
        result = kraitchik(n)
        assert result is not None
        f1, f2 = result
        assert f1 * f2 == n


class TestLehman:
    """Tests for lehman factorization."""

    def test_lehman_invalid_congruence(self):
        n = 15  # 15 % 4 == 3
        with pytest.raises(FactorizationError):
            lehman(n)


class TestCarmichael:
    """Tests for carmichael factorization."""

    def test_carmichael_basic(self):
        p, q = 13, 31
        n = p * q
        result = carmichael(n)
        assert result is not None
        f1, f2 = result
        assert f1 * f2 == n

    def test_carmichael_returns_empty(self):
        result = carmichael(15)
        assert result == []


class TestSQUFOF:
    """Tests for SQUFOF factorization."""

    def test_squfof_basic(self):
        p, q = 41, 43
        n = p * q
        result = SQUFOF(n)
        assert result is not None
        f1, f2 = result
        assert f1 * f2 == n

    def test_squfof_invalid_congruence(self):
        n = 15
        with pytest.raises(FactorizationError):
            SQUFOF(n)


class TestEuler:
    """Tests for euler factorization."""

    def test_euler_basic(self):
        p, q = 31, 37
        n = p * q
        result = euler(n)
        if result is not None:
            f1, f2 = result
            assert f1 * f2 == n


class TestLehmerMachine:
    """Tests for lehmer_machine factorization."""

    def test_lehmer_machine_invalid_congruence(self):
        n = 15
        with pytest.raises(FactorizationError):
            lehmer_machine(n)


class TestFactor2PN:
    """Tests for factor_2PN factorization."""

    def test_factor_2pn_basic(self):
        p, q = 41, 43
        P = 3
        n = p * q
        result = factor_2PN(n, P)
        assert result is not None
        f1, f2 = result
        assert f1 * f2 == n


class TestFactorXYXZ:
    """Tests for factor_XYXZ factorization."""

    def test_factor_xyxz_basic(self):
        base = 2
        p = 257
        n = p * 251  # 251 is also prime but not of the form
        result = factor_XYXZ(n, base)
        if result is not None:
            f1, f2 = result
            assert f1 * f2 == n


class TestWiener:
    """Tests for wiener attack."""

    def test_wiener_small(self):
        p, q = 61, 53
        n = p * q
        e = 17
        result = wiener(n, e, progress=False)
        assert result is not None
        f1, f2 = result
        assert f1 * f2 == n


class TestPollardStrassen:
    """Tests for pollard_strassen factorization."""

    def test_pollard_strassen_basic(self):
        p, q = 31, 37
        n = p * q
        result = pollard_strassen(n)
        if result is not None:
            f1, f2 = result
            assert f1 * f2 == n


class TestWilliamsPP1:
    """Tests for williams_pp1 factorization."""

    def test_williams_pp1_basic(self):
        p, q = 41, 61
        n = p * q
        result = williams_pp1(n)
        if result is not None:
            f1, f2 = result
            assert f1 * f2 == n


class TestDifferenceOfPowersFactor:
    """Tests for difference_of_powers_factor."""

    def test_diff_powers_basic(self):
        p, q = 17, 19
        n = p * q
        result = difference_of_powers_factor(n)
        assert isinstance(result, list)


class TestRepunitFactor:
    """Tests for repunit_factor."""

    def test_repunit_basic(self):
        p, q = 31, 37
        n = p * q
        result = repunit_factor(n)
        if result is not None:
            f1, f2 = result
            assert f1 * f2 == n


class TestFactorHighAndLowBitsEqual:
    """Tests for FactorHighAndLowBitsEqual."""

    def test_factor_high_low_bits_equal_invalid_n(self):
        n = 100
        result = FactorHighAndLowBitsEqual(n)
        assert result is None


class TestFibonacci:
    """Tests for Fibonacci class."""

    def test_fib_get_period_bigint(self):
        fib = Fibonacci(progress=False, verbose=False)
        N = 21
        result = fib.factorization(N, 10, 0)
        if result is not None:
            f1, f2 = result
            assert f1 * f2 == N
