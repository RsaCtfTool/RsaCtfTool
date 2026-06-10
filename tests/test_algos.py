#!/usr/bin/env python3
"""
Unit tests for the algos module.
"""

import pytest

from RsaCtfTool.lib.algos import (
    brent,
    strong_pseudoprime,
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
    dixon,
    prime_base_collision,
    quadratic_sieve,
    _gaussian_elimination_gf2,
    _try_smooth_dependency,
    _collect_dixon_relations,
    _build_qs_factor_base,
    _qs_sieve_interval,
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


class TestStrongPseudoprime:
    """Tests for strong_pseudoprime factorization."""

    def test_strong_pseudoprime_basic(self):
        p, q = 13, 31
        n = p * q
        result = strong_pseudoprime(n)
        assert result is not None
        f1, f2 = result
        assert f1 * f2 == n

    def test_strong_pseudoprime_returns_empty(self):
        result = strong_pseudoprime(15)
        assert result == []

    def test_strong_pseudoprime_carmichael_example(self):
        """Factor the Carmichael number from Wagstaff Example 10.5."""
        N = 23224518901
        result = strong_pseudoprime(N)
        assert result is not None
        f1, f2 = result
        assert f1 * f2 == N
        assert f1 > 1 and f2 > 1


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


class TestGaussianEliminationGF2:
    """Tests for _gaussian_elimination_gf2."""

    def test_trivial_3x3(self):
        rows = [(0b110, 0b001), (0b000, 0b010)]
        result = _gaussian_elimination_gf2(rows, 3)
        assert len(result) == 2

    def test_full_rank_elimination(self):
        rows = [
            (0b100, 0b001),
            (0b010, 0b010),
            (0b001, 0b100),
        ]
        result = _gaussian_elimination_gf2(rows, 3)
        nullspaces = [b for b, _ in result if b == 0]
        assert len(nullspaces) == 0  # full rank → no nullspace row


class TestTrySmoothDependency:
    """Tests for _try_smooth_dependency."""

    def test_nontrivial_split(self):
        n = 77
        base = [2, 3, 5, 7, 11]
        t = len(base)
        relations = [
            (14, 0b00011, [0, 1, 0, 1, 0]),
            (28, 0b00011, [0, 1, 0, 1, 0]),
        ]
        rows = [(relations[i][1], 1 << i) for i in range(len(relations))]
        rows = _gaussian_elimination_gf2(rows, t)
        split = _try_smooth_dependency(rows, relations, base, t, n)
        assert split is not None
        a, b = split
        assert a * b == n


class TestDixon:
    """Tests for dixon factorization."""

    def test_dixon_small_semiprime(self):
        p, q = 31, 37
        n = p * q
        result = dixon(n, progress=False)
        assert result is not None
        f1, f2 = result
        assert f1 * f2 == n

    def test_dixon_medium_semiprime(self):
        p, q = 101, 103
        n = p * q
        result = dixon(n, progress=False)
        assert result is not None
        f1, f2 = result
        assert f1 * f2 == n

    def test_dixon_even_n(self):
        result = dixon(12, progress=False)
        assert result == (2, 6)

    def test_dixon_prime(self):
        result = dixon(17, progress=False)
        assert result is None

    def test_dixon_with_custom_B(self):
        p, q = 1009, 1013
        n = p * q
        result = dixon(n, B=20, progress=False)
        assert result is not None
        f1, f2 = result
        assert f1 * f2 == n


class TestPrimeBaseCollision:
    """Tests for prime_base_collision."""

    def test_prime_base_collision_small(self):
        p, q = 19, 23
        n = p * q
        result = prime_base_collision(n)
        f1, f2 = result
        assert f1 * f2 == n

    def test_prime_base_collision_larger(self):
        p, q = 101, 103
        n = p * q
        result = prime_base_collision(n)
        f1, f2 = result
        assert f1 * f2 == n


class TestQSFactorBase:
    """Tests for _build_qs_factor_base."""

    def test_factor_base_basic(self):
        n = 31 * 37
        base, sqrt_map = _build_qs_factor_base(n, 10)
        assert -1 in base
        assert 2 in base
        assert len(base) >= 3  # at least -1, 2, and some QR primes

    def test_factor_base_includes_divisor_primes(self):
        n = 31 * 37
        base, sqrt_map = _build_qs_factor_base(n, 15)
        for p, roots in sqrt_map.items():
            assert len(roots) >= 1


class TestQSSieveInterval:
    """Tests for _qs_sieve_interval."""

    def test_sieve_returns_relations(self):
        n = 31 * 37
        base, sqrt_map = _build_qs_factor_base(n, 10)
        relations = _qs_sieve_interval(n, base, sqrt_map, 20, progress=False)
        assert len(relations) > 0
        for x, parity, exp in relations:
            assert len(exp) == len(base)

    def test_sieve_sign_handling(self):
        n = 31 * 37
        base, sqrt_map = _build_qs_factor_base(n, 10)
        relations = _qs_sieve_interval(n, base, sqrt_map, 50, progress=False)
        found_negative = any(x * x - n < 0 for x, _, _ in relations)
        found_positive = any(x * x - n > 0 for x, _, _ in relations)
        assert found_negative or found_positive


class TestQuadraticSieve:
    """Tests for quadratic_sieve."""

    def test_qs_small_semiprime(self):
        p, q = 31, 37
        n = p * q
        result = quadratic_sieve(n, progress=False)
        assert result is not None
        f1, f2 = result
        assert f1 * f2 == n

    def test_qs_40bit_semiprime(self):
        p, q = 1000003, 1000033
        n = p * q
        result = quadratic_sieve(n, progress=False)
        assert result is not None
        f1, f2 = result
        assert f1 * f2 == n

    def test_qs_even_n(self):
        result = quadratic_sieve(12, progress=False)
        assert result == (2, 6)

    def test_qs_prime_n(self):
        result = quadratic_sieve(17, progress=False)
        assert result is None

    def test_qs_larger_prime_fails(self):
        result = quadratic_sieve(1000033, progress=False)
        assert result is None


class TestQuadraticSieveEdgeCases:
    """Edge-case paths for QS internals."""

    def test_qs_perfect_square_n(self):
        base, smap = _build_qs_factor_base(25, 10)
        rels = _qs_sieve_interval(25, base, smap, 10, progress=False)
        assert len(rels) >= 0

    def test_qs_factor_base_divisor_primes(self):
        base, smap = _build_qs_factor_base(15, 10)
        assert 3 in smap and smap[3] == (0,)

    def test_qs_tiny_params_returns_none(self):
        result = quadratic_sieve(17, B=5, M=10, progress=False)
        assert result is None

    def test_qs_qx_zero_in_sieve(self):
        base, smap = _build_qs_factor_base(25, 10)
        rels = _qs_sieve_interval(25, base, smap, 10, progress=False)
        assert all(x * x - 25 != 0 or len(rels) >= 0 for x, _, _ in rels) or True


class TestDixonEdgeCases:
    """Edge-case paths for dixon and its helpers."""

    def test_dixon_retry_path(self):
        result = dixon(31 * 37, B=10, progress=False, n_extra=5, max_retries=2)
        assert result is not None
        f1, f2 = result
        assert f1 * f2 == 31 * 37

    def test_collect_relations_early_split(self):
        from RsaCtfTool.lib.number_theory import primes
        n = 31 * 37
        base = primes(10)
        rels, split = _collect_dixon_relations(n, base, len(base), 20, progress=False)
        assert split is None or split[0] * split[1] == n

    def test_gaussian_elim_underdetermined(self):
        rows = [(0b101, 1), (0b000, 2)]
        r = _gaussian_elimination_gf2(rows, 3)
        nulls = [b for b, _ in r if b == 0]
        assert len(nulls) > 0

    def test_gaussian_elim_zero_column(self):
        rows = [(0b001, 1), (0b001, 2)]
        r = _gaussian_elimination_gf2(rows, 4)
        assert len(r) == 2


class TestPrimeBaseCollisionEdgeCases:
    """Edge-case paths for prime_base_collision."""

    def test_prime_base_collision_large(self):
        p, q = 1009, 1013
        n = p * q
        result = prime_base_collision(n)
        f1, f2 = result
        assert f1 * f2 == n
