#!/usr/bin/env python3
"""
Unit tests for the Coppersmith module.
"""

import pytest

from RsaCtfTool.lib.coppersmith import (
    CoppersmithError,
    CoppersmithParameters,
    _coppersmith_bound_holds,
    _select_coppersmith_parameters,
)

class TestCoppersmithParameters:
    """Tests for Coppersmith parameter validation."""

    def test_valid_parameters(self):
        parameters = CoppersmithParameters(
            beta=0.5,
            m=3,
            t=2,
            X=2**64,
        )

        assert parameters.beta == 0.5
        assert parameters.m == 3
        assert parameters.t == 2
        assert parameters.X == 2**64

    def test_beta_must_be_positive(self):
        with pytest.raises(ValueError):
            CoppersmithParameters(
                beta=0,
                m=3,
                t=2,
                X=100,
            )

    def test_beta_cannot_exceed_one(self):
        with pytest.raises(ValueError):
            CoppersmithParameters(
                beta=1.1,
                m=3,
                t=2,
                X=100,
            )

    def test_must_be_positive(self):
        with pytest.raises(ValueError):
            CoppersmithParameters(
                beta=0.5,
                m=0,
                t=2,
                X=100,
            )

    def test_t_may_be_zero(self):
        parameters = CoppersmithParameters(
            beta=0.5,
            m=3,
            t=0,
            X=100,
        )

        assert parameters.t == 0

    def test_t_cannot_be_negative(self):
        with pytest.raises(ValueError):
            CoppersmithParameters(
                beta=0.5,
                m=3,
                t=-1,
                X=100,
            )

    def test_x_must_be_positive(self):
        with pytest.raises(ValueError):
            CoppersmithParameters(
                beta=0.5,
                m=3,
                t=2,
                X=0,
            )


class TestCoppersmithBound:
    """Tests for the Howgrave-Graham parameter bound."""

    def test_invalid_dimension_fails(self):
        assert not _coppersmith_bound_holds(
            degree=1,
            modulus=101,
            beta=0.5,
            m=0,
            t=0,
            X=2,
        )
    # @pytest.mark.skip(reason="Skip for now")
    def test_known_small_instance_has_viable_parameters(self):
        viable = []

        for m in range(1, 10):
            for t in range(4):
                if _coppersmith_bound_holds(
                    degree=1,
                    modulus=2**64,
                    beta=1.0,
                    m=m,
                    t=t,
                    X=2**16,
                ):
                    viable.append((m, t))

        assert viable

    def test_larger_root_bound_is_harder(self):
        easy = _coppersmith_bound_holds(
            degree=2,
            modulus=2**64,
            beta=0.5,
            m=4,
            t=2,
            X=2**16,
        )

        hard = _coppersmith_bound_holds(
            degree=2,
            modulus=2**64,
            beta=0.5,
            m=4,
            t=2,
            X=2**32,
        )

        assert easy or not hard


class TestCoppersmithSelector:
    """Tests for automatic (m, t) selection."""

    def test_selected_parameters_satisfy_bound(self):
        m, t = _select_coppersmith_parameters(
            degree=1, modulus=2**1024, beta=0.5, X=2**100
        )

        assert _coppersmith_bound_holds(
            degree=1, modulus=2**1024, beta=0.5, m=m, t=t, X=2**100
        )

    def test_selection_is_minimal_dimension(self):
        degree, modulus, beta, X = 3, 2**1024, 0.5, 2**60
        m, t = _select_coppersmith_parameters(degree, modulus, beta, X)
        best = degree * m + t

        for mm in range(1, 21):
            for tt in range(degree * mm * 2 + 1):
                if degree * mm + tt < best:
                    assert not _coppersmith_bound_holds(
                        degree, modulus, beta, mm, tt, X
                    )

    def test_t_exceeds_degree_for_small_beta(self):
        _, t = _select_coppersmith_parameters(
            degree=1, modulus=2**1024, beta=0.5, X=2**100
        )

        assert t >= 1

    def test_harder_root_bound_needs_larger_lattice(self):
        m1, t1 = _select_coppersmith_parameters(1, 2**1024, 0.5, 2**100)
        m2, t2 = _select_coppersmith_parameters(1, 2**1024, 0.5, 2**200)

        assert m2 + t2 > m1 + t1

    def test_no_solution_raises(self):
        with pytest.raises(CoppersmithError):
            _select_coppersmith_parameters(
                degree=1, modulus=2**1024, beta=0.5, X=2**400
            )


class TestCoppersmithWiring:
    """Tests that coppersmith_univariate resolves m/t before the backend."""

    class _Poly:
        def degree(self):
            return 1

    def _run(self, monkeypatch, parameters):
        import sys
        import types

        captured = {}
        fake = types.ModuleType("RsaCtfTool.sage.coppersmith")

        def backend(polynomial, modulus, params):
            captured["params"] = params
            return [42]

        fake.coppersmith_univariate_sage = backend
        monkeypatch.setitem(sys.modules, "RsaCtfTool.sage.coppersmith", fake)

        from RsaCtfTool.lib.coppersmith import coppersmith_univariate

        result = coppersmith_univariate(self._Poly(), 2**1024, parameters)
        return result, captured["params"]

    def test_auto_selection_resolves_m_and_t(self, monkeypatch):
        result, params = self._run(
            monkeypatch, CoppersmithParameters(beta=0.5, X=2**100)
        )

        assert result == [42]
        assert (params.m, params.t) == (1, 2)

    def test_manual_parameters_pass_through(self, monkeypatch):
        _, params = self._run(
            monkeypatch, CoppersmithParameters(beta=0.5, X=2**100, m=5, t=3)
        )

        assert (params.m, params.t) == (5, 3)

    def test_missing_t_defaults_to_zero(self, monkeypatch):
        _, params = self._run(
            monkeypatch, CoppersmithParameters(beta=0.5, X=2**100, m=5)
        )

        assert (params.m, params.t) == (5, 0)


class TestCoppersmithSageEndToEnd:
    """End-to-end tests; skipped when Sage is unavailable."""

    def test_auto_parameters_recover_known_root_1024_bit(self):
        sage_all = pytest.importorskip("sage.all")

        from RsaCtfTool.lib.coppersmith import coppersmith_univariate

        p = sage_all.next_prime(2**512 + 12345)
        q = sage_all.next_prime(2**512 + 98765)
        n = p * q
        x0 = sage_all.ZZ(2**100 - 12345)

        ring = sage_all.PolynomialRing(sage_all.Zmod(n), "x")
        f = ring.gen() + (p - x0)

        roots = coppersmith_univariate(
            f, n, CoppersmithParameters(beta=0.49, X=2**101)
        )

        assert x0 in roots
