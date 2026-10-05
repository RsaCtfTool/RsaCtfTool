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
        candidates = _select_coppersmith_parameters(
            degree=1, modulus=2**1024, beta=0.5, X=2**100
        )
        # Verify that at least one candidate strictly satisfies the bound
        assert any(
            _coppersmith_bound_holds(
                degree=1, modulus=2**1024, beta=0.5, m=m, t=t, X=2**100
            )
            for m, t in candidates
        )

    def test_selection_is_minimal_dimension(self):
        degree, modulus, beta, X = 3, 2**1024, 0.5, 2**60
        candidates = _select_coppersmith_parameters(degree, modulus, beta, X)
        
        # The strict bound candidate is the last one in the list (or the only one)
        m, t = candidates[-1]
        best = degree * m + t

        for mm in range(1, 21):
            for tt in range(degree * mm * 2 + 1):
                if degree * mm + tt < best:
                    assert not _coppersmith_bound_holds(
                        degree, modulus, beta, mm, tt, X
                    )

    def test_t_exceeds_degree_for_small_beta(self):
        candidates = _select_coppersmith_parameters(
            degree=1, modulus=2**1024, beta=0.5, X=2**100
        )

        assert all(t >= 1 for _, t in candidates)

    def test_harder_root_bound_needs_larger_lattice(self):
        candidates1 = _select_coppersmith_parameters(1, 2**1024, 0.5, 2**100)
        candidates2 = _select_coppersmith_parameters(1, 2**1024, 0.5, 2**200)

        m1, t1 = candidates1[-1]
        m2, t2 = candidates2[-1]

        assert m2 + t2 > m1 + t1

    def test_no_solution_raises(self):
        with pytest.raises(CoppersmithError):
            _select_coppersmith_parameters(
                degree=1, modulus=2**1024, beta=0.5, X=2**400, max_m=0
            )


class TestCoppersmithWiring:
    """Tests that coppersmith_univariate resolves m/t before the backend."""

    class _Poly:
        def degree(self):
            return 1

    def _run(self, monkeypatch, parameters, mock_backend=None):
        import sys
        import types

        captured = {}
        fake = types.ModuleType("RsaCtfTool.sage.coppersmith")

        def default_backend(polynomial, modulus, params):
            captured["params"] = params
            return [42]

        fake.coppersmith_univariate_sage = mock_backend or default_backend
        monkeypatch.setitem(sys.modules, "RsaCtfTool.sage.coppersmith", fake)

        from RsaCtfTool.lib.coppersmith import coppersmith_univariate

        result = coppersmith_univariate(self._Poly(), 2**1024, parameters)
        return result, captured.get("params")

    def test_auto_selection_resolves_m_and_t(self, monkeypatch):
        result, params = self._run(
            monkeypatch, CoppersmithParameters(beta=0.5, X=2**100)
        )

        assert result == [42]
        # The heuristic candidate is chosen first, which is (4, 4) for beta=0.5
        assert (params.m, params.t) == (4, 4)

    def test_iteration_falls_back_to_strict_candidate(self, monkeypatch):
        called_params = []

        def failing_backend(polynomial, modulus, params):
            called_params.append((params.m, params.t))
            if len(called_params) == 2:
                # Succeed on the second candidate (the strict one)
                return [1337]
            return []  # Fail on the heuristic one

        result, _ = self._run(
            monkeypatch, 
            CoppersmithParameters(beta=0.5, X=2**100),
            mock_backend=failing_backend
        )

        assert result == [1337]
        assert len(called_params) == 2
        assert called_params[0] == (4, 4)  # Heuristic first
        assert called_params[1] != (4, 4)  # Strict second

    def test_iteration_short_circuits_on_success(self, monkeypatch):
        called_params = []

        def succeeding_backend(polynomial, modulus, params):
            called_params.append((params.m, params.t))
            return [999]  # Succeed immediately

        result, _ = self._run(
            monkeypatch, 
            CoppersmithParameters(beta=0.5, X=2**100),
            mock_backend=succeeding_backend
        )

        assert result == [999]
        assert len(called_params) == 1
        assert called_params[0] == (4, 4)

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
