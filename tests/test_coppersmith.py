#!/usr/bin/env python3
"""
Unit tests for the Coppersmith module.
"""

import pytest

from RsaCtfTool.lib.coppersmith import (
    CoppersmithParameters,
    _coppersmith_bound_holds,
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
