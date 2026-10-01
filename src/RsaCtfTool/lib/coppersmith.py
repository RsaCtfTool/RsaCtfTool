#!/usr/bin/env python3
"""
Reusable Coppersmith small-root attack interface.

This module deliberately has no Sage dependency.  Sage is an optional
dependency of RsaCtfTool and is only required when a Coppersmith attack
is actually executed.
"""
import math
from dataclasses import dataclass

__all__ = [
    "CoppersmithParameters",
    "CoppersmithError",
]


class CoppersmithError(Exception):
    """Base exception for Coppersmith-related errors."""


@dataclass(frozen=True)
class CoppersmithParameters:
    """
    Parameters for the univariate Coppersmith/Howgrave-Graham method.

    If m/t are None, the Coppersmith engine selects them automatically.
    """

    beta: float
    X: int
    m: int | None = None
    t: int | None = None

    def __post_init__(self):
        if not 0 < self.beta <= 1:
            raise ValueError("beta must satisfy 0 < beta <= 1")

        if self.X <= 0:
            raise ValueError("X must be positive")

        if self.m is not None and self.m <= 0:
            raise ValueError("m must be positive")

        if self.t is not None and self.t < 0:
            raise ValueError("t must be non-negative")

        if self.m is None and self.t is not None:
            raise ValueError("t cannot be specified when m is None")

def coppersmith_univariate(
    polynomial,
    modulus,
    parameters,
):
    """
    Find small integer roots of a monic univariate polynomial modulo N.

    Sage is intentionally not imported here.  The actual lattice
    construction and LLL reduction are delegated to the optional Sage
    backend.

    Args:
        polynomial: Polynomial represented by the backend's polynomial type.
        modulus: RSA modulus N.
        parameters: CoppersmithParameters instance.

    Returns:
        List of integer roots.

    Raises:
        CoppersmithError: If the Coppersmith backend cannot be used.
        ValueError: For invalid modulus or parameters.
    """
    if modulus <= 1:
        raise ValueError("modulus must be greater than 1")

    if not isinstance(parameters, CoppersmithParameters):
        raise TypeError(
            "parameters must be a CoppersmithParameters instance"
        )

    try:
        from RsaCtfTool.sage.coppersmith import coppersmith_univariate_sage
    except ImportError as exc:
        raise CoppersmithError(
            "Coppersmith requires the optional Sage dependency"
        ) from exc

    return coppersmith_univariate_sage(
        polynomial,
        modulus,
        parameters,
    )

def _coppersmith_bound_holds(
    degree,
    modulus,
    beta,
    m,
    t,
    X,
):
    """
    Test the Howgrave-Graham bound for a univariate Coppersmith lattice.

    Returns True when the standard determinant bound predicts that an
    LLL-reduced vector can satisfy the required small-root condition.
    """
    dimension = degree * m + t

    if dimension <= 0:
        return False

    # Determinant of the standard univariate Coppersmith lattice:
    #
    # det(L) =
    #   N^(d*m*(m+1)/2)
    #   * X^(
    #       d*m*(m-1)/2
    #       + m*d*(d-1)/2
    #       + t*d*m
    #       + t*(t-1)/2
    #     )
    #
    # We compare logarithms to avoid constructing enormous integers.
    d = degree

    log_det_n =  d * m * (m + 1) / 2

    log_det_x = (
        d * m * (m - 1) / 2
        + m * d * (d - 1) / 2
        + t * d * m
        + t * (t - 1) / 2
    )
    log_det = (
        log_det_n * math.log(modulus)
        + log_det_x * math.log(X)
    )

    # Howgrave-Graham:
    #
    # 2^((n-1)/4) * det(L)^(1/n)
    #       < N^(beta*m) / sqrt(n)
    #
    # Work entirely in logarithms.
    lhs = (
        ((dimension - 1) / 4) * math.log(2)
        + log_det / dimension
    )

    rhs = (
        beta * m * math.log(modulus)
        - 0.5 * math.log(dimension)
    )

    return lhs < rhs
