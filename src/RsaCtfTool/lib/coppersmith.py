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
    "coppersmith_univariate",
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

    if parameters.m is None:
        m, t = _select_coppersmith_parameters(
            degree=int(polynomial.degree()),
            modulus=int(modulus),
            beta=parameters.beta,
            X=parameters.X,
        )
        parameters = CoppersmithParameters(
            beta=parameters.beta,
            X=parameters.X,
            m=m,
            t=t,
        )
    elif parameters.t is None:
        parameters = CoppersmithParameters(
            beta=parameters.beta,
            X=parameters.X,
            m=parameters.m,
            t=0,
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
    degree, modulus, m, t, X = int(degree), int(modulus), int(m), int(t), int(X)
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

    log_det_n = d * m * (m + 1) / 2

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


def _select_coppersmith_parameters(
    degree,
    modulus,
    beta,
    X,
    max_m=20,
):
    """
    Select a viable (m, t) pair for the univariate Coppersmith lattice.

    Candidates are tested using the Howgrave-Graham determinant bound.
    Smaller lattice dimensions (d*m + t) are preferred; ties go to
    smaller m.

    For beta < 1, t must grow like d*m*(1/beta - 1), so t is searched
    up to d*m*ceil(1/beta).
    """
    candidates = []
    for m in range(1, max_m + 1):
        t_max = degree * m * math.ceil(1 / beta)
        for t in range(t_max + 1):
            candidates.append((degree * m + t, m, t))

    candidates.sort()

    for _, m, t in candidates:
        if _coppersmith_bound_holds(
            degree=degree,
            modulus=modulus,
            beta=beta,
            m=m,
            t=t,
            X=X,
        ):
            return m, t

    raise CoppersmithError(
        "No viable Coppersmith parameters found within the search limit"
    )
