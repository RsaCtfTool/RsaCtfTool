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
        candidates = _select_coppersmith_parameters(
            degree=int(polynomial.degree()),
            modulus=int(modulus),
            beta=parameters.beta,
            X=parameters.X,
        )
    elif parameters.t is None:
        candidates = [(parameters.m, 0)]
    else:
        candidates = [(parameters.m, parameters.t)]

    try:
        from RsaCtfTool.sage.coppersmith import coppersmith_univariate_sage
    except ImportError as exc:
        raise CoppersmithError(
            "Coppersmith requires the optional Sage dependency"
        ) from exc

    for m, t in candidates:
        cand_params = CoppersmithParameters(
            beta=parameters.beta,
            X=parameters.X,
            m=m,
            t=t,
        )
        roots = coppersmith_univariate_sage(
            polynomial,
            modulus,
            cand_params,
        )
        if roots:
            return roots

    return []


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
    Select viable (m, t) pairs for the univariate Coppersmith lattice.

    Returns a list of candidates to try, ranked by expected speed/success:
    1. A heuristic choice matching Sage's small_roots (fast, often succeeds).
    2. The smallest lattice strictly satisfying the Howgrave-Graham bound
       (slower, but mathematically guarantees finding the root if it exists).
    """
    candidates = []

    # 1. Sage's heuristic choice
    epsilon = beta / 8
    m_heuristic = math.ceil(max(beta**2 / (degree * epsilon), 7 * beta / degree))
    t_heuristic = math.floor(degree * m_heuristic * (1 / beta - 1))
    
    if m_heuristic <= max_m:
        candidates.append((m_heuristic, t_heuristic))

    # 2. Strict determinant bound
    strict_candidates = []
    for m in range(1, max_m + 1):
        t_max = degree * m * math.ceil(1 / beta)
        for t in range(t_max + 1):
            strict_candidates.append((degree * m + t, m, t))

    strict_candidates.sort()

    for _, m, t in strict_candidates:
        if _coppersmith_bound_holds(
            degree=degree,
            modulus=modulus,
            beta=beta,
            m=m,
            t=t,
            X=X,
        ):
            if (m, t) not in candidates:
                candidates.append((m, t))
            break

    if not candidates:
        raise CoppersmithError(
            "No viable Coppersmith parameters found within the search limit"
        )
        
    return candidates
