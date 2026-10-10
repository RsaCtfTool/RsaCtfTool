#!/usr/bin/env python3

from sage.all import ZZ, Matrix, RealField, gcd


def divisor_bound_holds(divisor, modulus, beta):
    """
    Test divisor >= modulus**beta using >= and 256-bit log precision.

    Avoids float overflow of modulus**beta for large (e.g. 1024-bit+) moduli.
    """
    field = RealField(256)
    return field(divisor).log() >= field(beta) * field(modulus).log()


def coppersmith_univariate_sage(
    polynomial,
    modulus,
    parameters,
):
    """
    Sage backend for univariate Coppersmith/Howgrave-Graham.

    Args:
        polynomial: Monic univariate Sage polynomial over Z_modulus.
        modulus: Modulus N.
        parameters: CoppersmithParameters instance.

    Returns:
        List of integer small roots.
    """
    beta = parameters.beta
    m = parameters.m
    t = parameters.t
    X = ZZ(parameters.X)
    modulus = ZZ(modulus)

    if not polynomial.is_monic():
        raise ArithmeticError("Polynomial must be monic.")

    degree = polynomial.degree()
    dimension = degree * m + t

    if dimension <= 0:
        return []

    polynomial_z = polynomial.change_ring(ZZ)
    x = polynomial_z.parent().gen()

    # Construct the Coppersmith lattice basis polynomials.
    basis = []

    for i in range(m):
        basis.extend(
            (x * X) ** j
            * modulus ** (m - i)
            * polynomial_z(x * X) ** i
            for j in range(degree)
        )

    basis.extend(
        (x * X) ** i * polynomial_z(x * X) ** m
        for i in range(t)
    )

    # Convert the polynomial basis into the coefficient lattice.
    lattice = Matrix(ZZ, dimension)

    for i in range(dimension):
        for j in range(i + 1):
            lattice[i, j] = basis[i][j]

    # Find a short vector corresponding to a polynomial that
    # vanishes at the desired small root.
    lattice = lattice.LLL()

    recovered = sum(
        x**i * lattice[0, i] / X**i
        for i in range(dimension)
    )

    roots = []

    for root, _ in recovered.roots():
        if not root.is_integer():
            continue

        root = ZZ(root)
        if abs(root) > X:
            continue

        value = polynomial_z(root)

        if gcd(modulus, value) > 1 and divisor_bound_holds(
            gcd(modulus, value), modulus, beta
        ):
            roots.append(root)

    return roots
