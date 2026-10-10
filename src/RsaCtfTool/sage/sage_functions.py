

def coppersmith_howgrave_univariate(pol, modulus, beta, mm, tt, XX):
    """
    Coppersmith revisited by Howgrave-Graham

    Delegates to the shared Coppersmith backend, which fixes the silent
    float overflow of modulus**beta for moduli >= 2**1024.
    """
    from RsaCtfTool.lib.coppersmith import CoppersmithParameters
    from RsaCtfTool.sage.coppersmith import coppersmith_univariate_sage

    if not 0 < beta <= 1:
        raise ValueError("beta should belongs in [0, 1]")

    return coppersmith_univariate_sage(
        pol, modulus, CoppersmithParameters(beta=beta, X=XX, m=mm, t=tt)
    )

