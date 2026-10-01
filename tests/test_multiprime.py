#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from RsaCtfTool.lib.keys_wrapper import PrivateKey, PublicKey
from RsaCtfTool.lib.number_theory import recursive_factorize, factor_ned_universal
from RsaCtfTool.attacks.single_key.brent import Attack as BrentAttack
from RsaCtfTool.attacks.single_key.fermat import Attack as FermatAttack


def test_multiprime_private_key():
    from RsaCtfTool.lib.number_theory import next_prime
    p1 = int(next_prime(10**25))
    p2 = int(next_prime(p1 + 100))
    p3 = int(next_prime(p2 + 100))
    p4 = int(next_prime(p3 + 100))
    primes = [p1, p2, p3, p4]
    n = p1 * p2 * p3 * p4
    e = 65537

    priv = PrivateKey(primes=primes, e=e, n=n)
    assert priv.d is not None
    assert len(priv.primes) == 4

    # Encrypt and decrypt test message
    msg = b"FLAG{multi_prime_rsa_4_primes_cracked}"
    m_int = int.from_bytes(msg, "big")
    c_int = pow(m_int, e, n)
    c_bytes = c_int.to_bytes((c_int.bit_length() + 7) // 8, "big")

    decrypted = priv.decrypt(c_bytes)
    print("decrypted:", decrypted)
    print("expected:", msg)
    assert decrypted[0] == msg


def test_recursive_factorize_4_primes():
    p1 = 10007
    p2 = 10009
    p3 = 10037
    p4 = 10039
    primes = sorted([p1, p2, p3, p4])
    n = p1 * p2 * p3 * p4

    factors = recursive_factorize(n)
    assert sorted(factors) == primes


def test_miller_rabin_factor_from_ed():
    p1 = 65539
    p2 = 65543
    p3 = 65551
    p4 = 65557
    primes = sorted([p1, p2, p3, p4])
    n = p1 * p2 * p3 * p4
    e = 65537

    import functools
    phi = functools.reduce(lambda acc, p: acc * (p - 1), primes, 1)
    d = pow(e, -1, phi)

    split = factor_ned_universal(n, e, d)
    assert split is not None
    assert len(split) >= 2


if __name__ == "__main__":
    test_multiprime_private_key()
    test_recursive_factorize_4_primes()
    test_miller_rabin_factor_from_ed()
    print("ALL MULTIPRIME TESTS PASSED!")
