#!/usr/bin/python3

from subprocess import check_output
import libnum

# Source:
# https://0day.work/0ctf-2016-quals-writeups/

# Based on:
# RSA? Challenge in 0ctf 2016

# we are given a private key masked and have the components of the
# chinese remainder theorem and a partial "q"

# The above writeup detailed a method to derive q candidates
# given the CRT component dQ

# CRT Components definition
# dP    = e^-1 mod(p-1)
# dQ    = e^-1 mod(q-1)
# qInv  = q^-1 mod p

# Equations from https://0day.work/0ctf-2016-quals-writeups/

# dP Equalities
# -------------
# dP                 = d mod (p - 1)
# dP                 = d mod (p - 1)
# e * dP             = 1 mod (p - 1)
# e * dP - k*(p - 1) = 1
# e * dP             = 1 + k*(p-1)
# e * dP -1          = k*(p-1)
# (e * dP -1)/k      = (p-1)
# (e * dP -1)/k +1   = p

# dQ Equalities
# -------------
# dQ                 = d mod (q - 1)
# dQ                 = d mod (q - 1)
# e * dQ             = 1 mod (q - 1)
# e * dQ - k*(p - 1) = 1
# e * dQ             = 1 + k*(q-1)
# e * dQ -1          = k*(q-1)
# (e * dQ -1)/k      = (q-1)
# (e * dQ -1)/k +1   = p

# qInv Equalities
# ---------------
# qInv            = q^-1 mod p
# q * qInv        = 1 (mod p)
# q * qInv - k*p  = 1            (For some value "k")
# q * qInv        = 1 + k*p
# q * qInv - 1    = k*p
# (q * qInv -1)/k = p

# Additionally the following paper details an algorithm to generate
# p and q prime candidates with just the CRT components

# https://eprint.iacr.org/2004/147.pdf


def partial_q(e, dp, dq, qi, part_q):
    # Tunable to search longer
    N = 100000

    for j in range(N, 1, -1):
        q = (e * dq - 1) / j + 1
        if str(hex(q)).strip('L').endswith(part_q):
            break

    for k in range(1, N, 1):
        p = (e * dp - 1) / k + 1
        try:
            m = libnum.invmod(q, p)
            if m == qi:
                break
        except:
            pass

    print("p = " + str(p))
    print("q = " + str(q))


if __name__ == "__main__":
    # import the private key manually
    keyfile = 'examples/masked.pem'
    keycmd = ['openssl', 'asn1parse', '-in', keyfile]
    private_key = [long(x.split(':')[3], 16) for x in check_output(keycmd).splitlines() if 'INTEGER' in x]

    # dq from examples/masked.pem
    dp = private_key[4]
    dq = private_key[5]
    qi = private_key[6]

    # the last part of q we recovered in examples/masked.pem
    part_q = hex(private_key[3]).strip('L').replace('0x', '')

    # guessing exponent is standard
    e = 65537
    partial_q(e, dp, dq, qi, part_q)
