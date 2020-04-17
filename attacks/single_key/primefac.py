#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from __future__ import print_function, division
import logging
import _primefac
from threading import Timer
from _primefac._prime import primes
from lib.timeout import timeout
from lib.rsalibnum import gcd
from lib.keys_wrapper import PrivateKey
from _primefac._util import listprod
from lib.exceptions import FactorizationError

# Note that the multiprocing incurs relatively significant overhead.
# Only call this if n is proving difficult to factor.


def kill_procs(procs):
    """Kill it with fire !!!
    """
    for p in procs:
        p.terminate()


def multifactor(
    n,
    methods=(
        _primefac.pollardRho_brent,
        _primefac.pollard_pm1,
        _primefac.williams_pp1,
        _primefac.ecm,
        _primefac.mpqs,
        _primefac.fermat,
        _primefac.factordb,
    ),
    verbose=False,
    timeout=59,
):
    """Multifactor implementation
    """
    from multiprocessing import Process, Queue as mpQueue
    from six.moves import xrange, reduce
    import six

    def factory(method, n, output):
        """Simple factory
        """
        try:
            g = method(n)
        except OverflowError:
            return None
        if g is not None:
            output.put((g, str(method).split()[1]))

    factors = mpQueue()

    procs = [Process(target=factory, args=(m, n, factors)) for m in methods]
    timer = Timer(timeout, kill_procs, [procs])
    try:
        timer.start()
        for p in procs:
            p.start()

        (f, g) = factors.get()
        for p in procs:
            try:
                p.terminate()
            except:
                pass
    finally:
        timer.cancel()
    return f


"""
Obtains a complete factorization of n, yielding the prime factors as they are
obtained. If the user explicitly specifies a splitting method, use that method.
Otherwise,
1.  Pull out small factors with trial division.
2.  Do a few rounds of _primefac.pollard's Rho algorithm.
    TODO: a few rounds of ECM by itself?
    TODO: a certain amount of P-1?
3.  Launch multifactor on the remainder.  Multifactor has enough overhead that
    we want to be fairly sure that rho isn't likely to yield new factors soon.
    The default value of rho_rounds=42000 seems good for that but is probably
    overkill.
"""


def primefac(
    n,
    trial_limit=1000,
    rho_rounds=42000,
    verbose=False,
    methods=(
        _primefac.pollardRho_brent,
        _primefac.pollard_pm1,
        _primefac.williams_pp1,
        _primefac.ecm,
        _primefac.mpqs,
        _primefac.fermat,
        _primefac.factordb,
    ),
    timeout=60,
):
    """Primefac implementation
    """
    from _primefac import isprime, isqrt, primegen
    from six.moves import xrange, reduce
    from random import randrange
    import six

    timeout = timeout - 1
    if n < 2:
        return
    if isprime(n):
        yield n
        return

    factors, nroot = [], isqrt(n)
    # Note that we remove factors of 2 whether the user wants to or not.
    for p in primegen():
        if n % p == 0:
            while n % p == 0:
                yield p
                n //= p
            nroot = isqrt(n)
            if isprime(n):
                yield n
                return
        if p > nroot:
            if n != 1:
                yield n
            return
        if p >= trial_limit:
            break
    if isprime(n):
        yield n
        return

    if rho_rounds == "inf":
        factors = [n]
        while len(factors) != 0:
            n = min(factors)
            factors.remove(n)
            f = _primefac.pollardRho_brent(n)
            if isprime(f):
                yield f
            else:
                factors.append(f)
            n //= f
            if isprime(n):
                yield n
            else:
                factors.append(n)
        return

    factors, difficult = [n], []
    while len(factors) != 0:
        rhocount = 0
        n = factors.pop()
        try:
            g = n
            while g == n:
                x, c, g = randrange(1, n), randrange(1, n), 1
                y = x
                while g == 1:
                    if rhocount >= rho_rounds:
                        raise Exception
                    rhocount += 1
                    x = (x ** 2 + c) % n
                    y = (y ** 2 + c) % n
                    y = (y ** 2 + c) % n
                    g = gcd(x - y, n)
            # We now have a nontrivial factor g of n.  If we took too long to get here, we're actually at the except statement.
            if isprime(g):
                yield g
            else:
                factors.append(g)
            n //= g
            if isprime(n):
                yield n
            else:
                factors.append(n)
        except Exception:
            difficult.append(
                n
            )  # Factoring n took too long.  We'll have multifactor chug on it.

    factors = difficult
    while len(factors) != 0:
        n = min(factors)
        factors.remove(n)
        f = multifactor(n, methods=methods, verbose=verbose, timeout=timeout)
        if isprime(f):
            yield f
        else:
            factors.append(f)
        n //= f
        if isprime(n):
            yield n
        else:
            factors.append(n)


def factorint(
    n,
    trial_limit=1000,
    rho_rounds=42000,
    methods=(
        _primefac.pollardRho_brent,
        _primefac.pollard_pm1,
        _primefac.williams_pp1,
        _primefac.ecm,
        _primefac.mpqs,
        _primefac.fermat,
        _primefac.factordb,
    ),
):
    """Factorize int
    """
    out = {}
    for p in primefac(
        n, trial_limit=trial_limit, rho_rounds=rho_rounds, methods=methods
    ):
        out[p] = out.get(p, 0) + 1
    return out


usage = """
This is primefac-fork version 1.1.
USAGE:
    primefac [-vs|-sv] [-v|--verbose] [-s|--summary] [-t=NUM] [-r=NUM]
          [-m=[prb][,p-1][,p+1][,ecm][,mpqs][,fermat][,factordb]] rpn
    "rpn" is evaluated using integer arithmetic.  Each number that remains on
    the stack after evaluation is then factored.
    "-t" is the trial division limit.  Default == 1000.  Use "-t=inf" to use
    trial division exclusively.
    "-r" is the number of rounds of _primefac.pollard's rho algorithm to try before
    calling a factor "difficult".  Default == 42,000.  Use "-r=inf" to use
    _primefac.pollard's rho exclusively once the trial division is completed.
    If verbosity is invoked, we indicate in the output which algorithm produced
    which factors during the multifactor phase.
    If the summary flag is absent, then output is identical to the output of the
    GNU factor command, except possibly for the order of the factors and, if
    verbosity has been turned on, the annotations indicating which algorithm
    produced which factors.
    If the summary flag is present, then output is modified by adding a single
    newline between each item's output, before the first, and after the last.
    Each item's output is also modified by printing a second line of data
    summarizing the results by describing the number of decimal digits in the
    input, the number of decimal digits in each prime factor, and the factors'
    multiplicities.  For example:
    >>> user@computer:~$ primefac  -s   24 ! 1 -   7 !
    >>>
    >>> 620448401733239439359999: 991459181683 625793187653
    >>> Z24  =  P12 x P12  =  625793187653 x 991459181683
    >>>
    >>> 5040: 2 2 2 2 3 3 5 7
    >>> Z4  =  P1^4 x P1^2 x P1 x P1  =  2^4 x 3^2 x 5 x 7
    >>>
    >>> user@computer:~$
    Note that the primes in the summary lines are listed in strictly-increasing
    order, regardless of the order in which they were found.
    The single-character versions of the verbosity and summary flags may be
    combined into a single flag, "-vs" or "-sv".
    The "-m" flag controls what methods are run during the multifactor phase.
    prb and ecm can be listed repeatedly to run multiple instances of these
    methods; running multiple instances of p-1, p+1, or mpqs confers no benefit,
    so repeated listings of those methods are ignored.
    This program can also be imported into your Python scripts as a module.
DETAILS:
    Factoring: 1.  Trial divide using the primes <= the specified limit.
               2.  Run _primefac.pollard's rho algorithm on the remainder.  Declare a
                   cofactor "difficult" if it survives more than the specified
                   number of rounds of rho.
               3.  Subject each remaining cofactor to five splitting methods in
                   parallel: _primefac.pollard's rho algorithm with Brent's improvement,
                             _primefac.pollard's p-1 method,
                             _primefac.williams' p+1 method,
                             the elliptic curve method,
                             the multiple-polynomial quadratic sieve,
                             the fermat's factorization method,
                             and search known factors using factordb.
               Using the "verbose" option will cause primefac to report which of
               the various splitting methods separated which factors in stage 3.
    RPN:       The acceptable binary operators are + - * / % **.
               They all have the same meaning as they do in Python source code
               --- i.e., they are addition, subtraction, multiplication, integer
               division, remainder, and exponentiation.
               The acceptable unary operators are ! #.  They are the factorial
               and primorial, respectively.
               There are three aliases: x for *, xx for **, and p! for #.
               You may enclose the RPN expression in quotes if you so desire.
PERFORMANCE:
CREDITS:
    Not much of this code was mine from the start.
     * The MPQS code was copied mostly verbatim from
       https://codegolf.stackexchange.com/questions/8629/9088#9088
     * The functions to manipulate points in the elliptic curve method were
       copied from a reply to the Programming Praxis post at
       http://programmingpraxis.com/2010/04/23/
"""  # TODO performance, credits


def rpn(instr):
    """RPN implementation
    """
    stack = []
    for token in instr.split():
        if set(token).issubset("1234567890L"):
            stack.append(int(token.rstrip("L")))
        elif (
            len(token) > 1
            and token[0] == "-"
            and set(token[1:]).issubset("1234567890L")
        ):
            stack.append(int(token))
        elif token in ("+", "-", "*", "/", "%", "**", "x", "xx"):  # binary operators
            b = stack.pop()
            a = stack.pop()
            if token == "+":
                res = a + b
            elif token == "-":
                res = a - b
            elif token == "*":
                res = a * b
            elif token == "x":
                res = a * b
            elif token == "/":
                res = a / b
            elif token == "%":
                res = a % b
            elif token == "**":
                res = a ** b
            elif token == "xx":
                res = a ** b
            stack.append(res)
        elif token in ("!", "#", "p!"):  # unary operators
            a = stack.pop()
            if token == "!":
                res = listprod(range(1, a + 1))
            elif token == "#":
                res = listprod(primes(a + 1))
            elif token == "p!":
                res = listprod(primes(a + 1))
            stack.append(res)
        else:
            raise Exception(
                "Failed to evaluate RPN expression: not sure what to do with '{t}'.".format(
                    t=token
                )
            )
    return [_primefac.mpz(i) for i in stack]


def attack(attack_rsa_obj, publickey, cipher=[]):
    """Use primefac
    """
    try:
        with timeout(seconds=attack_rsa_obj.args.timeout):
            result = list(primefac(publickey.n, timeout=attack_rsa_obj.args.timeout))
    except FactorizationError:
        return (None, None)

    if len(result) == 2:
        publickey.p = int(result[0])
        publickey.q = int(result[1])
        priv_key = PrivateKey(
            int(publickey.p), int(publickey.q), int(publickey.e), int(publickey.n)
        )
        return (priv_key, None)

    return (None, None)
