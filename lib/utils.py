#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os
import time
import errno
import signal
import logging
import subprocess
import contextlib
from lib.rsalibnum import invmod
from lib.keys_wrapper import PublicKey

# used to track the location of RsaCtfTool
# allows sage scripts to be launched anywhere in the fs
_libutil_ = os.path.realpath(__file__)
rootpath, _libutil_ = os.path.split(_libutil_)
rootpath = "%s/.." % rootpath  # up one dir


def get_numeric_value(value):
    """Parse input (hex or numerical)"""
    if value.startswith("0x"):
        return int(value, 16)
    else:
        return int(value)


def sageworks():
    """Check if sage is installed and working"""
    try:
        sageversion = subprocess.check_output(["sage", "-v"], timeout=10)
    except OSError:
        return False

    if "SageMath version" in sageversion.decode("utf-8"):
        return True
    else:
        return False


def print_results(args, publickey, private_key, uncipher):
    """Print results to output"""
    logger = logging.getLogger("global_logger")
    if (
        (args.private and private_key is not None)
        or (args.dumpkey)
        or (args.uncipher and uncipher not in [None, []])
    ):
        if publickey is not None:
            logger.info("\nResults for %s:" % publickey)
    if private_key is not None:
        if not isinstance(private_key, list):
            private_keys = [private_key]
        else:
            private_keys = private_key

        if args.private:
            logger.info("\nPrivate key :")
            for priv_key in private_keys:
                if priv_key is not None:
                    if args.output:
                        try:
                            with open(args.output, "a") as output_fd:
                                output_fd.write("%s\n" % str(priv_key))
                        except:
                            logger.error("Can't write output file : %s" % args.output)
                    logger.info(priv_key)

        if args.dumpkey:
            for priv_key in private_keys:
                if priv_key.n is not None:
                    logger.info("n: " + str(priv_key.n))
                if priv_key.e is not None:
                    logger.info("e: " + str(priv_key.e))
                if priv_key.d is not None:
                    logger.info("d: " + str(priv_key.d))
                if priv_key.p is not None:
                    logger.info("p: " + str(priv_key.p))
                if priv_key.q is not None:
                    logger.info("q: " + str(priv_key.q))
                if args.ext:
                    dp = priv_key.d % (priv_key.p - 1)
                    dq = priv_key.d % (priv_key.q - 1)
                    pinv = invmod(priv_key.p, priv_key.q)
                    qinv = invmod(priv_key.q, priv_key.p)
                    logger.info("dp: " + str(dp))
                    logger.info("dq: " + str(dq))
                    logger.info("pinv: " + str(pinv))
                    logger.info("qinv: " + str(qinv))
    else:
        if args.private:
            logger.critical("Sorry, cracking failed.")

    if args.dumpkey:
        if args.publickey is not None:
            for public_key in args.publickey:
                with open(public_key, "rb") as pubkey_fd:
                    publickey_obj = PublicKey(pubkey_fd.read(), publickey)
                    logger.info("\nPublic key details for %s" % publickey_obj.filename)
                    logger.info("n: " + str(publickey_obj.n))
                    logger.info("e: " + str(publickey_obj.e))

    if args.uncipher:
        if uncipher is not None:
            if not isinstance(uncipher, list):
                uncipher = [uncipher]
            if len(uncipher) > 0:
                logger.info("\nUnciphered data :")
                for uncipher_ in uncipher:
                    if not isinstance(uncipher_, list):
                        uncipher_ = [uncipher_]

                    for c in uncipher_:
                        if args.output:
                            try:
                                with open(args.output, "ab") as output_fd:
                                    output_fd.write(c)
                            except:
                                logger.error(
                                    "Can't write output file : %s" % args.output
                                )

                        logger.info(f"HEX : 0x{c.hex()}")

                        int_big = int.from_bytes(c, "big")
                        int_little = int.from_bytes(c, "little")

                        logger.info(f"INT (big endian) : {int_big}")
                        logger.info(f"INT (little endian) : {int_little}")
                        logger.info(f"STR : {repr(c)}")
        else:
            logger.critical("Sorry, unciphering failed.")


def isqrt(n):
    if n == 0:
        return 0
    x, y = n, (n + 1) // 2
    while y < x:
        x, y = y, (y + n // y) // 2
    return x


def gcd(a, b):
    while b:
        a, b = b, a % b
    return abs(a)


def introot(n, r=2):
    if n < 0:
        return None if r % 2 == 0 else -introot(-n, r)
    if n < 2:
        return n
    if r == 2:
        return isqrt(n)
    lower, upper = 0, n
    while lower != upper - 1:
        mid = (lower + upper) // 2
        m = mid ** r
        if m == n:
            return mid
        elif m < n:
            lower = mid
        elif m > n:
            upper = mid
    return lower


def modinv(a, m):
    a, x, u = a % m, 0, 1
    while a:
        x, u, m, a = u, x - (m // a) * u, a, m % a
    return x


class TimeoutError(Exception):
    def __init__(self, value="Timed Out"):
        self.value = value

    def __str__(self):
        return repr(self.value)


DEFAULT_TIMEOUT_MESSAGE = os.strerror(errno.ETIME)


class timeout(contextlib.ContextDecorator):
    def __init__(
        self,
        seconds,
        *,
        timeout_message=DEFAULT_TIMEOUT_MESSAGE,
        suppress_timeout_errors=False,
    ):
        self.seconds = int(seconds)
        self.timeout_message = timeout_message
        self.suppress = bool(suppress_timeout_errors)
        self.logger = logging.getLogger("global_logger")

    def _timeout_handler(self, signum, frame):
        self.logger.warning("[!] Timeout.")
        raise TimeoutError(self.timeout_message)

    def __enter__(self):
        signal.signal(signal.SIGALRM, self._timeout_handler)
        signal.alarm(self.seconds)

    def __exit__(self, exc_type, exc_val, exc_tb):
        signal.alarm(0)
        if self.suppress and exc_type is TimeoutError:
            return True
