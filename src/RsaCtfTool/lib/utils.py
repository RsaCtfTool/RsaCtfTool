#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os
import errno
import signal
import base64
import logging
import contextlib
import psutil
import binascii
from threading import Timer
from RsaCtfTool.lib.keys_wrapper import PublicKey
from RsaCtfTool.lib.number_theory import invmod

# used to track the location of RsaCtfTool
# allows sage scripts to be launched anywhere in the fs
_libutil_ = os.path.realpath(__file__)
rootpath, _libutil_ = os.path.split(_libutil_)
rootpath = f"{rootpath}/.."


def get_numeric_value(value):
    """Parse input (hex or numerical)"""
    if isinstance(value, int):
        return value
    return int(value, 16) if str(value).startswith("0x") else int(value)


def get_base64_value(value):
    """Decode base64 input; pass anything else through unchanged.

    The round-trip check compares b64encode's bytes output against the
    input, so string input must be encoded first - comparing bytes to str
    never matches and base64 strings used to pass through undecoded.
    """
    try:
        if isinstance(value, str):
            value = value.encode()
        if base64.b64encode(d := base64.b64decode(value)) == value:
            return d
        else:
            return value
    except Exception:
        return value


def print_decrypted_res(c, logger):
    logger.info(f"HEX : 0x{c.hex()}")

    int_big = int.from_bytes(c, "big")
    int_little = int.from_bytes(c, "little")

    logger.info(f"INT (big endian) : {int_big}")
    logger.info(f"INT (little endian) : {int_little}")
    with contextlib.suppress(UnicodeDecodeError):
        c_utf8 = c.decode("utf-8")
        logger.info(f"utf-8 : {c_utf8}")
    with contextlib.suppress(UnicodeDecodeError):
        c_utf16 = c.decode("utf-16")
        logger.info(f"utf-16 : {c_utf16}")
    logger.info(f"STR : {repr(c)}")


def _print_private_key(args, private_keys, logger):
    logger.info("\nPrivate key :")
    for priv_key in private_keys:
        if priv_key is None:
            continue
        if args.output:
            try:
                with open(args.output, "a") as output_fd:
                    output_fd.write("%s\n" % str(priv_key))
            except Exception:
                logger.error(f"Can't write output file : {args.output}")
        if not str(priv_key):
            logger.warning("Key format seems wrong, check input data to solve this.")
            if priv_key.n is not None:
                logger.info(f"n: {priv_key.n}")
            if priv_key.e is not None:
                logger.info(f"e: {priv_key.e}")
            if priv_key.d is not None:
                logger.info(f"d: {priv_key.d}")
        else:
            logger.info(priv_key)


def _print_dumpkey_private(args, private_keys, logger):
    logger.info("\nPrivate key details:")
    for priv_key in private_keys:
        if priv_key.n is not None:
            logger.info(f"n: {str(priv_key.n)}")
        if priv_key.e is not None:
            logger.info(f"e: {str(priv_key.e)}")
        if priv_key.d is not None:
            logger.info(f"d: {str(priv_key.d)}")
        if getattr(priv_key, "primes", None) and len(priv_key.primes) > 2:
            logger.info(
                f"primes ({len(priv_key.primes)}): {', '.join(str(p) for p in priv_key.primes)}"
            )
        else:
            if priv_key.p is not None:
                logger.info(f"p: {str(priv_key.p)}")
            if priv_key.q is not None:
                logger.info(f"q: {str(priv_key.q)}")
        if args.ext:
            if (
                priv_key.d is not None
                and priv_key.p is not None
                and priv_key.q is not None
            ):
                dp = priv_key.d % (priv_key.p - 1)
                dq = priv_key.d % (priv_key.q - 1)
                logger.info(f"dp: {str(dp)}")
                logger.info(f"dq: {str(dq)}")
                try:
                    pinv = invmod(priv_key.p, priv_key.q)
                    qinv = invmod(priv_key.q, priv_key.p)
                    logger.info(f"pinv: {str(pinv)}")
                    logger.info(f"qinv: {str(qinv)}")
                except (ZeroDivisionError, ValueError):
                    # p == q (square modulus) has no CRT inverse.
                    logger.info("pinv/qinv: undefined for p == q")


def _print_dumpkey_public(args, publickey, logger):
    for public_key in args.publickey:
        with open(public_key, "rb") as pubkey_fd:
            publickey_obj = PublicKey(pubkey_fd.read(), publickey)
            logger.info("\nPublic key details for %s" % publickey_obj.filename)
            logger.info(f"n: {str(publickey_obj.n)}")
            logger.info(f"e: {str(publickey_obj.e)}")


def _print_decrypt_results(args, decrypt, logger):
    if decrypt is None:
        logger.critical("Sorry, decrypting failed.")
        return
    if not isinstance(decrypt, list):
        decrypt = [decrypt]
    if len(decrypt) == 0:
        return
    logger.info("\nDecrypted data :")
    for decrypted_ in decrypt:
        if not isinstance(decrypted_, list):
            decrypted_ = [decrypted_]
        for c in decrypted_:
            if args.output:
                try:
                    with open(args.output, "ab") as output_fd:
                        output_fd.write(c)
                except Exception:
                    logger.error(f"Can't write output file : {args.output}")
            print_decrypted_res(c, logger)
            if len(c) > 3 and c[0] == 0 and c[1] == 2:
                with contextlib.suppress(ValueError):
                    # Malformed data whose padding never reaches a 0
                    # separator must not crash the result printer.
                    nc = c[c[2:].index(0) + 2 :]
                    logger.info("\nPKCS#1.5 padding decoded!")
                    print_decrypted_res(nc, logger)


def print_results(args, publickey, private_key, decrypt):
    """Print results to output"""
    logger = logging.getLogger("global_logger")
    if any(
        (
            (args.private and private_key is not None),
            args.dumpkey,
            (args.decrypt and decrypt not in [None, []]),
        )
    ):
        if publickey is not None and isinstance(publickey, str):
            logger.info("\nResults for %s:" % publickey)
    if private_key is not None:
        private_keys = private_key if isinstance(private_key, list) else [private_key]
        if args.private:
            _print_private_key(args, private_keys, logger)
        if args.dumpkey:
            _print_dumpkey_private(args, private_keys, logger)
    else:
        if args.private:
            logger.critical("Sorry, cracking failed.")
        if args.dumpkey:
            _print_dumpkey_public(args, publickey, logger)

    if args.decrypt:
        _print_decrypt_results(args, decrypt, logger)


class TimeoutError(Exception):
    def __init__(self, value="Timed Out"):
        self.value = value

    def __str__(self):
        return repr(self.value)


# errno.ETIME is Linux-specific (absent on macOS); fall back to ETIMEDOUT.
DEFAULT_TIMEOUT_MESSAGE = os.strerror(getattr(errno, "ETIME", errno.ETIMEDOUT))


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
        self.timer = None
        self._old_handler = None

    def _timeout_handler(self, _signum, _frame):
        self.logger.warning("[!] Timeout.")
        raise TimeoutError(self.timeout_message)

    def __enter__(self):
        # The CLI help promises that values < 1 behave like MAX_INT, i.e.
        # no timeout at all - never arm a negative-interval Timer that
        # would fire immediately.
        if self.seconds < 1:
            return self
        self._old_handler = signal.getsignal(signal.SIGTERM)
        signal.signal(signal.SIGTERM, self._timeout_handler)

        def alarm_func():  # send signal
            signal.raise_signal(signal.SIGTERM)

        self.timer = Timer(
            self.seconds, alarm_func
        )  # this thread will send signal when timeout
        self.timer.start()
        return self

    def __exit__(self, exc_type, _exc_val, _exc_tb):
        if self.timer is not None:
            self.timer.cancel()
            self.timer = None
        if self._old_handler is not None:
            # Restore the previous handler so a later SIGTERM terminates
            # the process instead of raising our TimeoutError forever.
            signal.signal(signal.SIGTERM, self._old_handler)
            self._old_handler = None
        if self.suppress and exc_type is TimeoutError:
            return True


def s2n(s):
    """
    String to number.
    """
    return 0 if not len(s) else int(binascii.hexlify(s), 16)


def n2s(n):
    """
    Number to string.
    """
    s = hex(n)[2:].rstrip("L")
    if len(s) & 1 != 0:
        s = f"0{s}"

    return binascii.unhexlify(s)


def binary_search(L, n):
    """Finds item index in O(log2(N))"""
    left = 0
    right = len(L) - 1
    while left <= right:
        mid = ((right - left) >> 1) + left
        if n == L[mid]:
            return mid
        elif n < L[mid]:
            right = mid - 1
        else:
            left = mid + 1
    return -1


def terminate_proc_tree(pid, including_parent=False):
    parent = psutil.Process(pid)
    children = parent.children(recursive=True)
    for child in children:
        child.kill()
    if including_parent:
        parent.kill()
