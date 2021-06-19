#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os
import errno
import signal
import base64
import logging
import subprocess
import contextlib
import binascii
from lib.keys_wrapper import PublicKey
from lib.rsalibnum import invmod

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


def get_base64_value(value):
    """Parse input (hex or numerical)"""
    try:
        if base64.b64encode(base64.b64decode(value)) == value:
            return base64.b64decode(value)
        else:
            return value
    except:
        return value


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
                    if str(priv_key) != "":
                        logger.info(priv_key)
                    else:
                        logger.warning(
                            "Key format seems wrong, check input data to solve this."
                        )

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
                        try:
                            c_utf8 = c.decode("utf-8")
                            logger.info(f"utf-8 : { c_utf8 }")
                        except UnicodeDecodeError:
                            pass
                        try:
                            c_utf16 = c.decode("utf-16")
                            logger.info(f"utf-16 : { c_utf16 }")
                        except UnicodeDecodeError:
                            pass
                        logger.info(f"STR : {repr(c)}")
        else:
            logger.critical("Sorry, unciphering failed.")


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


def s2n(s):
    """
    String to number.
    """
    if not len(s):
        return 0
    return int(binascii.hexlify(s), 16)


def n2s(n):
    """
    Number to string.
    """
    s = hex(n)[2:].rstrip("L")
    if len(s) & 1 != 0:
        s = "0" + s

    return binascii.unhexlify(s)


def binary_search(L, n):
    """ Finds item index in O(log2(N)) """
    left = 0
    right = len(L) - 1
    while left <= right:
        mid = (left + right) >> 1
        if n == L[mid]:
            return mid
        elif n < L[mid]:
            right = mid - 1
        else:
            left = mid + 1
    return -1
