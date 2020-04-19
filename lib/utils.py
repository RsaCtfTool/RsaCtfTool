#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import logging
import subprocess
from lib.rsalibnum import invmod
from lib.keys_wrapper import PublicKey


def get_numeric_value(value):
    """Parse input (hex or numerical)
    """
    if value.startswith("0x"):
        return int(value, 16)
    else:
        return int(value)


def sageworks():
    """Check if sage is installed and working
    """
    try:
        sageversion = subprocess.check_output(["sage", "-v"], timeout=10)
    except OSError:
        return False

    if "SageMath version" in sageversion.decode("utf-8"):
        return True
    else:
        return False


def print_results(args, publickey, private_key, uncipher):
    """ Print results to output
    """
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
                    if args.output:
                        try:
                            with open(args.output, "ab") as output_fd:
                                output_fd.write(uncipher_)
                        except:
                            logger.error("Can't write output file : %s" % args.output)
                    logger.info(uncipher_)
        else:
            logger.critical("Sorry, unciphering failed.")
