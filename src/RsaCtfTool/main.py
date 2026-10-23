#!/usr/bin/env python3

"""
----------------------------------------------------------------------------
"MIT License:
ganapati (@G4N4P4T1) is the original author of this project. As long as you retain this notice you
can do whatever you want with this stuff. If we meet some day, and you think
this stuff is worth it, you can buy me a beer in return.
----------------------------------------------------------------------------
"""

import argparse
import logging
import os
import sys
import tempfile
from glob import glob
from os.path import basename, dirname, isfile, join

import urllib3
from urllib3.exceptions import InsecureRequestWarning

from RsaCtfTool.lib.crypto_wrapper import RSA
from RsaCtfTool.lib.customlogger import CustomFormatter, logger_levels
from RsaCtfTool.lib.idrsa_pub_disector import disect_idrsa_pub
from RsaCtfTool.lib.is_roca_test import is_roca_vulnerable
from RsaCtfTool.lib.keys_wrapper import (
    PrivateKey,
    generate_keys_from_p_q_e_n,
    generate_pq_from_n_and_p_or_q,
)
from RsaCtfTool.lib.number_theory import factor_ned, invmod
from RsaCtfTool.lib.rsa_attack import RSAAttack
from RsaCtfTool.lib.utils import get_base64_value, get_numeric_value, n2s, print_results

# Remove insecure warning for factordb.com
urllib3.disable_warnings(InsecureRequestWarning)

# Change recursion limit for... you know, factorizing stuff...
sys.setrecursionlimit(5000)


def banner():
    cEND = "\033[0m"
    cRED = "\033[1;31m"
    return (
        r"""
__________               R_______________________________E __                .__
\______   \ ___________  R\_   ___ \__    ___/\_   _____/E/  |_  ____   ____ |  |
 |       _//  ___/\__  \ R/    \  \/ |    |    |    __)E \   __\/  _ \ /  _ \|  |
 |    |   \\\___ \  / __ \R\     \____|    |    |     \E   |  | (  <_> |  <_> )  |__
 |____|_  /____  >(____  /R\______  /|____|    \___  /E   |__|  \____/ \____/|____/
        \/     \/      \/        R\/E               R\/E

""".replace("R", cRED).replace("E", cEND)
        + """
Disclaimer: this tool is meant for educational purposes, for those doing CTF's first try:

Learning the basis of RSA math, understand number theory, modular arithmetic, integer factorization, fundamental theorem of arithmetic.
Read the code in this repo to see what and how it does and how to improve it, send PR's.
Avoid copy-paste-run and at last run this tool (knowing the math is more valuable than knowing how to run this tool).

"""
    )


def parse_args():
    parser = argparse.ArgumentParser(description="RSA CTF Tool")

    parser.add_argument(
        "--publickey", help="public key file. You can use wildcards for multiple keys."
    )
    parser.add_argument(
        "--output", help="output file for results (private keys, plaintext data)."
    )
    parser.add_argument(
        "--timeout",
        help="Timeout for long attacks in seconds. default is 60s min: MIN_INT in C, max: MAX_INT in C, values < 1 have the same effect as MAX_INT",
        default=60,
        type=int,
    )
    parser.add_argument(
        "--createpub",
        help="Take n and e from cli and just print a public key then exit",
        action="store_true",
    )
    parser.add_argument(
        "--dumpkey",
        help="Just dump the RSA variables from a key - n,e,d,p,q",
        action="store_true",
    )
    parser.add_argument(
        "--ext",
        help="Extended dump of RSA private variables in --dumpkey mode - dp,dq,pinv,qinv).",
        action="store_true",
    )
    parser.add_argument(
        "--decryptfile",
        help="decrypt a file, using commas to separate multiple paths",
        default=None,
    )
    parser.add_argument(
        "--decrypt",
        help="decrypt a cipher, using commas to separate multiple ciphers",
        default=None,
    )
    parser.add_argument(
        "--verbosity", help="verbose mode", choices=logger_levels.keys(), default="INFO"
    )
    parser.add_argument(
        "--private", help="Display private key if recovered", action="store_true"
    )
    parser.add_argument("--tests", help="Run tests on attacks", action="store_true")
    parser.add_argument(
        "--ecmdigits",
        type=int,
        help="Optionally an estimate as to how long one of the primes is for ECM method",
        default=None,
    )
    parser.add_argument("-n", help="Specify the modulus. format : int or 0xhex")
    parser.add_argument(
        "-p", help="Specify the first prime number. format : int or 0xhex"
    )
    parser.add_argument(
        "-q", help="Specify the second prime number. format : int or 0xhex"
    )
    parser.add_argument(
        "-e",
        help="Specify the public exponent, using commas to separate multiple exponents. format : int or 0xhex",
    )
    parser.add_argument(
        "-d",
        help="Specify the private exponent. Format : int or 0xhex",
    )
    parser.add_argument("--key", help="Specify the private key file.")
    parser.add_argument("--password", help="Private key password if needed.")
    parser.add_argument(
        "--fr-a",
        help="Franklin-Reiter attack: 'a' parameter in m1 = a*m2 + b. format : int or 0xhex",
    )
    parser.add_argument(
        "--fr-b",
        help="Franklin-Reiter attack: 'b' parameter in m1 = a*m2 + b. format : int or 0xhex",
    )
    parser.add_argument(
        "--sm-prefix",
        help="Stereotyped message attack: known prefix of the message (use 0x... for hex, everything else treated as ASCII)",
    )
    parser.add_argument(
        "--sm-suffix",
        help="Stereotyped message attack: known suffix of the message (use 0x... for hex, everything else treated as ASCII)",
    )
    parser.add_argument(
        "--sm-len",
        type=int,
        help="Stereotyped message attack: length in bytes of the unknown part",
    )
    parser.add_argument(
        "--p-high",
        help="partial_p attack: known high bits of p. format : int or 0xhex",
    )
    parser.add_argument(
        "--p-unknown-bits",
        type=int,
        help="partial_p attack: number of unknown lower bits of p",
    )
    parser.add_argument(
        "--d-known-bits",
        type=int,
        help="partial_d attack: explicit number of known low bits of d",
    )
    parser.add_argument(
        "--dp",
        help="dp_leak attack: leaked dp = d mod (p-1). format : int or 0xhex",
    )
    parser.add_argument(
        "--dq",
        help="dp_leak attack: leaked dq = d mod (q-1). format : int or 0xhex",
    )
    parser.add_argument(
        "--fault-sig",
        help="bellcore attack: faulty RSA-CRT signature. format : int or 0xhex",
    )
    parser.add_argument(
        "--fault-msg",
        help="bellcore attack: the signed (padded) message as an integer. format : int or 0xhex",
    )
    parser.add_argument(
        "--good-sig",
        help="bellcore attack: correct signature of the same message. format : int or 0xhex",
    )

    # If no arguments, display help and exit
    if len(sys.argv) == 1:
        print(banner())
        parser.print_help()
        sys.exit(1)

    # Dynamic load all attacks for choices in argparse
    attacks = sorted(
        glob(join(dirname(os.path.realpath(__file__)), "attacks", "single_key", "*.py"))
    )
    attacks += sorted(
        glob(join(dirname(os.path.realpath(__file__)), "attacks", "multi_keys", "*.py"))
    )

    attacks_filtered = [
        basename(f)[:-3] for f in attacks if isfile(f) and not f.endswith("__init__.py")
    ]
    attacks_list = [_ for _ in attacks_filtered if _ != "nullattack"] + ["all"]
    parser.add_argument(
        "--attack",
        help="Specify the attack modes.",
        default="all",
        nargs="+",
        choices=attacks_list,
    )
    parser.add_argument(
        "--sendtofdb", help="Send results to factordb", action="store_true"
    )
    parser.add_argument(
        "--isconspicuous", help="conspicuous key check", action="store_true"
    )
    parser.add_argument(
        "--isroca", help="Check if given key is roca", action="store_true"
    )

    parser.add_argument(
        "--convert_idrsa_pub", help="Convert idrsa.pub to pem", action="store_true"
    )
    parser.add_argument(
        "--check_publickey",
        help="Check publickey if modulus is well formed before attack",
        action="store_true",
    )

    parser.add_argument(
        "--partial",
        help="work with partial private keys",
        action="store_true",
    )

    parser.add_argument(
        "--cleanup",
        help="cleanup *.pub files after finish",
        action="store_true",
    )

    parser.add_argument(
        "--withtraceback",
        help="show tracebacks",
        action="store_true",
    )

    parser.add_argument(
        "--show_modulus",
        help="print the modulus when provided via -n",
        action="store_true",
    )

    args = parser.parse_args()
    args.attacks_list = attacks_list
    return args


def run_conspicuous_check(args, logger):
    try:
        if args.key is not None:
            priv_key = PrivateKey(filename=args.key, password=args.password)
        else:
            _, priv_key = generate_keys_from_p_q_e_n(
                args.p, args.q, args.e, args.n
            )
    except Exception as exc:
        logger.error("Unable to load the private key: %s", exc)
        return False
    if priv_key is None or any(
        value is None
        for value in (priv_key.n, priv_key.p, priv_key.q, priv_key.d, priv_key.e)
    ):
        logger.error("A complete private key is required for conspicuousness checks.")
        return False
    c = priv_key.is_conspicuous()
    if c:
        logger.warning("[!] Key is conspicuous...")
    return c


def run_attacks(args, logger):
    # Run attacks
    attackobj = RSAAttack(args)
    selected_attacks = args.attacks_list

    # Run tests
    if args.publickey is None and args.tests:
        if args.attack is not None:
            selected_attacks = args.attack
        if "all" in selected_attacks:
            selected_attacks = args.attacks_list
        logger.info(
            "Testing attacks: %d" % len([a for a in selected_attacks if a != "all"])
        )

        # Write and close before use: Windows can't reopen a file that a
        # NamedTemporaryFile still holds open.
        with tempfile.NamedTemporaryFile(delete=False) as tmpfd:
            tmpfd.write(RSA.construct((35, 3)).publickey().exportKey())
        try:
            attackobj.attack_single_key(tmpfd.name, selected_attacks, test=True)
        finally:
            os.unlink(tmpfd.name)
        sys.exit(0)

    # Drives the exit code: 0 if anything was recovered, 1 otherwise.
    args.cracked = False

    # Attack multiple keys
    cracked = set()
    if args.publickey is not None and len(args.publickey) > 1:
        result = attackobj.attack_multiple_keys(args.publickey, selected_attacks)
        args.cracked |= result is True or attackobj.has_results()
        cracked = attackobj.cracked_filenames()

    # Attack key
    if args.publickey is not None:
        for publickey in args.publickey:
            if publickey in cracked:
                logger.info("\n[*] Key %s already cracked, skipping." % publickey)
                continue
            attackobj.implemented_attacks = []
            attackobj.decrypted = []
            # Without this reset a private key recovered for an earlier
            # key would be printed again as this key's result whenever
            # every attack for this key is skipped (can_run preflight).
            attackobj.priv_key = None
            logger.info("\n[*] Testing key %s." % publickey)
            result = attackobj.attack_single_key(publickey, selected_attacks)
            args.cracked |= result is True or attackobj.has_results()
    if args.publickey is None:
        if args.partial:
            priv_key = PrivateKey(filename=args.key, password=None)
            result = attackobj.attack_single_key(priv_key, selected_attacks)
            args.cracked |= result is True or attackobj.has_results()
        else:
            logger.error("No key specified")
    return args


def convert_idrsa_pub(args, logger):
    # for publickey in args.publickey:
    publickeys = glob(args.publickey)
    for publickey in publickeys:
        logger.info(f"Converting {publickey}: to pem...")
        with open(publickey, "r") as key_data_fd:
            for line in key_data_fd:
                n, e = disect_idrsa_pub(line.rstrip())
                if n and e:
                    pub_key, _ = generate_keys_from_p_q_e_n(None, None, e, n)
                    if pub_key:
                        logger.info(pub_key.decode("utf-8"))
                    else:
                        logger.error("Error generating keys from n and e values.")


def check_is_roca(args, logger):
    """
    Checks the given list of public key files for the ROCA vulnerability.

    Args:
        args (Namespace): Command line arguments or configuration settings.
        logger: Logger instance for logging messages.

    Returns:
        bool: True if any of the public keys are vulnerable, False otherwise.
    """
    vuln = False
    pubkeyfilelist = glob(args.publickey)
    for publickey in pubkeyfilelist:
        logger.info(f"[-] Details for {publickey}:")
        with open(publickey, "rb") as key_data_fd:
            try:
                key = RSA.importKey(key_data_fd.read())
            except Exception:
                key = None
                logger.error(f"[!] Error file format: {publickey}")
            if key is not None:
                if is_roca_vulnerable(key.n):
                    vuln = True
                    logger.warning(f"[!] Public key {publickey}: is roca!!!")
                else:
                    logger.info(
                        f"[-] Public key {publickey}: is not roca, you are safe"
                    )
    return vuln


def load_keys(args, logger):
    tmpfile = None
    args.publickey = []
    for e in args.e if isinstance(args.e, list) else [args.e]:
        try:
            pub_pem = RSA.construct((args.n, e)).publickey().exportKey()
        except ValueError:
            logger.error(
                "[!] Cannot build a public key from the given n and e (e must be odd, > 1 and < n)."
            )
            sys.exit(1)
        with tempfile.NamedTemporaryFile(delete=False) as tmpfd:
            tmpfd.write(pub_pem)
        args.publickey.append(tmpfd.name)
    return args


def dump_key_parameters(args):
    key_data = open(args.key, "rb").read()
    key = RSA.importKey(key_data)
    print(f"n: {str(key.n)}")
    print(f"e: {str(key.e)}")
    if key.has_private():
        print(f"d: {str(key.d)}")
        print(f"p: {str(key.p)}")
        print(f"q: {str(key.q)}")
        if args.ext:
            dp = key.d % (key.p - 1)
            dq = key.d % (key.q - 1)
            pinv = invmod(key.p, key.q)
            qinv = invmod(key.q, key.p)
            print(f"dp: {str(dp)}")
            print(f"dq: {str(dq)}")
            print(f"pinv: {str(pinv)}")
            print(f"qinv: {str(qinv)}")


def decrypt_file(args, logger):
    """
    Decrypts files specified in args.decryptfile using the provided private key, or prepares files for decryption with a public key.
    Note: Currently, decryption with a private key may not work correctly.

    Args:
        args (Namespace): Command-line arguments.
        logger (Logger): Logger object for logging messages.

    Returns:
        bool: True if decryption is successful with a private key, or if files are prepared for decryption with a public key; False otherwise.
    """
    decrypt_array = []
    for decrypt in args.decryptfile.split(","):
        try:
            with open(decrypt, "rb") as cipherfile_fd:
                decrypt_value = get_base64_value(cipherfile_fd.read())
                decrypt_array.append(decrypt_value)
        except OSError:
            logger.info("--decryptfile : file not found or not readable.")
            return False
    args.decrypt = decrypt_array

    # Check if a private key is provided and there's something to decrypt
    if args.key and args.decrypt:
        priv_key = PrivateKey(filename=args.key, password=args.password)
        decrypts = priv_key.decrypt(args.decrypt)
        print_results(args, None, priv_key, decrypts)
        return True

    # Check if a public key is provided
    if args.publickey:
        return True

    # Check if n and e are provided
    if args.n and args.e:
        return True

    # No private key or public key provided
    logger.error("Private key or public key and decrypted data are required.")
    return False


def pubkey_detail(args, logger):
    publickeys = args.publickey
    if isinstance(publickeys, str):
        if "*" in publickeys or "?" in publickeys:
            publickeys = glob(publickeys)
        elif "," in publickeys:
            publickeys = publickeys.split(",")
        else:
            publickeys = [publickeys]

    for publickey in publickeys:
        logger.info(f"Details for {publickey}:")
        with open(publickey, "rb") as key_data_fd:
            key = RSA.importKey(key_data_fd.read())
            print(f"n: {str(key.n)}")
            print(f"e: {str(key.e)}")


def cleanup(args):
    # Only remove files load_keys() created this run; those always live in
    # the system temp directory, so anchoring on it avoids touching any
    # user file that merely contains "tmp" in its name.
    tmpdir = os.path.join(tempfile.gettempdir(), "")
    if args.publickey is not None:
        for pub in args.publickey:
            try:
                if os.path.abspath(pub).startswith(tmpdir):
                    os.remove(pub)
            except OSError:
                continue


def _setup_logging(args):
    logging.basicConfig(level=logger_levels[args.verbosity])
    # httpx logs every request URL at INFO; the wolframalpha attack sends
    # its API key in the query string, so that would print the key.
    logging.getLogger("httpx").setLevel(logging.WARNING)
    ch = logging.StreamHandler(sys.stderr)
    ch.setFormatter(CustomFormatter())
    logger = logging.getLogger("global_logger")
    logger.propagate = False
    logger.addHandler(ch)
    if not args.private and not args.tests:
        logger.warning(
            "private argument is not set, the private key will not be displayed, even if recovered."
        )
    return logger


def _parse_numeric_args(args):
    if args.p is not None:
        args.p = get_numeric_value(args.p)
    if args.q is not None:
        args.q = get_numeric_value(args.q)
    if args.d is not None:
        args.d = get_numeric_value(args.d)
    if args.n is not None:
        args.n = get_numeric_value(args.n)
    if args.e is not None:
        e_array = [get_numeric_value(e) for e in args.e.split(",")]
        args.e = e_array if len(e_array) > 1 else e_array[0]
    elif args.n is not None or (args.p is not None and args.q is not None):
        # _compute_n_from_pq() derives n from p*q later, so cover that case
        # here too; otherwise a bare "-p ... -q ..." invocation reaches
        # key generation with e=None and crashes in RSA.construct.
        args.e = 65537

    if args.fr_a is not None:
        args.fr_a = get_numeric_value(args.fr_a)
    if args.fr_b is not None:
        args.fr_b = get_numeric_value(args.fr_b)
    if args.p_high is not None:
        args.p_high = get_numeric_value(args.p_high)
    if args.dp is not None:
        args.dp = get_numeric_value(args.dp)
    if args.dq is not None:
        args.dq = get_numeric_value(args.dq)
    for name in ("fault_sig", "fault_msg", "good_sig"):
        if getattr(args, name) is not None:
            setattr(args, name, get_numeric_value(getattr(args, name)))

    return args


def _warn_if_extra_primes(args, logger):
    if args.n is not None and (args.p is not None or args.q is not None):
        logger.warning(
            "[!] It seems you already provided one of the prime factors, nothing to do here..."
        )


def _compute_n_from_pq(args):
    if args.n is None and args.p is not None and args.q is not None:
        args.n = args.p * args.q


def _recover_pq_from_ned(args, logger):
    if not (args.n is not None
            and args.e is not None
            and args.d is not None
            and args.p is None
            and args.q is None):
        return
    pq = factor_ned(args.n, args.e, args.d)
    if pq is not None:
        args.p, args.q = pq
    else:
        logger.warning("[!] Impossible to recover p and q from d")


def _compute_other_prime(args, logger):
    if args.n and (args.p or args.q):
        try:
            args.p, args.q = generate_pq_from_n_and_p_or_q(args.n, args.p, args.q)
        except ValueError as exc:
            logger.error(f"[!] {exc}")
            sys.exit(1)


def _compute_missing_values(args, logger):
    _warn_if_extra_primes(args, logger)
    _compute_n_from_pq(args)
    _recover_pq_from_ned(args, logger)
    _compute_other_prime(args, logger)
    return args


def _handle_decrypt_input(args, logger):
    if args.decrypt is not None:
        decrypt_array = []
        for decrypt in args.decrypt.split(","):
            try:
                decrypt = n2s(get_numeric_value(decrypt))
            except Exception:
                # Not a number: n2s only accepts ints, so base64-decoded
                # bytes must skip it and go straight into the array.
                decrypt = get_base64_value(decrypt)
            decrypt_array.append(decrypt)
        args.decrypt = decrypt_array
    if args.decryptfile is not None:
        if not decrypt_file(args, logger):
            sys.exit(-1)
    return args


def _handle_early_exit_modes(args, logger):
    if args.convert_idrsa_pub:
        convert_idrsa_pub(args, logger)
        sys.exit(0)
    if args.isroca:
        check_is_roca(args, logger)
        sys.exit(0)
    if args.createpub:
        pub_key, priv_key = generate_keys_from_p_q_e_n(args.p, args.q, args.e, args.n)
        print(pub_key.decode("utf-8"))
        sys.exit(0)
    if (
        args.dumpkey
        and args.decrypt is None
        and args.decryptfile is None
        and args.publickey is not None
    ):
        pubkey_detail(args, logger)
        sys.exit(0)
    if args.key is not None and args.dumpkey:
        dump_key_parameters(args)
        sys.exit(0)
    if args.isconspicuous:
        if run_conspicuous_check(args, logger):
            sys.exit(-1)
        sys.exit(0)
    return False


def _load_public_keys(args):
    if args.publickey is None and args.e is not None and args.n is not None:
        args = load_keys(args, logging.getLogger("global_logger"))
    elif args.publickey is not None:
        if "*" in args.publickey or "?" in args.publickey:
            pattern = args.publickey
            args.publickey = sorted(glob(pattern))
            if not args.publickey:
                logging.getLogger("global_logger").error(
                    f"[!] No file matches {pattern}"
                )
                sys.exit(1)
        elif "," in args.publickey:
            args.publickey = args.publickey.split(",")
        else:
            args.publickey = [args.publickey]
    return args


def _handle_fully_specified_key(args, logger):
    decrypts = []
    if not (
        args.p is not None
        and args.q is not None
        and args.e is not None
        and args.n is not None
    ):
        return

    try:
        pub_key, priv_key = generate_keys_from_p_q_e_n(args.p, args.q, args.e, args.n)
    except ValueError:
        logger.error(
            "Looks like the values for generating key are not ok... (no invmod)"
        )
        sys.exit(1)

    if args.createpub:
        pub_key, priv_key = generate_keys_from_p_q_e_n(args.p, args.q, args.e, args.n)
        print(pub_key.decode("utf-8"))

    if args.decrypt is not None:
        if priv_key is not None:
            decrypts = priv_key.decrypt(args.decrypt)
            if not isinstance(decrypts, list):
                decrypts = [decrypts]
        else:
            logger.error(
                "Looks like the values for generating key are not ok... (no invmod)"
            )
            sys.exit(1)
    if isinstance(args.publickey, list):
        pubkey_name = args.publickey[0] if args.publickey else None
    else:
        pubkey_name = args.publickey
    print_results(args, pubkey_name, priv_key, decrypts)
    sys.exit(0)


def _validate_args(args, logger):
    """
    Checks if provided arguments are valid for proper run, i.e., if required args are provided for specific attacks.

    Args:
        args (Namespace): Command-line arguments.
        logger (Logger): Logger object for logging messages.
    """
    if args.attack is None or args.tests:
        return

    if "franklin_reiter" in args.attack and "all" not in args.attack:
        if args.fr_a is None or args.fr_a == 0 or args.fr_b is None or args.fr_b == 0:
            logger.error(
                "[!] --fr-a and --fr-b are mandatory and must not be zero when using --attack franklin_reiter"
            )
            sys.exit(1)

    if "stereotyped_message" in args.attack and "all" not in args.attack:
        if args.sm_len is None or (args.sm_prefix is None and args.sm_suffix is None):
            logger.error(
                "[!] stereotyped_message requires --sm-len and at least one of --sm-prefix or --sm-suffix"
            )
            sys.exit(1)

    if "partial_p" in args.attack and "all" not in args.attack:
        if args.p_high is None or args.p_unknown_bits is None:
            logger.error(
                "[!] partial_p attack requires both --p-high and --p-unknown-bits together"
            )
            sys.exit(1)

    if "dp_leak" in args.attack and "all" not in args.attack:
        if args.dp is None and args.dq is None:
            logger.error("[!] dp_leak attack requires --dp or --dq")
            sys.exit(1)

    if "bellcore" in args.attack and "all" not in args.attack:
        if args.fault_sig is None or (args.fault_msg is None and args.good_sig is None):
            logger.error(
                "[!] bellcore attack requires --fault-sig and --fault-msg or --good-sig"
            )
            sys.exit(1)


def main():
    args = parse_args()
    logger = _setup_logging(args)
    args = _parse_numeric_args(args)
    args = _compute_missing_values(args, logger)
    args = _handle_decrypt_input(args, logger)

    if _handle_early_exit_modes(args, logger):
        return

    _validate_args(args, logger)

    # Fully specified p/q/e/n short-circuits before any key files are
    # generated, so an invalid combination (e.g. e > n on toy moduli)
    # fails cleanly here instead of crashing inside load_keys.
    _handle_fully_specified_key(args, logger)
    args = _load_public_keys(args)
    args = run_attacks(args, logger)

    if args.cleanup:
        cleanup(args)

    if not args.cracked:
        sys.exit(1)


if __name__ == "__main__":
    main()
