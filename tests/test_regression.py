#!/usr/bin/env python3
"""
Regression tests for:
  - Issue #505: --private crash when n = p^2 (PrivateKey.__str__ returned None)
  - Issue #506: --decryptfile not displaying decrypted content (raw RSA decrypt bug)
"""

import os
import sys
import subprocess
import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from RsaCtfTool.lib.keys_wrapper import PrivateKey  # noqa: E402
from RsaCtfTool.lib.number_theory import invmod, powmod  # noqa: E402


# ---------------------------------------------------------------------------
# Issue #505: PrivateKey.__str__ must return a str (not None) even when the
# PEM key cannot be constructed (e.g. n = p^2, p == q).
# ---------------------------------------------------------------------------


def test_private_key_str_never_returns_none():
    """PrivateKey.__str__ must always return a str, not None."""
    # 1000000007 (10^9+7) is a well-known prime used in competitive programming
    p = 1000000007
    n = p * p
    e = 65537
    phi = (p - 1) * p  # correct phi for n = p^2
    d = invmod(e, phi)

    priv_key = PrivateKey(n=n, e=e, d=d)
    result = str(priv_key)
    assert isinstance(result, str), (
        "PrivateKey.__str__ must return a str, not %r" % type(result)
    )


def test_private_key_str_empty_when_no_pem():
    """PrivateKey.__str__ returns an empty string when PEM cannot be constructed."""
    # 1000000007 (10^9+7) is a well-known prime used in competitive programming
    p = 1000000007
    n = p * p
    e = 65537
    phi = (p - 1) * p
    d = invmod(e, phi)

    priv_key = PrivateKey(n=n, e=e, d=d)
    # key should not be constructable as PEM for n=p^2
    assert str(priv_key) == ""


def test_private_key_str_normal_case():
    """PrivateKey.__str__ returns a non-empty PEM for a normal distinct-prime key."""
    # Small but valid RSA key
    p = 61
    q = 53
    n = p * q
    e = 17

    priv_key = PrivateKey(p=p, q=q, e=e, n=n)
    pem = str(priv_key)
    assert isinstance(pem, str)
    assert "BEGIN RSA PRIVATE KEY" in pem or "BEGIN PRIVATE KEY" in pem


# ---------------------------------------------------------------------------
# Issue #506: Raw RSA decrypt should work correctly (hex conversion bug fix).
# ---------------------------------------------------------------------------


def _make_rsa_key(p, q, e):
    """Return (n, PrivateKey) for the given p, q, e."""
    n = p * q
    return n, PrivateKey(p=p, q=q, e=e, n=n)


def test_raw_rsa_decrypt():
    """PrivateKey.decrypt correctly decrypts raw-RSA-encrypted ciphertext."""
    p = 61
    q = 53
    e = 17
    n, priv_key = _make_rsa_key(p, q, e)

    plaintext_int = 42
    cipher_int = powmod(plaintext_int, e, n)
    cipher_bytes = cipher_int.to_bytes((cipher_int.bit_length() + 7) // 8, "big")

    decrypted_list = priv_key.decrypt(cipher_bytes)
    assert len(decrypted_list) > 0, "decrypt() returned empty list"

    # The raw-RSA result should be in the list; convert back to int
    found = False
    for candidate in decrypted_list:
        if isinstance(candidate, (bytes, bytearray)):
            val = int.from_bytes(candidate, "big")
            if val == plaintext_int:
                found = True
                break
    assert found, "Raw RSA decryption did not recover the plaintext"


def test_raw_rsa_decrypt_known_value():
    """Cross-check: encrypt with known key, decrypt and match."""
    # p=1021, q=1019 are primes
    p, q = 1021, 1019
    e = 65537
    n, priv_key = _make_rsa_key(p, q, e)

    msg = b"hi"
    msg_int = int.from_bytes(msg, "big")
    c_int = powmod(msg_int, e, n)
    c_bytes = c_int.to_bytes((c_int.bit_length() + 7) // 8, "big")

    decrypted_list = priv_key.decrypt(c_bytes)
    assert len(decrypted_list) > 0

    found = False
    for candidate in decrypted_list:
        if isinstance(candidate, (bytes, bytearray)):
            if int.from_bytes(candidate, "big") == msg_int:
                found = True
                break
    assert found, "decrypt did not recover expected plaintext for known key"


# ---------------------------------------------------------------------------
# Integration: CLI --decryptfile produces output
# ---------------------------------------------------------------------------


def test_cli_decryptfile_shows_output():
    """Running the CLI with --decryptfile should display decrypted data."""
    examples = os.path.join(os.path.dirname(__file__), "..", "examples")
    pub = os.path.join(examples, "small_q.pub")
    cipher = os.path.join(examples, "small_q.cipher")

    if not os.path.exists(pub) or not os.path.exists(cipher):
        pytest.skip("example files not found")

    result = subprocess.run(
        [
            sys.executable,
            "-m",
            "RsaCtfTool.main",
            "--publickey",
            pub,
            "--decryptfile",
            cipher,
            "--attack",
            "smallq",
        ],
        capture_output=True,
        text=True,
        timeout=60,
    )

    combined = result.stdout + result.stderr
    assert "Decrypted data" in combined, (
        "--decryptfile produced no 'Decrypted data' section.\nSTDERR:\n%s\nSTDOUT:\n%s"
        % (result.stderr, result.stdout)
    )


def test_cli_private_n_eq_p_squared_no_crash():
    """CLI --private with n=p^2 must not crash with TypeError."""
    # p=1000000007, n=p^2
    result = subprocess.run(
        [
            sys.executable,
            "-m",
            "RsaCtfTool.main",
            "-n",
            "1000000014000000049",
            "-e",
            "65537",
            "--private",
            "--attack",
            "nonRSA",
        ],
        capture_output=True,
        text=True,
        timeout=60,
    )

    # Must not have returned with a Python traceback
    assert "TypeError" not in result.stderr, (
        "CLI crashed with TypeError:\n%s" % result.stderr
    )
    assert "Traceback" not in result.stderr, (
        "CLI crashed with traceback:\n%s" % result.stderr
    )
    # Should produce some private key output (even if only n/e/d)
    combined = result.stdout + result.stderr
    assert "Private key" in combined or "Key format seems wrong" in combined, (
        "No private key section found.\nSTDERR:\n%s\nSTDOUT:\n%s"
        % (
            result.stderr,
            result.stdout,
        )
    )
