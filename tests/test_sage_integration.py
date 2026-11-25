import shutil
from pathlib import Path
from types import SimpleNamespace

import pytest

import RsaCtfTool.attacks.abstract_attack as abstract_attack
from RsaCtfTool.attacks.single_key import (
    binary_polynomial_factoring,
    lattice,
    partial_d,
    partial_p,
    short_pad,
    smallfraction,
    stereotyped_message,
)
from RsaCtfTool.lib.keys_wrapper import PrivateKey, PublicKey

def test_sage_attacks_declare_their_runtime_dependency():
    # These attacks import Sage in the current Python process.
    in_process = (partial_p, short_pad, stereotyped_message)

    for module in in_process:
        attack = module.Attack()
        assert attack.required_python_modules == ["sage.all"]
        assert attack.required_binaries == []

    # These attacks invoke Sage as an external process.
    subprocess_attacks = (
        partial_d,
        lattice,
        binary_polynomial_factoring,
        smallfraction,
    )

    for module in subprocess_attacks:
        attack = module.Attack()
        assert attack.required_binaries == ["sage"]
        assert attack.required_python_modules == []

def test_partial_d_parses_sage_factors(monkeypatch):
    key = object.__new__(PrivateKey)
    key.n = 15
    key.e = 7
    key.d = 3
    key.p = None
    key.q = None

    monkeypatch.setattr(
        partial_d.subprocess,
        "check_output",
        lambda *args, **kwargs: "3 5\n",
    )

    private_key, plaintext = partial_d.Attack().attack(key)

    assert plaintext is None
    assert private_key.p * private_key.q == key.n


def test_lattice_parses_sage_factor_list(monkeypatch):
    key = SimpleNamespace(n=15, e=7, p=3)
    monkeypatch.setattr(
        lattice.subprocess,
        "check_output",
        lambda *args, **kwargs: "[3, 5]\n",
    )

    private_key, plaintext = lattice.Attack().attack(key)

    assert plaintext is None
    assert private_key.p * private_key.q == key.n


def test_partial_p_recovers_factors():
    pytest.importorskip("sage.all")

    fixture = Path(__file__).resolve().parents[1] / "examples" / "partial_p.pub"
    key = PublicKey(fixture.read_bytes())

    p = int("11814314815079808793202754845823415996236940468297640287934698158609319560359607901183228305190944525696915884370873052504610782679806230947564723036978431")
    q = int("6850324446788129079827624526540564637521699316237423751807524631616380311577742212267150797376483718097199550312926103390141403454742728224455964881423377")

    p_high = p & ((1 << 512) - (1 << 212))

    attack = partial_p.Attack(
        p_high=p_high,
        p_unknown_bits=212,
    )

    priv, _ = attack.attack(key, progress=False)

    expected = { p, q }
    assert priv is not None
    assert {int(priv.p), int(priv.q)} == expected


def test_binary_polynomial_factoring_parses_sage_factor_list(monkeypatch):
    key = SimpleNamespace(n=15, e=7)
    monkeypatch.setattr(
        binary_polynomial_factoring.subprocess,
        "check_output",
        lambda *args, **kwargs: "[3, 5]\n",
    )

    private_key, plaintext = binary_polynomial_factoring.Attack().attack(key)

    assert plaintext is None
    assert private_key.p * private_key.q == key.n


@pytest.mark.attack
def test_binary_polynomial_factoring_runs_with_sage():
    if shutil.which("sage") is None:
        pytest.skip("SageMath is not available on PATH")

    key = SimpleNamespace(n=15, e=7)
    private_key, plaintext = binary_polynomial_factoring.Attack(timeout=30).attack(
        key
    )

    assert plaintext is None
    assert private_key.p * private_key.q == key.n


class _FakeProc:
    def __init__(self, stdout):
        self._out = stdout

    def wait(self, timeout=None):
        return 0

    def communicate(self):
        return self._out, b""


def test_ecm2_parses_factor_tuple(monkeypatch):
    from RsaCtfTool.attacks.single_key import ecm2

    key = SimpleNamespace(n=15, e=7)
    monkeypatch.setattr(
        ecm2.subprocess, "Popen", lambda *a, **k: _FakeProc(b"(3, 5)\n")
    )
    # phi(15) = 8, d = 7^-1 mod 8 = 7, m=2 -> c = 2^7 mod 15 = 8
    private_key, plaintext = ecm2.Attack().attack(key, [b"\x08"])
    assert private_key is None
    assert plaintext == [b"\x02"]


def test_sage_functions_delegates_to_shared_backend(monkeypatch):
    pytest.importorskip("sage.all")
    import sys
    import types

    captured = {}
    fake = types.ModuleType("RsaCtfTool.sage.coppersmith")

    def mock_coppersmith(pol, modulus, params):
        captured["pol"] = pol
        captured["modulus"] = modulus
        captured["params"] = params
        return [1337]

    fake.coppersmith_univariate_sage = mock_coppersmith
    monkeypatch.setitem(sys.modules, "coppersmith", fake)
    monkeypatch.setitem(sys.modules, "RsaCtfTool.sage.coppersmith", fake)

    from RsaCtfTool.sage.sage_functions import coppersmith_howgrave_univariate

    res = coppersmith_howgrave_univariate(
        pol="fake_poly", modulus=2**512, beta=0.5, mm=4, tt=2, XX=2**100
    )

    assert res == [1337]
    assert captured["pol"] == "fake_poly"
    assert captured["modulus"] == 2**512
    assert captured["params"].beta == 0.5
    assert captured["params"].m == 4
    assert captured["params"].t == 2
    assert captured["params"].X == 2**100


@pytest.mark.parametrize(
    "module",
    [partial_p, short_pad, stereotyped_message],
)
def test_in_process_sage_attack_can_run_when_sage_importable(
    monkeypatch, module
):
    def fake_import(name):
        assert name == "sage.all"
        return object()

    monkeypatch.setattr(
        abstract_attack.importlib, "import_module", fake_import
    )

    assert module.Attack().can_run()


@pytest.mark.parametrize(
    "module",
    [partial_p, short_pad, stereotyped_message],
)
def test_in_process_sage_attack_can_run_when_sage_importable(
    monkeypatch, module
):
    def fake_import(name):
        assert name == "sage.all"
        return object()

    monkeypatch.setattr(
        abstract_attack.importlib, "import_module", fake_import
    )

    # Sage executable is unavailable, but Python can import Sage.
    monkeypatch.setattr(
        abstract_attack.shutil, "which", lambda _: None
    )

    assert module.Attack().can_run()

