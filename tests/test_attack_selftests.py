"""Every attack module must ship a real self-test (``Attack.test``)."""

import ast
import importlib
import pkgutil

import pytest

import RsaCtfTool.attacks.multi_keys as multi_keys
import RsaCtfTool.attacks.single_key as single_key

# Attacks whose self-test is still a stub. Remove from this set once implemented;
# the test below fails if an entry here no longer needs to be listed.
#  - partial_q: needs a partial private key with CRT components.
#  - wolframalpha: needs network access and a WA_API_KEY.
KNOWN_MISSING = {"partial_q", "wolframalpha"}


def _attack_modules():
    for package in (single_key, multi_keys):
        for info in pkgutil.iter_modules(package.__path__):
            yield f"{package.__name__}.{info.name}", info.name


def _test_is_stub(module_name):
    """True if Attack.test is missing or only raises NotImplementedError."""
    module = importlib.import_module(module_name)
    tree = ast.parse(open(module.__file__, encoding="utf-8").read())
    for cls in (n for n in tree.body if isinstance(n, ast.ClassDef)):
        if cls.name != "Attack":
            continue
        for fn in (n for n in cls.body if isinstance(n, ast.FunctionDef)):
            if fn.name != "test":
                continue
            body = [
                n
                for n in fn.body
                if not (isinstance(n, ast.Expr) and isinstance(n.value, ast.Constant))
            ]
            first = body[0] if body else None
            return isinstance(first, ast.Raise) and "NotImplementedError" in ast.dump(
                first
            )
    return True


@pytest.mark.parametrize("module_name,short", list(_attack_modules()))
def test_attack_has_selftest(module_name, short):
    stub = _test_is_stub(module_name)
    if short in KNOWN_MISSING:
        assert stub, f"{short} now has a self-test: remove it from KNOWN_MISSING"
    else:
        assert not stub, f"{short}: Attack.test() is missing or not implemented"


@pytest.mark.parametrize(
    "module_name",
    [
        "RsaCtfTool.attacks.single_key.comfact_cn",
        "RsaCtfTool.attacks.single_key.franklin_reiter",
        "RsaCtfTool.attacks.multi_keys.common_factors",
    ],
)
def test_new_selftests_pass(module_name):
    assert importlib.import_module(module_name).Attack().test() is True
