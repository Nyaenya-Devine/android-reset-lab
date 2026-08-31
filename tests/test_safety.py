# tests/test_safety.py - the lab audits its own code for destructive calls
import ast
import os
import sys

BANNED_CALLS = {"remove", "rmtree", "system", "popen", "unlink", "rmdir", "removedirs"}
BANNED_MODULES = {"subprocess", "shutil"}
BANNED_NAMES = {"eval", "exec"}

PROJECT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, PROJECT)


def _python_files():
    for root, dirs, files in os.walk(PROJECT):
        dirs[:] = [d for d in dirs if d not in (".git", "__pycache__")]
        for name in files:
            if name.endswith(".py"):
                yield os.path.join(root, name)


def test_no_destructive_calls():
    for path in _python_files():
        with open(path, encoding="utf-8") as f:
            tree = ast.parse(f.read())
        for node in ast.walk(tree):
            if isinstance(node, ast.Attribute) and node.attr in BANNED_CALLS:
                raise AssertionError(path + " uses banned call " + node.attr)
            if isinstance(node, ast.Name) and node.id in BANNED_NAMES:
                raise AssertionError(path + " uses " + node.id)
            if isinstance(node, ast.Import):
                for alias in node.names:
                    if alias.name in BANNED_MODULES:
                        raise AssertionError(path + " imports " + alias.name)
            if isinstance(node, ast.ImportFrom) and node.module in BANNED_MODULES:
                raise AssertionError(path + " imports " + node.module)


def test_simulation_mode_on():
    import config
    assert config.SIMULATION_MODE is True