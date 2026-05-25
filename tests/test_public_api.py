"""Pin the public ``aioesphomeapi`` namespace exported via ``from .model import *``."""

from __future__ import annotations

import ast
from pathlib import Path

import aioesphomeapi
from aioesphomeapi import model


def _model_public_defined_names() -> set[str]:
    """Public top-level names defined (not imported) in model.py."""
    tree = ast.parse(Path(model.__file__).read_text())
    names: set[str] = set()
    for node in tree.body:
        if isinstance(node, (ast.ClassDef, ast.FunctionDef, ast.AsyncFunctionDef)):
            names.add(node.name)
        elif isinstance(node, ast.Assign):
            names.update(t.id for t in node.targets if isinstance(t, ast.Name))
        elif isinstance(node, ast.AnnAssign) and isinstance(node.target, ast.Name):
            names.add(node.target.id)
    return {n for n in names if not n.startswith("_")}


def test_model_all_matches_defined_names() -> None:
    """__all__ stays in sync with the module's own public definitions.

    Guards both directions: a new public class added to model.py must be
    added to __all__ (else it silently stops being re-exported), and no
    imported name may be listed.
    """
    assert set(model.__all__) == _model_public_defined_names()


def test_stdlib_imports_not_leaked_into_public_api() -> None:
    """``from .model import *`` must not re-export model.py's own imports."""
    for leaked in (
        "field",
        "fields",
        "asdict",
        "dataclass",
        "partial",
        "cache",
        "lru_cache",
        "cast",
        "enum",
        "contextlib",
        "UUID",
        "Any",
        "Self",
        "TypeVar",
    ):
        assert not hasattr(aioesphomeapi, leaked)


def test_representative_model_classes_stay_exported() -> None:
    """Re-exported model classes remain importable from the top-level package."""
    for name in (
        "APIVersion",
        "DeviceInfo",
        "EntityInfo",
        "ClimateInfo",
        "MediaPlayerInfo",
        "BluetoothGATTService",
        "UserService",
        "build_unique_id",
    ):
        assert hasattr(aioesphomeapi, name)


def test_fix_float_helper_remains_public() -> None:
    """The float-normalization helper stays reachable at the package root."""
    assert hasattr(aioesphomeapi, "fix_float_single_double_conversion")
