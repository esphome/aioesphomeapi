"""Pin the public ``aioesphomeapi`` namespace exported via ``from .model import *``."""

from __future__ import annotations

import ast
from pathlib import Path

import aioesphomeapi
from aioesphomeapi import model


def _model_public_defined_names() -> set[str]:
    """Public top-level names defined (not imported) in model.py."""
    path = Path(model.__file__)
    tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    names: set[str] = set()
    for node in tree.body:
        if isinstance(node, (ast.ClassDef, ast.FunctionDef, ast.AsyncFunctionDef)):
            names.add(node.name)
        elif isinstance(node, ast.Assign):
            names.update(t.id for t in node.targets if isinstance(t, ast.Name))
        elif isinstance(node, ast.AnnAssign) and isinstance(node.target, ast.Name):
            names.add(node.target.id)
    return {n for n in names if not n.startswith("_")}


# Public-named but intentionally internal: defined in model.py yet kept out of
# __all__ so ``from .model import *`` does not re-export them. Real consumers
# reach them via explicit imports, which __all__ does not gate.
_NOT_EXPORTED = {
    "cached_fields",
    "converter_field",
    "message_types_to_names",
}


def test_model_all_matches_defined_names() -> None:
    """__all__ stays in sync with the module's own public definitions.

    A new public class added to model.py must be added to __all__ (else it
    silently stops being re-exported) or listed in _NOT_EXPORTED, and no
    imported name may appear in __all__.
    """
    assert set(model.__all__) == _model_public_defined_names() - _NOT_EXPORTED


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
        "COMPONENT_TYPE_TO_INFO",
        "DeviceInfo",
        "EntityInfo",
        "ClimateInfo",
        "MediaPlayerInfo",
        "BluetoothGATTService",
        "UserService",
        "build_device_unique_id",
        "build_unique_id",
    ):
        assert hasattr(aioesphomeapi, name)


def test_fix_float_helper_not_public() -> None:
    """The float-normalization helper is not exported at the package root."""
    assert not hasattr(aioesphomeapi, "fix_float_single_double_conversion")
