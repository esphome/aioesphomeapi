"""Pin that the noise/cryptography stack stays off the import path."""

from __future__ import annotations

import asyncio
import subprocess
import sys
from unittest.mock import patch

from aioesphomeapi import connection as connection_module
from aioesphomeapi._frame_helper.noise import APINoiseFrameHelper

# Modules that must only load for encrypted (noise) connections.
DEFERRED_MODULES = (
    "noise",
    "noise.connection",
    "chacha20poly1305_reuseable",
    "cryptography.hazmat.primitives.ciphers.aead",
    "aioesphomeapi._frame_helper.noise",
    "aioesphomeapi._frame_helper.noise_encryption",
)


def test_import_does_not_load_noise_stack() -> None:
    """Importing the package must not pull in the noise/cryptography stack."""
    script = (
        "import sys, aioesphomeapi\n"
        f"loaded = [m for m in {DEFERRED_MODULES!r} if m in sys.modules]\n"
        "print(','.join(loaded))\n"
    )
    result = subprocess.run(  # noqa: S603
        [sys.executable, "-c", script],
        capture_output=True,
        text=True,
        check=True,
    )
    assert result.stdout.strip() == "", f"unexpectedly loaded: {result.stdout.strip()}"


async def test_load_noise_frame_helper_inline_when_already_imported() -> None:
    """A warm import binds inline without hopping to the executor."""
    loop = asyncio.get_running_loop()
    with patch.object(loop, "run_in_executor") as mock_executor:
        cls = await connection_module._async_load_noise_frame_helper(loop)

    assert cls is APINoiseFrameHelper
    mock_executor.assert_not_called()


async def test_load_noise_frame_helper_uses_executor_when_cold(monkeypatch) -> None:
    """A cold import is run in the executor so it never blocks the loop."""
    monkeypatch.delitem(
        sys.modules, connection_module._NOISE_FRAME_HELPER_MODULE, raising=False
    )
    loop = asyncio.get_running_loop()
    future = loop.create_future()
    future.set_result(APINoiseFrameHelper)
    with patch.object(loop, "run_in_executor", return_value=future) as mock_executor:
        cls = await connection_module._async_load_noise_frame_helper(loop)

    assert cls is APINoiseFrameHelper
    mock_executor.assert_called_once_with(
        None, connection_module._import_noise_frame_helper
    )
