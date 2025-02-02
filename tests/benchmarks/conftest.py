import logging

import pytest


@pytest.fixture(autouse=True)
def no_debug_logging():
    # Enable debug logging is not on for benchmarks
    aioesphomeapi_logger = logging.getLogger("aioesphomeapi")
    original_level = aioesphomeapi_logger.level
    aioesphomeapi_logger.setLevel(logging.WARNING)
    yield
    aioesphomeapi_logger.setLevel(original_level)
