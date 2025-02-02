import logging

import pytest


@pytest.fixture(autouse=True)
def no_debug_logging():
    # Enable debug logging is not on for benchmarks
    logging.getLogger("aioesphomeapi").setLevel(logging.WARNING)
