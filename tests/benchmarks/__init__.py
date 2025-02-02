import logging

# Enable debug logging is not on for benchmarks
logging.getLogger("aioesphomeapi").setLevel(logging.WARNING)
