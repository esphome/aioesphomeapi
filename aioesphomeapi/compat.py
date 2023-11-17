from __future__ import annotations

import sys
from dataclasses import dataclass
from functools import partial

if sys.version_info[:2] < (3, 10):
    _dataclass_decorator = dataclass
    _frozen_dataclass_decorator = partial(dataclass, frozen=True)
else:
    _dataclass_decorator = partial(dataclass, slots=True)
    _frozen_dataclass_decorator = partial(dataclass, frozen=True, slots=True)
