# Notes for Claude

A short orientation file for an LLM working in this repo. Skim
before making changes; keep edits consistent with what's described
here. Read [README.rst](README.rst) for the user-facing intro.

## What this project is

`aioesphomeapi` is the asyncio Python client for the ESPHome
[Native API](https://esphome.io/components/api/). It talks
length-prefixed protobuf frames over TCP — either plaintext or
Noise (`Noise_NNpsk0_25519_ChaChaPoly_SHA256`) — to ESPHome-flashed
devices. Used directly by the Home Assistant `esphome` integration
and by anything else that wants to drive an ESPHome device from
Python.

The protocol is defined firmware-side in `esphome/esphome`'s
`api.proto`; this repo's `aioesphomeapi/api.proto` is the
matching client view. Any protocol change lands in the firmware
repo *first* (see PR workflow).

Hot paths (`connection.py`, `client_base.py`, `_frame_helper/*`)
are Cythonized at build time for throughput. They keep working as
pure Python — `SKIP_CYTHON=1` disables the extension build — but
production wheels ship compiled and benchmarks track that path.

## Code style

- **Docstrings: terse, default to single-line.** A docstring is
  the function's *contract*, not its narrative. Almost every
  docstring should be one line — `"""Summary."""` — describing
  what the function does and what the caller can pass. Multi-line
  is the exception, only justified when there is non-obvious
  caller-visible behaviour the type signature and parameter names
  don't already convey.

  **What does NOT belong in docstrings or comments:**
  * Rationale / motivation / "why we used to do X" — that's the
    PR description and the commit message. Git already remembers.
  * Cross-references to issue numbers ("closes #N", "follow-up
    to #M") — the PR body carries those.
  * Restatement of the function body in prose. If the next line
    of the docstring is just describing what the next line of
    code does, delete the docstring line.
  * Test docstrings retelling the production-side story. A test
    docstring should name what the test pins, in one sentence —
    not re-explain the bug, the fix, or the surrounding flow.

- **Comments**: same bar. Default to writing no comments. Add
  one only when the *why* is non-obvious: a hidden constraint, a
  subtle invariant, a workaround for a specific bug, behaviour
  that would surprise a reader. If removing the comment wouldn't
  confuse a future reader, don't write it.

  **Don't remove existing comments** unless the code they
  describe is gone — the original author left them for a reason.

- **Don't pad commits, docstrings, or comments with cross-
  references** to old codepaths or issue numbers unless there's
  a clear reason a future reader needs that link.

- **Method order**: public API at the top, private helpers
  (`_underscore_prefixed`) at the bottom.

- **Line length**: ruff default. Python 3.11+
  (`python_requires = ">=3.11"`, `target-version = "py311"`
  for ruff).

- **Imports**: ruff/isort sorted (`force-sort-within-sections`,
  `combine-as-imports`, `split-on-trailing-comma = false`).
  `from __future__ import annotations` at the top of regular
  source modules so we can use modern type syntax. Known
  exceptions: generated `*_pb2.py`, the re-export `__init__.py`,
  and `_frame_helper/packets.py` (Cython needs annotations
  evaluated at runtime).

- **Generated files are excluded from lint.** `api_pb2.py` and
  `api_options_pb2.py` are ruff-excluded — never hand-edit them;
  regenerate via the docker builder (see *Regenerating protobuf*
  below).

## Commit / PR conventions

- **No `Co-Authored-By: Claude` trailer.** Project preference.
- Imperative-mood subject line ("Add X", not "Added X").
- The PR template lives in `.github/PULL_REQUEST_TEMPLATE.md`;
  fill in every section, tick exactly one "Types of changes" box.
  The `pr-workflow` skill (under `.claude/skills/pr-workflow/`)
  walks through filling it in — branch off `origin/main`, pass
  the body via `--body-file` so the template's backticks aren't
  shell-escaped.
- **`api.proto` changes need an upstream esphome PR first.** The
  firmware repo owns the protocol; the matching change lands
  there before the client PR. Link the esphome PR in the body
  and tick the corresponding checklist row.
- Pre-commit / CI runs ruff (lint + format). Run
  `./venv/bin/ruff check --fix . && ./venv/bin/ruff format .`
  before pushing. Failures auto-fix where possible, then the
  commit needs to be re-staged.

## Running tests

```bash
./venv/bin/python -m pytest tests/ -v
```

The asyncio mode is `auto` (configured in `pyproject.toml`); test
files don't need an explicit marker. CodSpeed benchmarks live
under `tests/benchmarks/` and run in CI on a separate path.

## Regenerating protobuf files

When modifying `api.proto`, regenerate the bindings with the
official docker image (the version-pinned image ensures `api_pb2.py`
stays compatible with the protobuf runtime used by the project):

```bash
docker run --rm -v $PWD:/aioesphomeapi \
  ghcr.io/esphome/aioesphomeapi-proto-builder:latest
```

Or with podman:

```bash
podman run --rm -v $PWD:/aioesphomeapi --userns=keep-id \
  ghcr.io/esphome/aioesphomeapi-proto-builder:latest
```

Don't hand-edit `api_pb2.py` / `api_options_pb2.py` — regenerate
through the builder. They're excluded from ruff for a reason.

## Build conventions

- **Cython is optional but expected in wheels.** `setup.py`
  cythonizes the hot paths listed in `TO_CYTHONIZE`
  (`connection.py`, `client_base.py`, `_frame_helper/{base,
  noise, noise_encryption, packets, plain_text}.py`, plus
  `_frame_helper/pack.pyx`). `OptionalBuildExt` swallows build
  failures so source installs fall back to pure Python; CI wheel
  builds set `REQUIRE_CYTHON=1` to make the build fail loudly if
  the extension can't be produced.
- Modules that get Cythonized ship a sibling `.pxd` for type
  declarations. When changing the signature of a Cythonized
  function, update its `.pxd` in the same commit, or the
  extension build will pick up a stale declaration.
- `language_level = "3"`, `freethreading_compatible = True`
  (PEP 703). New `.py` / `.pyx` paths added to `TO_CYTHONIZE`
  must stay free-threading-safe.

## Cython gotchas (things that have bitten us)

These are non-obvious traps in the `.py` + `.pxd` setup that work
fine in pure-Python mode but break or silently misbehave in the
shipped Cython wheels. Tests pass locally with `SKIP_CYTHON=1`
fallback paths, then CI on `use_cython` builds catches the issue —
or worse, the issue ships and only manifests in production wheels.

- **`cdef`-typed module constants are not Python-importable.**
  Declaring `cdef int _MAX_X` in `.pxd` makes Cython treat
  `_MAX_X = 5` in the `.py` as a C int assignment; the Python
  module dict never gets the binding. `from module import _MAX_X`
  succeeds in pure-Python but raises `ImportError` under Cython.
  **Pattern**: define both names — `MAX_X = 5` (Python-importable)
  and `_MAX_X = MAX_X` (cdef-typed for hot-path comparisons).
  Tests import the public name; production code uses either.

- **`noexcept` cdef paths must be pure C.** Calling a Python
  method that can raise (e.g. `_handle_error_and_close`) from
  inside a `cdef ... noexcept` function is undefined / lossy —
  Cython prints the exception via WriteUnraisable and silently
  continues. Keep `noexcept` paths to sentinel returns and let
  the caller handle Python-level work.

- **`unsigned int` result returned through `cdef int` can flip
  sign.** A varuint decoded into `result="unsigned int"` and
  returned via `cdef int` will come back negative for any value
  with bit 31 set. If the caller does `if x < 0: return`, an
  attacker-controlled large value silently hits the "incomplete"
  / "stop processing" branch instead of being rejected. Either
  cap the input range so decoded values stay in signed-int range,
  or check explicit sentinel values (`x == _SENTINEL_A`) instead
  of generic `< 0`. Issue #1642 / PR #1651 was exactly this trap.

- **`except *` / `except? -N` adds per-call exception checks.**
  Switching a hot-path `cdef ... noexcept` to `except *` or
  `except? -3` adds a `PyErr_Occurred()` check after every call.
  Negligible for cold paths, measurable on hot paths — CodSpeed
  caught a ~14% regression on BLE plaintext benchmarks when this
  was applied to `_read_varuint`. Prefer `noexcept` for hot paths
  and route error handling through the caller.

- **Module-level Python int constants force PyLong conversion in
  hot path comparisons.** `if length > _MAX_FRAME_SIZE` compiles
  to a Python attribute lookup + `PyLong_AsLong` per call. Adding
  `cdef int _MAX_FRAME_SIZE` to the `.pxd` makes it a native C
  comparison. CodSpeed caught a measurable degradation when this
  was missed; restoring the cdef declaration recovered it.

- **Sign-compare warnings in generated C are real.** `gcc/clang`
  warns when comparing `unsigned int` with `int` because the
  signed value is implicitly converted to unsigned for the
  compare — a negative value becomes a huge positive. Match the
  signedness of compared operands in the `.pxd` (e.g. if the
  local is `unsigned int`, declare the constant as
  `cdef unsigned int`; if the local is `int`, declare it
  `cdef int`). The warning predicts a class of overflow bug like
  the unsigned->signed varuint trap above.

- **CodSpeed regressions only show in the Cython build.** Pure-Python
  (`SKIP_CYTHON=1`) tests can pass while the production
  wire-format hot paths regress. Trust the CodSpeed check on PRs
  that touch any file in `TO_CYTHONIZE`; run the following
  locally before pushing if perf-sensitive code changed:

  ```sh
  REQUIRE_CYTHON=1 python setup.py build_ext --inplace
  ```

## Useful entry points

| Path | What |
|---|---|
| `aioesphomeapi/client.py` | High-level `APIClient` — what most callers use |
| `aioesphomeapi/client_base.py` | Lower-level `APIClientBase` (Cythonized) |
| `aioesphomeapi/connection.py` | `APIConnection`, framing, handshake (Cythonized) |
| `aioesphomeapi/_frame_helper/` | Plaintext + Noise frame helpers (Cythonized) |
| `aioesphomeapi/model.py` | Public dataclasses re-exported via `aioesphomeapi.*` |
| `aioesphomeapi/core.py` | Exception hierarchy + message-type tables |
| `aioesphomeapi/reconnect_logic.py` | `ReconnectLogic` retry/backoff helper |
| `aioesphomeapi/host_resolver.py` | DNS / mDNS resolution for connect |
| `aioesphomeapi/discover.py` | `aioesphomeapi-discover` CLI |
| `aioesphomeapi/log_reader.py` | `aioesphomeapi-logs` CLI |
| `aioesphomeapi/api.proto` | Client-side protocol definition (mirror of firmware) |
| `aioesphomeapi/api_pb2.py` | **Generated** — do not hand-edit |
| `tests/` | Pytest suite (asyncio_mode=auto) |
| `tests/benchmarks/` | CodSpeed benchmarks |

## Things not to do

- **Don't hand-edit `api_pb2.py` / `api_options_pb2.py`.**
  Regenerate via the docker builder.
- **Don't land an `api.proto` change without the matching
  esphome PR.** The firmware side is the source of truth.
- **Don't add `Co-Authored-By: Claude` to commits** in this repo.
- **Don't change Cythonized module signatures without updating
  the `.pxd`** — the extension build will silently pick up a
  stale declaration.
- **Don't bypass `OptionalBuildExt`'s exception swallowing in
  setup.py without thought.** Pure-Python fallback is a feature
  for source installs on platforms without a compiler.
