# Claude Code Instructions for aioesphomeapi

## Code Formatting

Always use `ruff` to ensure Python code formatting is correct before committing:

```bash
# Check and fix linting issues
./venv/bin/ruff check --fix .

# Format code
./venv/bin/ruff format .
```

## Regenerating Protobuf Files

When modifying `api.proto`, regenerate the protobuf bindings using the official docker image with docker/podman (depending on what is available on your system):

```bash
docker run --rm -v $(pwd):/aioesphomeapi:Z --userns=keep-id ghcr.io/esphome/aioesphomeapi-proto-builder:latest
```

```bash
podman run --rm -v $(pwd):/aioesphomeapi:Z --userns=keep-id ghcr.io/esphome/aioesphomeapi-proto-builder:latest
```

This ensures the generated `api_pb2.py` is compatible with the protobuf runtime version used in the project.

## Running Tests

```bash
./venv/bin/python -m pytest tests/ -v
```
