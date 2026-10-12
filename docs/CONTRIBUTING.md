# Contributing

Thanks for your interest in SluiceGate!

## Scope
This repository is a monorepo containing the `open-core` policy library, `sg-service`, Minion protocols/implementations, deployment tooling, and a reference demo. Keep changes within the owning project boundary; policy semantics belong in Core, durable transactions and Mission Central Command in Service, privileged target operations in Minions, and host installation/build logic in `deployment/`.

Use the root uv workspace to build and test the Python distributions:

```sh
uv sync --all-packages
uv build --package sg-core
uv build --package sg-service
uv run --package sg-service --group dev pytest -q sg-service/tests
```

## How to contribute
- File issues for bugs, clarity problems, or missing docs
- Submit PRs that improve:
  - correctness
  - documentation
  - tests
  - reference examples

## Code style
- Keep core logic deterministic and side-effect free where possible
- Push vendor-specific code into adapters (connectors/notifications)
- Prefer small PRs with tests

## License / CLA
By contributing, you agree that your contribution may be incorporated under this repo’s license terms.
