# Contributing

Thanks for your interest in SluiceGate!

## Scope
This repository is a monorepo containing the `open-core` policy library, `sg-service`, Minion protocols/implementations, deployment tooling, and a reference demo. Keep changes within the owning project boundary; policy semantics belong in Core, durable transactions and Minion Mission Control in Service, privileged target operations in Minions, and host installation/build logic in `deployment/`.

Use the root uv workspace to build and test the Python distributions:

```sh
uv sync --all-packages
uv build --package sg-core
uv build --package sg-service
uv run --package sg-service --group dev pytest -q sg-service/tests
```

## Continuous integration

The [Tests workflow](../.github/workflows/test.yml) runs on pushes, pull
requests, merge queues, and manual dispatches. It runs the Service test suite on GitHub-hosted
Ubuntu 24.04 and Windows Server 2022 using Python 3.11 and PowerShell, and
builds both Python distributions on Linux. A separate Windows job runs the
patch policy script, builds the Minion service host, and runs its .NET tests.
The PowerShell protocol and installer-helper scripts are exercised by the
Service test suite; they are not standalone pass/fail tests.

The **Demo browser and Minion end-to-end** job builds the demo Compose stack
and uses Chromium to submit ALLOW, PAUSE, rejection, and BLOCK requests.
It approves requests through both the demo and administrative interfaces,
checks that paused and rejected requests are not executed, and verifies the
demo Minion's signed no-op results in the service audit log. Each run uses
temporary test keys, an isolated Compose project, dynamically allocated ports,
and a fresh database and writable policy copy; the containers and volume are
removed afterward. The browser test also checks policy wizard generation,
local file exchange, activation and patch-request decisions.

To run it locally, install Node.js 20 or newer, Docker with Compose 2.24.4 or
newer, and OpenSSL with Ed25519 support. From the repository root:

```sh
npm ci --prefix sluice-demo/tests/e2e
cd sluice-demo/tests/e2e && npx playwright install chromium && cd ../../..
bash sluice-demo/tests/e2e/run.sh
```

On Linux, Playwright may also require system libraries; use
`npx playwright install --with-deps chromium` when appropriate. For an
existing Chromium-compatible browser, set `SG_E2E_CHROMIUM_PATH` to its
executable instead of installing Playwright's browser.

Open the **Actions** tab to inspect a run. Pytest JUnit XML results are
available as an artifact for each operating system, including on test failure.
Review the pytest output for any skipped tests. Once the workflow is running
reliably, a repository administrator can require the application, Windows
Minion, and demo end-to-end checks in a branch protection rule or ruleset.

These jobs do not test the complete deployed stack: the WSL container installer
tests use a fake WSL, and the workflow does not install a Windows service,
reboot a host, exercise a real patch installation, or connect a Windows Minion
to a separately deployed Linux service. Browser coverage is limited to the
demo decision and approval flows. Those scenarios require additional
integration tests and, for the Windows deployment lifecycle, an appropriately
configured disposable Windows Server 2022 environment.

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
