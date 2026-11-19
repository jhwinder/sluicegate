# TEST Stub Minion

This worker simulates patching Missions for automated integration tests. It reports signed status/results and release fingerprints, but performs no external action. Its result contains `test: true` and `executed: false`.

The worker has its own `test-stub` release family and `TEST-STUB-01` deployment ID. It is not copied into the service or DEMO images and is never provisioned by service startup. The test harness imports its manifest, creates its instance and credentials through authenticated administrative APIs, and starts it only for the test run.

From the repository root, run:

```sh
npm ci --prefix sluice-demo/tests/e2e
npm exec --prefix sluice-demo/tests/e2e -- playwright install chromium
bash sg-service/tests/integration/run.sh
```

The runner creates an isolated Compose project, temporary policy/templates, database, and signing keys. It removes its containers, images, volume, and temporary files on exit. Set `SG_TEST_FORCE_FAILURE=true` when invoking the runner to exercise failure cleanup.

The service currently routes submitted actions in the `prod` environment. The harness uses that matching value in its disposable database, with exact test-host scopes; isolation comes from separate containers, credentials, volumes, and policy files.

Both Minion manifests are verified by `python minion-registry/release_manifest.py`. The full CI workflow builds/runs both DEMO and TEST stacks. Building `sg-service/Dockerfile` alone does not start or build the TEST worker.
