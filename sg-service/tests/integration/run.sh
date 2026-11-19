#!/usr/bin/env bash
set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
export SG_BOOTSTRAP_ADMIN_KEY="$(openssl rand -hex 32)"
export SG_E2E_IMAGE_TAG="test-$(openssl rand -hex 6)"
export SG_TEST_MINION_KEY=""
workdir="$(mktemp -d "${TMPDIR:-/tmp}/sluicegate-test.XXXXXXXX")"
export SG_E2E_SECRETS_DIR="$workdir"
echo "TEST RUN: project=$SG_E2E_IMAGE_TAG workspace=$workdir"
compose=(docker compose --project-name "$SG_E2E_IMAGE_TAG" -f "$root/sg-service/tests/integration/docker-compose.yml" --profile test)

cleanup() {
  local result=$?
  trap - EXIT
  if (( result != 0 )); then
    "${compose[@]}" logs --no-color --tail=100 >&2 || true
  fi
  if ! "${compose[@]}" down --volumes --remove-orphans; then
    result=1
  fi
  for image in "sluicegate-test-service:$SG_E2E_IMAGE_TAG" "sluicegate-test-minion:$SG_E2E_IMAGE_TAG"; do
    if docker image inspect "$image" >/dev/null 2>&1 && ! docker image rm "$image"; then
      result=1
    fi
  done
  # Only remove the temporary directory created by this invocation.
  if ! rm -rf "$workdir"; then
    echo "Failed to clean up $workdir" >&2
    result=1
  fi
  exit "$result"
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

umask 077
mkdir -p "$workdir/policy/templates"
cp "$root/sg-service/tests/fixtures/policies/test-policy.yml" "$workdir/policy/test-policy.yml"
cp "$root/sg-service/src/sg_service/policy_templates/catalog.json" "$workdir/policy/templates/catalog.json"
openssl genpkey -algorithm ED25519 -out "$workdir/sg-signing-key.pem"
openssl genpkey -algorithm ED25519 -out "$workdir/test-minion-key.pem"
openssl pkey -in "$workdir/test-minion-key.pem" -pubout -out "$workdir/test-minion-public.pem"

"${compose[@]}" up --build --detach sg-service
"${compose[@]}" exec -T sg-service python - < "$root/sg-service/tests/integration/verify_runtime.py"
export SG_E2E_SERVICE_PORT="$("${compose[@]}" port sg-service 8443 | awk -F: '{print $NF}')"
node "$root/sluice-demo/tests/e2e/provision.mjs"
export SG_TEST_MINION_KEY="$(cat "$workdir/test-minion-api-key")"
"${compose[@]}" up --build --no-deps --detach test-minion
export SG_E2E_MINION_CONTAINER="$("${compose[@]}" ps -q test-minion)"
if [[ "${SG_TEST_FORCE_FAILURE:-false}" == "true" ]]; then
  echo "Deliberate failure to verify test teardown" >&2
  exit 1
fi
node "$root/sluice-demo/tests/e2e/integration.mjs"
