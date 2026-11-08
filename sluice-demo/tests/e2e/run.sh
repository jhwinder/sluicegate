#!/usr/bin/env bash
set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
export SG_BOOTSTRAP_ADMIN_KEY="$(openssl rand -hex 32)"
export SG_DEMO_AGENT_KEY="$(openssl rand -hex 32)"
export SG_DEMO_MINION_KEY="$(openssl rand -hex 32)"
export RESEND_API_KEY=""
project="sluice-e2e-$(openssl rand -hex 6)"
workdir="$(mktemp -d "${TMPDIR:-/tmp}/sluicegate-e2e.XXXXXXXX")"
export SG_E2E_SECRETS_DIR="$workdir"
export SG_E2E_IMAGE_TAG="$project"
compose=(docker compose --project-name "$project" -f "$root/sluice-demo/docker-compose.yml" -f "$root/sluice-demo/tests/e2e/compose.override.yml")

cleanup() {
  local result=$?
  trap - EXIT
  if (( result != 0 )); then
    "${compose[@]}" logs --no-color --tail=100 >&2 || true
  fi
  if ! "${compose[@]}" down --volumes --remove-orphans; then
    echo "Failed to clean up Compose project $project" >&2
    result=1
  fi
  for image in "sluicegate-e2e:$project" "$project-backend" "$project-demo-minion"; do
    if docker image inspect "$image" >/dev/null 2>&1 && ! docker image rm "$image"; then
      echo "Failed to clean up image $image" >&2
      result=1
    fi
  done
  rm -f "$workdir/sg-signing-key.pem" "$workdir/demo-minion-key.pem" "$workdir/demo-minion-public.pem"
  if [[ -d "$workdir/policy" ]]; then
    rm -f "$workdir/policy/demo-policy.yml" "$workdir"/policy/demo-policy.yml.*.bak
    if ! rmdir "$workdir/policy"; then
      echo "Failed to clean up $workdir/policy" >&2
      result=1
    fi
  fi
  if ! rmdir "$workdir"; then
    echo "Failed to clean up $workdir" >&2
    result=1
  fi
  exit "$result"
}
trap cleanup EXIT

umask 077
mkdir "$workdir/policy"
cp "$root/sg-service/policies/demo-policy.yml" "$workdir/policy/demo-policy.yml"
openssl genpkey -algorithm ED25519 -out "$workdir/sg-signing-key.pem"
openssl genpkey -algorithm ED25519 -out "$workdir/demo-minion-key.pem"
openssl pkey -in "$workdir/demo-minion-key.pem" -pubout -out "$workdir/demo-minion-public.pem"

"${compose[@]}" up --build --detach
export SG_E2E_SERVICE_PORT="$("${compose[@]}" port sg-service 8443 | awk -F: '{print $NF}')"
export SG_E2E_BACKEND_PORT="$("${compose[@]}" port backend 8000 | awk -F: '{print $NF}')"
export SG_E2E_FRONTEND_PORT="$("${compose[@]}" port frontend 80 | awk -F: '{print $NF}')"
export SG_E2E_MINION_CONTAINER="$("${compose[@]}" ps -q demo-minion)"

cd "$root/sluice-demo/tests/e2e"
npm test
