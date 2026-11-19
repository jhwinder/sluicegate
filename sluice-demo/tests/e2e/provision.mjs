import assert from "node:assert/strict";
import { readFile, writeFile } from "node:fs/promises";
import { service, adminHeaders, json, waitFor } from "./helpers.mjs";

await waitFor("TEST service readiness", async () => (await json(`${service}/health`)).status === "ok");
const minions = await json(`${service}/admin/v1/minions`, { headers: adminHeaders });
assert.deepEqual(minions, [], "Ordinary service startup must not seed DEMO or TEST");
assert.deepEqual(await json(`${service}/admin/v1/minion-types`, { headers: adminHeaders }), []);

async function create(path, body) {
  const response = await fetch(`${service}${path}`, {
    method: "POST", headers: { ...adminHeaders, "Content-Type": "application/json" }, body: JSON.stringify(body),
  });
  assert.equal(response.status, 201, `${path}: ${await response.clone().text()}`);
  return response.json();
}

const manifest = JSON.parse(await readFile(new URL("../../../minion-registry/minions/test_stub/minion-release.json", import.meta.url), "utf8"));
await create("/admin/v1/minion-types", manifest);
const minion = await create("/admin/v1/minions", {
  minion_id: "TEST-STUB-01", type_id: manifest.type_id, capabilities: manifest.capabilities,
  environment: "prod", scope_metadata: { targets: ["patch-test.example.gov", "patch-reboot-test.example.gov", "direct-test.example.gov"] },
  public_key: await readFile(`${process.env.SG_E2E_SECRETS_DIR}/test-minion-public.pem`, "utf8"),
});
const agent = await create("/admin/v1/agents", { name: "Integration test agent" });
await writeFile(`${process.env.SG_E2E_SECRETS_DIR}/test-minion-api-key`, minion.api_key, { mode: 0o600 });
await writeFile(`${process.env.SG_E2E_SECRETS_DIR}/test-agent-api-key`, agent.api_key, { mode: 0o600 });
