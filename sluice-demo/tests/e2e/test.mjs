import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import { generateKeyPairSync } from "node:crypto";
import { execFileSync } from "node:child_process";
import { setTimeout as sleep } from "node:timers/promises";
import { chromium } from "playwright";

const service = `http://127.0.0.1:${process.env.SG_E2E_SERVICE_PORT}`;
const backend = `http://127.0.0.1:${process.env.SG_E2E_BACKEND_PORT}`;
const frontend = `http://127.0.0.1:${process.env.SG_E2E_FRONTEND_PORT}`;
const adminHeaders = { Authorization: `Bearer ${process.env.SG_BOOTSTRAP_ADMIN_KEY}` };

async function json(url, options = {}) {
  const response = await fetch(url, { ...options, signal: AbortSignal.timeout(5000) });
  assert.equal(response.status, 200, `${url} returned HTTP ${response.status}`);
  return response.json();
}

async function waitFor(name, check, timeout = 60000) {
  const deadline = Date.now() + timeout;
  let lastError;
  while (Date.now() < deadline) {
    try {
      const result = await check();
      if (result) return result;
    } catch (error) {
      lastError = error;
    }
    await sleep(500);
  }
  throw new Error(`Timed out waiting for ${name}${lastError ? `: ${lastError.message}` : ""}`);
}

async function requestState(requestId) {
  return json(`${service}/admin/v1/requests/${requestId}`, { headers: adminHeaders });
}

async function auditEvents(requestId) {
  const result = await json(`${service}/admin/v1/audit-events?request_id=${requestId}`, {
    headers: adminHeaders,
  });
  return result.events;
}

async function assertCompleted(requestId) {
  const state = await waitFor(`mission ${requestId} to complete`, async () => {
    const current = await requestState(requestId);
    return ["MISSION_COMPLETE_SUCCEEDED", "CLOSED", "MISSION_COMPLETE_FAILED", "MISSION_EXPIRED"].includes(current.status)
      ? current
      : null;
  });
  assert.equal(state.status, "MISSION_COMPLETE_SUCCEEDED");
  assert.equal(state.minion_id, "DEMO-STUB-01");
  const events = await auditEvents(requestId);
  const result = events.find((event) => event.event_type === "minion.result");
  assert.ok(result, "Missing Minion result audit event");
  assert.equal(result.signature_verified, true);
  assert.equal(result.detail.signed_payload.result.executed, false);
  assert.equal(result.detail.signed_payload.result.demo, true);
}

async function assertNotExecuted(requestId) {
  const events = await auditEvents(requestId);
  assert.ok(!events.some((event) => event.event_type === "mission.claimed"), "Mission was claimed");
  assert.ok(!events.some((event) => event.event_type === "minion.result"), "Mission produced a result");
}

await waitFor("service and backend readiness", async () => {
  const health = await json(`${backend}/health`);
  return health.ok && health.sg_service_connected;
});
await waitFor("demo Minion check-in", async () => {
  const minions = await json(`${service}/admin/v1/minions`, { headers: adminHeaders });
  return minions.some((minion) =>
    minion.minion_id === "DEMO-STUB-01" && minion.health_status === "HEALTHY" && minion.release_status === "MATCH",
  );
});

const browser = await chromium.launch({
  headless: true,
  ...(process.env.SG_E2E_CHROMIUM_PATH ? { executablePath: process.env.SG_E2E_CHROMIUM_PATH } : {}),
});
try {
  const page = await browser.newPage({ timezoneId: "America/Los_Angeles" });
  await page.route("http://localhost:8000/**", (route) =>
    route.continue({ url: route.request().url().replace("http://localhost:8000", backend) }),
  );
  await page.goto(frontend, { waitUntil: "load" });
  assert.match(await page.title(), /SluiceGate Demo/);

  async function submit(amount, decision) {
    await page.locator("#amount").selectOption(String(amount));
    const responsePromise = page.waitForResponse((response) =>
      response.url().endsWith("/api/decide") && response.request().method() === "POST",
    );
    await page.locator('button[onclick="submitReq()"]').click();
    const response = await responsePromise;
    assert.equal(response.status(), 200);
    const result = await response.json();
    assert.equal(result.decision, decision);
    assert.ok(result.request_id);
    await page.waitForFunction(
      ({ id, expected }) => {
        const status = document.querySelector("#statusLine").innerText;
        return status.includes(id) && status.includes(`gate_decision=${expected}`);
      },
      { id: result.request_id, expected: decision },
    );
    return result.request_id;
  }

  async function assertDemoAudit(requestId, decision, status) {
    const events = await json(`${backend}/api/audit?request_id=${requestId}&limit=200`);
    const serviceEvents = await auditEvents(requestId);
    assert.ok(events.length > 0);
    assert.deepEqual(events.map((event) => event.audit_id), serviceEvents.map((event) => event.audit_id));
    assert.ok(events.every((event) => event.request_id === requestId));
    assert.ok(events.every((event) => event.policy_decision === decision && event.current_status === status));
    assert.ok(events.every((event) => !("detail" in event)));
    assert.ok(events.some((event) => event.event_type === "policy.decision"));
    await page.evaluate(() => refreshAudit());
    const headers = await page.locator("#auditTable th").allTextContents();
    assert.deepEqual(headers, ["Time (local)", "Event", "Request", "Actor", "Policy decision", "Mission status"]);
    assert.match(await page.locator("#auditTable").innerText(), new RegExp(`Latest request snapshot at refresh: decision / outcome: ${decision}; mission status: ${status}`));
    const first = events[0];
    const cells = page.locator("#auditTable tbody tr").first().locator("td");
    const [expectedTime, utcTime] = await page.evaluate((timestamp) => [
      new Date(timestamp * 1000).toLocaleString(),
      new Date(timestamp * 1000).toLocaleString(undefined, { timeZone: "UTC" }),
    ], first.timestamp);
    assert.notEqual(expectedTime, utcTime);
    assert.equal(await cells.nth(0).innerText(), expectedTime);
    assert.equal(await cells.nth(1).innerText(), first.event_type);
    assert.equal(await cells.nth(3).innerText(), `${first.actor_type} / ${first.actor_id}`);
    assert.equal(await cells.nth(4).innerText(), first.event_decision || "—");
    assert.equal(await cells.nth(5).innerText(), first.summary);
    for (const [index, event] of events.entries()) {
      const row = page.locator("#auditTable tbody tr").nth(index).locator("td");
      assert.equal(await row.nth(4).innerText(), event.event_decision || "—");
      assert.equal(await row.nth(5).innerText(), event.summary);
    }
    return events;
  }

  const allowed = await submit(100, "ALLOW");
  await assertCompleted(allowed);
  const allowedEvents = await assertDemoAudit(allowed, "ALLOW", "MISSION_COMPLETE_SUCCEEDED");
  assert.equal(allowedEvents.find((e) => e.event_type === "request.received").event_decision, null);
  assert.equal(allowedEvents.find((e) => e.event_type === "policy.decision").event_decision, "ALLOW");
  assert.equal(allowedEvents.find((e) => e.event_type === "mission.issued").event_mission_status, "QUEUED");
  assert.equal(allowedEvents.find((e) => e.event_type === "mission.claimed").event_mission_status, "CLAIMED");
  assert.ok(allowedEvents.some((e) => e.event_type === "minion.status" && e.event_mission_status === "MISSION_IN_PROGRESS"));
  assert.equal(allowedEvents.find((e) => e.event_type === "minion.result").event_mission_status, "MISSION_COMPLETE_SUCCEEDED");
  console.log("ALLOW: browser submission and signed no-op Minion result verified");

  await page.locator("#showAllAudit").check();
  await page.evaluate(() => refreshAudit());
  assert.match(await page.locator("#auditTable").innerText(), /All events/);
  assert.doesNotMatch(await page.locator("#auditTable").innerText(), /Latest request snapshot/);
  await page.locator("#showAllAudit").uncheck();

  let releaseDemoAudit;
  let demoAuditRequested;
  const demoRequested = new Promise((resolve) => { demoAuditRequested = resolve; });
  const demoDelayed = new Promise((resolve) => { releaseDemoAudit = resolve; });
  await page.route(`**/api/audit?request_id=${allowed}&limit=200`, async (route) => {
    demoAuditRequested();
    await demoDelayed;
    await route.continue({ url: route.request().url().replace("http://localhost:8000", backend) });
  }, { times: 1 });
  await page.evaluate(() => { window.delayedAuditRefresh = refreshAudit(); });
  await demoRequested;
  const paused = await submit(500, "PAUSE");
  await page.locator("#waitPanel").waitFor({ state: "visible" });
  assert.equal((await requestState(paused)).status, "WAITING_FOR_APPROVAL");
  await sleep(3000);
  assert.equal((await requestState(paused)).status, "WAITING_FOR_APPROVAL");
  await assertNotExecuted(paused);
  await assertDemoAudit(paused, "PAUSE", "WAITING_FOR_APPROVAL");
  releaseDemoAudit();
  await page.evaluate(() => window.delayedAuditRefresh);
  assert.match(await page.locator("#auditTable").innerText(), /decision \/ outcome: PAUSE; mission status: WAITING_FOR_APPROVAL/);
  assert.match(await page.locator("#auditTable").innerText(), new RegExp(`Events for ${paused.slice(0, 8)}`));
  const approval = page.waitForResponse((response) =>
    response.url().endsWith(`/api/requests/${paused}/approve`) && response.request().method() === "POST",
  );
  await page.locator("#approveBtn").click();
  assert.equal((await approval).status(), 200);
  await assertCompleted(paused);
  const approvedEvents = await assertDemoAudit(paused, "ALLOW", "MISSION_COMPLETE_SUCCEEDED");
  assert.equal(approvedEvents.find((e) => e.event_type === "policy.decision").event_decision, "PAUSE");
  assert.equal(approvedEvents.find((e) => e.event_type === "mission.issued").event_mission_status, "WAITING_FOR_APPROVAL");
  assert.equal(approvedEvents.find((e) => e.event_type === "approval.re_evaluated").event_decision, "ALLOW");
  assert.ok((await auditEvents(paused)).some((event) => event.event_type === "approval.re_evaluated"));
  console.log("PAUSE: no execution before browser approval; signed result verified afterward");

  const adminPaused = await submit(500, "PAUSE");
  assert.equal((await requestState(adminPaused)).status, "WAITING_FOR_APPROVAL");
  const adminPage = await browser.newPage();
  adminPage.on("dialog", (dialog) => dialog.accept("Approved by E2E test"));
  await adminPage.goto(`${service}/admin/ui`, { waitUntil: "load" });
  assert.match(await adminPage.locator("header h1").innerText(), /^SluiceGate\s+v/i);
  assert.equal(await adminPage.locator("#tab-agents h2").first().innerText(), "Registered Agents");
  assert.equal(await adminPage.locator("#tab-minions h2").first().innerText(), "Registered Minions");
  await adminPage.locator("#adminTokenInput").fill(process.env.SG_BOOTSTRAP_ADMIN_KEY);
  await adminPage.locator('button[onclick="saveAdminToken()"]').click();
  await adminPage.locator('.nav-tab[onclick="switchTab(\'minions\')"]').click();
  const manifest = {
    schema_version: 2, type_id: "E2E-PATCHER", family: "e2e-patcher", name: "E2E Patcher", version: "2.0",
    runtime_type: "powershell", artifact: "patcher.zip", package_sha256: "a".repeat(64),
    capabilities: ["windows.patch.reconcile", "windows.patch.status"], requires_target_scope: true,
    instance_fields: [{ id: "owner", label: "Owner team", required: true }], release_files: ["worker.py"],
  };
  await adminPage.locator("#minionManifestFile").setInputFiles({
    name: "patcher.json", mimeType: "application/json", buffer: Buffer.from(JSON.stringify(manifest)),
  });
  const typeRow = adminPage.locator("#minionTypesTableBody tr").filter({ hasText: manifest.type_id });
  await typeRow.waitFor();
  await adminPage.getByRole("button", { name: "+ Add Deployed Minion" }).click();
  await adminPage.locator("#deployMinionType").selectOption(manifest.type_id);
  assert.match(await adminPage.locator("#deployMinionTypeDetails").innerText(), /patcher.zip/);
  await adminPage.locator("#newMinionId").fill("E2E-INSTANCE");
  await adminPage.locator("#newMinionTargets").fill("test-*.example.gov");
  await adminPage.locator('#deployMinionFields input[data-field-id="owner"]').fill("Operations");
  await adminPage.locator('#deployMinionCapabilities input[value="windows.patch.status"]').uncheck();
  const publicKey = generateKeyPairSync("ed25519").publicKey.export({ type: "spki", format: "pem" });
  await adminPage.locator("#newMinionPubKey").fill(publicKey);
  await adminPage.locator("#registerMinionModal").getByRole("button", { name: "Save" }).click();
  const instanceRow = adminPage.locator("#minionsTableBody tr").filter({ hasText: "E2E-INSTANCE" });
  await instanceRow.waitFor();
  assert.match(await instanceRow.innerText(), /NOT REPORTED/);
  const nextRelease = { ...manifest, type_id: "E2E-NEW-PATCHER", version: "3.0", package_sha256: "b".repeat(64) };
  await adminPage.locator("#minionManifestFile").setInputFiles({
    name: "patcher-3.json", mimeType: "application/json", buffer: Buffer.from(JSON.stringify(nextRelease)),
  });
  const nextTypeRow = adminPage.locator("#minionTypesTableBody tr").filter({ hasText: nextRelease.type_id });
  await nextTypeRow.waitFor();
  await instanceRow.getByRole("button", { name: "Assign Release" }).click();
  await adminPage.locator("#assignMinionRelease").selectOption(nextRelease.type_id);
  await adminPage.locator("#assignMinionReleaseModal").getByRole("button", { name: "Assign", exact: true }).click();
  await instanceRow.getByText("Assigned: 3.0").waitFor();
  assert.ok(await nextTypeRow.getByRole("button", { name: "Delete" }).isDisabled());
  assert.ok(await nextTypeRow.getByRole("button", { name: "Disable" }).isDisabled());
  await instanceRow.getByRole("button", { name: "Edit" }).click();
  assert.equal(await adminPage.locator('#deployMinionFields input[data-field-id="owner"]').inputValue(), "Operations");
  await adminPage.locator("#newMinionTargets").fill("updated.example.gov");
  await adminPage.locator('#deployMinionCapabilities input[value="windows.patch.status"]').check();
  await adminPage.locator("#registerMinionModal").getByRole("button", { name: "Save" }).click();
  await instanceRow.getByText("updated.example.gov").waitFor();
  assert.match(await instanceRow.innerText(), /windows\.patch\.status/i);
  await instanceRow.getByRole("button", { name: "Disable" }).click();
  await instanceRow.getByRole("button", { name: "Enable", exact: true }).waitFor();
  await instanceRow.getByRole("button", { name: "Enable", exact: true }).click();
  await instanceRow.getByRole("button", { name: "Disable", exact: true }).waitFor();
  await instanceRow.getByRole("button", { name: "Delete", exact: true }).click();
  await instanceRow.waitFor({ state: "detached" });
  await typeRow.getByRole("button", { name: "Disable" }).click();
  await typeRow.getByRole("button", { name: "Enable" }).waitFor();
  await typeRow.getByRole("button", { name: "Delete" }).click();
  await typeRow.waitFor({ state: "detached" });
  await nextTypeRow.getByRole("button", { name: "Delete" }).click();
  await nextTypeRow.waitFor({ state: "detached" });
  console.log("MINIONS: manifest import and type/deployment lifecycle verified");
  await adminPage.locator('.nav-tab[onclick="switchTab(\'missions\')"]').click();
  await adminPage.locator("#auditRequestId").fill(allowed);
  const auditCard = adminPage.locator(".card").filter({ has: adminPage.getByRole("heading", { name: "Audit Events" }) });
  const filteredResponse = adminPage.waitForResponse((response) =>
    response.url().includes(`/admin/v1/audit-events?request_id=${allowed}`) && response.status() === 200,
  );
  await auditCard.getByRole("button", { name: "Filter", exact: true }).click();
  await filteredResponse;
  await adminPage.locator("#auditEventsTableBody tr").filter({ hasText: allowed }).first().waitFor();
  const storedEvents = await auditEvents(allowed);
  const dialog = adminPage.locator("#clearAuditDialog");
  await auditCard.getByRole("button", { name: "Clear", exact: true }).click();
  await dialog.getByRole("button", { name: "Cancel" }).click();
  assert.ok((await adminPage.locator("#auditEventsTableBody").innerText()).includes(allowed));

  let releaseAudit;
  let auditRequested;
  const requested = new Promise((resolve) => { auditRequested = resolve; });
  const delayed = new Promise((resolve) => { releaseAudit = resolve; });
  await adminPage.route("**/admin/v1/audit-events?**", async (route) => {
    auditRequested();
    await delayed;
    await route.continue();
  }, { times: 1 });
  await adminPage.evaluate(() => { loadAudit(true); });
  await requested;
  await auditCard.getByRole("button", { name: "Clear", exact: true }).click();
  await dialog.getByRole("button", { name: "Continue" }).click();
  const delayedResponse = adminPage.waitForResponse((response) =>
    response.url().includes(`/admin/v1/audit-events?request_id=${allowed}`),
  );
  releaseAudit();
  await delayedResponse;
  assert.match(await adminPage.locator("#auditEventsTableBody").innerText(), /Display cleared/);
  assert.equal(await adminPage.locator("#auditOlderButton").isVisible(), false);
  assert.deepEqual((await auditEvents(allowed)).map((event) => event.audit_id), storedEvents.map((event) => event.audit_id));
  const reloadResponse = adminPage.waitForResponse((response) =>
    response.url().includes(`/admin/v1/audit-events?request_id=${allowed}`) && response.status() === 200,
  );
  await auditCard.getByRole("button", { name: "Reload", exact: true }).click();
  await reloadResponse;
  await adminPage.locator("#auditEventsTableBody tr").filter({ hasText: allowed }).first().waitFor();
  assert.equal(await adminPage.locator("#auditRequestId").inputValue(), allowed);
  await auditCard.getByRole("button", { name: "Reset filters" }).click();
  assert.equal(await adminPage.locator("#auditRequestId").inputValue(), "");
  await adminPage.locator('.nav-tab[onclick="switchTab(\'approvals\')"]').click();
  const row = adminPage.locator("#approvalsTableBody tr").filter({ hasText: adminPaused });
  await row.waitFor({ state: "visible" });
  const adminApproval = adminPage.waitForResponse((response) =>
    response.url().endsWith(`/admin/v1/requests/${adminPaused}/approve`) && response.request().method() === "POST",
  );
  await row.getByRole("button", { name: "Approve" }).click();
  assert.equal((await adminApproval).status(), 200);
  await assertCompleted(adminPaused);
  assert.ok((await auditEvents(adminPaused)).some((event) => event.event_type === "approval.re_evaluated"));
  await adminPage.close();
  console.log("ADMIN: authenticated console approval and signed Minion result verified");

  const rejected = await submit(500, "PAUSE");
  await page.locator("#waitPanel").waitFor({ state: "visible" });
  const rejection = page.waitForResponse((response) =>
    response.url().endsWith(`/api/requests/${rejected}/reject`) && response.request().method() === "POST",
  );
  await page.locator("#rejectBtn").click();
  assert.equal((await rejection).status(), 200);
  await waitFor("rejected request to close", async () =>
    (await requestState(rejected)).status === "CLOSED",
  );
  await assertNotExecuted(rejected);
  assert.ok((await auditEvents(rejected)).some((event) => event.event_type === "approval.rejected"));
  const rejectedEvents = await assertDemoAudit(rejected, "REJECTED", "CLOSED");
  assert.equal(rejectedEvents.find((e) => e.event_type === "approval.rejected").event_decision, null);
  assert.equal(rejectedEvents.find((e) => e.event_type === "approval.rejected").event_mission_status, null);
  console.log("REJECT: browser rejection closed the request without Minion execution");

  const blocked = await submit(1000, "BLOCK");
  assert.equal((await requestState(blocked)).status, "CLOSED");
  await assertNotExecuted(blocked);
  const blockedEvents = await assertDemoAudit(blocked, "BLOCK", "CLOSED");
  assert.equal(blockedEvents.find((e) => e.event_type === "policy.decision").event_decision, "BLOCK");
  assert.equal(blockedEvents.find((e) => e.event_type === "mission.issued").event_mission_status, "CLOSED");
  assert.deepEqual(await json(`${backend}/api/audit?request_id=unknown&limit=1`), []);
  const allEvents = await json(`${backend}/api/audit?limit=1`);
  assert.equal(allEvents.length, 1);
  assert.equal((await fetch(`${backend}/api/audit?limit=501`)).status, 422);
  await page.route("http://localhost:8000/api/audit?**", (route) =>
    route.fulfill({ status: 503, body: "unavailable" }),
  );
  await page.evaluate(() => refreshAudit());
  assert.match(await page.locator("#auditTable").innerText(), /Unable to load audit events: HTTP 503/);
  console.log("BLOCK: browser submission was denied without Minion execution");

  const policyPage = await browser.newPage({ acceptDownloads: true });
  let acceptConfirmation = true;
  policyPage.on("dialog", async (dialog) => {
    if (acceptConfirmation) await dialog.accept();
    else await dialog.dismiss();
  });
  await policyPage.goto(`${service}/admin/ui`);
  await policyPage.locator("#adminTokenInput").fill(process.env.SG_BOOTSTRAP_ADMIN_KEY);
  await policyPage.locator('button[onclick="saveAdminToken()"]').click();
  await policyPage.locator('.nav-tab[onclick="switchTab(\'policy\')"]').click();
  await policyPage.waitForFunction(() => document.getElementById("policyHashInfo").textContent.startsWith("File SHA-256:"));
  const activePolicy = await json(`${service}/admin/v1/policy`, { headers: adminHeaders });
  const editor = policyPage.locator("#policyEditor");
  await policyPage.getByRole("button", { name: "Edit Policy", exact: true }).click();
  await policyPage.waitForFunction(() => document.getElementById("policyFeedback").textContent.includes("Could not open policy wizard"));
  assert.equal(await editor.inputValue(), activePolicy.content);
  await editor.fill("# unsaved\n" + activePolicy.content);
  acceptConfirmation = false;
  await policyPage.getByRole("button", { name: "Reload from Service" }).click();
  assert.ok((await editor.inputValue()).startsWith("# unsaved\n"));
  await policyPage.locator('.nav-tab[onclick="switchTab(\'agents\')"]').click();
  await policyPage.locator('.nav-tab[onclick="switchTab(\'policy\')"]').click();
  assert.ok((await editor.inputValue()).startsWith("# unsaved\n"));
  await policyPage.getByRole("button", { name: "Create New" }).click();
  const wizard = policyPage.locator("#policyWizard");
  await wizard.getByRole("button", { name: "Generate YAML" }).click();
  assert.ok((await editor.inputValue()).startsWith("# unsaved\n"));
  acceptConfirmation = true;
  await wizard.getByRole("button", { name: "Generate YAML" }).click();
  const blank = await editor.inputValue();
  assert.match(blank, /decision: BLOCK/);
  assert.match(blank, /rules: \[\]/);
  assert.equal((await json(`${service}/admin/v1/policy`, { headers: adminHeaders })).content, activePolicy.content);
  await policyPage.getByRole("button", { name: "Save and Activate" }).click();
  await policyPage.waitForFunction(() => document.getElementById("policyFeedback").textContent.includes("Policy saved and activated"));
  assert.equal((await json(`${service}/admin/v1/policy`, { headers: adminHeaders })).content, blank);

  await policyPage.getByRole("button", { name: "Create New" }).click();
  assert.ok(await wizard.locator("#wizardZone option[value='America/New_York']").count());
  await wizard.locator("#wizardTargets").fill("patch-test.example.gov");
  await wizard.locator('input[name="wizardSource"][value="nessus_catalog"]').check();
  await wizard.locator("#wizardExecutables").fill("msiexec.exe");
  await wizard.locator("#wizardWindowEnabled").check();
  await wizard.locator("#wizardZone").selectOption("America/New_York");
  await wizard.locator('input[name="wizardDay"][value="SAT"]').check();
  await wizard.locator("#wizardEnd").fill("01:00");
  await wizard.getByRole("button", { name: "Add rule" }).click();
  assert.match(await wizard.locator("#wizardError").innerText(), /different start and end times/);
  await wizard.locator("#wizardEnd").fill("05:00");
  await wizard.getByRole("button", { name: "Add rule" }).click();
  await wizard.locator("#wizardTargets").fill("direct-test.example.gov");
  await wizard.locator("#wizardApproval").uncheck();
  await wizard.getByRole("button", { name: "Add rule" }).click();
  assert.equal(await wizard.locator("#wizardRuleList li").count(), 2);
  await wizard.getByRole("button", { name: "Generate YAML" }).click();
  const generated = await editor.inputValue();
  assert.match(generated, /default:\n  decision: BLOCK/);
  await policyPage.getByRole("button", { name: "Edit Policy", exact: true }).click();
  assert.equal(await wizard.locator("#wizardRuleList li").count(), 2);
  await wizard.getByRole("button", { name: "Edit rule 1" }).click();
  assert.equal(await wizard.locator("#wizardTargets").inputValue(), "patch-test.example.gov");
  assert.equal(await wizard.locator("#wizardApproval").isChecked(), true);
  assert.equal(await wizard.locator("#wizardZone").inputValue(), "America/New_York");
  await wizard.locator("#wizardReboot").check();
  await wizard.getByRole("button", { name: "Update rule" }).click();
  await wizard.getByRole("button", { name: "Generate YAML" }).click();
  const edited = await editor.inputValue();
  assert.notEqual(edited, generated);
  assert.match(edited, /allow_reboot: true/);
  assert.equal((await json(`${service}/admin/v1/policy`, { headers: adminHeaders })).content, blank);
  await policyPage.getByRole("button", { name: "Edit Policy", exact: true }).click();
  await wizard.getByRole("button", { name: "Edit rule 1" }).click();
  assert.equal(await wizard.locator("#wizardReboot").isChecked(), true);
  await wizard.locator("#wizardReboot").uncheck();
  await wizard.getByRole("button", { name: "Update rule" }).click();
  await wizard.getByRole("button", { name: "Generate YAML" }).click();
  assert.equal(await editor.inputValue(), generated);
  await editor.fill("# preserve comment\n" + generated);
  await policyPage.getByRole("button", { name: "Edit Policy", exact: true }).click();
  await policyPage.waitForFunction(() => document.getElementById("policyFeedback").textContent.includes("unsupported rules, comments, or formatting"));
  assert.equal(await editor.inputValue(), "# preserve comment\n" + generated);
  await editor.fill(generated);
  const validation = await json(`${service}/admin/v1/policy/validate`, {
    method: "POST", headers: { ...adminHeaders, "Content-Type": "application/json" },
    body: JSON.stringify({ content: generated }),
  });
  assert.equal(validation.is_valid, true, JSON.stringify(validation.issues));
  assert.equal((await json(`${service}/admin/v1/policy`, { headers: adminHeaders })).content, blank);
  const downloadPromise = policyPage.waitForEvent("download");
  await policyPage.getByRole("button", { name: "Download YAML" }).click();
  const download = await downloadPromise;
  assert.equal(await readFile(await download.path(), "utf8"), generated);

  const imported = "# imported policy, preserve unknown content\nversion: 1\ndefault: {decision: BLOCK}\nrules: []\n";
  await policyPage.locator("#policyFile").setInputFiles({ name: "custom.yaml", mimeType: "application/yaml", buffer: Buffer.from(imported) });
  await policyPage.waitForFunction((text) => document.getElementById("policyEditor").value === text, imported);
  assert.equal((await json(`${service}/admin/v1/policy`, { headers: adminHeaders })).content, blank);
  await policyPage.locator("#policyFile").setInputFiles({ name: "generated.yaml", mimeType: "application/yaml", buffer: Buffer.from(generated) });
  await policyPage.waitForFunction((text) => document.getElementById("policyEditor").value === text, generated);
  await policyPage.getByRole("button", { name: "Save and Activate" }).click();
  await policyPage.waitForFunction(() => document.getElementById("policyFeedback").textContent.includes("Policy saved and activated"));

  async function submitPatch(servers) {
    const response = await fetch(`${service}/api/v1/patch-requests`, {
      method: "POST",
      headers: { Authorization: "Bearer " + process.env.SG_DEMO_AGENT_KEY, "Content-Type": "application/json" },
      body: JSON.stringify({ servers }),
    });
    if (response.status !== 202) throw new Error(`Patch request failed: ${response.status} ${await response.text()}`);
    return response.json();
  }
  const pendingPatch = await submitPatch(["patch-test.example.gov"]);
  assert.equal((await requestState(pendingPatch.request_id)).status, "WAITING_FOR_APPROVAL");
  const issued = (await auditEvents(pendingPatch.request_id)).find((event) => event.event_type === "mission.issued");
  assert.deepEqual(issued.detail.signed_envelope.target.servers, ["patch-test.example.gov"]);
  const parameters = issued.detail.signed_envelope.parameters;
  assert.deepEqual(parameters.patch_sources, ["wsus", "nessus_catalog"]);
  assert.deepEqual(parameters.patch_constraints.allowed_patch_types, ["SECURITY"]);
  assert.equal(parameters.patch_constraints.allow_reboot, false);
  assert.deepEqual(parameters.maintenance_window, { timezone: "America/New_York", days: ["SAT"], start: "01:00", end: "05:00" });
  assert.deepEqual(
    issued.detail.signed_envelope.obligations.find((item) => item.type === "allowed_patch_executables").data.executables,
    ["msiexec.exe"],
  );
  const approvedPatch = await fetch(`${service}/admin/v1/requests/${pendingPatch.request_id}/approve`, {
    method: "POST", headers: { ...adminHeaders, "Content-Type": "application/json" }, body: "{}",
  });
  assert.equal(approvedPatch.status, 200);
  assert.equal((await approvedPatch.json()).decision, "ALLOW");
  const unrelatedPatch = await submitPatch(["other.example.gov"]);
  assert.equal((await requestState(unrelatedPatch.request_id)).status, "CLOSED");
  assert.equal((await requestState(unrelatedPatch.request_id)).policy_decision, "BLOCK");
  const directPatch = await submitPatch(["direct-test.example.gov"]);
  assert.equal((await requestState(directPatch.request_id)).policy_decision, "ALLOW");
  const active = await json(`${service}/admin/v1/policy`, { headers: adminHeaders });
  const otherSave = await fetch(`${service}/admin/v1/policy`, {
    method: "POST", headers: { ...adminHeaders, "Content-Type": "application/json" },
    body: JSON.stringify({ content: blank, expected_file_hash: active.file_hash }),
  });
  assert.equal(otherSave.status, 200);
  await editor.fill(generated + "# stale local draft\n");
  await policyPage.getByRole("button", { name: "Save and Activate" }).click();
  await policyPage.waitForFunction(() => document.getElementById("policyFeedback").textContent.includes("Policy was not activated"));
  assert.match(await policyPage.locator("#policyFeedback").innerText(), /changed since it was loaded/);
  assert.equal((await json(`${service}/admin/v1/policy`, { headers: adminHeaders })).content, blank);
  await policyPage.close();
  console.log("POLICY: wizard, file round-trip, draft safety, and patch decisions verified");

  const container = process.env.SG_E2E_MINION_CONTAINER;
  assert.ok(container, "Missing isolated demo Minion container ID");
  function minionPython(code) {
    execFileSync("docker", ["exec", container, "python", "-c", code], { stdio: "pipe" });
  }
  try {
    minionPython("from pathlib import Path; p=Path('/app/worker.py'); Path('/tmp/worker-backup').write_bytes(p.read_bytes()); p.write_bytes(p.read_bytes()+b'\\n# drift\\n')");
    await waitFor("release drift to clear the report", async () => {
      const minions = await json(`${service}/admin/v1/minions`, { headers: adminHeaders });
      return minions.find((minion) => minion.minion_id === "DEMO-STUB-01")?.release_status === "NOT REPORTED";
    });
  } finally {
    minionPython("from pathlib import Path; Path('/app/worker.py').write_bytes(Path('/tmp/worker-backup').read_bytes())");
  }
  await waitFor("restored running release to match", async () => {
    const minions = await json(`${service}/admin/v1/minions`, { headers: adminHeaders });
    return minions.find((minion) => minion.minion_id === "DEMO-STUB-01")?.release_status === "MATCH";
  });
  console.log("RELEASE: running Minion detects modified files and recovers after restoration");
} finally {
  await browser.close();
}
