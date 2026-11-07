import assert from "node:assert/strict";
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
    minion.minion_id === "DEMO-STUB-01" && minion.health_status === "HEALTHY",
  );
});

const browser = await chromium.launch({
  headless: true,
  ...(process.env.SG_E2E_CHROMIUM_PATH ? { executablePath: process.env.SG_E2E_CHROMIUM_PATH } : {}),
});
try {
  const page = await browser.newPage();
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

  const allowed = await submit(100, "ALLOW");
  await assertCompleted(allowed);
  console.log("ALLOW: browser submission and signed no-op Minion result verified");

  const paused = await submit(500, "PAUSE");
  await page.locator("#waitPanel").waitFor({ state: "visible" });
  assert.equal((await requestState(paused)).status, "WAITING_FOR_APPROVAL");
  await sleep(3000);
  assert.equal((await requestState(paused)).status, "WAITING_FOR_APPROVAL");
  await assertNotExecuted(paused);
  const approval = page.waitForResponse((response) =>
    response.url().endsWith(`/api/requests/${paused}/approve`) && response.request().method() === "POST",
  );
  await page.locator("#approveBtn").click();
  assert.equal((await approval).status(), 200);
  await assertCompleted(paused);
  assert.ok((await auditEvents(paused)).some((event) => event.event_type === "approval.re_evaluated"));
  console.log("PAUSE: no execution before browser approval; signed result verified afterward");

  const adminPaused = await submit(500, "PAUSE");
  assert.equal((await requestState(adminPaused)).status, "WAITING_FOR_APPROVAL");
  const adminPage = await browser.newPage();
  adminPage.on("dialog", (dialog) => dialog.accept("Approved by E2E test"));
  await adminPage.goto(`${service}/admin/ui`, { waitUntil: "load" });
  await adminPage.locator("#adminTokenInput").fill(process.env.SG_BOOTSTRAP_ADMIN_KEY);
  await adminPage.locator('button[onclick="saveAdminToken()"]').click();
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
  console.log("REJECT: browser rejection closed the request without Minion execution");

  const blocked = await submit(1000, "BLOCK");
  assert.equal((await requestState(blocked)).status, "CLOSED");
  await assertNotExecuted(blocked);
  console.log("BLOCK: browser submission was denied without Minion execution");
} finally {
  await browser.close();
}
