import assert from "node:assert/strict";
import { setTimeout as sleep } from "node:timers/promises";
import { chromium } from "playwright";
import { service, adminHeaders, json, waitFor, requestState, auditEvents } from "./helpers.mjs";

const backend = `http://127.0.0.1:${process.env.SG_E2E_BACKEND_PORT}`;
const frontend = `http://127.0.0.1:${process.env.SG_E2E_FRONTEND_PORT}`;

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
    await page.waitForFunction(({ id, amount }) => {
      try {
        const detail = JSON.parse(document.getElementById("details").textContent);
        return detail.request_id === id && detail.payload.amount === amount;
      } catch { return false; }
    }, { id: result.request_id, amount });
    const detail = await json(`${backend}/api/requests/${result.request_id}`);
    assert.equal(detail.payload.amount, amount);
    assert.equal(detail.payload.action, await page.locator("#action").inputValue());
    assert.equal(detail.payload.currency, (await page.locator("#currency").inputValue()).toUpperCase());
    assert.equal(detail.payload.metadata.demo, true);
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
  assert.match(await adminPage.locator("header h1").innerText(), /^SluiceGate Mission Control\s+v/i);
  assert.equal(await adminPage.locator("#tab-agents h2").first().innerText(), "Registered Agents");
  assert.equal(await adminPage.locator("#tab-minions h2").first().innerText(), "Registered Minions");
  await adminPage.locator("#adminTokenInput").fill(process.env.SG_BOOTSTRAP_ADMIN_KEY);
  await adminPage.locator('button[onclick="saveAdminToken()"]').click();
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
  await adminPage.evaluate(requestId => viewMissionDetail(requestId), allowed);
  assert.match(await adminPage.locator("#requestDetails").innerText(), /Amount\s+100/);
  assert.match(await adminPage.locator("#requestDetails").innerText(), /Currency\s+USD/);
  await adminPage.locator("#missionDetailModal").getByRole("button", { name: "Close", exact: true }).click();
  await adminPage.evaluate(auditId => viewAuditEvent(auditId), storedEvents[0].audit_id);
  assert.match(await adminPage.locator("#requestDetails").innerText(), /historical event below/);
  assert.match(await adminPage.locator("#requestDetails").innerText(), /Amount\s+100/);
  assert.equal(JSON.parse(await adminPage.locator("#detailContent").innerText()).audit_id, storedEvents[0].audit_id);
  await adminPage.locator("#missionDetailModal").getByRole("button", { name: "Close", exact: true }).click();
  await adminPage.route(`**/admin/v1/requests/${allowed}`, route => route.fulfill({ status: 404, body: "Not found" }), { times: 1 });
  await adminPage.evaluate(auditId => viewAuditEvent(auditId), storedEvents[0].audit_id);
  assert.match(await adminPage.locator("#requestDetails").innerText(), /Linked request unavailable/);
  assert.equal(JSON.parse(await adminPage.locator("#detailContent").innerText()).audit_id, storedEvents[0].audit_id);
  await adminPage.locator("#missionDetailModal").getByRole("button", { name: "Close", exact: true }).click();
  let releaseDetail;
  let detailRequested;
  const detailStarted = new Promise(resolve => { detailRequested = resolve; });
  const detailDelayed = new Promise(resolve => { releaseDetail = resolve; });
  await adminPage.route(`**/admin/v1/requests/${allowed}`, async route => {
    detailRequested();
    await detailDelayed;
    await route.continue();
  }, { times: 1 });
  await adminPage.evaluate(id => { window.oldDetail = viewMissionDetail(id); }, allowed);
  await detailStarted;
  await adminPage.evaluate(id => viewMissionDetail(id), paused);
  assert.match(await adminPage.locator("#requestDetails").innerText(), /Amount\s+500/);
  releaseDetail();
  await adminPage.evaluate(() => window.oldDetail);
  assert.match(await adminPage.locator("#detailTitle").innerText(), new RegExp(paused));
  assert.match(await adminPage.locator("#requestDetails").innerText(), /Amount\s+500/);
  await adminPage.locator("#missionDetailModal").getByRole("button", { name: "Close", exact: true }).click();
  const unlinked = (await json(`${service}/admin/v1/audit-events?event_type=admin.mutation`, { headers: adminHeaders })).events[0];
  assert.equal(unlinked.request_id, null);
  await adminPage.evaluate(event => { auditEventsById.set(event.audit_id, event); return viewAuditEvent(event.audit_id); }, unlinked);
  assert.equal(await adminPage.locator("#requestDetails").innerText(), "");
  assert.equal(JSON.parse(await adminPage.locator("#detailContent").innerText()).audit_id, unlinked.audit_id);
  await adminPage.locator("#missionDetailModal").getByRole("button", { name: "Close", exact: true }).click();
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
  await page.reload();
  assert.equal((await json(`${backend}/api/requests/${blocked}`)).payload.amount, 1000);
  const patchResponse = await fetch(`${service}/api/v1/patch-requests`, {
    method: "POST", headers: { Authorization: `Bearer ${process.env.SG_DEMO_AGENT_KEY}`, "Content-Type": "application/json" },
    body: JSON.stringify({ servers: ["patch-test.example.gov"] }),
  });
  assert.equal(patchResponse.status, 202);
  const patchState = await requestState((await patchResponse.json()).request_id);
  assert.equal(patchState.policy_decision, "BLOCK");
  assert.equal(patchState.minion_id, "UNASSIGNED");
  const minions = await json(`${service}/admin/v1/minions`, { headers: adminHeaders });
  assert.deepEqual(minions.map(minion => minion.minion_id), ["DEMO-STUB-01"]);
  assert.ok(minions.every(minion => !minion.capabilities.some(capability => capability.startsWith("windows.patch."))));


} finally {
  await browser.close();
}
