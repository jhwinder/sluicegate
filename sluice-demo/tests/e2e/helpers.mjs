import assert from "node:assert/strict";
import { setTimeout as sleep } from "node:timers/promises";

const service = `http://127.0.0.1:${process.env.SG_E2E_SERVICE_PORT}`;
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


export { service, adminHeaders, json, waitFor, requestState, auditEvents };
