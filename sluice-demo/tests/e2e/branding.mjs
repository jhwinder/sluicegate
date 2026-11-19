import assert from "node:assert/strict";
import { readFile, mkdir } from "node:fs/promises";
import { chromium } from "playwright";

// Deterministic presentation fixtures; real workflows remain covered by both E2E stacks.
const baseline = process.argv.includes("--baseline");
const output = process.env.SG_BRANDING_ARTIFACTS_DIR || "/tmp/sluicegate-branding-review";
const source = new URL("../../../sg-service/src/sg_service/static/", import.meta.url);
const request = {
  request_id: "REQ-branding-preview", mission_id: "MISSION-branding-preview", agent_id: "BILLING-01",
  minion_id: "DEMO-STUB-01", status: "MISSION_COMPLETE_SUCCEEDED", policy_decision: "ALLOW",
  created_at: 1795055798, updated_at: 1795055800, request_source: "stored_request",
  submitted_request: { capability: "stripe.refund", target: { type: "API", id: "stripe.refund" }, parameters: { amount: 100, currency: "USD" }, context: { ticket: "REFUND-101" } },
  mission_envelope: { capability: "stripe.refund", parameters: { amount: 100, currency: "USD" }, policy_decision: "ALLOW" },
};
const event = {
  audit_id: 1, event_type: "minion.result", actor_type: "MINION", actor_id: "DEMO-STUB-01",
  request_id: request.request_id, mission_id: request.mission_id, agent_id: request.agent_id,
  minion_id: request.minion_id, status: request.status, occurred_at: request.updated_at,
  received_at: request.updated_at, signature_verified: true, detail: { result: { executed: false, demo: true } },
};
const policy = "version: 1\ndefault:\n  decision: BLOCK\nrules: []\n";
const browser = await chromium.launch({ headless: true });
await mkdir(output, { recursive: true });
try {
  const page = await browser.newPage({ viewport: { width: 1440, height: 1000 } });
  const pageErrors = [];
  page.on("pageerror", error => pageErrors.push(error.message));
  if (process.argv.includes("--logo-metadata")) {
    const bytes = await readFile(new URL("assets/sluicegate-logo.png", source));
    const metadata = await page.evaluate(async url => {
      const image = new Image(); image.src = url; await image.decode();
      const canvas = document.createElement("canvas"); canvas.width = image.width; canvas.height = image.height;
      const context = canvas.getContext("2d"); context.drawImage(image, 0, 0);
      const pixels = context.getImageData(0, 0, image.width, image.height).data;
      return [1, 32, 128, 224].map(threshold => {
        let left = image.width, top = image.height, right = 0, bottom = 0, count = 0;
        for (let y = 0; y < image.height; y++) for (let x = 0; x < image.width; x++) {
          if (pixels[(y * image.width + x) * 4 + 3] < threshold) continue;
          left = Math.min(left, x); right = Math.max(right, x); top = Math.min(top, y); bottom = Math.max(bottom, y); count++;
        }
        return { threshold, left, top, right, bottom, count };
      });
    }, `data:image/png;base64,${bytes.toString("base64")}`);
    console.log("Logo alpha bounds:", JSON.stringify(metadata));
  }
  await page.route("http://branding.local/**", async route => {
    const path = new URL(route.request().url()).pathname;
    if (path === "/admin/ui") return route.fulfill({ contentType: "text/html", body: await readFile(new URL("admin.html", source)) });
    if (path.startsWith("/admin/assets/")) {
      const file = path.split("/").pop();
      return route.fulfill({ contentType: file.endsWith(".css") ? "text/css" : "image/png", body: await readFile(new URL(`assets/${file}`, source)) });
    }
    let body = [];
    if (path === "/admin/v1/missions") body = [request];
    else if (path === "/admin/v1/audit-events") body = { events: [event], next_before_id: null };
    else if (path === `/admin/v1/requests/${request.request_id}`) body = request;
    else if (path === "/admin/v1/policy") body = { content: policy, file_hash: "a".repeat(64), active_policy_hash: "a".repeat(64) };
    else if (path === "/admin/v1/policy/time-zones") body = ["UTC", "America/New_York"];
    else if (path === "/admin/v1/policy/templates") body = [{ id: "patching", name: "Patching Policy", description: "Windows patching and approval rules", editor_mode: "patching_wizard" }];
    else if (path === "/admin/v1/policy/templates/patching") body = { id: "patching", name: "Patching Policy", editor_mode: "patching_wizard" };
    return route.fulfill({ json: body });
  });
  await page.goto("http://branding.local/admin/ui");
  await page.locator("#missionsTableBody tr").filter({ hasText: request.request_id }).waitFor();
  const prefix = baseline ? "before" : "after";
  await page.screenshot({ path: `${output}/${prefix}-missions-desktop.png`, fullPage: true });
  for (const [tab, label] of [["policy", "policies"], ["minions", "registry"]]) {
    await page.locator(`.nav-tab[onclick="switchTab('${tab}')"]`).click();
    if (tab === "policy") await page.waitForFunction(() => document.getElementById("policyEditor").value.length > 0);
    await page.screenshot({ path: `${output}/${prefix}-${label}-desktop.png`, fullPage: true });
  }
  await page.evaluate(id => viewMissionDetail(id), request.request_id);
  await page.screenshot({ path: `${output}/${prefix}-inspect-desktop.png`, fullPage: true });
  await page.locator("#missionDetailModal").getByRole("button", { name: "Close", exact: true }).click();
  if (!baseline) {
    const logo = page.locator(".brand-logo");
    assert.ok(await logo.evaluate(image => image.complete && image.naturalWidth === 1024 && image.naturalHeight === 1536));
    assert.equal(await page.locator('link[rel="stylesheet"]').count(), 1);
    assert.equal(await page.locator(".nav-tabs [role='tab']").count(), 7);
    for (const width of [1440, 1024, 768, 390]) {
      await page.setViewportSize({ width, height: 900 });
      for (const tab of ["missions", "approvals", "agents", "minions", "notifications", "adapters", "policy"]) {
        await page.locator(`.nav-tab[onclick="switchTab('${tab}')"]`).click();
        assert.equal(await page.locator(`#tab-${tab}`).isVisible(), true);
        assert.equal(await page.locator(".nav-tab[aria-selected='true']").count(), 1);
        assert.ok(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth), `Page overflow: ${tab} at ${width}px`);
      }
      await page.locator(".nav-tab[onclick=\"switchTab('missions')\"]").click();
      await page.screenshot({ path: `${output}/after-missions-${width}.png`, fullPage: true });
    }
    const tab = page.locator(".nav-tab").first();
    await tab.focus();
    await page.keyboard.press("ArrowRight");
    assert.equal(await page.locator(".nav-tab[aria-selected='true']").innerText(), "Pending Approvals (0)");
    assert.ok(await page.locator(".nav-tab[aria-selected='true']").evaluate(element => element.matches(":focus-visible") && getComputedStyle(element).outlineStyle !== "none"));
    await page.setViewportSize({ width: 390, height: 480 });
    await page.locator(".nav-tab[onclick=\"switchTab('policy')\"]").click();
    await page.getByRole("button", { name: "Create New" }).click();
    await page.locator("#policyTemplateChoice").selectOption("patching");
    await page.locator("#policyTemplateContinue").click();
    await page.locator("#policyWizard").waitFor({ state: "visible" });
    assert.ok(await page.locator("#policyWizard").evaluate(element => element.getBoundingClientRect().height <= innerHeight));
    await page.screenshot({ path: `${output}/after-policy-dialog-phone.png` });
    await page.keyboard.press("Escape");
    assert.equal(await page.locator("#policyWizard").isVisible(), false);
    assert.ok(await page.evaluate(() => document.activeElement !== document.body));
    await page.evaluate(id => viewMissionDetail(id), request.request_id);
    assert.ok(await page.locator("#missionDetailModal .modal").evaluate(element => element.getBoundingClientRect().height <= innerHeight));
    const firstFocusable = await page.locator("#missionDetailModal").evaluate(modal => modalFocusables(modal)[0].outerHTML);
    await page.keyboard.press("Shift+Tab");
    assert.equal(await page.locator("#missionDetailModal").getByRole("button", { name: "Close", exact: true }).evaluate(button => button === document.activeElement), true);
    await page.keyboard.press("Tab");
    assert.equal(await page.evaluate(() => document.activeElement.outerHTML), firstFocusable);
    await page.keyboard.press("Escape");
    assert.equal(await page.locator("#missionDetailModal").isVisible(), false);
    await page.emulateMedia({ reducedMotion: "reduce" });
    await page.locator(".nav-tab").first().focus();
    assert.equal(await page.locator(".nav-tab").first().evaluate(element => getComputedStyle(element).transitionDuration), "0s");
    // Check rendered component contrast rather than asserting CSS declarations.
    const contrast = await page.evaluate(() => {
      const samples = document.createElement("div");
      samples.className = "card";
      samples.innerHTML = '<span class="muted">Help text</span><span class="badge badge-info">Queued</span><span class="badge badge-success">Healthy</span><span class="badge badge-warning">Pending approval</span><span class="badge badge-danger">Failed</span><button>Save</button><button class="secondary">Cancel</button><button class="danger">Delete</button><input aria-label="Contrast sample" value="Value" /><textarea class="policy-editor" aria-label="YAML contrast sample">version: 1</textarea>';
      document.body.append(samples);
      const rgb = color => color.match(/[\d.]+/g).slice(0, 3).map(Number);
      const luminance = color => rgb(color).map(value => value / 255).map(value => value <= 0.04045 ? value / 12.92 : ((value + 0.055) / 1.055) ** 2.4).reduce((sum, value, index) => sum + value * [0.2126, 0.7152, 0.0722][index], 0);
      const ratio = (first, second) => { const a = luminance(first), b = luminance(second); return (Math.max(a, b) + 0.05) / (Math.min(a, b) + 0.05); };
      const results = [...samples.children].map(element => {
        const style = getComputedStyle(element);
        const background = style.backgroundColor === "rgba(0, 0, 0, 0)" ? getComputedStyle(samples).backgroundColor : style.backgroundColor;
        return { label: element.textContent || element.value, ratio: ratio(style.color, background) };
      });
      for (const control of samples.querySelectorAll("input, textarea")) {
        const style = getComputedStyle(control);
        results.push({ label: `${control.tagName} border`, ratio: ratio(style.borderColor, style.backgroundColor), minimum: 3 });
      }
      const focus = getComputedStyle(document.querySelector(".nav-tab:focus-visible"));
      results.push({ label: "Focus indicator", ratio: ratio(focus.outlineColor, getComputedStyle(document.body).backgroundColor), minimum: 3 });
      samples.remove();
      return results;
    });
    for (const sample of contrast) assert.ok(sample.ratio >= (sample.minimum || 4.5), `${sample.label} contrast: ${sample.ratio.toFixed(2)}`);
    console.log("CONTRAST:", contrast.map(sample => `${sample.label} ${sample.ratio.toFixed(2)}:1`).join(", "));
    await page.setViewportSize({ width: 768, height: 800 });
    await page.addStyleTag({ content: 'body { font-size: 18px; } button.nav-tab { font-size: 17px; } table { font-size: 17px; } .card-header h2 { font-size: 24px; }' });
    assert.ok(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth), "Page overflow with enlarged text");
    await page.screenshot({ path: `${output}/after-enlarged-text.png`, fullPage: true });
    assert.deepEqual(pageErrors, []);
  }
  console.log(`${prefix.toUpperCase()}: branding screenshots saved to ${output}`);
} finally {
  await browser.close();
}
