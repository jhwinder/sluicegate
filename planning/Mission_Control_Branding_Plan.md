# Mission Control Branding and Stylesheet Plan

**Status:** COMPLETE — implemented and locally validated on `CSS`.
**Branch:** `CSS`
**Related backlog item:** [Backlog 1.11](Backlog.md)
**Scope:** The `sg-service` Mission Control administrative app, including all tabs and dialogs.
**Checklist:** 22 of 22 items complete.

## Implementation Results

- Added the packaged `mission-control.css` stylesheet and the original supplied PNG at `/admin/assets/`, with matching wheel/container delivery and no external asset dependencies.
- Applied the light monochrome theme across all seven tabs, tables, forms, badges, policy tools, and both dialog types. The header uses the complete logo mark with CSS framing; its PNG bytes are unchanged.
- Added keyboard-operable tabs, visible focus, modal focus containment/return, consistent field labels, responsive table/code scrolling, and reduced-motion support. Inspect preserves focus while its request details load.
- Validation: **137 application tests passed**, both isolated DEMO/TEST browser suites passed, the service distribution built successfully, and final wheel assets matched the workspace byte for byte. Running container checks verified asset MIME types and existing authentication boundaries.
- Branding browser checks passed at 1440, 1024, 768, and 390 px widths, with a short viewport and enlarged text. Rendered text contrast measured **5.18:1–17.31:1**, control boundaries **3.48:1–3.76:1**, and the focus indicator **4.29:1**.
- Before/after screenshots are available locally under `/tmp/sluicegate-branding-review`. CI now produces and uploads branding previews. See [Mission Control Branding](../docs/Mission_Control_Branding.md) for maintenance and validation details.
- Existing user containers were not redeployed. Rebuild/recreate the service container to apply these source changes to a running installation.

## 1. Visual Direction

Create a clean, predominantly monochrome interface: off-white page background, white surfaces, charcoal text, light gray borders, and restrained shadows. Use the supplied SluiceGate logo as the main brand element in the header. Draw small blue and green accents from the logo for focus, selection, and successful outcomes.

The proposed baseline is a light theme. Favor clear typography, consistent spacing, and readable operational data over large decorative panels. Preserve the existing information hierarchy and workflows while making their presentation consistent.

### Proposed palette

These are starting design tokens inspired by the logo, not sampled or finalized brand specifications. Confirm them against the image and actual UI during implementation.

| Role | Initial value | Intended use |
| --- | --- | --- |
| Page | `#F6F7F8` | App background. |
| Surface | `#FFFFFF` | Cards, dialogs, inputs. |
| Surface subtle | `#F0F2F4` | Table headings, neutral badges, secondary controls. |
| Text | `#171B1F` | Headings, body text, table values. |
| Muted text | `#59636D` | Descriptions, timestamps, secondary labels. |
| Border | `#D8DDE2` | Structural dividers and surface borders; interactive controls may need a stronger border. |
| Primary action | `#252B31` | Main buttons with white text; slightly lighter charcoal on hover. |
| Brand navy | `#172B63` | Small header details or selected labels. |
| Brand blue | `#087FA1` | Focus rings, active-tab indicator, selected control accents. |
| Brand green | `#4F701F` | Restrained success/healthy indicators with pale neutral or green-tinted backgrounds. |

Keep ordinary buttons and informational badges neutral. Limit the blue/green splash to the logo and a few purposeful UI indicators. Preserve small, muted amber/red treatments where warnings, validation failures, or destructive actions need distinct meaning; do not make every status or card colorful. Always retain status text, so meaning remains clear without color.

## 2. Baseline Application Findings

| Area | Current implementation | Planned treatment |
| --- | --- | --- |
| Stylesheet | `sg-service/src/sg_service/static/admin.html` contains the main `<style>` block, many inline presentation styles, and styles inside generated markup. | Move presentation into a reusable stylesheet with tokens, component rules, and a small set of layout utilities. |
| Header | Text title, version badge, subtitle, and a single-row bearer-token toolbar. | Add the logo beside the existing product title; make the identity and token controls wrap cleanly. |
| Navigation | Seven tabs rendered as clickable `div` elements. | Keep all tab names and views; add consistent active/focus treatments and keyboard-operable tab controls if markup needs adjustment. |
| Tables and forms | Full-width tables, mixed inline action layouts, fixed control widths. | Standardize spacing and control heights, contain wide tables, and improve narrow-screen behavior. |
| Inspect and policy dialogs | Both custom modal backdrops and native `<dialog>` elements use `.modal`. JSON has a dark background and bright cyan text. | Style both modal mechanisms consistently while respecting their different open/closed behavior; use readable neutral code surfaces. |
| Runtime visibility | JavaScript changes `style.display`, `hidden`, and `disabled` for tabs, dialogs, adapter fields, and pagination. | Separate visibility behavior from decorative/layout rules so CSS extraction does not reveal hidden UI or prevent it opening. |
| Asset delivery | `/admin/ui` returns an HTML file; no dedicated admin static-asset route is currently defined. | Serve the stylesheet and logo locally from a narrowly scoped asset directory. |
| Packaging and tests | The service wheel packages `src/sg_service`; browser tests locate current headings, IDs, tabs, and controls. | Verify packaged assets in wheels/images and retain stable selectors or deliberately update tests when semantic markup improves. |

## 3. Logo and Header Plan

Source artwork: `/Users/jhwinder/Desktop/SluiceGate/SluiceGate_Logo_Transparent.png`.

The supplied PNG is **1024 × 1536**, approximately **2 MB**, and has an alpha channel. The visible mark occupies a smaller central area of a tall canvas. An alpha channel alone does not establish that every surrounding pixel is fully transparent; inspect the actual visible bounds and glow on the chosen header background before deciding how to frame it.

- [x] Preserve the supplied artwork as the source of truth. Bring a repository-owned copy into the project during implementation so the app never depends on a Desktop path.
- [x] Inspect transparency, visible bounds, and small-size legibility on white and off-white. Determine a tight framing that retains the complete lettering, gate graphic, and intended glow.
- [x] Prepare an optimized header asset if needed, keeping the original proportions and artwork. Do not stretch, recolor, redraw, or replace the logo as part of this work.
- [x] Put the logo to the left of **SluiceGate Mission Control**, with the version and **Administrative Console & Decision Ledger** as secondary information. Keep the text title available even if the image fails to load.
- [x] Start with a framed logo around 64–80 CSS pixels high on desktop and 48–56 pixels on narrow screens, then adjust after previewing the stacked wordmark. These dimensions apply to the visible mark rather than the original padded canvas.
- [x] Keep the header compact enough that Missions & Audit remains visible without a large branding banner. Do not apply additional glow or gradients to the surrounding interface.
- [x] Give the image explicit dimensions/aspect ratio to reserve space. Use suitable alternative text, avoiding redundant announcement when adjacent text already supplies the brand name.
- [x] Keep token entry and its Save/Reload actions readable and usable. On narrower screens, move the toolbar below the identity instead of squeezing or overlapping it.

## 4. Stylesheet Structure and Asset Delivery

Proposed runtime layout:

```text
sg-service/src/sg_service/static/
  admin.html
  assets/
    mission-control.css
    sluicegate-logo.png
```

Keep the complete source image in a repository branding/source location if a separate optimized header asset is produced. The deliverable app should use only the asset it needs.

- [x] Add a local asset route, proposed as `/admin/assets/`, that serves only the dedicated packaged asset directory. Resolve paths using the installed package location so source, wheel, and container runs behave consistently.
- [x] Link the stylesheet and logo using stable app URLs. Keep them available wherever the existing admin HTML is available, while preserving authentication on all administrative data and action APIs.
- [x] Keep fonts, styles, and images local. Use the existing system sans-serif stack and a system monospace stack for IDs, YAML, hashes, and JSON; no CDN or new UI framework is needed.
- [x] Organize the stylesheet into tokens; base typography; shell/header/navigation; cards/tables/forms/buttons; badges/feedback; dialogs/code views; layout utilities; and responsive rules.
- [x] Use semantic token names for colors, spacing, border radii, shadows, control heights, and focus styles. Consolidate repeated inline presentation rules into shared classes, including markup created by JavaScript.
- [x] Retain intentional behavior-controlled visibility, or migrate it consistently to `hidden`/state classes. Do not indiscriminately remove inline styles or use broad `!important` overrides.
- [x] Preserve the service's existing security headers and asset MIME handling. Check stylesheet/logo URLs directly in the built container; normal page reloads should retrieve the current assets.

## 5. Component Styling Plan

| Component | Planned appearance and behavior |
| --- | --- |
| App shell | Balanced page gutters and a consistent spacing scale, with room for wide operational tables. Avoid a narrow marketing-page width constraint. |
| Typography | Product title around 22–26 px, section titles around 17–19 px, controls/body text around 14 px, secondary table text no smaller than needed for comfortable reading. Prefer font weight and spacing over extra colors. |
| Navigation | Quiet neutral tabs with a strong selected label and a thin blue indicator. Wrap or scroll the tab strip within its own region on narrow screens; keep the selected tab recognizable without color alone. |
| Cards | White background, fine gray border, modest radius, minimal shadow, consistent heading/action alignment. |
| Tables | Subtle heading fill, clear row separators, restrained hover treatment, aligned action groups, and contained horizontal scrolling when columns cannot fit. Preserve all data columns. |
| Buttons | Charcoal primary actions; neutral secondary controls; restrained destructive treatment. Define hover, active, focus-visible, loading, and disabled states without shifting layout. |
| Forms | Consistent label placement, control heights, border/focus treatment, descriptions, checkbox spacing, and validation feedback. Allow long labels and values to wrap or scroll appropriately. |
| Status badges | Mostly neutral with explicit status text. Use subdued blue/green only for meaningful states, and small amber/red exceptions for warnings/failures. Avoid bright backgrounds on every badge. |
| Inspect | Readable label/value summaries, clear separation of submitted input from current state and historical events, and unobtrusive expandable JSON/envelope sections. |
| YAML/JSON | Neutral text and backgrounds, visible focus, comfortable line height, preserved whitespace, and local scrolling for long lines. Remove the bright cyan-on-dark styling as the default. |
| Dialogs | Consistent surface, title spacing, footer actions, backdrop, and internal scrolling. Keep the close/cancel controls accessible in a short viewport. |
| Feedback | Consistent loading, empty, success, warning, and error presentation. Preserve the text that explains policy validation, draft replacement, and activation outcomes. |

## 6. Responsive and Accessibility Work

- [x] Validate representative layouts at 1440 px desktop, 1024 px laptop/tablet, 768 px tablet, and 390 px phone widths, plus a short viewport and enlarged text.
- [x] Let header controls, card actions, and filter forms wrap. Restrict necessary horizontal scrolling to tables or code blocks rather than the entire page.
- [x] Measure contrast for text, controls, focus indicators, and badges against their actual backgrounds. Design targets: at least 4.5:1 for normal text and 3:1 for large text and key control boundaries/focus indicators; adjust provisional palette values where necessary.
- [x] Add a visible `:focus-visible` treatment. Use native buttons for clickable tab controls if needed and provide keyboard selection/selected-state semantics without changing which view opens.
- [x] Retain clear labels, readable status text, and sufficient hit areas. Verify disabled controls remain distinguishable and cannot be confused with active ones.
- [x] Respect reduced-motion preferences if transitions are used. Keep animation subtle and optional.
- [x] Check native `<dialog>` and custom modal behavior independently. Preserve existing cancel/confirm workflows; verify focus placement and return when a dialog opens/closes.

## 7. Implementation Sequence

1. Capture baseline screenshots of Missions & Audit, Policies, a registry view, and Inspect; record existing interactions and selectors used by tests.
2. Confirm the logo's header framing and the neutral/blue/green palette in a desktop preview. Keep the provided artwork intact.
3. Add packaged asset delivery and extract the current styles into the new stylesheet without changing behavior.
4. Apply the design tokens and style the header, navigation, and shared components. Replace repeated presentation styles in static and generated markup.
5. Complete the remaining tabs, forms, code panels, and both types of dialogs; add responsive and keyboard/focus improvements.
6. Run focused verification, review screenshots across the target sizes, and document the stylesheet/asset locations. Check off completed tasks only after their implementation and checks are done.

## 8. Acceptance and Validation

| Check | Expected evidence |
| --- | --- |
| Branding | Supplied logo appears clearly in the header with correct proportions, no clipping, no large unused image canvas, and no Desktop-path dependency. |
| Visual consistency | All seven tabs and their dialogs share the same neutral palette, typography, spacing, controls, and restrained blue/green accents. |
| Readability | Missions, audit events, policy YAML, request parameters, amounts/currencies, status labels, and errors remain easy to read. |
| Responsive layout | Header and actions remain usable at the target widths; long tables/JSON scroll within their own regions; dialogs fit short viewports. |
| Interaction | Navigation, Inspect, approval/rejection, credentials, registry editing, template selection, YAML import/export, validation, and Save and Activate retain their behavior. |
| Accessibility | Keyboard focus is visible, tab controls are operable, selected state is clear, logo text is accessible, and measured contrast meets the stated targets. |
| Packaging | Installed wheels and the final service image serve the CSS/logo with the correct content types; no external network asset requests or missing-file errors occur. |
| Regression checks | Existing app and DEMO/TEST browser suites pass, with selectors updated only where justified by improved markup. Screenshots document the changed views. |

During implementation, extend focused API checks for asset availability/MIME types and browser checks for logo loading, visible focus, and responsive overflow. Reuse existing behavioral coverage rather than adding tests that merely assert CSS declaration strings.

```sh
uv run --locked --package sg-service --group dev pytest -q -rs sg-service/tests
bash sluice-demo/tests/e2e/run.sh
bash sg-service/tests/integration/run.sh
uv build --package sg-service
```

Asset availability was verified from both the built wheel and running containers, in addition to the source-checkout browser previews. The browser previews use deterministic presentation fixtures; the separate DEMO and TEST suites exercise the real service workflows.

## 9. Scope Boundaries

This plan covers Mission Control branding and presentation. It preserves policy decisions, request data, APIs, authentication, release management, and confirmation semantics. The separate customer-facing demo frontend, email templates, and older policy editor are outside this styling pass. A dark theme, user theme switcher, new icon system, redesigned logo, JavaScript framework migration, and navigation restructuring can be considered separately if requested.

Implementation is complete. The supplied image remains unchanged; the app stylesheet and header now follow this plan. Changes remain on `CSS` for review.
