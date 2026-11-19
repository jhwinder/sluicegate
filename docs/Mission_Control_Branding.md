# Mission Control Branding

The administrative app uses a light monochrome theme with SluiceGate blue and green accents. Its presentation assets are packaged with `sg-service`; no frontend build step, external fonts, or CDN is required.

| File | Purpose |
| --- | --- |
| `sg-service/src/sg_service/static/admin.html` | App markup and existing interaction logic. |
| `sg-service/src/sg_service/static/assets/mission-control.css` | Design tokens, shared components, utilities, and responsive rules. |
| `sg-service/src/sg_service/static/assets/sluicegate-logo.png` | Original supplied logo, copied without changing image data. |

The service mounts only the asset directory at `/admin/assets/`. Styles and artwork are public like the admin HTML; administrative data and action APIs retain their authentication. Security headers also apply to asset responses. Installed wheels and container images serve the assets using package-relative paths.

## Logo

The runtime PNG is the supplied 1024 × 1536 transparent image. It has SHA-256:

```text
441c6404a6fc0efe5ee017f4a750de4297ffe3a3d7b98715f4fb33444863c30f
```

The original canvas contains extensive transparent space and a few nearly transparent pixels outside the artwork. `.brand-mark` provides a proportional CSS viewport around source coordinates `x=256, y=551, width=488, height=366`, retaining the complete visible lettering and gate graphic. The PNG is neither cropped nor re-encoded. The visible mark is approximately 78 px tall on desktop and 52 px on phones. The adjacent text heading supplies the accessible product name, so the redundant image has empty alternative text.

The repository asset is self-contained; the app never refers to the original Desktop location. If replacing the artwork later, inspect its visible bounds and adjust the framing rather than assuming a replacement has identical padding.

## Styles and Behavior

The `:root` tokens define surface, text, border, accent, status, spacing, and control styles. Ordinary buttons use charcoal or neutral surfaces. Active tabs and focus use blue; success/health use subdued green. Warnings and destructive actions retain restrained amber/red treatments with explicit status text.

Presentation belongs in the stylesheet, including generated table-row markup. Visibility uses `hidden`, with one deliberate `[hidden]` override to prevent layout classes from revealing hidden elements. Reduced-motion overrides suppress optional transitions. Avoid introducing inline presentation styles or broad selector overrides that interfere with either behavior.

Tabs use native buttons and a roving keyboard focus: Left/Right moves between tabs, Home/End selects the first/last tab, and the selected button exposes `aria-selected`. Custom modals isolate background content, keep Tab focus within the open dialog, close on Escape, and restore focus. Native dialogs use their browser-managed modal behavior with opener restoration. Inspect initially focuses its heading while request data loads, so late-arriving details do not move keyboard focus unexpectedly.

Wide tables and code blocks scroll within their own regions. Layout rules adapt the header, token controls, navigation, filter forms, actions, and dialogs to narrow or short viewports. The same stylesheet covers all seven tabs, the policy wizard, template selector, registries, and Inspect.

## Validation and Previews

```sh
uv run --locked --package sg-service --group dev pytest -q -rs sg-service/tests
node sluice-demo/tests/e2e/branding.mjs
bash sluice-demo/tests/e2e/run.sh
bash sg-service/tests/integration/run.sh
uv build --package sg-service
```

The branding browser check uses deterministic presentation fixtures, with real workflows covered separately by the two Compose suites. It checks all tabs at 1440, 1024, 768, and 390 px widths, short dialogs, enlarged text, keyboard navigation, focus trapping/return, reduced motion, and rendered contrast. Screenshots default to `/tmp/sluicegate-branding-review`; override this with `SG_BRANDING_ARTIFACTS_DIR`.

CI runs the branding check and uploads its screenshots as the `mission-control-branding` artifact. Runtime inspection in both Compose suites verifies that the installed wheel includes the CSS/logo and that the running image serves both with correct MIME types. Unit tests also verify asset availability, authentication boundaries, and path-traversal rejection.
