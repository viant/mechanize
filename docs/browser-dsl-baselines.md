# Browser DSL baselines and surface-aware roadmap

Date: 2026-10-02

This note compares the installed Endly WebDriver contract, the Codex native browser MCP contract inspected for this design, and Mechanize's implemented browser path. These are different execution environments. The Codex contract is a design baseline; it does not qualify Mechanize runtime behavior or authorize using Codex to execute Mechanize workflows.

## Baselines

| Concern | Endly WebDriver (installed source) | Codex native browser MCP contract | Mechanize today / direction |
| --- | --- | --- | --- |
| Lifecycle and tabs | `start`, `stop`, `open`, `close`; `call-driver`/`call-element`; `run`; `stop-loading`. Driver calls include tab enumeration/switch/new/close in `tabs.go`. | Browser exposes tabs list/get/new/selected and user-owned open-tab claim; session naming. Tab supports goto/back/forward/reload/close plus title/url. | Chrome extension inventories enrolled tabs/documents and pins an exact root document authority. Lifecycle, arbitrary tab selection and navigation are not exposed through the current shared DSL. Add web-specific browser/tab scope operations only with enrolled-profile and ownership rules. |
| Locate and observe | Selenium selectors (CSS/XPath/etc.), Playwright-inspired `page.getBy*`/`locator`; strict locators and waits; legacy command behavior can be first-match. DOM text/attributes and expectation commands. | Playwright-style `domSnapshot`, `frameLocator`, `getByRole/Label/Text/Placeholder/TestId`, `locator`; locator composition/filtering, `count`/`all`/`nth`; read-only `evaluate`. | Shared IR has role/id/name/text/label/testId, ancestry and bounded plural queries. The live Chrome control gateway currently qualifies only exact role/id/testId/label root-frame targeting; snapshot/read paths have other readiness gates. Capability checks must be tied to the active provider, not registry declarations. |
| Actions | Selenium method proxy plus Playwright `click`, `fill`, `check`, `uncheck`, `selectOption`, key/text actions. Optional JS click fallback is explicitly opt-in in Endly. | Locator click/double-click/fill/type/press/pressSequentially/check/uncheck/setChecked/selectOption; reads include attribute/text/count. `evaluate` is read-only. | Shared action registry has activate/open, press/submit/fill/check/uncheck/select/pressKey/read/expect. The production web mutation gate presently permits only `element.press` and `element.fill`. Other actions are declarations, not evidence of web support. Never reinterpret read-only evaluate as a DOM mutation escape hatch. |
| Waiting and navigation | `webdriver:run` supports bounded command waits/repeats; goto navigation guards; `waitForResponse`, visibility waits, URL/title/text assertions and load strategies. `stop-loading` can interrupt Chrome loads. | `waitForURL`, load state/navigation, download and file chooser waits; locator `waitFor`. | Step timeout and observation polling exist. Full web navigation/download/file-chooser/network-wait vocabulary is not implemented as browser DSL. Add typed web-only actions with bounded deadlines and explicit evidence. Endly owns workflow loops/conditions; do not create a second workflow scheduler. |
| Frames and native browser UI | Frame switching exists; WebDriver session owns the browser instance. | Frame locators target page frames. Browser tab/file chooser/download/dialog APIs are explicit. | Chrome extension inventories frame/document identities, while current control rejects non-root frames. Browser DOM operations cannot control browser chrome, OS dialogs, or native menus; route those to native surface APIs after qualification. |
| Capture and diagnostics | `capture-start/stop/status/clear/export` capture bounded console/network data for Chrome/Edge; screenshots and navigation reports are supported. | Full-page/clip screenshots, dialogs, clipboard, dev logs, export and artifact retention/handoff/delivery. | Chrome event recording and screenshot/artifact services exist in parts of the system; these are distinct capabilities and not all are attached to an executable DSL action. Add only after their provider advertises and qualifies the specific capability. |
| Safety and identity | Endly owns sessions/workflows and can clean up. Strict Playwright selectors help; compatibility syntax has looser matching. | User-open tab claim and artifact handoff make ownership explicit; locator refs are scoped to a tab/page context. | Web mutations require enrolled origin, verified browser/native-host/renderer authority, fresh document identity/generation, exact locator, durable intent and reconciliation. Preserve those controls across every new verb. |

Installed-source anchors: `/Users/awitas/go/src/github.com/viant/endly/skills/endly-webdriver/SKILL.md` and `references/service.md`; `service/testing/runner/webdriver/service.go`, `contract.go`, `tabs.go`, `interactions.go`, `README.md`. Endly's source-declared service actions are start/stop/open/close/run/call-driver/call-element/stop-loading and capture-start/stop/status/clear/export. The README's richer Playwright-inspired command syntax is implemented through `run`, not a separate MCP method per locator operation.

Codex native-browser baseline was inspected from the initialized `cua.getBrowser` API contract, including Browser, Tab, Locator, NativeTarget and artifact methods. This is a reference contract only; it is not an implementation dependency or test result for Mechanize.

## Mechanize status and compatibility rule

Implemented shared front end: `script/compiler.go`, `script/registry.go`, `script/schema.go`, `script/grammar.md`, and `model/action.go` define a closed typed DSL/IR, shared surface selectors, locator methods, strict cardinality, actions, assertions, and explicit capability checks. The web extension has typed protocol validation in `extension/chrome/protocol.js`, DOM querying in `extension/chrome/dom.js`, and host admission/execution in `host/web_control.go` / `backend/chrome`. The current control provider reports only press/fill and role/id/testId/label as mutation readiness.

Status must be reported in three categories:

1. **Implemented and qualified:** present in the active adapter and advertised by its current capability response, including required identity/authority checks.
2. **Implemented but unqualified:** code/contracts exist, but no active adapter qualification or release evidence supports exposing it as available.
3. **Planned:** absent from the executable path. It must fail validation as unsupported, rather than compile into a silent fallback.

`Registry.CheckCapabilities` is an explicit gate, but a general static capability map is insufficient by itself: runtime qualification must bind capabilities to the selected surface, provider, frame and document generation. The current web path is intentionally narrower than either baseline. Existing syntax such as a `frame(...)`, `submit`, `select`, `pressKey`, plural query, or `read` does not establish that a live Chrome adapter can execute it.

## Proposed DSL shape

Keep shared concepts in the typed core: surface identity, locator strategy, strict cardinality, typed values, bounded timeout, effect class, pre/postcondition, durable attempt and evidence references. Put browser-specific operations/options under a web namespace or web-targeted action definitions, with capability requirements in the schema. Examples below are roadmap syntax, not currently executable contracts:

```text
let page = web.tab(origin: "https://crm.example", id: "tab-ref")
page.goto(url: "https://crm.example/cases", waitUntil: "domContentLoaded", timeout: 15s)
let save = page.getByRole("button", name: "Save", exact: true)
save.click(timeout: 5s)
page.expect(save).toBeEnabled(timeout: 5s)
let frame = page.frame(locator: {strategy: "title", value: "Details"})
frame.getByLabel("Status", exact: true).select(value: "Approved")
```

Surface-specific items include tab selection/claim, navigation and wait condition, frame targeting, download/file chooser, browser dialog, screenshot mode, and console/network event capture. Their options belong to that operation (`waitUntil`, `fullPage`, response predicate), not a universal bag of untyped arguments. Common timeout remains typed and bounded. Unsupported option names and cross-surface calls fail before input. A native `app(...)` target cannot invoke `page.goto`; a web target cannot invoke macOS window control.

Use the same Observe → Act → Verify loop across surfaces, but keep evidence native to the surface. Browser locators must resolve freshly against the same tab/frame/document generation immediately before action; stale targets trigger a new observation and replanning, never silent target substitution. Use exact-one matching by default. `all`/`nth` require bounded complete ordered results. Return compact observations with stable semantic fields, capability failures with actionable reasons, and post-action assertions. Browser navigation readiness must use explicit bounded conditions rather than fixed sleeps.

Do not import either baseline's broad method proxy into the shared IR. A closed action/option registry preserves cross-surface validation, known effects, discoverability and LLM generation quality. Keep recovery, repeat/forEach, named subflows and schedules in Endly workflow definitions. Mechanize may compile bounded low-level action sequences to Endly, but must not duplicate its scheduler.

## Delivery sequence and qualification gates

1. **Capability truth first:** make `doctor`/surface readiness return qualified actions, locators, waits, frames, capture and ownership semantics per provider. Reject unsupported action, locator, option and scope combinations before dispatch. Add contract tests against actual provider capabilities.
2. **Read-only browser loop:** qualify tab identity, bounded DOM snapshots, semantic locators, count/text/value/attribute reads, URL/title and visible/enabled assertions. Confirm truncation/ordering metadata, frame scoping, and stale-generation rejection.
3. **Core mutations:** incrementally qualify click/fill/check/select/key actions with exact-one target resolution, effect classification, durable intent, pinned renderer authority, postcondition evidence and timeout/reconciliation behavior. Keep each action absent from advertised capability until its full gate passes.
4. **Browser lifecycle and waits:** add explicit tab claim/navigation/back/forward/reload and URL/load-state/response waits. Verify browser ownership, origin scope, deadlines, stop-loading and interruption behavior. Navigation that can commit an external effect must carry effect/reconciliation metadata.
5. **Advanced surface features:** add frames, downloads, file choosers, dialogs, screenshots, console/network capture and artifact handoff one capability at a time. Preserve root-frame restrictions until frame identities, origins and execution authority are independently qualified.
6. **Cross-surface workflow:** qualify explicit transitions between native browser chrome/OS dialogs and web content. Keep each step's surface and capability requirements in the plan; re-observe after focus or document changes. Run only against disposable fixtures and record the exact tested browser/provider cohort.

Release evidence must distinguish compiler acceptance, adapter implementation, active capability qualification and end-to-end verification. Passing parser tests or matching Codex/Endly vocabulary is not runtime parity. Do not claim an operation is supported until the provider advertises it and its surface-specific qualification and recovery gates pass.
