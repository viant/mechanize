# Mechanize Computer API

An initial Node.js adapter for the target-oriented interaction pattern exposed
by Codex Computer Use. This is a Mechanize SDK, not an OpenAI SDK or a complete
implementation of Codex's private runtime API.

Pass an already authenticated MCP `callTool(name, arguments)` function. The
adapter does not read, store, or return MCP tokens or Vault credentials.

```js
import { createComputer } from './index.mjs';
const computer = await createComputer({ callTool, grantId, purpose: 'Compose a public test message' });
const inventory = await computer.listTabs({ origin: 'http://localhost:3000' });
const tab = await computer.getTab({ origin: 'http://localhost:3000', tabId: inventory.tabs[0].handle });
await tab.getAXState();
await tab.playwright.getByTestId('chat-composer-input').fill('Public test', {
  businessKey: { test: 'public-message-1' },
  // Supply a Mechanize predicate and its required adapters to verify outcome.
  postcondition, adapters: ['web'],
});
await tab.getAXState();
await computer.close();
```

Native `getApp` takes the exact bundle/PID/birth identity from Mechanize window
inventory and an optional physical window ID. `getAXState()` returns concise
indexed role/name/state metadata. `click(index)` and `setValue(index, text)`
require a unique named control from the most recent state. Refresh state after
input; duplicate names require an explicit locator instead of guessing.

Supported target methods: `getAXState`, `getScreenshot` (native),
`getClickScreenshot` (native), `click`, `setValue`, `pressKey` (native), `activate`,
`goto` (same-origin web), `getByRole`, and `getByTestId`. Locator methods are
`click` and `fill`. Native coordinate clicks require a fresh one-use frame
capture and integer **original image pixels**; display previews must be mapped
using returned dimensions. Ordinary screenshots do not authorize clicking.

Each action requires public string business keys. Existing consent, identity,
Vault and durable-effect checks stay in the broker. Default action timeout is
3 seconds. The adapter polls the same operation for bounded completion, never
replays unknown input, and returns operation/run handles when reconciliation is
needed. Successful execution alone does not prove the business objective.

Unsupported API methods (arbitrary evaluation, clipboard credential transfer,
scroll, uploads/downloads, new-tab creation, nested locators) are not simulated.
Private login stays in Mechanize's credential prepare/status/apply/submit flow.

Run `node --test sdk/computer/index.test.mjs` from the repository root.

## Comparing automation loops

Pass `onTiming(event)` to record `{tool, elapsedMs, outcome}` for each MCP call.
Events contain no arguments, page content, result bodies, or raw errors. A timing
callback failure cannot alter execution. Capture/screenshot calls currently
return original MCP content directly and are not included in this callback.

Use the same Chrome profile, visible test page, viewport, and public fixture
for both providers. Measure separately: target selection, state read, composer
fill, verified value, Send, and returned tool result. Record end-to-end elapsed
time and number of calls; do not compare backend input time with the other
provider's complete observation/action loop. A missing connector, protection
barrier, or approval is a recorded blocker, not an action latency result.

Verify each result before the next action. Reset only the disposable test page
between providers. Never replay a failed Send unless it is proven not dispatched.
Login secrets and payment submissions are excluded from the initial comparison.
