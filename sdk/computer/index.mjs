import { randomUUID } from 'node:crypto';
const scalar = string => ({ kind: 'string', string });
const purposeDefault = 'Operate the selected application';
function unwrap(result) {
  if (result?.isError) throw new Error('Mechanize request refused');
  if (result?.structuredContent) return result.structuredContent;
  const block = result?.content?.find(item => item.type === 'text');
  if (!block) throw new Error('Mechanize result unavailable');
  return JSON.parse(block.text);
}
/** API-shape adapter over an existing authenticated MCP client. No token handling. */
export async function createComputer({ callTool, grantId, purpose = purposeDefault, timeoutMs = 3000, onTiming }) {
  if (typeof callTool !== 'function' || !Number.isInteger(timeoutMs) || timeoutMs < 100 || timeoutMs > 9000) throw new Error('Invalid computer configuration');
  const call = async (name, args) => {
    const started = performance.now();
    let outcome = 'failed';
    try { const result = unwrap(await callTool(name, args)); outcome = 'returned'; return result; }
    finally {
      // Only tool name, elapsed time and closed outcome. Never arguments,
      // targets, result bodies, credentials, or raw exception text.
      try { onTiming?.({ tool: name, elapsedMs: Math.round(performance.now() - started), outcome }); } catch { /* telemetry cannot own execution */ }
    }
  };
  const { sessionId } = await call('mechanize_session_open', { name: 'Computer API' });
  const base = { sessionId, grantId, purpose };
  let closed = false;
  const check = () => { if (closed) throw new Error('Computer session closed'); };
  const request = async (name, args) => { check(); return call(name, { ...(name === 'mechanize_operation_status' ? { sessionId } : base), ...args }); };
  class Target {
    constructor(surface, windowId) { this.surface = Object.freeze({ ...surface }); this.windowId = windowId; this.nodes = undefined; this.playwright = this; }
    async getAXState() {
      const state = await request('mechanize_observe', { surface: this.surface });
      this.nodes = state.nodes;
      return { nodes: state.nodes.map((n, index) => ({ index, role: n.role, name: n.name, enabled: n.enabled, focused: n.focused })), truncated: state.truncated, epoch: state.epoch };
    }
    async getScreenshot() {
      if (this.surface.kind !== 'native' || !this.windowId) throw new Error('Exact native window required for screenshot');
      check();
      return callTool('mechanize_capture', { ...base, surface: this.surface, pid: this.surface.processId, windowId: this.windowId });
    }
    getByRole(role, { name, exact = true } = {}) {
      return new Locator(this, { strategy: 'role', value: scalar(role), ...(name !== undefined ? { name: scalar(name) } : {}), exact });
    }
    getByTestId(id) { return new Locator(this, { strategy: 'testId', value: scalar(id), exact: true }); }
    async click(index, options) {
      if (Array.isArray(index)) {
        const frame = this.frame; this.frame = undefined;
        if (!frame || index.length !== 2 || !index.every(Number.isInteger)) throw new Error('Fresh screenshot coordinates required');
        const [x, y] = index;
        if (x < 0 || y < 0 || x >= frame.metadata.widthPixels || y >= frame.metadata.heightPixels) throw new Error('Screenshot coordinates out of bounds');
        return this.command(`target.clickWindowFrame(captureRef:${JSON.stringify(frame.captureRef)},x:${x},y:${y})`, options);
      }
      return this.indexLocator(index).click(options);
    }
    async getClickScreenshot() {
      if (this.surface.kind !== 'native' || !this.windowId) throw new Error('Exact native window required for screenshot');
      check();
      const result = await callTool('mechanize_capture_window_frame', { ...base, surface: this.surface, pid: this.surface.processId, windowId: this.windowId });
      this.frame = unwrap(result);
      return result;
    }
    async pressKey(key, options) {
      if (this.surface.kind !== 'native' || !this.windowId || typeof key !== 'string') throw new Error('Exact native window and key required');
      return this.command(`target.pressWindowKey(windowId:${this.windowId},key:${JSON.stringify(key)})`, options);
    }
    async goto(url, options) {
      if (this.surface.kind !== 'web' || typeof url !== 'string' || new URL(url).origin !== this.surface.origin) throw new Error('Navigation requires the selected origin');
      return this.command(`target.navigate(${JSON.stringify(url)})`, options);
    }
    async activate(options) { return this.command(this.surface.kind === 'web' ? 'target.activateTab()' : 'target.activate()', options); }
    command(command, options) { return this.action(undefined, undefined, {}, options, command); }
    async setValue(index, value, options) { return this.indexLocator(index).fill(value, options); }
    indexLocator(index) {
      if (!Number.isInteger(index) || !this.nodes?.[index]) throw new Error('Fresh state index required');
      const node = this.nodes[index];
      if (!node.name || this.nodes.filter(n => n.role === node.role && n.name === node.name).length !== 1) throw new Error('Ambiguous state index; use an explicit locator');
      return this.getByRole(node.role, { name: node.name, exact: true });
    }
    async action(action, locator, args, options = {}, command) {
      check();
      if (!options.businessKey || typeof options.businessKey !== 'object' || Array.isArray(options.businessKey) || Object.keys(options.businessKey).length === 0) throw new Error('Explicit businessKey required');
      const deadline = options.timeoutMs ?? timeoutMs;
      if (!Number.isInteger(deadline) || deadline < 100 || deadline > 9000) throw new Error('Invalid action deadline');
      this.nodes = undefined; // Old numeric indices cannot survive an input attempt.
      this.frame = undefined;
      const step = { id: 'action', action, target: { surface: this.surface, scope: {}, cardinality: 'one', ...(locator ? { locator } : {}) }, arguments: args, timeoutMs: deadline, effect: { class: 'externalNonIdempotent', businessKey: Object.fromEntries(Object.entries(options.businessKey).map(([k,v]) => { if (typeof v !== 'string') throw new Error('Business keys must be public strings'); return [k, scalar(v)]; })) }, source: { offset: 0, line: 1, column: 1 }, ...(options.postcondition ? { postcondition: options.postcondition } : {}) };
      const normalized = command ? { id: step.id, command, timeoutMs: deadline, effect: step.effect, ...(step.postcondition ? { postcondition: step.postcondition } : {}) } : step;
      const result = await request('mechanize_script_run', { clientRequestId: randomUUID(), format: 'json', source: JSON.stringify({ schemaVersion: 1, name: 'Computer action', surfaces: { target: this.surface }, ...(options.adapters ? { requires: { adapters: options.adapters } } : {}), steps: [normalized] }) });
      const end = Date.now() + deadline + 5000;
      let status = result;
      while (['queued', 'running'].includes(status.executionStatus) && Date.now() < end) {
        await new Promise(resolve => setTimeout(resolve, 100));
        status = await request('mechanize_operation_status', { operationId: result.operationId });
      }
      if (status.executionStatus !== 'succeeded') { const error = new Error('Action outcome unresolved; inspect original operation before retrying'); error.operationId = result.operationId; error.runId = result.runId; throw error; }
      return status;
    }
  }
  class Locator {
    constructor(target, locator) { this.target = target; this.locator = locator; }
    click(options) { return this.target.action('element.press', this.locator, {}, options); }
    fill(value, options) { if (typeof value !== 'string') throw new Error('Public string required; credentials use private Vault'); return this.target.action('element.fill', this.locator, { value: scalar(value) }, options); }
  }
  return {
    getApp: async ({ bundleId, processId, processStartToken, windowId }) => {
      if (!bundleId || !Number.isInteger(processId) || !processStartToken) throw new Error('Exact app identity required');
      return new Target({ kind: 'native', bundleId, processId, processStartToken }, windowId);
    },
    getTab: async ({ origin, tabId }) => {
      const inventory = await request('mechanize_browser_tabs', { surface: { kind: 'web', origin } });
      if (!inventory.complete || !inventory.tabs.some(tab => tab.handle === tabId)) throw new Error('Owned tab unavailable');
      return new Target({ kind: 'web', origin, tabId });
    },
    listTabs: async ({ origin }) => request('mechanize_browser_tabs', { surface: { kind: 'web', origin } }),
    close: async () => { if (closed) return; closed = true; return call('mechanize_session_close', { sessionId }); },
  };
}
