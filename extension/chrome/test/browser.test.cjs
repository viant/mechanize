const {test} = require('node:test');
const assert = require('node:assert/strict');
const vm = require('node:vm');
const fs = require('node:fs');
const path = require('node:path');
const identity = {profileChannel: 'p1', browserInstance: 'b1', tabId: 7, frameId: 0, documentId: 'doc1', documentGeneration: 1};
const command = (action = 'browser.navigate', extra = {}) => ({requestId: 'r1', action, identity, brokerEpoch: 'broker1', channelEpoch: 'channel1', scopeHash: 'scope1', attemptId: 'a1', deadlineUnixMs: Date.now() + 1000, args: {url: 'https://fixture.example.test/next'}, ...extra});
function fixture() {
  const state = {updates: 0, committed: false, redirect: false, stored: {}, listenersBeforeDispatch: false};
  const completed = new Set(), failed = new Set();
  const chrome = {
    storage: {session: {async get(keys) { if (keys === null) return {...state.stored}; if (typeof keys === 'string') return {[keys]: state.stored[keys]}; return Object.fromEntries(keys.map(k => [k, state.stored[k]])); }, async set(values) { Object.assign(state.stored, values); }}},
    tabs: {async sendMessage() { return {validated: true, identity}; }, async update(tabId, changes) { state.updates++; state.listenersBeforeDispatch = completed.size > 0; state.committed = true; for (const f of completed) f({tabId, frameId: 0}); }, async get() { return {id: 7, active: true, title: 'Cases', url: state.redirect ? 'https://untrusted.example.test' : 'https://fixture.example.test/next'}; }},
    webNavigation: {onCompleted: {addListener: f => completed.add(f), removeListener: f => completed.delete(f)}, onErrorOccurred: {addListener: f => failed.add(f), removeListener: f => failed.delete(f)}, async getAllFrames() { return [{frameId: 0, documentId: state.committed ? 'doc2' : 'doc1', url: state.redirect ? 'https://untrusted.example.test' : 'https://fixture.example.test/next'}]; }}
  };
  const context = vm.createContext({chrome, TextEncoder, URL, Date, setTimeout, clearTimeout, crypto: require('node:crypto').webcrypto});
  for (const file of ['protocol.js', 'browser.js']) vm.runInContext(fs.readFileSync(path.join(__dirname, '..', file), 'utf8'), context);
  return {state, api: context.MechanizeBrowser, enrollment: {origins: ['https://fixture.example.test']}, context};
}
test('navigation subscribes first, dispatches once, persists receipt and never replays', async () => {
  const f = fixture();
  const c = command();
  const receipt = await f.api.execute(c, f.enrollment);
  assert.equal(f.state.listenersBeforeDispatch, true);
  assert.equal(receipt.ready, true);
  assert.equal(receipt.newDocument.documentId, 'doc2');
  assert.equal(receipt.identity.documentId, 'doc1'); // Original executor receipt identity.
  assert.equal(f.state.updates, 1);
  assert.ok(!JSON.stringify(f.state.stored).includes('/next'));
  const cached = await f.api.execute({...c, requestId: 'r2'}, f.enrollment);
  assert.equal(cached.dispatchState, 'dispatched');
  assert.equal(f.state.updates, 1);
  await assert.rejects(f.api.execute({...c, args: {url: 'https://fixture.example.test/different'}}, f.enrollment), e => e.code === 'attemptConflict');
});
test('forbidden destination blocks input and missing receipt after restart stays unknown', async () => {
  const f = fixture();
  await assert.rejects(f.api.execute(command('browser.navigate', {args: {url: 'https://untrusted.example.test'}}), f.enrollment), e => e.code === 'originDenied');
  assert.equal(f.state.updates, 0);
  f.state.stored['browserIntent:a1'] = {identity, brokerEpoch: 'broker1', channelEpoch: 'channel1', scopeHash: 'scope1'};
  const receipt = await f.api.query(command('receipt.query', {args: undefined}));
  assert.equal(receipt.dispatchState, 'unknown');
  assert.equal(receipt.receiptAvailable, false);
  assert.equal(f.state.updates, 0);
});
test('redirect denial preserves unknown effect and tab activation does not imply window focus', async () => {
  const f = fixture();
  const oldUpdate = f.context.chrome.tabs.update;
  f.context.chrome.tabs.update = async (...args) => { await oldUpdate(...args); f.state.redirect = true; };
  const result = await f.api.execute(command(), f.enrollment);
  assert.equal(result.error.code, 'redirectOriginDenied');
  assert.equal(result.error.dispatchState, 'unknown');
  const a = fixture();
  const activated = await a.api.execute(command('browser.activate', {args: undefined}), a.enrollment);
  assert.equal(activated.active, true);
  assert.ok(activated.inputSemantics.includes('physical window focus not verified'));
});
