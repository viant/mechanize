const {test} = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const {webcrypto, createHash} = require('node:crypto');
const {JSDOM} = require('jsdom');
const identity = {profileChannel: 'profile1', browserInstance: 'browser1', tabId: 7, frameId: 0, documentId: 'doc1', documentGeneration: 1};
const binding = {identity, brokerEpoch: 'broker1', channelEpoch: 'channel1', scopeHash: 'scope1'};
const command = (action, extra = {}) => ({requestId: 'request1', action, ...binding, deadlineUnixMs: Date.now() + 5000, ...extra});
function fixture() {
  const dom = new JSDOM('<input id="field"><button id="save">Save</button><div id="animation"></div>', {url: 'https://fixture.example.test', runScripts: 'outside-only'});
  const window = dom.window, listeners = [];
  window.TextEncoder = TextEncoder;
  window.HTMLElement.prototype.getClientRects = () => [{width: 100, height: 20}];
  Object.defineProperty(window, 'crypto', {value: webcrypto, configurable: true});
  window.chrome = {runtime: {id: 'fixture', onMessage: {addListener: f => listeners.push(f)}}};
  for (const file of ['protocol.js', 'dom.js', 'recorder.js', 'content.js']) window.eval(fs.readFileSync(path.join(__dirname, '..', file), 'utf8'));
  const sync = message => {let response; listeners[0](message, {id: 'fixture'}, value => response = value); return response;};
  const send = message => new Promise(resolve => listeners[0](message, {id: 'fixture'}, resolve));
  sync({type: 'bind', binding});
  return {window, sync, send, close: () => window.close()};
}
const mutate = (f, attemptId, extra = {}) => f.sync(command('element.press', {attemptId, locator: {strategy: 'id', value: 'save'}, ...extra}));
const exported = (f, args = {offset: 0, limit: 64}, extra = {}) => f.send(command('executor.receipts', {args, ...extra}));
function delayDigest(f) {
  let entered, release;
  const started = new Promise(resolve => entered = resolve), wait = new Promise(resolve => release = resolve);
  Object.defineProperty(f.window, 'crypto', {value: {subtle: {digest: async (...args) => {entered(); await wait; return webcrypto.subtle.digest(...args);}}}, configurable: true});
  return {started, release};
}
test('exports resolved and unknown receipts with SHA256 and no private result data', async t => {
  const f = fixture(); t.after(f.close);
  const secret = 'PRIVATE_VALUE https://private.example/secret?token=secret';
  const fill = command('element.fill', {attemptId: 'filled', locator: {strategy: 'id', value: 'field'}, args: {value: secret}});
  assert.equal(f.sync(fill).dispatchState, 'dispatched');
  f.window.MechanizeDOM.act = () => {throw {code: secret, message: secret, dispatchState: 'unknown', effectState: 'unknown', value: secret};}; mutate(f, 'unknown');
  const result = await exported(f); assert.equal(result.version, 1); assert.equal(result.total, 2); assert.equal(result.revision, 2);
  assert.equal(result.receipts[0].fingerprintSHA256, createHash('sha256').update(JSON.stringify({...fill, requestId: null, deadlineUnixMs: null})).digest('hex'));
  assert.equal(result.receipts[0].dispatchState, 'dispatched'); assert.equal(result.receipts[0].effectState, 'unverified');
  assert.equal(result.receipts[1].dispatchState, 'unknown'); assert.equal(result.receipts[1].effectState, 'unknown'); assert.equal(result.receipts[1].errorCode, 'unclassified');
  for (const denied of ['PRIVATE_VALUE', 'private.example', 'token=', 'fingerprint"', 'inputSemantics', 'locator', 'value"', 'message"']) assert.ok(!JSON.stringify(result).includes(denied), denied);
  assert.deepEqual(Object.keys(result.receipts[0]).sort(), ['attemptId', 'dispatchState', 'effectState', 'fingerprintSHA256']);
});
test('paged export is bounded and later pages require exact revision', async t => {
  const f = fixture(); t.after(f.close); for (let i = 0; i < 65; i++) mutate(f, `attempt${i}`);
  const first = await exported(f); assert.equal(first.receipts.length, 64); assert.equal(first.nextOffset, 64); assert.equal(first.truncated, true);
  const last = await exported(f, {offset: 64, limit: 64, expectedRevision: first.revision}); assert.equal(last.receipts.length, 1); assert.equal(last.nextOffset, 65); assert.equal(last.truncated, false);
  assert.equal((await exported(f, {offset: 65, limit: 1, expectedRevision: first.revision})).nextOffset, 65);
  for (const args of [{offset: 64, limit: 1}, {offset: 0, limit: 65}, {offset: -1, limit: 1}, {offset: 0.5, limit: 1}, {offset: 513, limit: 1}, {offset: 0, limit: 1, extra: 'secret'}, {offset: 0, limit: 1, expectedRevision: -1}, null, []]) assert.equal((await exported(f, args)).error.code, 'invalidReceiptExport');
  assert.equal((await exported(f, {offset: 66, limit: 1, expectedRevision: first.revision})).error.code, 'invalidReceiptExport');
  assert.equal((await exported(f, {offset: 64, limit: 1, expectedRevision: 1})).error.code, 'receiptRevisionMismatch');
  mutate(f, 'new'); assert.equal((await exported(f, {offset: 64, limit: 1, expectedRevision: first.revision})).error.code, 'receiptRevisionMismatch');
});
test('receipt query and duplicate mutation retain original semantics and revision', async t => {
  const f = fixture(); t.after(f.close); let clicks = 0; f.window.document.getElementById('save').addEventListener('click', () => clicks++);
  mutate(f, 'same'); mutate(f, 'same', {requestId: 'duplicate'}); assert.equal(clicks, 1);
  assert.equal(f.sync(command('receipt.query', {attemptId: 'same'})).dispatchState, 'dispatched'); assert.equal(f.sync(command('receipt.query', {attemptId: 'missing'})).receiptAvailable, false);
  assert.equal((await exported(f)).revision, 1);
});
test('concurrent new receipt rejects snapshot without losing history', async t => {
  const f = fixture(); t.after(f.close); mutate(f, 'first'); const delay = delayDigest(f); const pending = exported(f); await delay.started;
  mutate(f, 'second'); delay.release(); assert.equal((await pending).error.code, 'receiptSnapshotChanged'); assert.equal((await exported(f)).total, 2);
});
test('page-only DOM mutation does not invalidate immutable receipt export', async t => {
  const f = fixture(); t.after(f.close); mutate(f, 'first'); const delay = delayDigest(f); const pending = exported(f); await delay.started;
  f.window.document.getElementById('animation').textContent = 'unrelated animation'; delay.release(); const result = await pending;
  assert.equal(result.total, 1); assert.ok(result.identity.documentGeneration > 1); assert.equal(result.error, undefined);
});
test('lease, quiescence and recording changes during hash fail closed', async t => {
  for (const action of ['executor.acquire', 'executor.quiesce', 'record.start']) {
    const f = fixture(); t.after(f.close); mutate(f, 'first'); const delay = delayDigest(f); const pending = exported(f); await delay.started;
    const extra = action === 'executor.acquire' ? {controlLease: {id: 'lease1', generation: 1}} : action === 'record.start' ? {args: {recordingId: 'PRIVATE_RECORDING_ID', leaseExpiresUnixMs: Date.now() + 5000}} : {};
    assert.equal(f.sync(command(action, extra)).error, undefined); delay.release(); assert.equal((await pending).error.code, 'receiptSnapshotChanged');
  }
});
test('quiesced export retains receipts and never reopens executor', async t => {
  const f = fixture(); t.after(f.close); mutate(f, 'first'); f.sync(command('executor.quiesce'));
  const result = await exported(f); assert.equal(result.readiness.quiesced, true); assert.equal(result.total, 1);
  assert.equal(f.sync({type: 'bind', binding}).error.code, 'executorQuiesced'); assert.equal(mutate(f, 'new').error.code, 'executorQuiesced');
  assert.equal(f.sync(command('receipt.query', {attemptId: 'first'})).dispatchState, 'dispatched');
});
test('safe readiness excludes recording events and identity', async t => {
  const f = fixture(); t.after(f.close); const lease = {id: 'lease1', generation: 1}; f.sync(command('executor.acquire', {controlLease: lease}));
  f.sync(command('record.start', {args: {recordingId: 'PRIVATE_RECORDING_ID', leaseExpiresUnixMs: Date.now() + 5000}}));
  const result = await exported(f); assert.equal(result.readiness.controlLease.id, lease.id); assert.equal(result.readiness.controlLeaseHeld, true); assert.equal(result.readiness.recordingState, 'recording'); assert.equal(result.readiness.recordingLastSequence, 1);
  assert.ok(!JSON.stringify(result).includes('PRIVATE_RECORDING_ID')); assert.ok(!JSON.stringify(result).includes('events'));
});
test('stale channel/document fences and extraneous authority fields reject export', async t => {
  const f = fixture(); t.after(f.close);
  for (const extra of [{brokerEpoch: 'other'}, {channelEpoch: 'other'}, {scopeHash: 'other'}, {identity: {...identity, documentId: 'other'}}, {identity: {...identity, frameId: 1}}]) assert.equal((await exported(f, undefined, extra)).error.code, 'staleIdentity');
  for (const extra of [{attemptId: 'attempt'}, {locator: {strategy: 'id', value: 'save'}}, {controlLease: {id: 'lease', generation: 1}}]) assert.equal((await exported(f, undefined, extra)).error.code, 'invalidReceiptExport');
});
test('expired request or hash deadline returns bounded static failure', async t => {
  const f = fixture(); t.after(f.close); mutate(f, 'first'); assert.equal((await exported(f, undefined, {deadlineUnixMs: Date.now() - 1})).error.code, 'dispatchExpired');
  const delay = delayDigest(f); const pending = exported(f, undefined, {deadlineUnixMs: Date.now() + 50}); await delay.started;
  const result = await pending; assert.equal(result.error.code, 'dispatchExpired'); delay.release(); assert.ok(!JSON.stringify(result).includes('fingerprintSHA256'));
});
test('crypto failure and output byte cap do not leak exceptions', async t => {
  const f = fixture(); t.after(f.close); mutate(f, 'first'); Object.defineProperty(f.window, 'crypto', {value: {subtle: {digest: async () => {throw Error('PRIVATE_CRYPTO_FAILURE');}}}, configurable: true});
  const failed = await exported(f); assert.equal(failed.error.code, 'receiptExportUnavailable'); assert.ok(!JSON.stringify(failed).includes('PRIVATE_CRYPTO_FAILURE'));
  Object.defineProperty(f.window, 'crypto', {value: webcrypto, configurable: true}); f.window.MechanizeProtocol.MAX_BYTES = 100; assert.equal((await exported(f)).error.code, 'frameTooLarge');
});
test('maximum history exports without eviction and blocks further mutation', async t => {
  const f = fixture(); t.after(f.close); for (let i = 0; i < 512; i++) mutate(f, `attempt${i}`); assert.equal(mutate(f, 'overflow').error.code, 'receiptCapacity');
  let offset = 0, revision; const retained = [];
  do {const result = await exported(f, {offset, limit: 64, ...(offset ? {expectedRevision: revision} : {})}); assert.equal(result.total, 512); revision = result.revision; retained.push(...result.receipts); offset = result.nextOffset;} while (offset < 512);
  assert.equal(retained.length, 512); assert.equal(retained[0].attemptId, 'attempt0'); assert.equal(retained.at(-1).attemptId, 'attempt511');
});
test('receipt export remains internal and is absent from worker capabilities', async t => {
  const f = fixture(); t.after(f.close); const protocol = f.window.MechanizeProtocol;
  assert.equal(protocol.actions.has('executor.receipts'), false);
  assert.throws(() => protocol.validate(command('executor.receipts', {args: {offset: 0, limit: 1}})), e => e.code === 'unsupportedAction');
  assert.equal((await exported(f)).total, 0);
});
test('lease acquire then retire during hashing cannot hide a readiness transition', async t => {
  const f = fixture(); t.after(f.close); mutate(f, 'first'); const delay = delayDigest(f); const pending = exported(f); await delay.started;
  const lease = {id: 'lease1', generation: 1}; f.sync(command('executor.acquire', {controlLease: lease})); f.sync(command('executor.retire', {controlLease: lease}));
  delay.release(); assert.equal((await pending).error.code, 'receiptSnapshotChanged'); assert.equal((await exported(f)).readiness.controlLeaseHeld, false);
});
test('known no-dispatch errors and malformed receipt states remain closed metadata', async t => {
  const f = fixture(); t.after(f.close); mutate(f, 'missing', {locator: {strategy: 'id', value: 'absent'}});
  f.window.MechanizeDOM.act = () => ({dispatchState: 'PRIVATE_DISPATCH', effectState: 'PRIVATE_EFFECT', value: 'PRIVATE_VALUE'}); mutate(f, 'malformed');
  const result = await exported(f); assert.equal(result.receipts[0].dispatchState, 'notDispatched'); assert.equal(result.receipts[0].effectState, 'none'); assert.equal(result.receipts[0].errorCode, 'targetNotFound');
  assert.equal(result.receipts[1].dispatchState, 'unknown'); assert.equal(result.receipts[1].effectState, 'unknown'); assert.ok(!JSON.stringify(result).includes('PRIVATE_'));
});
