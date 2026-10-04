const {test} = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const {JSDOM} = require('jsdom');
function fixture() {
  const dom = new JSDOM('<input id="case" value="CASE-42"><input type="password" id="password" value="swordfish"><div data-mechanize-secret><input id="hidden-secret" value="private"></div><button id="save">Save</button>', {url: 'https://fixture.example.test', runScripts: 'outside-only'});
  dom.window.TextEncoder = TextEncoder;
  for (const file of ['protocol.js', 'dom.js', 'recorder.js']) dom.window.eval(fs.readFileSync(path.join(__dirname, '..', file), 'utf8'));
  const identity = {profileChannel: 'p1', browserInstance: 'b1', tabId: 7, frameId: 0, documentId: 'doc1', documentGeneration: 1};
  const recorder = new dom.window.MechanizeRecorder(dom.window.document, () => identity, dom.window.location.origin);
  return {dom, recorder};
}
test('explicit scoped recording excludes injected events and redacts secrets locally', t => {
  const {dom, recorder} = fixture();
  t.after(() => dom.window.close());
  const doc = dom.window.document;
  recorder.capture({isTrusted: true, type: 'input', target: doc.getElementById('case')});
  assert.equal(recorder.events.length, 0);
  recorder.control('record.start', {leaseExpiresUnixMs: Date.now() + 29000, recordingId: 'r1'});
  doc.getElementById('case').dispatchEvent(new dom.window.Event('input', {bubbles: true}));
  assert.equal(recorder.events.length, 1); // Only explicit start marker.
  recorder.capture({isTrusted: true, type: 'input', target: doc.getElementById('password')});
  recorder.capture({isTrusted: true, type: 'input', target: doc.getElementById('hidden-secret')});
  recorder.capture({isTrusted: true, type: 'input', target: doc.getElementById('case')});
  const batch = recorder.control('record.events', {leaseExpiresUnixMs: Date.now() + 29000, recordingId: 'r1', afterSequence: 1});
  assert.equal(batch.events[0].redacted, true);
  assert.equal(batch.events[0].value, undefined);
  assert.equal(batch.events[1].redacted, true);
  assert.equal(batch.events[2].value, 'CASE-42');
  assert.equal(batch.events[2].selectorConfidence, 'uniqueDOM');
  assert.equal(batch.events[2].lineage, 'r1:doc1:4');
  assert.ok(!JSON.stringify(batch).includes('swordfish'));
  assert.ok(!JSON.stringify(batch).includes('private'));
});
test('pause/stop and bounded overflow expose gaps without silent replay', t => {
  const {dom, recorder} = fixture();
  t.after(() => dom.window.close());
  recorder.control('record.start', {leaseExpiresUnixMs: Date.now() + 29000, recordingId: 'r1'});
  const event = {isTrusted: true, type: 'click', target: dom.window.document.getElementById('save')};
  for (let i = 0; i < 150; i++) recorder.capture({...event});
  const batch = recorder.control('record.events', {leaseExpiresUnixMs: Date.now() + 29000, recordingId: 'r1', limit: 64});
  assert.equal(recorder.events.length, 128);
  assert.equal(batch.events.length, 64);
  assert.equal(batch.gaps[0].lost, 23);
  assert.equal(batch.truncated, true);
  recorder.control('record.pause', {leaseExpiresUnixMs: Date.now() + 29000, recordingId: 'r1'});
  const paused = recorder.sequence;
  recorder.capture(event);
  assert.equal(recorder.sequence, paused);
  recorder.control('record.start', {leaseExpiresUnixMs: Date.now() + 29000, recordingId: 'r1'});
  recorder.capture(event);
  const once = recorder.sequence;
  recorder.capture(event);
  assert.equal(recorder.sequence, once); // Exact same event object, not lookalike events.
  recorder.control('record.stop', {leaseExpiresUnixMs: Date.now() + 29000, recordingId: 'r1'});
  const stopped = recorder.sequence;
  recorder.capture(event);
  assert.equal(recorder.sequence, stopped);
  assert.throws(() => recorder.control('record.start', {leaseExpiresUnixMs: Date.now() + 29000, recordingId: 'r1'}), e => e.code === 'recordingStopped');
});

test('recording lease expiry stops capture and retains an explicit coverage gap', t => {
  const {dom, recorder} = fixture();
  t.after(() => dom.window.close());
  recorder.control('record.start', {leaseExpiresUnixMs: Date.now() + 29000, recordingId: 'r1'});
  recorder.expiresAt = Date.now() - 1;
  recorder.capture({isTrusted: true, type: 'input', target: dom.window.document.getElementById('case')});
  assert.equal(recorder.active, false);
  assert.equal(recorder.events.at(-1).kind, 'gap');
  assert.equal(recorder.events.at(-1).reason, 'recordingLeaseExpired');
  assert.equal(recorder.events.some(e => e.value === 'CASE-42'), false);
});

test('broker consent bounds recording and expiry cannot silently resume', t => {
  const {dom, recorder} = fixture(); t.after(() => dom.window.close());
  assert.throws(() => recorder.control('record.start', {recordingId: 'r1'}), e => e.code === 'recordingExpired');
  assert.throws(() => recorder.control('record.start', {recordingId: 'r1', leaseExpiresUnixMs: Date.now() + 60000}), e => e.code === 'recordingExpired');
  const expiry = Date.now() + 2000;
  recorder.control('record.start', {recordingId: 'r1', leaseExpiresUnixMs: expiry});
  assert.equal(recorder.expiresAt, expiry);
  recorder.expiresAt = Date.now() - 1;
  const batch = recorder.control('record.events', {recordingId: 'r1', leaseExpiresUnixMs: Date.now() + 29000});
  assert.equal(batch.recordingState, 'paused');
  assert.equal(recorder.active, false);
  assert.equal(batch.events.at(-1).reason, 'recordingLeaseExpired');
});
