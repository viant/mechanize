const {test} = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const {JSDOM} = require('jsdom');
function fixture(html) {
  const dom = new JSDOM(html, {url: 'https://fixture.example.test', runScripts: 'outside-only'});
  dom.window.TextEncoder = TextEncoder;
  dom.window.HTMLElement.prototype.getClientRects = function () { return [{width: 100, height: 20}]; };
  const listeners = [];
  dom.window.chrome = {runtime: {id: 'fixture', onMessage: {addListener: f => listeners.push(f)}}};
  for (const file of ['protocol.js', 'dom.js', 'recorder.js', 'content.js']) dom.window.eval(fs.readFileSync(path.join(__dirname, '..', file), 'utf8'));
  return {window: dom.window, document: dom.window.document, api: dom.window.MechanizeDOM,
    send: message => { let reply; listeners[0](message, {id: 'fixture'}, value => reply = value); return reply; }};
}
const identity = {profileChannel: 'profile1', browserInstance: 'browser1', tabId: 7, frameId: 0, documentId: 'doc1', documentGeneration: 1};
const binding = {identity, brokerEpoch: 'broker1', channelEpoch: 'channel1', scopeHash: 'scope1'};
const command = (action, extra = {}) => ({requestId: 'request1', action, ...binding, deadlineUnixMs: Date.now() + 5000, ...extra});
test('bounded snapshot redacts secret values and excludes page scripts', () => {
  const f = fixture('<input type="password" id="password" value="swordfish"><input name="token" value="bearer-secret"><button>Save</button><script>private-data</script>');
  const result = f.api.snapshot(f.document);
  assert.equal(result.nodes[0].value, '[redacted]');
  assert.equal(result.nodes[1].value, '[redacted]');
  assert.ok(!JSON.stringify(result).includes('swordfish'));
  assert.ok(!JSON.stringify(result).includes('bearer-secret'));
  assert.equal(f.api.snapshot(f.document, {limit: 1}).truncated, true);
});
test('strict unique locator, label and open shadow-root semantics', () => {
  const f = fixture('<label for="case">Case ID</label><input id="case"><button>Save</button><button>Save</button><div id="host"></div>');
  assert.equal(f.api.resolve(f.document, {strategy: 'label', value: 'Case ID'}).id, 'case');
  assert.throws(() => f.api.resolve(f.document, {strategy: 'role', value: 'button', name: 'Save'}), e => e.code === 'ambiguousTarget');
  f.document.getElementById('host').attachShadow({mode: 'open'}).innerHTML = '<button data-testid="shadow">Shadow</button>';
  assert.equal(f.api.resolve(f.document, {strategy: 'testId', value: 'shadow'}).textContent, 'Shadow');
});
test('fill uses native setter with untrusted events; file controls require activation', () => {
  const f = fixture('<input id="case"><input type="file" id="file"><button disabled id="disabled">Save</button>');
  const events = [];
  f.document.getElementById('case').addEventListener('input', e => events.push(e.isTrusted));
  f.api.act(f.document, 'element.fill', {strategy: 'id', value: 'case'}, {value: 'literal ${x}\n"quoted"'});
  assert.equal(f.document.getElementById('case').value, 'literal ${x}"quoted"'); // native input strips newlines
  assert.deepEqual(events, [false]);
  assert.throws(() => f.api.act(f.document, 'element.press', {strategy: 'id', value: 'file'}), e => e.code === 'userActivationRequired');
  assert.throws(() => f.api.act(f.document, 'element.press', {strategy: 'id', value: 'disabled'}), e => e.code === 'targetNotActionable');
});
test('document receipts prevent duplicate dispatch and detect attempt conflicts', () => {
  const f = fixture('<button id="save">Save</button>');
  let clicks = 0;
  f.document.getElementById('save').addEventListener('click', () => clicks++);
  f.send({type: 'bind', binding});
  const c = command('element.press', {attemptId: 'attempt1', locator: {strategy: 'id', value: 'save'}});
  assert.equal(f.send(c).dispatchState, 'dispatched');
  assert.equal(f.send({...c, requestId: 'request2'}).dispatchState, 'dispatched');
  assert.equal(clicks, 1);
  assert.equal(f.send({...c, requestId: 'request3', locator: {strategy: 'id', value: 'other'}}).error.code, 'attemptConflict');
  assert.equal(f.send(command('receipt.query', {attemptId: 'attempt1'})).dispatchState, 'dispatched');
  assert.equal(f.send(command('receipt.query', {attemptId: 'lost'})).effectState, 'unknown');
});
test('stale document/frame/generation fails closed; observation refreshes generation', () => {
  const f = fixture('<button id="save">Save</button>');
  f.send({type: 'bind', binding});
  const c = command('element.press', {attemptId: 'attempt1', locator: {strategy: 'id', value: 'save'}});
  assert.equal(f.send({...c, identity: {...identity, documentId: 'doc2'}}).error.code, 'staleIdentity');
  assert.equal(f.send({...c, identity: {...identity, frameId: 1}}).error.code, 'staleIdentity');
  f.document.getElementById('save').textContent = 'Changed';
  assert.equal(f.send(c).error.code, 'staleGeneration');
  assert.ok(f.send(command('observe')).identity.documentGeneration > 1);
  assert.ok(f.send({type: 'bind', binding: {...binding, identity: {...identity, documentGeneration: 20}}}).identity.documentGeneration > 1);
  assert.equal(f.send(command('executor.quiesce')).quiescent, true);
  assert.equal(f.send(c).error.code, 'executorQuiesced');
});
test('schema rejects arbitrary code, expired dispatch and oversized frames', () => {
  const f = fixture('<button>Save</button>');
  const p = f.window.MechanizeProtocol;
  assert.throws(() => p.validate(command('eval', {args: {script: 'alert(1)'}})), e => e.code === 'unsupportedAction');
  assert.throws(() => p.validate(command('observe', {code: 'alert(1)'})), e => e.code === 'invalidRequest');
  assert.throws(() => p.validate(command('observe', {deadlineUnixMs: Date.now() - 1})), e => e.code === 'dispatchExpired');
  assert.throws(() => p.validate(command('observe', {args: {value: 'x'.repeat(256 * 1024)}})), e => e.code === 'frameTooLarge');
});
test('retired exact renderer authority rejects delayed input while fresh lease permits sequential steps', () => {
  const f = fixture('<button id="save">Save</button>');
  let clicks = 0; f.document.getElementById('save').addEventListener('click', () => clicks++);
  f.send({type: 'bind', binding: {...binding, leaseRequired: true}});
  const first = {id: 'first', generation: 1}, second = {id: 'second', generation: 2};
  const mutation = (lease, attemptId) => command('element.press', {controlLease: lease, attemptId, locator: {strategy: 'id', value: 'save'}});
  assert.equal(f.send(mutation(undefined, 'missing')).error.code, 'staleAuthority');
  assert.equal(f.send(command('executor.acquire', {controlLease: first})).validated, true);
  assert.equal(f.send(mutation(first, 'first-attempt')).dispatchState, 'dispatched');
  assert.equal(f.send(command('executor.retire', {controlLease: first})).retiredAuthorityQuiesced, true);
  assert.equal(f.send(mutation(first, 'delayed-old')).error.code, 'staleAuthority');
  assert.equal(f.send(command('executor.acquire', {controlLease: first})).error.code, 'staleAuthority');
  assert.equal(f.send(command('executor.acquire', {controlLease: second})).validated, true);
  assert.equal(f.send(mutation(second, 'second-attempt')).dispatchState, 'dispatched');
  assert.equal(clicks, 2);
  assert.equal(f.send(command('executor.retire', {controlLease: second})).retiredAuthorityQuiesced, true);
  assert.equal(f.send(command('executor.quiesce')).quiescent, true);
  assert.equal(f.send(command('executor.acquire', {controlLease: {id:'third', generation:3}})).error.code, 'executorQuiesced');
});
test('DOM navigation/generation invalidation prevents old admitted authority dispatch', () => {
  const f = fixture('<button id="save">Save</button>');
  f.send({type:'bind', binding:{...binding, leaseRequired:true}});
  const lease = {id:'one',generation:1};
  assert.equal(f.send(command('executor.acquire',{controlLease:lease})).validated,true);
  f.window.dispatchEvent(new f.window.Event('popstate'));
  assert.equal(f.send(command('element.press',{controlLease:lease,attemptId:'old',locator:{strategy:'id',value:'save'}})).error.code,'staleGeneration');
  assert.equal(f.send(command('executor.retire',{controlLease:lease})).retiredAuthorityQuiesced,true);
});
