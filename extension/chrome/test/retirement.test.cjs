const {test} = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const {webcrypto, createHash} = require('node:crypto');
const api = require('../retirement.js');
const golden = JSON.parse(fs.readFileSync(path.join(__dirname, '../../../testdata/chrome-retirement-canonical-v1.json')));
const goldenV2 = JSON.parse(fs.readFileSync(path.join(__dirname, '../../../testdata/chrome-retirement-canonical-v2.json')));
const copy = value => JSON.parse(JSON.stringify(value));
const channel = {profileChannel: 'fixture-channel', browserInstance: 'fixture-browser'};
const oldFence = {brokerEpoch: 'broker-old', channelEpoch: 'channel-old', scopeHash: 'd'.repeat(64)};
const nextFence = n => ({brokerEpoch: `broker-next${n}`, channelEpoch: `channel-next${n}`, scopeHash: oldFence.scopeHash});
const base = (transitionId = 'transition1', fence = oldFence) => ({channel, transitionId, oldFence: fence});
const manifest = () => ({version: 1, complete: true, executors: [copy(golden.cases[1].manifest)]});
async function proof(value = manifest()) {return {manifest: value, envelopeDigest: await api.envelopeDigest(value, webcrypto), hostResolutionDigest: 'c'.repeat(64)};}
function storageFixture() {
  const state = {lastGrant: copy(oldFence), requests: ['retained-request'], unknownAttempts: ['retained-unknown'], privateBrowserReceipt: 'PRIVATE_EXISTING_RECEIPT'};
  const behavior = {}, stats = {writes: 0};
  return {state, behavior, stats, adapter: {
    async get(key) {if (behavior.readFailure || behavior.failNextRead) {behavior.failNextRead = false; throw Error('PRIVATE_STORAGE_READ');} return Object.hasOwn(state, key) ? {[key]: copy(state[key])} : {};},
    async set(values) {stats.writes++; if (behavior.beforeWrite) throw Error('PRIVATE_BEFORE_WRITE'); if (!behavior.dropWrite) Object.assign(state, copy(values)); if (behavior.afterWrite) throw Error('PRIVATE_AFTER_WRITE'); if (behavior.readbackFailure) behavior.failNextRead = true;}
  }};
}
const machine = fixture => api.create(fixture.adapter, {crypto: webcrypto});
const rejects = (promise, code) => assert.rejects(promise, error => error.code === code && error.inhibited === true && error.needsAttention === true && !error.message.includes('PRIVATE'));
async function cycle(m, request = base(), value = manifest(), successor = nextFence(1)) {
  const p = await proof(value); await m.intend({...request, expectedRevision: 0});
  const prepared = await m.prepare({...request, ...p, expectedRevision: 1});
  await m.release({...request, envelopeDigest: p.envelopeDigest, hostResolutionDigest: p.hostResolutionDigest, expectedRevision: 2});
  const adopted = await m.adopt({...request, envelopeDigest: p.envelopeDigest, hostResolutionDigest: p.hostResolutionDigest, newFence: successor, expectedRevision: 3});
  return {prepared, adopted, p};
}
test('canonical bytes and hashes match shared Go/JS golden manifests', () => {
  for (const value of [...golden.cases, ...goldenV2.cases]) {const bytes = api.canonicalExecutor(value.manifest); assert.equal(bytes, value.canonical); assert.equal(createHash('sha256').update(bytes).digest('hex'), value.sha256);}
});
test('nonempty completed history persists unchanged without modifying grants or receipts', async () => {
  const f = storageFixture(), initial = copy(f.state), m = machine(f); const {prepared, adopted, p} = await cycle(m);
  assert.equal(adopted.record.phase, 'adopted'); assert.equal(adopted.storeRevision, 4); assert.equal(adopted.inhibited, true); assert.equal(f.stats.writes, 4);
  assert.deepEqual(adopted.record.manifest, prepared.record.manifest); assert.equal(adopted.record.hostResolutionDigest, p.hostResolutionDigest); assert.equal(adopted.record.envelopeDigest, p.envelopeDigest);
  assert.equal(adopted.record.manifest.executors[0].receipts[0].effectState, 'unverified');
  for (const key of Object.keys(initial)) assert.deepEqual(f.state[key], initial[key]);
});
test('unknown receipt history cannot prepare or release', async () => {
  for (const field of ['dispatchState', 'effectState', 'errorDispatchState']) {
    const f = storageFixture(), m = machine(f), value = manifest(); value.executors[0].receipts[1][field] = 'unknown';
    await m.intend({...base(), expectedRevision: 0});
    await rejects(m.prepare({...base(), expectedRevision: 1, manifest: value, envelopeDigest: 'a'.repeat(64), hostResolutionDigest: 'c'.repeat(64)}), 'retirementHistoryUnknown');
    await rejects(m.release({...base(), expectedRevision: 2, envelopeDigest: 'a'.repeat(64), hostResolutionDigest: 'c'.repeat(64)}), 'retirementPhaseConflict');
    assert.equal(f.stats.writes, 1);
  }
});
test('active lease recording and incomplete inventories block preparation', async () => {
  for (const change of [v => v.complete = false, v => v.executors[0].readiness.quiesced = false, v => v.executors[0].readiness.controlLeaseHeld = true, v => v.executors[0].readiness.recordingState = 'recording', v => v.executors[0].readiness.recordingState = 'paused', v => v.executors[0].readiness.recordingDroppedThrough = 1, v => v.executors[0].receiptRevision++]) {
    const f = storageFixture(), m = machine(f), value = manifest(); change(value); await m.intend({...base(), expectedRevision: 0});
    await assert.rejects(m.prepare({...base(), expectedRevision: 1, manifest: value, envelopeDigest: 'a'.repeat(64), hostResolutionDigest: 'c'.repeat(64)}), e => e.inhibited && e.needsAttention); assert.equal(f.stats.writes, 1);
  }
});
test('closed manifests reject secrets and claimed business-completion flags', async () => {
  for (const change of [v => v.executors[0].receipts[0].args = {value: 'PRIVATE_TOKEN'}, v => v.executors[0].identity.origin = 'https://PRIVATE_URL', v => v.completeResolved = true, v => v.executors[0].readiness.controlLease = {id: 'PRIVATE_TOKEN'}, v => v.executors[0].receipts[1].errorCode = 'PRIVATE_MESSAGE']) {
    const f = storageFixture(), m = machine(f), value = manifest(); change(value); await m.intend({...base(), expectedRevision: 0});
    await assert.rejects(m.prepare({...base(), expectedRevision: 1, manifest: value, envelopeDigest: 'a'.repeat(64), hostResolutionDigest: 'c'.repeat(64)}), e => e.inhibited && !e.message.includes('PRIVATE'));
    assert.ok(!JSON.stringify(f.state[api.KEY]).includes('PRIVATE'));
  }
});
test('wrong phase revision fence channel or proof cannot advance persisted state', async () => {
  const f = storageFixture(), m = machine(f), p = await proof();
  await rejects(m.prepare({...base(), ...p, expectedRevision: 1}), 'retirementPhaseConflict'); await m.intend({...base(), expectedRevision: 0});
  await rejects(m.intend({...base('conflict'), expectedRevision: 0}), 'retirementTransitionConflict');
  await rejects(m.prepare({...base(), ...p, oldFence: {...oldFence, brokerEpoch: 'other'}, expectedRevision: 1}), 'retirementTransitionConflict');
  await rejects(m.prepare({...base(), ...p, channel: {...channel, browserInstance: 'other'}, expectedRevision: 1}), 'retirementChannelMismatch');
  await rejects(m.prepare({...base(), ...p, expectedRevision: 2}), 'retirementRevisionConflict');
  await rejects(m.prepare({...base(), ...p, envelopeDigest: 'a'.repeat(64), expectedRevision: 1}), 'retirementChangedProof');
  await m.prepare({...base(), ...p, expectedRevision: 1});
  await rejects(m.release({...base(), envelopeDigest: p.envelopeDigest, hostResolutionDigest: 'e'.repeat(64), expectedRevision: 2}), 'retirementChangedProof'); assert.equal(f.stats.writes, 2);
});
test('exact duplicate phases adopt only readback and changed adoption remains rejected', async () => {
  const f = storageFixture(), m = machine(f), p = await proof();
  const intended = {...base(), expectedRevision: 0}; await m.intend(intended); await m.intend(intended); assert.equal(f.stats.writes, 1);
  const prepared = {...base(), ...p, expectedRevision: 1}; await m.prepare(prepared); await m.prepare(prepared); assert.equal(f.stats.writes, 2);
  const released = {...base(), envelopeDigest: p.envelopeDigest, hostResolutionDigest: p.hostResolutionDigest, expectedRevision: 2}; await m.release(released); await m.release(released); assert.equal(f.stats.writes, 3);
  const adopted = {...base(), envelopeDigest: p.envelopeDigest, hostResolutionDigest: p.hostResolutionDigest, newFence: nextFence(1), expectedRevision: 3}; await m.adopt(adopted); await m.adopt(adopted); assert.equal(f.stats.writes, 4);
  await rejects(m.adopt({...adopted, newFence: nextFence(2)}), 'retirementChangedProof');
  await rejects(m.adopt({...adopted, newFence: {...nextFence(1), scopeHash: 'f'.repeat(64)}}), 'retirementChangedProof');
  await rejects(m.adopt({...adopted, newFence: {...nextFence(1), channelEpoch: oldFence.channelEpoch}}), 'retirementChangedProof');
  await rejects(m.prepare(prepared), 'retirementPhaseConflict');
});
test('write failures before after or during readback do not report confirmation', async () => {
  for (const mode of ['beforeWrite', 'afterWrite', 'dropWrite', 'readbackFailure']) {
    const f = storageFixture(), m = machine(f); f.behavior[mode] = true; await rejects(m.intend({...base(), expectedRevision: 0}), 'retirementWriteUnconfirmed'); f.behavior[mode] = false;
    const status = await m.status(channel); assert.equal(status.confirmed, mode === 'afterWrite' || mode === 'readbackFailure');
    if (status.confirmed) {const writes = f.stats.writes; await m.intend({...base(), expectedRevision: 0}); assert.equal(f.stats.writes, writes);}
    assert.deepEqual(f.state.lastGrant, oldFence); assert.equal(f.state.privateBrowserReceipt, 'PRIVATE_EXISTING_RECEIPT');
  }
});
test('unknown invalid or unreadable stored schemas inhibit without overwriting facts', async () => {
  for (const stored of [null, {version: 2, secret: 'PRIVATE_RECORD'}, {version: 1, channel, revision: 1, activeTransitionId: 'one', transitions: [{version: 1, phase: 'future'}]}]) {
    const f = storageFixture(); f.state[api.KEY] = copy(stored); const before = JSON.stringify(f.state), m = machine(f), status = await m.status(channel);
    assert.equal(status.confirmed, false); assert.equal(status.inhibited, true); assert.equal(status.needsAttention, true); assert.ok(!JSON.stringify(status).includes('PRIVATE'));
    await assert.rejects(m.intend({...base(), expectedRevision: 0})); assert.equal(f.stats.writes, 0); assert.equal(JSON.stringify(f.state), before);
  }
  const f = storageFixture(), m = machine(f); f.behavior.readFailure = true; assert.equal((await m.status(channel)).reason, 'retirementReadUnavailable');
});
test('concurrent machines serialize one transition and reject actor or channel substitution', async () => {
  const f = storageFixture(), first = machine(f), second = machine(f);
  const results = await Promise.allSettled([first.intend({...base('one'), expectedRevision: 0}), second.intend({...base('two'), expectedRevision: 0})]);
  assert.equal(results.filter(v => v.status === 'fulfilled').length, 1); assert.equal(f.stats.writes, 1);
  const p = await proof(), request = {...base('one'), ...p, expectedRevision: 1}; await Promise.all([first.prepare(request), second.prepare(request)]); assert.equal(f.stats.writes, 2);
  await rejects(first.prepare({...request, actor: 'PRIVATE_ACTOR'}), 'retirementInvalidSchema');
});
test('second nonempty cycle retains first tombstone and requires exact successor fence', async () => {
  const f = storageFixture(), m = machine(f), first = await cycle(m);
  await rejects(m.intend({...base('second', oldFence), expectedRevision: 0}), 'retirementChangedProof');
  const second = await cycle(m, base('second', nextFence(1)), manifest(), nextFence(2));
  assert.equal(second.adopted.history.length, 1); assert.deepEqual(second.adopted.history[0], first.adopted.record); assert.equal(second.adopted.storeRevision, 8);
  await rejects(m.intend({...base('transition1', nextFence(2)), expectedRevision: 0}), 'retirementTransitionConflict');
});
test('transition capacity inhibits before write without evicting retained tombstones', async () => {
  const f = storageFixture(), m = machine(f); let fence = oldFence;
  for (let i = 1; i <= 32; i++) {await cycle(m, base(`cycle${i}`, fence), {version: 1, complete: true, executors: []}, nextFence(i)); fence = nextFence(i);}
  const before = JSON.stringify(f.state[api.KEY]), writes = f.stats.writes;
  await rejects(m.intend({...base('overflow', fence), expectedRevision: 0}), 'retirementCapacity');
  assert.equal(f.stats.writes, writes); assert.equal(JSON.stringify(f.state[api.KEY]), before); assert.equal((await m.status(channel)).history.length, 31);
});
test('executor and aggregate receipt bounds reject complete-looking oversized histories', async () => {
  const good = copy(golden.cases[0].manifest);
  const executors = Array.from({length: 65}, (_, i) => ({...copy(good), identity: {...good.identity, tabId: i + 1, documentId: `doc${i}`}}));
  await rejects(api.envelopeDigest({version: 1, complete: true, executors}, webcrypto), 'retirementInventoryIncomplete');
  const large = Array.from({length: 9}, (_, index) => ({...copy(good), identity: {...good.identity, tabId: index + 1, documentId: `doc${index}`}, receiptRevision: 512,
    receipts: Array.from({length: 512}, (_, i) => ({attemptId: `attempt${index}-${i}`, fingerprintSHA256: 'a'.repeat(64), dispatchState: 'dispatched', effectState: 'unverified'}))}));
  await rejects(api.envelopeDigest({version: 1, complete: true, executors: large}, webcrypto), 'retirementCapacity');
  await rejects(api.envelopeDigest({version: 1, complete: true, executors: [copy(good), copy(good)]}, webcrypto), 'retirementInvalidSchema');
});
test('tampered stored manifest and absent host attestation cannot release', async () => {
  const f = storageFixture(), m = machine(f), p = await proof(); await m.intend({...base(), expectedRevision: 0});
  await rejects(m.prepare({...base(), manifest: p.manifest, envelopeDigest: p.envelopeDigest, expectedRevision: 1}), 'retirementChangedProof');
  await m.prepare({...base(), ...p, expectedRevision: 1});
  f.state[api.KEY].transitions[0].manifest.executors[0].receipts[0].fingerprintSHA256 = 'f'.repeat(64);
  const before = JSON.stringify(f.state[api.KEY]);
  await rejects(m.release({...base(), envelopeDigest: p.envelopeDigest, hostResolutionDigest: p.hostResolutionDigest, expectedRevision: 2}), 'retirementChangedProof');
  assert.equal((await m.status(channel)).needsAttention, true); assert.equal(JSON.stringify(f.state[api.KEY]), before); assert.equal(f.stats.writes, 2);
});
test('whole-store byte capacity blocks preparation without pruning older manifests', async () => {
  const value = {version: 1, complete: true, executors: Array.from({length: 8}, (_, index) => {
    const executor = copy(golden.cases[0].manifest); executor.identity.tabId = index + 1; executor.identity.documentId = `doc${index}`; executor.receiptRevision = 512;
    executor.receipts = Array.from({length: 512}, (_, receipt) => ({attemptId: (`attempt${index}-${receipt}-` + 'x'.repeat(128)).slice(0, 128), fingerprintSHA256: 'a'.repeat(64), dispatchState: 'dispatched', effectState: 'unverified'}));
    return executor;
  })};
  value.executors = value.executors.map(item => JSON.parse(api.canonicalExecutor(item)));
  const p = await proof(value), f = storageFixture(), records = []; let fence = oldFence, storeRevision = 0, count = 1;
  while (true) {
    const candidate = {version: 1, channel, transitionId: `cycle${count}`, oldFence: fence, phase: 'adopted', revision: 4, manifest: copy(value), envelopeDigest: p.envelopeDigest, hostResolutionDigest: p.hostResolutionDigest, adoptedFence: nextFence(count)};
    const trial = {version: 1, channel, revision: storeRevision + 4, activeTransitionId: candidate.transitionId, transitions: [...records, candidate]};
    if (Buffer.byteLength(JSON.stringify(trial)) > 8 * 1024 * 1024) break;
    records.push(candidate); storeRevision += 4; fence = nextFence(count++);
  }
  const request = base(`cycle${count}`, fence), intended = {...request, version: 1, phase: 'intended', revision: 1};
  f.state[api.KEY] = {version: 1, channel, revision: storeRevision + 1, activeTransitionId: request.transitionId, transitions: [...records, intended]};
  const m = machine(f), before = JSON.stringify(f.state[api.KEY]);
  await rejects(m.prepare({...request, ...p, expectedRevision: 1}), 'retirementCapacity');
  assert.equal(f.stats.writes, 0); assert.equal(JSON.stringify(f.state[api.KEY]), before);
});
test('readback mismatch never confirms a write and explicit duplicate adopts persisted facts', async () => {
  const f = storageFixture(), original = f.adapter.get; let hideReadback = false;
  f.adapter.get = async key => {const value = await original(key); if (hideReadback) {hideReadback = false; return {};} return value;};
  const set = f.adapter.set; f.adapter.set = async values => {await set(values); hideReadback = true;};
  const m = machine(f); await rejects(m.intend({...base(), expectedRevision: 0}), 'retirementWriteUnconfirmed');
  assert.equal((await m.status(channel)).record.phase, 'intended'); const writes = f.stats.writes;
  await m.intend({...base(), expectedRevision: 0}); assert.equal(f.stats.writes, writes);
});
test('lost release and adoption writes retain complete prepared facts and require explicit readback', async () => {
  for (const phase of ['released', 'adopted']) for (const mode of ['beforeWrite', 'afterWrite', 'readbackFailure']) {
    const f = storageFixture(), m = machine(f), p = await proof();
    await m.intend({...base(), expectedRevision: 0}); await m.prepare({...base(), ...p, expectedRevision: 1});
    const release = {...base(), envelopeDigest: p.envelopeDigest, hostResolutionDigest: p.hostResolutionDigest, expectedRevision: 2};
    if (phase === 'adopted') await m.release(release);
    f.behavior[mode] = true;
    const request = phase === 'released' ? release : {...release, expectedRevision: 3, newFence: nextFence(1)};
    await rejects(phase === 'released' ? m.release(request) : m.adopt(request), 'retirementWriteUnconfirmed');
    f.behavior[mode] = false;
    const status = await m.status(channel);
    assert.equal(status.record.phase, mode === 'beforeWrite' ? (phase === 'released' ? 'prepared' : 'released') : phase);
    assert.deepEqual(status.record.manifest, (await proof()).manifest); assert.equal(status.record.hostResolutionDigest, p.hostResolutionDigest);
    if (mode !== 'beforeWrite') {const writes = f.stats.writes; if (phase === 'released') await m.release(request); else await m.adopt(request); assert.equal(f.stats.writes, writes);}
    assert.deepEqual(f.state.lastGrant, oldFence);
  }
});

const manifestV2 = () => ({version: 2, complete: true, executors: [copy(goldenV2.cases[1].manifest)]});
const v2Channel = {profileChannel: 'v2-fixture-channel', browserInstance: 'v2-fixture-browser'};
test('v2 persists exact known fingerprints and v1 serialization remains omitted', async () => {
  const value = manifestV2(), f = storageFixture(), m = machine(f);
  const request = {...base('v2-transition'), channel: v2Channel};
  const result = await cycle(m, request, value);
  assert.deepEqual(result.adopted.record.manifest, value);
  for (const row of result.adopted.record.manifest.executors[0].receipts) assert.equal(row.fingerprintVersion, 2);
  assert.equal((await m.status(v2Channel)).confirmed, true);
  assert.ok(!api.canonicalExecutor(golden.cases[1].manifest).includes('fingerprintVersion'));
});
test('explicit v2 rejects missing mixed unknown and downgraded fingerprint versions', async () => {
  for (const version of [undefined, null, 0, 1, 3, '2']) {
    const value = manifestV2();
    if (version === undefined) delete value.executors[0].receipts[0].fingerprintVersion;
    else value.executors[0].receipts[0].fingerprintVersion = version;
    await rejects(api.envelopeDigest(value, webcrypto), 'retirementInvalidSchema');
  }
  for (const version of [null, 0, 1, 2]) {
    const value = manifest(); value.executors[0].receipts[0].fingerprintVersion = version;
    await rejects(api.envelopeDigest(value, webcrypto), 'retirementInvalidSchema');
  }
  for (const change of [v => v.version = 1, v => v.version = 3, v => delete v.version, v => v.executors.push(copy(golden.cases[0].manifest))]) {
    const value = manifestV2(); change(value);
    await assert.rejects(api.envelopeDigest(value, webcrypto), e => e.inhibited && e.needsAttention);
  }
});
test('v1 tombstones survive explicit v2 upgrade but same channel cannot downgrade', async () => {
  const f = storageFixture(), m = machine(f);
  const first = await cycle(m);
  const oldBytes = JSON.stringify(first.adopted.record);
  const upgraded = manifestV2();
  upgraded.executors[0].identity.profileChannel = channel.profileChannel;
  upgraded.executors[0].identity.browserInstance = channel.browserInstance;
  const second = await cycle(m, base('v2-upgrade', nextFence(1)), upgraded, nextFence(2));
  assert.equal(JSON.stringify(second.adopted.history[0]), oldBytes);
  await m.intend({...base('downgrade', nextFence(2)), expectedRevision: 0});
  const writes = f.stats.writes, before = JSON.stringify(f.state[api.KEY]);
  await rejects(m.prepare({...base('downgrade', nextFence(2)), ...await proof(), expectedRevision: 1}), 'retirementVersionIncompatible');
  assert.equal(f.stats.writes, writes); assert.equal(JSON.stringify(f.state[api.KEY]), before);
  const status = await machine(f).status(channel);
  assert.equal(status.confirmed, true); assert.equal(status.record.phase, 'intended'); assert.equal(JSON.stringify(status.history[0]), oldBytes);
});
test('v2 preserves unknown history quiescence and complete inventory gates', async () => {
  for (const change of [v => v.executors[0].receipts[0].effectState = 'unknown', v => v.executors[0].readiness.quiesced = false, v => v.executors[0].readiness.controlLeaseHeld = true, v => v.executors[0].receiptRevision++]) {
    const f = storageFixture(), m = machine(f), value = manifestV2(); change(value);
    const request = {...base('v2-inhibited'), channel: v2Channel}; await m.intend({...request, expectedRevision: 0});
    await assert.rejects(m.prepare({...request, expectedRevision: 1, manifest: value, envelopeDigest: 'a'.repeat(64), hostResolutionDigest: 'c'.repeat(64)}), e => e.inhibited && e.needsAttention);
    assert.equal(f.stats.writes, 1);
  }
});
test('persisted v2 to v1 downgrade cannot qualify after restart or overwrite history', async () => {
  const f = storageFixture(), m = machine(f), request = {...base('v2-first'), channel: v2Channel};
  await cycle(m, request, manifestV2(), nextFence(1));
  const legacy = manifest();
  legacy.executors[0].identity.profileChannel = v2Channel.profileChannel;
  legacy.executors[0].identity.browserInstance = v2Channel.browserInstance;
  const p = await proof(legacy), store = f.state[api.KEY];
  store.transitions.push({version: 1, channel: v2Channel, transitionId: 'downgraded-record', oldFence: nextFence(1), phase: 'prepared', revision: 2, ...p});
  store.revision = 6; store.activeTransitionId = 'downgraded-record';
  const before = JSON.stringify(store), writes = f.stats.writes;
  const restarted = machine(f), status = await restarted.status(v2Channel);
  assert.equal(status.confirmed, false); assert.equal(status.reason, 'retirementVersionIncompatible');
  await rejects(restarted.release({...base('downgraded-record', nextFence(1)), channel: v2Channel, envelopeDigest: p.envelopeDigest, hostResolutionDigest: p.hostResolutionDigest, expectedRevision: 2}), 'retirementVersionIncompatible');
  assert.equal(f.stats.writes, writes); assert.equal(JSON.stringify(f.state[api.KEY]), before);
});
