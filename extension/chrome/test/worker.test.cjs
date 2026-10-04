const {test} = require('node:test');
const assert = require('node:assert/strict');
const vm = require('node:vm');
const fs = require('node:fs');
const path = require('node:path');
const identity = {profileChannel: 'p1', browserInstance: 'b1', tabId: 7, frameId: 0, documentId: 'd1', documentGeneration: 1};
const grant = {brokerEpoch: 'broker1', channelEpoch: 'channel1', scopeHash: 'a'.repeat(64)};
const command = (requestId, action = 'element.press', extra = {}) => ({requestId, action, identity, ...grant, deadlineUnixMs: Date.now() + 5000, attemptId: 'a1', locator: {strategy: 'id', value: 'save'}, ...extra});
async function fixture(sessionState = {}) {
  const messages = [], state = {url: 'https://fixture.example.test/page', frameURL: 'https://fixture.example.test/frame', lost: false, deliveries: 0, nativeConnections: 0};
  let runtimeMessage, nativeDisconnect;
  const statusMessages = [];
  const storage = {enrollment: {profileChannel: 'p1', browserInstance: 'b1', origins: ['https://fixture.example.test']}};
  const event = {addListener() {}};
  const chrome = {
    storage: {local: {async get(key) { if (state.rejectStorageRead === key) throw Error("PRIVATE_FAILURE credential https://private.example.test"); if(state.blockStorageReadKey===key) await state.blockStorageRead; return Object.hasOwn(storage,key) ? {[key]: storage[key]} : {}; }, async set(value) { if (state.rejectStorageWrite) throw Error("PRIVATE_FAILURE credential"); if(state.blockStorageWrite) await state.blockStorageWrite; Object.assign(storage, value); }}, session: {async get() { return {...sessionState}; }, async set(value) { if(state.rejectSessionWrite) throw Error("fixture private storage error"); Object.assign(sessionState,value); }}},
    runtime: {id: 'extension', getManifest: () => ({version: '0.1.0'}), getURL: value => `chrome-extension://extension/${value}`,
      onMessage: {addListener(listener) { runtimeMessage = listener; }},
      async sendMessage(message) { statusMessages.push(message); },
      connectNative: () => { state.nativeConnections++; if (state.nativeFailure) throw Error('private-native-error'); return {onMessage: event,
        onDisconnect: {addListener(listener) { nativeDisconnect = listener; }}, postMessage: message => messages.push(message)}; }},
    tabs: {query: async () => { state.inventoryReads = (state.inventoryReads || 0) + 1; if (state.rejectTabQuery || state.rejectSecondInventory && state.inventoryReads === 2) throw Error("PRIVATE_FAILURE URL"); return state.inventoryTabs || []; }, get: async () => ({id: 7, url: state.url}), onRemoved: event,
      async sendMessage(tabId, message) {
        if (message.type === 'bind') { state.binds = (state.binds || 0) + 1; if (state.rejectBind) throw Error('PRIVATE_FAILURE binding'); if (state.bindError) return {error:{code:'private-code',message:'PRIVATE_FAILURE credential'}}; if (state.badBoundDocument) return {identity:{...identity,documentId:'wrong-document'}}; return {identity, mutationFingerprintVersion: state.boundFingerprintVersion}; }
        state.deliveries++; state.lastRendererMessage = message;
        if (state.block) await state.block;
        if (state.lost) throw Error('Renderer disappeared');
        return {requestId: message.requestId, dispatchState: 'dispatched', identity};
      }},
    webNavigation: {getAllFrames: async () => { if (state.rejectFrameQuery) throw Error('PRIVATE_FAILURE frame'); return Array.from({length:state.frameCount || 1}, (_,i) => ({frameId:i,documentId:i ? `d${i+1}` : 'd1',url:state.frameURL})); }, onCommitted: event},
    scripting: {executeScript: async () => { state.injections = (state.injections || 0) + 1; if (state.rejectInjection) throw Error("PRIVATE_FAILURE injection URL"); }}
  };
  const context = vm.createContext({chrome, TextEncoder, URL, Date, console, setTimeout, clearTimeout, crypto: require('node:crypto').webcrypto});
  vm.runInContext(fs.readFileSync(path.join(__dirname, '..', 'protocol.js'), 'utf8'), context);
  vm.runInContext(fs.readFileSync(path.join(__dirname, '..', 'browser.js'), 'utf8'), context);
  vm.runInContext(fs.readFileSync(path.join(__dirname, '..', 'retirement.js'), 'utf8'), context);
  const worker = fs.readFileSync(path.join(__dirname, '..', 'worker.js'), 'utf8').replace(/import "\.\/(protocol|browser|retirement)\.js";/g, '');
  vm.runInContext(worker + '\nglobalThis.fixtureReceive = receive; globalThis.fixtureGuard = () => lifecycleGuardId;', context);
  await new Promise(resolve => setImmediate(resolve));
  await context.fixtureReceive({type: 'enrolled', ...grant});
  messages.length = 0;
  return {state, storage, sessionState, messages, statusMessages, receive: context.fixtureReceive, guard: context.fixtureGuard, runtimeMessage,
    disconnect() { nativeDisconnect(); }};
}
test('worker rejects unauthorized top-level and cross-origin frame documents', async () => {
  const f = await fixture();
  f.state.url = 'https://untrusted.example.test';
  await f.receive(command('r1'));
  assert.equal(f.messages.at(-1).error.code, 'originDenied');
  f.state.url = 'https://fixture.example.test';
  f.state.frameURL = 'https://untrusted.example.test';
  await f.receive(command('r2'));
  assert.equal(f.messages.at(-1).error.code, 'documentDenied');
  assert.equal(f.state.deliveries, 0);
});
test('lost renderer receipt blocks another mutation until original receipt query', async () => {
  const f = await fixture();
  f.state.lost = true;
  await f.receive(command('r1'));
  assert.equal(f.messages.at(-1).error.dispatchState, 'unknown');
  f.state.lost = false;
  await f.receive(command('r2', 'element.press', {attemptId: 'a2'}));
  assert.equal(f.messages.at(-1).error.code, 'unknownEffect');
  assert.equal(f.state.deliveries, 1);
  await f.receive(command('r3', 'receipt.query'));
  await f.receive(command('r4', 'element.press', {attemptId: 'a2'}));
  assert.equal(f.messages.at(-1).dispatchState, 'dispatched');
  assert.equal(f.state.deliveries, 3);
});
test('request replay and new epoch takeover fail closed', async () => {
  const f = await fixture();
  await f.receive(command('r1', 'observe'));
  await f.receive(command('r1', 'observe'));
  assert.equal(f.messages.at(-1).error.code, 'requestReplay');
  await f.receive({type: 'enrolled', ...grant, brokerEpoch: 'broker2'});
  assert.equal(f.messages.at(-1).error.code, 'storedFenceMismatch');
});
test('production preparation requires verified profile, server challenge and reconciled worker', async () => {
  const f = await fixture();
  await f.receive({type: 'processQualified', ...grant, profileQualified: false, executorQualified: false, executorChallenge: 'server1'});
  assert.equal(f.messages.at(-1).error.code, 'executorNotQuiescent');
  await f.receive(command('blocked', 'observe'));
  assert.equal(f.messages.at(-1).error.code, 'notEnrolled');
  await f.receive({type: 'processQualified', ...grant, profileQualified: true, executorQualified: false, executorChallenge: 'server2'});
  assert.ok(f.messages.some(m => m.type === 'executorPrepared' && m.executorChallenge === 'server2'));
});
test('changed production fence freezes the previous grant before refusing takeover', async () => {
  const f = await fixture();
  await f.receive({type: 'processQualified', ...grant, brokerEpoch: 'new-broker', profileQualified: true, executorChallenge: 'server2'});
  assert.equal(f.messages.at(-1).error.code, 'storedFenceMismatch');
  await f.receive(command('old', 'observe'));
  assert.equal(f.messages.at(-1).error.code, 'notEnrolled');
});
test('production worker requires renderer lease and refuses retirement during in-flight or unknown mutation', async () => {
  const f = await fixture();
  await f.receive({type:'processQualified', ...grant, profileQualified:true, executorQualified:false, executorChallenge:'server'});
  await f.receive(command('missing'));
  assert.equal(f.messages.at(-1).error.code, 'rendererAuthorityRequired');
  let unblock; f.state.block = new Promise(resolve => { unblock = resolve; });
  const lease = {id:'lease', generation:1};
  const pending = f.receive(command('in-flight','element.press',{controlLease:lease}));
  await new Promise(resolve => setImmediate(resolve));
  await f.receive(command('retire','executor.retire',{controlLease:lease}));
  assert.equal(f.messages.at(-1).error.code, 'mutationBusy');
  unblock(); await pending; f.state.block = null; f.state.lost = true;
  await f.receive(command('lost','element.press',{attemptId:'lost',controlLease:lease}));
  await f.receive(command('retire-unknown','executor.retire',{controlLease:lease}));
  assert.equal(f.messages.at(-1).error.code, 'unknownEffect');
});
test('explicit desktop scope qualifies renderer without forging profile launch proof', async () => {
  const f = await fixture();
  await f.receive({type:'processQualified', ...grant, trustScope:'desktop', scopeQualified:true, profileQualified:false, executorQualified:false, executorChallenge:'desktop-server'});
  assert.ok(f.messages.some(m => m.type === 'executorPrepared' && m.executorChallenge === 'desktop-server'));
  assert.equal(f.storage.lastGrant.trustScope, 'desktop');
  assert.equal(f.storage.lastGrant.scopeQualified, true);
  assert.equal(f.storage.lastGrant.profileQualified, false);
  assert.equal(f.storage.lastGrant.leaseRequired, true);
  const prepared = f.messages.find(m => m.type === 'executorPrepared');
  assert.equal(prepared.profileQualified, undefined);
  await f.receive(command('desktop-missing-lease'));
  assert.equal(f.messages.at(-1).error.code, 'rendererAuthorityRequired');
  await f.receive(command('desktop-authorized','element.press',{controlLease:{id:'lease',generation:1}}));
  assert.equal(f.messages.at(-1).dispatchState, 'dispatched');
});
test('worker rejects unknown contradictory or unqualified desktop/profile scope', async () => {
  for (const fields of [
    {trustScope:'desktop',scopeQualified:false,profileQualified:false},
    {trustScope:'desktop',profileQualified:false},
    {trustScope:'desktop',scopeQualified:true,profileQualified:true},
    {trustScope:'desktop',scopeQualified:true},
    {trustScope:'all',scopeQualified:true,profileQualified:true},
    {trustScope:null,scopeQualified:true,profileQualified:true},
    {trustScope:{mode:'desktop'},scopeQualified:true,profileQualified:false},
    {trustScope:'profile',scopeQualified:true,profileQualified:false},
    {trustScope:'profile',scopeQualified:false,profileQualified:true},
    {trustScope:'',scopeQualified:true,profileQualified:false}
  ]) {
    const f = await fixture();
    await f.receive({type:'processQualified', ...grant, ...fields, executorQualified:false, executorChallenge:'server'});
    assert.equal(f.messages.at(-1).error.code, 'executorNotQuiescent');
    assert.equal(f.messages.some(m => m.type === 'executorPrepared'), false);
    await f.receive(command('scope-rejected','observe'));
    assert.equal(f.messages.at(-1).error.code, 'notEnrolled');
    assert.equal(f.state.deliveries,0);
  }
});
test('desktop scope retains lost-receipt and changed-channel barriers', async () => {
  const f = await fixture();
  const ack = {type:'processQualified', ...grant, trustScope:'desktop', scopeQualified:true, profileQualified:false, executorQualified:false, executorChallenge:'desktop-server'};
  await f.receive(ack);
  f.state.lost = true;
  const controlLease = {id:'lease',generation:1};
  await f.receive(command('desktop-lost','element.press',{controlLease}));
  f.state.lost = false;
  await f.receive(command('desktop-retry','element.press',{controlLease,attemptId:'a2'}));
  assert.equal(f.messages.at(-1).error.code, 'unknownEffect');
  await f.receive({...ack,executorChallenge:'cannot-requalify-unknown'});
  assert.equal(f.messages.at(-1).error.code, 'executorNotQuiescent');
  await f.receive({...ack,brokerEpoch:'new-broker'});
  assert.equal(f.messages.at(-1).error.code, 'storedFenceMismatch');
  assert.equal(f.state.deliveries,1);
});
const desktopQualification = () => ({type:'processQualified', ...grant, trustScope:'desktop', scopeQualified:true,
  profileQualified:false, executorQualified:false, executorChallenge:'desktop-server'});
test('initial handshake diagnoses rejected storage and inventory promises without qualifying executor', async () => {
  for (const failure of ['stored fence read','enrollment read','tab inventory','frame inventory','final inventory','stored fence write']) {
    const f = await fixture();
    f.state.inventoryTabs = [{id:7,url:f.state.url}];
    f.state.inventoryReads = 0;
    if (failure === 'stored fence read') f.state.rejectStorageRead = 'lastGrant';
    if (failure === 'enrollment read') f.state.rejectStorageRead = 'enrollment';
    if (failure === 'tab inventory') f.state.rejectTabQuery = true;
    if (failure === 'frame inventory') f.state.rejectFrameQuery = true;
    if (failure === 'final inventory') f.state.rejectSecondInventory = true;
    if (failure === 'stored fence write') f.state.rejectStorageWrite = true;
    await assert.doesNotReject(f.receive(desktopQualification()), failure);
    assert.equal(f.messages.at(-1).type, 'attention', failure);
    assert.equal(f.messages.at(-1).error.code, 'inventoryUnavailable', failure);
    assert.equal(f.messages.some(m => m.type === 'executorPrepared'), false, failure);
    assert.equal(f.messages.some(m => m.type === 'documents'), false, failure);
    assert.equal(JSON.stringify(f.messages).includes('PRIVATE_FAILURE'), false, failure);
    assert.equal(JSON.stringify(f.messages).includes('private.example.test'), false, failure);
    // Restore storage only to inspect admission: the failed handshake left no grant.
    f.state.rejectStorageRead = undefined;
    await f.receive(command(`blocked-${failure}`, 'observe'));
    assert.equal(f.messages.at(-1).error.code, 'notEnrolled', failure);
    assert.equal(f.state.deliveries,0,failure);
  }
});
test('initial qualification separates incomplete inventory injection and exact binding failures', async () => {
  for (const [failure, code] of [['incomplete','inventoryIncomplete'],['injection','executorInjectionFailed'],
    ['bind rejection','executorBindingFailed'],['bind error reply','executorBindingFailed'],['wrong document','executorBindingFailed']]) {
    const f = await fixture();
    f.state.inventoryTabs = [{id:7,url:f.state.url}];
    if (failure === 'incomplete') f.state.frameCount = 201;
    if (failure === 'injection') f.state.rejectInjection = true;
    if (failure === 'bind rejection') f.state.rejectBind = true;
    if (failure === 'bind error reply') f.state.bindError = true;
    if (failure === 'wrong document') f.state.badBoundDocument = true;
    await assert.doesNotReject(f.receive(desktopQualification()),failure);
    assert.equal(f.messages.at(-1).error.code,code,failure);
    assert.equal(f.messages.some(m => m.type === 'executorPrepared'),false,failure);
    assert.equal(f.messages.some(m => m.type === 'documents'),false,failure);
    assert.equal(JSON.stringify(f.messages).includes('PRIVATE_FAILURE'),false,failure);
    assert.equal(JSON.stringify(f.messages).includes('https://fixture.example.test'),false,failure);
    if (failure === 'incomplete') assert.equal(f.state.injections || 0,0);
    if (failure === 'injection') assert.equal(f.state.binds || 0,0);
    await f.receive(command(`blocked-${failure}`,'observe'));
    assert.equal(f.messages.at(-1).error.code,'notEnrolled',failure);
    assert.equal(f.state.deliveries,0,failure);
  }
});
test('successful root binding is acknowledged before published inventory and empty inventory stays explicit', async () => {
  for (const populated of [false,true]) {
    const f = await fixture();
    if (populated) f.state.inventoryTabs = [{id:7,url:f.state.url}];
    await f.receive(desktopQualification());
    assert.equal(f.messages[0].type,'executorPrepared');
    assert.equal(f.messages[0].executorChallenge,'desktop-server');
    assert.equal(f.messages[1].type,'documents');
    assert.equal(f.messages[1].truncated,false);
    assert.equal(f.messages[1].documents.length,populated ? 1 : 0);
    assert.equal(f.state.injections || 0,populated ? 1 : 0);
    assert.equal(f.state.binds || 0,populated ? 1 : 0);
    assert.equal(f.storage.lastGrant.leaseRequired,true);
    assert.equal(f.messages.some(m => m.type === 'attention'),false);
  }
});
const optionsSender = (extra = {}) => ({id: 'extension', url: 'chrome-extension://extension/options.html',
  origin: 'chrome-extension://extension', frameId: 0, tab: {id: 9}, ...extra});
test('options tab root may request connection; web, iframe and foreign senders cannot', async () => {
  const f = await fixture();
  f.disconnect();
  const rejected = [optionsSender({id:'foreign'}), optionsSender({url:'https://fixture.example.test'}),
    optionsSender({url:'chrome-extension://extension/content.js'}), optionsSender({url:'chrome-extension://extension/options.html#forged'}),
    optionsSender({origin:'https://fixture.example.test'}), optionsSender({origin:'null'}), optionsSender({origin:undefined}),
    optionsSender({frameId:1}), optionsSender({frameId:undefined}), optionsSender({tab:undefined}), optionsSender({tab:{id:-1}}), null];
  for (const sender of rejected) {
    let replied = false;
    assert.equal(f.runtimeMessage({type:'connect'}, sender, () => { replied = true; }), undefined);
    await new Promise(resolve => setImmediate(resolve));
    assert.equal(replied, false);
    assert.equal(f.state.nativeConnections, 1);
  }
  assert.equal(f.runtimeMessage({type:'arbitrary'}, optionsSender(), () => {}), undefined);
  const response = await new Promise(resolve => {
    assert.equal(f.runtimeMessage({type:'connect'}, optionsSender(), resolve), true);
  });
  assert.equal(response.connected, true);
  assert.equal(f.state.nativeConnections, 2);
});
test('native transport disconnect and failed reconnect return only public disconnected status', async () => {
  const f = await fixture();
  f.disconnect();
  assert.equal(f.statusMessages.at(-1).type, 'nativeConnectionStatus');
  assert.equal(f.statusMessages.at(-1).connected, false);
  assert.equal(JSON.stringify(f.statusMessages).includes('private-native-error'), false);
  await f.receive(command('disconnected', 'observe'));
  assert.equal(f.state.deliveries, 0);
  f.state.nativeFailure = true;
  const response = await new Promise(resolve => f.runtimeMessage({type:'connect'}, optionsSender(), resolve));
  assert.equal(response.connected, false);
  assert.equal(Object.keys(response).join(), 'connected');
});

test('v2 preparation requires explicit worker and every root document support',async()=>{
 const f=await fixture();f.state.inventoryTabs=[{id:7,url:f.state.url}];f.state.boundFingerprintVersion=2;
 await f.receive({type:'processQualified',...grant,profileQualified:true,executorChallenge:'v2-challenge',mutationFingerprintVersion:2});
 const prepared=f.messages.find(m=>m.type==='executorPrepared');assert.equal(prepared.mutationFingerprintVersion,2);
 const published=f.messages.find(m=>m.type==='documents');assert.equal(published.documents[0].mutationFingerprintVersion,2);
 f.messages.length=0;await f.receive(command('legacy-on-v2','element.press',{controlLease:{id:'lease',generation:1}}));assert.equal(f.state.deliveries,0);assert.equal(f.messages.at(-1).error.code,'fingerprintMismatch');
});
test('legacy or unsupported document negotiation cannot qualify v2 executor',async()=>{
 for(const version of [undefined,1]){const f=await fixture();f.state.inventoryTabs=[{id:7,url:f.state.url}];f.state.boundFingerprintVersion=version;
 await f.receive({type:'processQualified',...grant,profileQualified:true,executorChallenge:'v2-challenge',mutationFingerprintVersion:2});assert.equal(f.messages.some(m=>m.type==='executorPrepared'),false);assert.equal(f.messages.at(-1).error.code,'executorBindingFailed');}
 const f=await fixture();await f.receive({type:'processQualified',...grant,profileQualified:true,executorChallenge:'future',mutationFingerprintVersion:3});assert.equal(f.messages.some(m=>m.type==='executorPrepared'),false);assert.equal(f.messages.at(-1).error.code,'executorBindingFailed');
});

test('private lifecycle uses existing executor, strips envelope and inhibits normal work', async () => {
  const f = await fixture();
  await f.receive(command('bind-first', 'observe'));
  const bound = f.state.binds, injected = f.state.injections;
  await f.receive(command('life-quiesce', 'executor.quiesce', {type:'lifecycle', lifecycleGuardId:'guard-1'}));
  assert.equal(f.messages.at(-1).requestId, 'life-quiesce');
  assert.equal(f.messages.at(-1).error, undefined);
  assert.equal(f.state.lastRendererMessage.type, undefined);
  assert.equal(f.state.lastRendererMessage.lifecycleGuardId, undefined);
  assert.equal(f.state.binds, bound);
  assert.equal(f.state.injections, injected);
  const delivered = f.state.deliveries;
  await f.receive(command('normal-after', 'element.press'));
  assert.equal(f.messages.at(-1).error.code, 'lifecycleInhibited');
  await f.receive(command('wrong-guard', 'executor.quiesce', {type:'lifecycle', lifecycleGuardId:'guard-2'}));
  assert.equal(f.messages.at(-1).error.code, 'lifecycleDenied');
  assert.equal(f.state.deliveries, delivered);
  await f.receive({type:'processQualified', ...grant, profileQualified:true, executorQualified:false, executorChallenge:'cannot-reset'});
  assert.equal(f.messages.at(-1).error.code, 'lifecycleInhibited');
});
test('lifecycle cannot create an executor or carry input mutations', async () => {
  const f = await fixture();
  await f.receive(command('missing-root', 'executor.quiesce', {type:'lifecycle', lifecycleGuardId:'guard-1'}));
  assert.equal(f.messages.at(-1).error.code, 'lifecycleDenied');
  await f.receive(command('forged-input', 'element.press', {type:'lifecycle', lifecycleGuardId:'guard-1'}));
  assert.equal(f.messages.at(-1).error.code, 'lifecycleDenied');
  assert.equal(f.state.deliveries, 0);
  assert.equal(f.state.injections, undefined);
});
test('receipt export is admitted only through private lifecycle envelope', async () => {
 const f=await fixture(); await f.receive(command('bind-export','observe'));
 const request={requestId:'ordinary-export',action:'executor.receipts',identity,...grant,deadlineUnixMs:Date.now()+5000,args:{offset:0,limit:64}};
 await f.receive(request); assert.equal(f.messages.at(-1).error.code,'unsupportedAction');
 await f.receive({...request,requestId:'private-export',type:'lifecycle',lifecycleGuardId:'guard-export'});
 assert.equal(f.messages.at(-1).error,undefined);
 assert.equal(f.state.lastRendererMessage.action,'executor.receipts');
 assert.equal(f.state.lastRendererMessage.lifecycleGuardId,undefined);
});
test('persisted lifecycle inhibition survives worker restart and explicit connect', async () => {
 const f=await fixture({mechanizeLifecycleInhibited:true});
 assert.equal(f.state.nativeConnections,0);
 await f.receive(command('cannot-resume','observe'));
 assert.ok(['notEnrolled','lifecycleInhibited'].includes(f.messages.at(-1)?.error?.code) || f.messages.length===0);
 const response=await new Promise(resolve=>f.runtimeMessage({type:'connect'},optionsSender(),resolve));
 assert.equal(response.connected,false);assert.equal(f.state.nativeConnections,0);
});
test('lifecycle storage failure prevents renderer dispatch and keeps admission inhibited', async () => {
 const f=await fixture();await f.receive(command('bind-storage','observe'));
 const before=f.state.deliveries;f.state.rejectSessionWrite=true;
 await f.receive(command('freeze-storage','executor.quiesce',{type:'lifecycle',lifecycleGuardId:'storage-guard'}));
 assert.equal(f.messages.at(-1).error.code,'transportFailure');assert.equal(f.state.deliveries,before);
 f.state.rejectSessionWrite=false;
 await f.receive(command('no-input-after-failure','element.press'));
 assert.equal(f.messages.at(-1).error.code,'lifecycleInhibited');assert.equal(f.state.deliveries,before);
});
const journalCommand = (requestId, action, args) => ({type:'lifecycle',lifecycleGuardId:'journal-guard',requestId,action,identity:{profileChannel:'p1',browserInstance:'b1',tabId:0,frameId:0,documentId:'',documentGeneration:0},...grant,deadlineUnixMs:Date.now()+5000,args});
test('private journal intends and prepares empty channel with confirmed persistent readback', async () => {
 const f=await fixture();const channel={profileChannel:'p1',browserInstance:'b1'};
 const input={channel,transitionId:'transition-1',oldFence:grant,expectedRevision:0};
 await f.receive(journalCommand('intend-1','retirement.intend',input));
 assert.equal(f.messages.at(-1).error,undefined,JSON.stringify(f.messages.at(-1)));
 assert.equal(f.messages.at(-1).retirement.confirmed,true);
 assert.equal(f.messages.at(-1).retirement.record.phase,'intended');
 assert.equal(f.sessionState.mechanizeLifecycleInhibited,true);
 assert.equal(f.state.deliveries,0);
 const manifest={version:2,complete:true,executors:[]};
 const envelopeDigest=await require('../retirement.js').envelopeDigest(manifest,require('node:crypto').webcrypto);
 await f.receive(journalCommand('prepare-1','retirement.prepare',{...input,expectedRevision:1,manifest,envelopeDigest,hostResolutionDigest:'a'.repeat(64)}));
 assert.equal(f.messages.at(-1).retirement.record.phase,'prepared');
 assert.equal(f.messages.at(-1).retirement.record.envelopeDigest,envelopeDigest);
 await f.receive(journalCommand('status-1','retirement.status',{browserInstance:'b1',profileChannel:'p1'}));
 assert.equal(f.messages.at(-1).retirement.record.phase,'prepared');
 assert.equal(f.messages.at(-1).retirement.storeRevision,2);
 const before=JSON.stringify(f.storage.mechanizeRetirementV1);
 await f.receive(journalCommand('changed-prepare','retirement.prepare',{...input,expectedRevision:1,manifest,envelopeDigest,hostResolutionDigest:'b'.repeat(64)}));
 assert.equal(f.messages.at(-1).error.code,'retirementChangedProof');
 assert.equal(JSON.stringify(f.storage.mechanizeRetirementV1),before);
});
test('journal rejects document-scoped and unqualified ordinary messages', async () => {
 const f=await fixture();
 await f.receive({...journalCommand('wrong-root','retirement.status',{profileChannel:'p1',browserInstance:'b1'}),identity});
 assert.equal(f.messages.at(-1).error.code,'lifecycleDenied');
 await f.receive(command('public-journal','retirement.intend'));
 assert.equal(f.messages.at(-1).error.code,'unsupportedAction');
 assert.equal(f.storage.mechanizeRetirementV1,undefined);
});
test('new guard status waits for prior journal work and never restores normal input', async () => {
 const f=await fixture();const channel={profileChannel:'p1',browserInstance:'b1'};
 let release;f.state.blockStorageWrite=new Promise(resolve=>{release=resolve;});
 const old=f.receive(journalCommand('queued-intend','retirement.intend',{channel,transitionId:'handoff-transition',oldFence:grant,expectedRevision:0}));
 await new Promise(resolve=>setImmediate(resolve));
 const next=f.receive({...journalCommand('new-status','retirement.status',channel),lifecycleGuardId:'successor-guard'});
 await new Promise(resolve=>setImmediate(resolve));
 assert.equal(f.messages.some(m=>m.requestId==='new-status'),false);
 release();await old;await next;f.state.blockStorageWrite=null;
 assert.equal(f.messages.at(-1).retirement.record.phase,'intended');
 await f.receive(journalCommand('stale-intend','retirement.intend',{channel,transitionId:'handoff-transition',oldFence:grant,expectedRevision:0}));
 assert.equal(f.messages.at(-1).error.code,'lifecycleDenied');
 await f.receive(command('input-still-blocked','element.press'));
 assert.equal(f.messages.at(-1).error.code,'lifecycleInhibited');
 await f.receive({...journalCommand('current-status','retirement.status',channel),lifecycleGuardId:'successor-guard'});
 assert.equal(f.messages.at(-1).retirement.record.phase,'intended');
});
test('disconnect during journal status cannot transfer the guard', async () => {
 const f=await fixture();const channel={profileChannel:'p1',browserInstance:'b1'};
 await f.receive(journalCommand('before-disconnect','retirement.intend',{channel,transitionId:'disconnect-transition',oldFence:grant,expectedRevision:0}));
 let release;f.state.blockStorageReadKey='mechanizeRetirementV1';f.state.blockStorageRead=new Promise(resolve=>{release=resolve;});
 const pending=f.receive({...journalCommand('disconnected-status','retirement.status',channel),lifecycleGuardId:'must-not-adopt'});
 await new Promise(resolve=>setImmediate(resolve));f.disconnect();release();await pending;
 assert.equal(f.guard(),'journal-guard');
 assert.equal(f.messages.some(m=>m.requestId==='disconnected-status'&&m.retirement?.confirmed),false);
});
test('corrupt journal status does not transfer inspection authority', async () => {
 const f=await fixture();const channel={profileChannel:'p1',browserInstance:'b1'};
 await f.receive(journalCommand('before-corruption','retirement.intend',{channel,transitionId:'corrupt-transition',oldFence:grant,expectedRevision:0}));
 f.storage.mechanizeRetirementV1={invalid:true};
 await f.receive({...journalCommand('corrupt-status','retirement.status',channel),lifecycleGuardId:'must-not-adopt'});
 assert.equal(f.messages.at(-1).retirement.confirmed,false);
 assert.equal(f.messages.at(-1).retirement.needsAttention,true);
 assert.equal(f.guard(),'journal-guard');
});
