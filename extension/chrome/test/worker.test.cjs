const {test} = require('node:test');
const assert = require('node:assert/strict');
const vm = require('node:vm');
const fs = require('node:fs');
const path = require('node:path');
const targetGuard = require('../playwright-target.js');
const {identity,grant,command,sortedStorageValue,fixture,privateFrame,privateFixture,privateSubmitFrame,privacyFrame,playwrightNative,playwrightCommand}=require('./worker-fixture.cjs');

function auditOriginal(f,record=f.storage.mechanizeReconnect) {
 if(record?.format==='activeHandoff')return JSON.parse(f.storage['mechanizeReconnectAudit:'+record.audit.digest].journalJSON);
 if(record?.recovery?.originalPending)return record.recovery.originalPending;
 return JSON.parse(f.storage['mechanizeReconnectPendingArchive:'+record.recovery.originalPendingRef.digest].pendingJSON);
}
function respondBindings(f,rows=[]) {
 const hash=value=>require('node:crypto').createHash('sha256').update(JSON.stringify(value)).digest('hex');
 f.state.emptyRendererReceipts=true;
 if(!f.state.frameRows)f.state.frameRows=[{frameId:0,parentFrameId:-1,documentId:f.state.documentId||'d1',url:f.state.frameURL,frameType:'outermost_frame',documentLifecycle:'active'}];
 f.state.nativePost=message=>{
  if(message.type==='reconnectBindings')queueMicrotask(()=>f.receive({type:'reconnectBindingsResult',requestId:message.requestId,pendingDigest:hash(message.pending),bindingsDigest:hash(rows),total:rows.length,offset:0,nextOffset:rows.length,bindings:rows}));
  if(message.type==='reconnectBindingsDone'&&message.complete)queueMicrotask(()=>f.receive({type:'reconnectBindingsCommitReady',requestId:message.requestId,complete:true}));
 };
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
test('all websites requires matching broker scope and permits new bound public frames', async () => {
  const f=await fixture();f.storage.enrollment={profileChannel:'p1',browserInstance:'b1',allWebsites:true,origins:[]};
  await f.receive({type:'enrolled',...grant});
  assert.equal(f.messages.at(-1).error.code,'websiteScopeMismatch');
  assert.equal(f.statusMessages.at(-1).attentionCode,'websiteScopeMismatch');
  await f.receive({type:'enrolled',...grant,allWebsites:true});
  f.state.url='https://another.example.test/page';f.state.frameURL='http://ordinary.example.test/frame';
  await f.receive(command('all-public'));assert.equal(f.state.deliveries,1);
  f.state.url='file:///private/fixture';await f.receive(command('all-file'));
  assert.equal(f.messages.at(-1).error.code,'originDenied');assert.equal(f.state.deliveries,1);
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
    let response;
    assert.equal(f.runtimeMessage({type:'connect'}, sender, value => { response = value; }), undefined);
    await new Promise(resolve => setImmediate(resolve));
    if (sender?.id === 'extension' && sender.url === 'chrome-extension://extension/options.html') {
      assert.deepEqual(JSON.parse(JSON.stringify(response)), {connected:false,attentionCode:'setupContextUnqualified'});
    } else assert.equal(response, undefined);
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
  assert.equal(Object.keys(response).sort().join(), 'attentionCode,connected');
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
 assert.equal(f.state.nativeConnections,1);
 await f.receive(command('cannot-resume','observe'));
 assert.ok(['notEnrolled','lifecycleInhibited'].includes(f.messages.at(-1)?.error?.code) || f.messages.length===0);
 const response=await new Promise(resolve=>f.runtimeMessage({type:'connect'},optionsSender(),resolve));
 assert.equal(response.connected,true);assert.equal(f.state.nativeConnections,1);assert.equal(f.state.deliveries,0);assert.ok(!f.messages.some(m=>m.type==='executorPrepared'));
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

test('concurrent options connection requests share one native launch and failed attempts may reconnect explicitly', async () => {
  const f=await fixture(); f.disconnect();
  let release; f.state.blockStorageReadKey='enrollment';
  f.state.blockStorageRead=new Promise(resolve=>{release=resolve;});
  const first=new Promise(resolve=>f.runtimeMessage({type:'connect'},optionsSender(),resolve));
  const second=new Promise(resolve=>f.runtimeMessage({type:'connect'},optionsSender({tab:{id:10}}),resolve));
  await new Promise(resolve=>setImmediate(resolve));
  assert.equal(f.state.nativeConnections,1);
  release(); const responses=await Promise.all([first,second]);
  assert.equal(f.state.nativeConnections,2);
  assert.equal(responses.every(value=>value.connected===true),true);
  f.disconnect(); f.state.blockStorageReadKey=null; f.state.nativeFailure=true;
  const failed=await new Promise(resolve=>f.runtimeMessage({type:'connect'},optionsSender(),resolve));
  assert.equal(failed.connected,false);
  f.state.nativeFailure=false;
  const recovered=await new Promise(resolve=>f.runtimeMessage({type:'connect'},optionsSender(),resolve));
  assert.equal(recovered.connected,true);
});

test('toolbar reuses only its exact setup tab and concurrent clicks create one page', async () => {
  const f=await fixture();
  f.state.setupTabs=[{id:9,windowId:2,url:'chrome-extension://extension/options.html'}, {id:10,windowId:3,url:'https://fixture.example.test'}];
  f.toolbarClick(); await new Promise(resolve=>setImmediate(resolve));
  assert.equal(f.state.activatedSetupTab.id,9); assert.equal(f.state.focusedWindow.id,2);
  assert.equal(f.state.createdSetupTabs || 0,0);
  f.state.setupTabs=[];
  let release;f.state.blockSetupQuery=new Promise(resolve=>{release=resolve;});
  f.toolbarClick();f.toolbarClick();await new Promise(resolve=>setImmediate(resolve));
  release();await new Promise(resolve=>setImmediate(resolve));
  assert.equal(f.state.createdSetupTabs,1);
  assert.equal(f.state.createdSetup.url,'chrome-extension://extension/options.html');
  assert.equal(f.state.setupQuery.url,'chrome-extension://extension/options.html');
});

test('private delivery never enters public receipts or storage and silences ordinary old-port output',async()=>{
  const f=await privateFixture();await f.receive(privateFrame());
  assert.equal(f.messages.length,1);assert.equal(f.messages[0].type,'credentialDeliveryResult');assert.equal(f.messages[0].status,'dispatched');
  assert.deepEqual(Object.keys(f.messages[0]).sort(),['attemptId','identity','requestId','status','type']);
  assert.equal(JSON.stringify(f.sessionState.mechanizeProtectedOrigins),JSON.stringify(['https://fixture.example.test']));
  assert.ok(!JSON.stringify([f.messages,f.storage,f.sessionState]).includes('CANARY'));
  await f.receive(command('after','observe'));assert.equal(f.messages.length,1);
});
test('private malformed renderer reply is unknown without echoing data',async()=>{
  for(const reply of [{status:'dispatched',value:'PASSWORD-CANARY'},{error:{message:'PASSWORD-CANARY'}},{status:'unexpected'}]) {
    const f=await privateFixture();f.state.privateReply=reply;await f.receive(privateFrame());
    assert.equal(f.messages[0].status,'unknown');assert.ok(!JSON.stringify(f.messages).includes('CANARY'));
  }
});
test('private lane refuses absent lease cross-frame and stale authority without public fallback',async()=>{
  for(const extra of [{controlLease:{id:'wrong',generation:1}},{identity:{...identity,frameId:1}},{channelEpoch:'wrong'}]) {
    const f=await privateFixture();const before=f.state.deliveries;await f.receive(privateFrame(extra));
    assert.equal(f.state.deliveries,before);assert.ok(!f.messages.length || f.messages.at(-1).status==='notDispatched');
    assert.ok(!JSON.stringify(f.messages).includes('CANARY'));
  }
});
test('private delayed reply cannot enter a disconnected or replacement port',async()=>{
  const f=await privateFixture();let release;f.state.block=new Promise(resolve=>release=resolve);
  const pending=f.receive(privateFrame());await new Promise(resolve=>setImmediate(resolve));
  f.disconnect();release();await pending;assert.equal(f.messages.length,0);
  await new Promise(resolve=>f.runtimeMessage({type:'connect'},{id:'extension',url:'chrome-extension://extension/options.html',origin:'chrome-extension://extension',frameId:0,tab:{id:8}},resolve));
  assert.ok(!f.messages.some(x=>x.type==='credentialDeliveryResult'));assert.ok(!JSON.stringify(f.messages).includes('CANARY'));
});
test('secure metadata probe returns only refreshed identity and readiness',async()=>{
  const f=await privateFixture(),probe=privateFrame({type:'credentialInspect'});
  for(const key of ['attemptId','controlLease','username','password']) delete probe[key];
  await f.receive(probe);assert.equal(f.messages[0].type,'credentialInspectResult');assert.equal(f.messages[0].ready,true);
  assert.deepEqual(Object.keys(f.messages[0]).sort(),['identity','privateCredentialProtocolVersion','ready','requestId','stage','type']);
});
test('retained protected origin excludes new documents and metadata after restart',async()=>{
  const f=await fixture({mechanizeProtectedOrigins:['https://fixture.example.test']});f.state.inventoryTabs=[{id:7,url:f.state.url,title:'PRIVATE-TITLE'}];
  await f.receive({type:'enrolled',...grant});assert.equal(f.messages.findLast(m=>m.type==='documents').documents.length,0);
  await f.receive(command('protected','observe'));assert.equal(f.messages.at(-1).error.code,'secureDocumentRequired');assert.equal(f.state.deliveries,0);
});

test('quarantined fresh root advertises only private identity and admits exact private inspection',async()=>{
 const origin='https://fixture.example.test';
 const f=await fixture({mechanizeProtectedOrigins:[origin]},{enroll:false});
 f.state.boundFingerprintVersion=2;
 f.state.inventoryTabs=[{id:7,url:origin+'/login',get title(){throw Error('TITLE-CANARY must never be read');}}];
 await f.receive({type:'processQualified',...grant,trustScope:'desktop',scopeQualified:true,profileQualified:false,fixtureOnly:false,executorChallenge:'challenge'});
 const inventory=f.messages.findLast(x=>x.type==='documents');
 assert.equal(inventory.documents.length,0);
 assert.equal(inventory.credentialCandidates.length,1);
 assert.deepEqual(Object.keys(inventory.credentialCandidates[0]).sort(),['browserInstance','documentGeneration','documentId','frameId','origin','profileChannel','tabId']);
 const probe=privateFrame({type:'credentialInspect'});
 for(const key of ['attemptId','controlLease','username','password'])delete probe[key];
 f.messages.length=0;await f.receive(probe);
 assert.equal(f.messages.at(-1)?.ready,true);
 assert.equal(f.state.binds,1);
 await f.receive(command('private-root-acquire','executor.acquire',{attemptId:undefined,locator:undefined,controlLease:{id:'lease-private',generation:1}}));
 assert.equal(f.messages.at(-1).validated,true);
 const before=f.messages.length;await f.receive(command('public-forbidden','observe'));
 assert.equal(f.messages.length,before);
 await f.receive(privateFrame());
 assert.equal(f.messages.at(-1).status,'dispatched');
 assert.ok(!JSON.stringify(f.messages).includes('CANARY'));
 assert.deepEqual(Array.from(f.storage.mechanizeProtectedOrigins),[origin]);
});

test('native host diagnostic maps only exact known messages to static codes',async()=>{
 for(const [message,code] of [['Specified native messaging host not found.','hostNotRegistered'],['Failed to start native messaging host.','hostLaunchFailed'],['Native host has exited.','hostExited'],['Access to the specified native messaging host is forbidden.','hostAccessDenied'],['PASSWORD-CANARY unexpected transport details','nativeHostDisconnected']]){
  const f=await fixture();f.disconnect(message);assert.equal(f.statusMessages.at(-1).attentionCode,code);assert.ok(!JSON.stringify(f.statusMessages).includes('CANARY'));
 }
});
test('retained lifecycle and missing configuration have separate bounded connection diagnostics',async()=>{
 const sender={id:'extension',url:'chrome-extension://extension/options.html',origin:'chrome-extension://extension',frameId:0,tab:{id:8}};
 const retained=await fixture({mechanizeLifecycleInhibited:true});
 const refused=await new Promise(resolve=>retained.runtimeMessage({type:'connectionStatusLocal'},sender,resolve));assert.equal(refused.attentionCode,'lifecycleInhibited');
 const broken=await fixture();broken.disconnect();broken.state.rejectStorageRead='enrollment';
 const unavailable=await new Promise(resolve=>broken.runtimeMessage({type:'connect'},sender,resolve));assert.equal(unavailable.attentionCode,'enrollmentUnavailable');
 assert.ok(!JSON.stringify(unavailable).includes('PRIVATE_FAILURE'));
});

test('private deadline returns unknown once and ignores late renderer resolution',async()=>{
 const f=await privateFixture();let release;f.state.block=new Promise(resolve=>release=resolve);
 await f.receive(privateFrame({deadlineUnixMs:Date.now()+25}));
 assert.equal(f.messages.length,1);assert.equal(f.messages[0].status,'unknown');
 release();await new Promise(resolve=>setImmediate(resolve));assert.equal(f.messages.length,1);
 assert.ok(!JSON.stringify([f.messages,f.storage,f.sessionState]).includes('CANARY'));
});
test('secure admission keeps ordinary output suppressed through lease and delivery',async()=>{
 const f=await privateFixture(),probe=privateFrame({type:'credentialInspect'});for(const key of ['attemptId','controlLease','username','password'])delete probe[key];
 await f.receive(probe);await f.receive(command('blocked-between','observe'));assert.equal(f.messages.length,1);
 await f.receive(command('secure-acquire','executor.acquire',{attemptId:undefined,locator:undefined,controlLease:{id:'lease-private',generation:1}}));
 assert.equal(f.messages.length,2);assert.equal(f.messages[1].validated,true);
 await f.receive(privateFrame());assert.equal(f.messages.at(-1).status,'dispatched');
});
test('fresh inspector matches retained lease without acquiring or adopting changed generation',async()=>{
 for(const mode of ['ready','wrongLease','changedGeneration']){
  const f=await privateFixture(),probe=privateFrame({type:'credentialInspect'});for(const key of ['attemptId','username','password'])delete probe[key];
  if(mode==='wrongLease')probe.controlLease={id:'other',generation:1};
  if(mode==='changedGeneration')f.state.privateReply={ready:true,stage:'pair',privateCredentialProtocolVersion:2,identity:{...identity,documentGeneration:2}};
  const before=f.state.deliveries;await f.receive(probe);assert.equal(f.messages.at(-1).ready,mode==='ready');
  assert.equal(f.state.deliveries-before,mode==='wrongLease'?0:1);
  assert.deepEqual(Object.keys(f.messages.at(-1)).sort(),['identity','privateCredentialProtocolVersion','ready','requestId','stage','type']);
 }
});

test('native startup cause stays closed and survives subsequent host exit',async()=>{
 for(const code of ['brokerPeerUnavailable','brokerPeerAuditUnavailable','brokerProcessUnqualified','brokerHelloUnavailable','brokerHelloRejected','brokerEnrollmentRefused','brokerChannelBusy','brokerScopeUnqualified','brokerHandshakeUnavailable','configUnavailable','processTrustUnavailable','runningImageMismatch','nativeHostSignatureUnavailable','chromeSignatureUnavailable','nativeHostProcessUnavailable','nativeHostUIDUnavailable','nativeHostDynamicSignatureUnavailable','chromeImagePathMismatch','chromeAncestryUnavailable','chromeParentUnavailable','ancestryChanged','launchScopeUnavailable','socketUnavailable','brokerUnavailable','brokerTrustUnavailable','enrollmentCredentialUnavailable','helloIdentityMismatch']){
  const f=await fixture({}, {enroll:false});f.nativeMessage({type:'nativeHostError',code});
  assert.equal(f.statusMessages.at(-1).attentionCode,code);assert.equal(f.messages.length,0);
  const pending=await new Promise(resolve=>f.runtimeMessage({type:'connect'},optionsSender(),resolve));
  assert.equal(pending.connected,false);assert.equal(pending.attentionCode,code);
  f.disconnect('Native host has exited.');assert.equal(f.statusMessages.at(-1).attentionCode,code);
 }
});
test('malformed native startup payload is generic and never forwarded to public command handling',async()=>{
 for(const frame of [{type:'nativeHostError',code:'configUnavailable',secret:'PASSWORD-CANARY'}, {type:'nativeHostError',code:'PASSWORD-CANARY'}, {type:'nativeHostError',code:{toString(){throw Error('PASSWORD-CANARY');}}}]){
  const f=await fixture({}, {enroll:false});f.nativeMessage(frame);assert.equal(f.statusMessages.at(-1).attentionCode,'nativeHostStartupUnavailable');
  assert.ok(!JSON.stringify([f.messages,f.statusMessages,f.storage]).includes('CANARY'));assert.equal(f.messages.length,0);
 }
});
test('stale native ports and post-forwarding startup frames cannot replace current diagnosis',async()=>{
 const f=await fixture({}, {enroll:false});f.nativeMessage({type:'nativeHostError',code:'configUnavailable'});f.disconnect('Native host has exited.');
 await new Promise(resolve=>f.runtimeMessage({type:'connect'},optionsSender(),resolve));
 const before=f.statusMessages.length;f.nativeMessage({type:'nativeHostError',code:'brokerTrustUnavailable'},0);f.state.nativePorts[0].disconnect();assert.equal(f.statusMessages.length,before);
 f.nativeMessage({type:'enrolled',...grant});await new Promise(resolve=>setImmediate(resolve));
 const qualified=f.statusMessages.length;f.nativeMessage({type:'nativeHostError',code:'brokerUnavailable'});assert.equal(f.statusMessages.length,qualified);
 f.disconnect('Native host has exited.');assert.equal(f.statusMessages.at(-1).attentionCode,'hostExited');
});

test('quarantined private submit advances only exact same-origin new root with scalar password stage',async()=>{
 const f=await privateFixture();await f.receive(privateFrame());const submit=privateSubmitFrame();await f.receive(submit);
 assert.equal(f.messages.at(-1).type,'credentialSubmitResult');assert.equal(f.messages.at(-1).status,'dispatched');
 const calls=f.state.deliveries;await f.receive({...submit,attemptId:'c'.repeat(64)});assert.equal(f.state.deliveries,calls);
 f.state.documentId='private-next';
 const advance={...submit,type:'credentialAdvance',requestId:'d'.repeat(64),nextLease:{id:'private-next-lease',generation:2}};delete advance.fillAttemptId;
 await f.receive(advance);const reply=f.messages.at(-1);assert.equal(reply.type,'credentialAdvanceResult');assert.equal(reply.ready,true);assert.equal(reply.stage,'password');assert.equal(reply.identity.documentId,'private-next');
 assert.deepEqual(Object.keys(reply).sort(),['attemptId','identity','ready','requestId','stage','type']);
 assert.ok(!JSON.stringify([f.messages,f.storage,f.sessionState]).includes('CANARY'));
 const output=f.messages.length;await f.receive(command('ordinary-after-private','observe'));assert.equal(f.messages.length,output);
});
test('private continuation refuses foreign navigation and never forwards value-bearing renderer result',async()=>{
 for(const mode of ['foreign','echo']) {
 const f=await privateFixture();await f.receive(privateFrame());const submit=privateSubmitFrame();await f.receive(submit);f.state.documentId='private-next';
 if(mode==='foreign')f.state.frameURL='https://other.example.test/login';else f.state.privateReply={ready:true,stage:'password',identity:{...identity,documentId:'private-next'},value:'PASSWORD-CANARY'};
 const advance={...submit,type:'credentialAdvance',requestId:'d'.repeat(64),nextLease:{id:'private-next-lease',generation:2}};delete advance.fillAttemptId;
 await f.receive(advance);assert.equal(f.messages.at(-1).ready,false);assert.ok(!JSON.stringify(f.messages).includes('CANARY'));
 }
});

test('private submit lost acknowledgement remains unknown and cannot be retried',async()=>{
 const f=await privateFixture();await f.receive(privateFrame());f.state.privateReply={status:'dispatched',value:'PASSWORD-CANARY'};
 await f.receive(privateSubmitFrame());assert.equal(f.messages.at(-1).status,'unknown');const calls=f.state.deliveries;
 await f.receive({...privateSubmitFrame(),attemptId:'e'.repeat(64)});assert.equal(f.state.deliveries,calls);assert.ok(!JSON.stringify(f.messages).includes('CANARY'));
});
test('private submit cancellation cannot reply into a replacement connection',async()=>{
 const f=await privateFixture();await f.receive(privateFrame());const before=f.messages.length;let release;f.state.block=new Promise(r=>release=r);
 const running=f.receive(privateSubmitFrame());await new Promise(r=>setImmediate(r));f.disconnect();release();await running;
 assert.equal(f.messages.length,before);assert.ok(!JSON.stringify(f.messages).includes('CANARY'));
});

test('DOM privacy remains closed until explicit broker commit and redacts ordinary replies',async()=>{
 const f=await privateFixture();await f.receive(privateFrame());await f.receive(privateSubmitFrame());f.state.documentId='privacy-doc';
 const proof=privacyFrame();await f.receive(proof);let response=f.messages.at(-1);assert.equal(response.type,'credentialPrivacyResult');assert.equal(response.ready,true);
 const count=f.messages.length;await f.receive(command('blocked','observe',{identity:response.identity}));assert.equal(f.messages.length,count);
 const commit={...proof,type:'credentialPrivacyCommit',requestId:'e'.repeat(64),identity:response.identity};await f.receive(commit);assert.equal(f.messages.at(-1).ready,true);
 f.state.publicReply={requestId:'safe-observe',identity:response.identity,value:'PASSWORD-CANARY',nodes:[{name:Buffer.from('USERNAME-CANARY').toString('base64'),text:'Transaction 123.45'}]};
 await f.receive(command('safe-observe','observe',{identity:response.identity}));response=f.messages.at(-1);
 assert.equal(response.value,'[redacted]');assert.equal(response.nodes[0].name,'[redacted]');assert.equal(response.nodes[0].text,'Transaction 123.45');
 assert.ok(!JSON.stringify([f.messages,f.storage,f.sessionState]).includes('CANARY'));
 const observations=f.state.deliveries;await f.receive(command('no-record','record.start',{identity:response.identity}));assert.equal(f.state.deliveries,observations);
});

test('browser pointer input accepts only the exact committed private DOM permit',async()=>{
 for(const committed of [false,true]) {
  const f=await privateFixture(true);await f.receive(privateFrame());await f.receive(privateSubmitFrame());f.state.documentId='privacy-doc';
  const proof=privacyFrame();await f.receive(proof);const id=f.messages.at(-1).identity;
  if(committed)await f.receive({...proof,type:'credentialPrivacyCommit',requestId:'e'.repeat(64),identity:id});
  const lease={id:'public-private-dom-lease',generation:2};
  if(committed){f.state.publicReply={requestId:'acquire-private-dom',identity:id,validated:true,controlLease:lease};await f.receive(command('acquire-private-dom','executor.acquire',{identity:id,attemptId:undefined,locator:undefined,controlLease:lease}));delete f.state.publicReply;}
  f.state.renderer=async(_,cmd)=>{
   if(cmd.action!=='element.press')throw Error('unexpected fixture command');
   return new Promise(resolve=>{
    const local={type:'browserInputLocal',requestId:cmd.requestId,attemptId:cmd.attemptId,deadlineUnixMs:cmd.deadlineUnixMs,action:'click',point:{x:20,y:20}};
    for(const listener of f.state.runtimeListeners)listener(local,{id:'extension',tab:{id:7},frameId:0,documentId:'privacy-doc'},r=>resolve({requestId:cmd.requestId,attemptId:cmd.attemptId,identity:id,...r}));
   });
  };
  const c=command('private-dom-pointer','element.press',{identity:id,locator:{strategy:'id',value:'save',exact:true},attemptId:'9'.repeat(64),controlLease:lease,fingerprintVersion:2,deadlineUnixMs:Date.now()+2000});
  c.fingerprintSHA256=(await require('../fingerprint.js').mutationV2(c)).sha256;
  await f.receive(c);
  assert.equal((f.state.debuggerInputs||[]).length,committed?3:0,JSON.stringify(f.messages.slice(-2).map(r=>({code:r.error?.code,state:r.dispatchState,errorCode:r.errorCode,validated:r.validated,document:r.identity?.documentId}))));
  assert.ok(!JSON.stringify(f.messages).includes('CANARY'));
 }
});
test('DOM privacy does not survive document replacement or missing retirement/redaction proof',async()=>{
 for(const mode of ['missingRetirement','echo']){
 const f=await privateFixture();await f.receive(privateFrame());await f.receive(privateSubmitFrame());f.state.documentId='privacy-doc';
 const request=privacyFrame();f.state.privateReply={ready:true,redactionReady:true,privateInputRetired:mode!=='missingRetirement',permitId:request.permitId,identity:{...identity,documentId:'privacy-doc'}};
 if(mode==='echo')f.state.privateReply.value='PASSWORD-CANARY';await f.receive(request);assert.equal(f.messages.at(-1).ready,false);assert.ok(!JSON.stringify(f.messages).includes('CANARY'));
 }
});
test('privacy qualification permits bounded read-only settling without repeating credential submission',async()=>{
 const f=await privateFixture();await f.receive(privateFrame());await f.receive(privateSubmitFrame());f.state.documentId='privacy-doc';
 const request=privacyFrame();f.state.privateReply={ready:false,redactionReady:true,privateInputRetired:true,permitId:request.permitId,identity:{...identity,documentId:'privacy-doc'}};
 f.state.privacyReadHook=n=>{if(n===2)f.state.privateReply=undefined;};
 await f.receive(request);
 assert.equal(f.messages.at(-1).ready,true);assert.equal(f.state.privacyReads,2);assert.equal(f.state.privateSubmits,1);
 // Binding alone still cannot admit ordinary control before broker commit.
 const before=f.messages.length;await f.receive(command('still-private','observe'));assert.equal(f.messages.length,before);
});
test('privacy settling never retries missing redaction or retirement proof',async()=>{
 for(const field of ['redactionReady','privateInputRetired']){
 const f=await privateFixture();await f.receive(privateFrame());await f.receive(privateSubmitFrame());f.state.documentId='privacy-doc';
 const request=privacyFrame();f.state.privateReply={ready:false,redactionReady:true,privateInputRetired:true,permitId:request.permitId,identity:{...identity,documentId:'privacy-doc'},[field]:false};
 await f.receive(request);assert.equal(f.messages.at(-1).ready,false);assert.equal(f.state.privacyReads,1);assert.equal(f.state.privateSubmits,1);
 }
});
test('privacy settling stays protected when its bounded readiness deadline expires',async()=>{
 const f=await privateFixture();await f.receive(privateFrame());await f.receive(privateSubmitFrame());f.state.documentId='privacy-doc';
 const request={...privacyFrame(),deadlineUnixMs:Date.now()+350};
 f.state.privateReply={ready:false,redactionReady:true,privateInputRetired:true,permitId:request.permitId,identity:{...identity,documentId:'privacy-doc'}};
 await f.receive(request);assert.equal(f.messages.at(-1).ready,false);assert.ok(f.state.privacyReads<=3);assert.equal(f.state.privateSubmits,1);
 const before=f.messages.length;await f.receive(command('deadline-private','observe'));assert.equal(f.messages.length,before);
});

test('quarantined reverse controller forwards only opaque credential refs and owned-session close',async()=>{
 const f=await privateFixture();await f.receive(privateFrame());const count=f.messages.length;
 const envelope={type:'controllerRequest',requestId:'request',operation:'tools/call',deadlineUnixMs:Date.now()+1000,origin:'https://controller.example.test',documentId:'controller-doc',sessionId:'approved-port',...grant};
 f.privateControllerSend({...envelope,params:{name:'mechanize_credential_status',arguments:{sessionId:'runtime-session',preparationId:'a'.repeat(64)}}});assert.equal(f.messages.length,count+1);
 f.privateControllerSend({...envelope,params:{name:'mechanize_session_close',arguments:{sessionId:'runtime-session'}}});assert.equal(f.messages.length,count+2);
 for(const params of [{name:'mechanize_observe',arguments:{sessionId:'runtime-session'}},{name:'mechanize_credential_apply',arguments:{sessionId:'runtime-session',preparationId:'a'.repeat(64),value:'PASSWORD-CANARY'}},{name:'mechanize_credential_prepare',arguments:{sessionId:'runtime-session',surface:{}}}])f.privateControllerSend({...envelope,params});
 assert.equal(f.messages.length,count+2);assert.ok(!JSON.stringify(f.messages).includes('CANARY'));
});

test('typed native challenge retains quarantine for a later explicit same-origin private reprobe',async()=>{
 const f=await privateFixture();await f.receive(privateFrame());const submit=privateSubmitFrame();await f.receive(submit);f.state.documentId='private-challenge';
 f.state.privateReply={identity:{...identity,documentId:'private-challenge'},ready:false,stage:'challenge'};
 const advance={...submit,type:'credentialAdvance',nextLease:{id:'challenge-lease',generation:2}};delete advance.fillAttemptId;
 await f.receive(advance);assert.equal(f.messages.at(-1).stage,'challenge');assert.equal(f.messages.at(-1).ready,false);
 const count=f.messages.length;await f.receive(command('ordinary-challenge','observe'));assert.equal(f.messages.length,count);
 f.state.privateReply={identity:{...identity,documentId:'private-challenge',documentGeneration:2},ready:true,stage:'password'};
 await f.receive({...advance,requestId:'f'.repeat(64),nextLease:{id:'post-human-lease',generation:3}});assert.equal(f.messages.at(-1).ready,true);assert.equal(f.messages.at(-1).stage,'password');assert.ok(!JSON.stringify(f.messages).includes('CANARY'));
});

test('fresh DOM verify reports typed document change without granting new document access',async()=>{
 const f=await privateFixture();await f.receive(privateFrame());await f.receive(privateSubmitFrame());f.state.documentId='privacy-one';
 const qualify=privacyFrame();await f.receive(qualify);const first=f.messages.at(-1).identity;
 await f.receive({...qualify,type:'credentialPrivacyCommit',identity:first});assert.equal(f.messages.at(-1).ready,true);
 f.state.documentId='privacy-two';await f.receive({...qualify,type:'credentialPrivacyVerify',identity:first,requestId:'e'.repeat(64)});
 const changed=f.messages.at(-1);assert.equal(changed.ready,false);assert.equal(changed.documentChanged,true);assert.equal(changed.identity.documentId,'privacy-two');assert.equal(changed.retiredAuthorityQuiesced,true);assert.equal(changed.redactionReady,true);
 const count=f.messages.length;await f.receive(command('denied-new','observe',{identity:changed.identity}));assert.equal(f.messages.length,count);
 const next={...qualify,identity:first,permitId:'d'.repeat(64),requestId:'c'.repeat(64)};await f.receive(next);const second=f.messages.at(-1);assert.equal(second.ready,true);
 await f.receive({...next,type:'credentialPrivacyCommit',identity:second.identity,requestId:'b'.repeat(64)});assert.equal(f.messages.at(-1).ready,true);
});
test('stale private inspector code cannot negotiate credential protocol v2 before any values',async()=>{
 for(const reply of [{ready:true,stage:'pair',identity},{ready:true,stage:'pair',identity,privateCredentialProtocolVersion:1}]){
 const f=await privateFixture();f.state.privateReply=reply;const probe=privateFrame({type:'credentialInspect'});for(const k of ['attemptId','username','password','controlLease'])delete probe[k];await f.receive(probe);assert.equal(f.messages.at(-1).ready,false);assert.ok(!JSON.stringify(f.messages).includes('CANARY'));
 }
});

const restartQualification=()=>({...desktopQualification(),fixtureOnly:false,mutationFingerprintVersion:2});
async function reconnectFixture(){
 const f=await fixture({}, {enroll:false});f.state.boundFingerprintVersion=2;f.state.inventoryTabs=[{id:7,url:f.state.url,title:'Public fixture'}];
 await f.receive(restartQualification());f.messages.length=0;f.disconnect();await f.connect();f.messages.length=0;f.state.reconnectSupported=true;return f;
}
test('trusted fresh native connection adopts changed epoch only after renderer proof and retains history',async()=>{
 const f=await reconnectFixture();f.state.reconnectRevision=3;
 await f.receive({...restartQualification(),brokerEpoch:'broker2',channelEpoch:'channel2',executorChallenge:'fresh-challenge'});
 assert.deepEqual(f.state.reconnectCalls.map(x=>x.phase),['inspect','prepare','adopt']);
 assert.equal(f.storage.lastGrant.brokerEpoch,'broker2');assert.equal(f.storage.mechanizeReconnect.phase,'adopted');
 assert.equal(f.storage.mechanizeReconnect.history[0].oldFence.brokerEpoch,'broker1');assert.equal(f.storage.mechanizeReconnect.history[0].executors[0].receiptCount,3);
 assert.ok(f.messages.some(x=>x.type==='executorPrepared'&&x.executorChallenge==='fresh-challenge'));assert.equal(f.state.deliveries,0);
 f.disconnect();await f.connect();f.messages.length=0;
 await f.receive({...restartQualification(),brokerEpoch:'broker3',channelEpoch:'channel3',executorChallenge:'next-challenge'});
 assert.equal(f.storage.mechanizeReconnect.history.length,1);assert.equal(JSON.parse(f.storage['mechanizeReconnectAudit:'+f.storage.mechanizeReconnect.audit.digest].journalJSON).history[0].oldFence.brokerEpoch,'broker1');
});
test('reconnect refuses changed scope unknown/private/recording proofs and old content without deleting lastGrant',async()=>{
 for(const mode of ['scope','private','unknown','recording','oldContent']){
  const f=await reconnectFixture();const before=JSON.stringify(f.storage.lastGrant);
  if(mode==='private')f.storage.mechanizeProtectedOrigins=['https://fixture.example.test'];
  if(mode==='unknown')f.sessionState['browserIntent:retained']={};
  if(mode==='recording')f.state.reconnectError='inspect';
  if(mode==='oldContent')f.state.reconnectSupported=false;
  await f.receive({...restartQualification(),brokerEpoch:'broker2',channelEpoch:'channel2',...(mode==='scope'?{scopeHash:'b'.repeat(64)}:{})});
  assert.equal(JSON.stringify(f.storage.lastGrant),before,mode);assert.equal(f.storage.mechanizeReconnect,undefined,mode);
  assert.equal(f.messages.at(-1).error.code,'storedFenceMismatch',mode);assert.equal(f.state.deliveries,0);
 }
});
test('uncertain renderer adoption or storage commit retains pending inhibition and cannot requalify',async()=>{
 for(const mode of ['adopt','commit','nonce']){
  const f=await reconnectFixture();if(mode==='adopt')f.state.reconnectError='adopt';if(mode==='commit')f.state.rejectReconnectCommit=true;if(mode==='nonce')f.state.badReconnectNonce=true;
  await f.receive({...restartQualification(),brokerEpoch:'broker2',channelEpoch:'channel2'});
  assert.equal(f.storage.mechanizeReconnect.phase,'pending',mode);assert.equal(f.storage.lastGrant.brokerEpoch,'broker1',mode);
  assert.ok(!f.messages.some(x=>x.type==='executorPrepared'),mode);f.disconnect();await f.connect();
  assert.equal(f.state.nativeConnections,3);assert.deepEqual(Array.from(f.messages.at(-1).documents),[]);f.messages.length=0;await f.receive({...restartQualification(),brokerEpoch:'blocked',channelEpoch:'blocked'});assert.ok(!f.messages.some(m=>m.type==='executorPrepared'));assert.equal(f.state.deliveries,0);
 }
});
test('native peer change while proof is pending cannot commit a new fence',async()=>{
 const f=await reconnectFixture();let release;f.state.blockReconnectPhase='prepare';f.state.reconnectBlock=new Promise(resolve=>{release=resolve});
 const pending=f.receive({...restartQualification(),brokerEpoch:'broker2',channelEpoch:'channel2'});
 while(!f.state.reconnectCalls?.some(x=>x.phase==='prepare'))await new Promise(resolve=>setImmediate(resolve));
 f.disconnect();release();await pending;
 assert.equal(f.storage.lastGrant.brokerEpoch,'broker1');assert.equal(f.storage.mechanizeReconnect.phase,'pending');assert.ok(!f.messages.some(x=>x.type==='executorPrepared'));
});

async function interruptedReconnectFixture() {
 const f=await reconnectFixture();f.state.reconnectError='adopt';
 await f.receive({...restartQualification(),brokerEpoch:'abandoned-broker',channelEpoch:'abandoned-channel'});
 // Seed the legacy v1 representation for migration tests. New active-format
 // production is covered separately; this fixture preserves old stored data.
 delete f.storage.mechanizeReconnect.format;delete f.storage.mechanizeReconnect.recoveryFences;delete f.storage.mechanizeReconnect.audit;
 const original=JSON.parse(JSON.stringify(f.storage.mechanizeReconnect));
 assert.equal(original.phase,'pending');f.disconnect();f.state.inventoryTabs=[];delete f.state.reconnectError;
 return {...f,original};
}
test('storage dictionary key reordering preserves reconnect authority and completes readback',async()=>{
 const f=await reconnectFixture();f.state.sortedStorage=true;
 await f.receive({...restartQualification(),brokerEpoch:'sorted-broker',channelEpoch:'sorted-channel'});
 assert.equal(f.storage.mechanizeReconnect.phase,'adopted');assert.ok(f.messages.some(x=>x.type==='executorPrepared'));
});
async function interruptedEmptyRecoveryFixture() {
 const f=await interruptedReconnectFixture();f.state.sortedStorage=true;await f.connect();
 f.state.afterPendingWrite=()=>f.disconnect();
 await f.receive({...restartQualification(),brokerEpoch:'interrupted-empty',channelEpoch:'interrupted-empty'});
 delete f.state.afterPendingWrite;
 delete f.storage.mechanizeReconnect.format;delete f.storage.mechanizeReconnect.recoveryFences;delete f.storage.mechanizeReconnect.audit;f.storage.mechanizeReconnect.version=2;f.storage.mechanizeReconnect.recovery={kind:'emptySetupDocuments',originalPending:structuredClone(f.original)};
 assert.equal(f.storage.mechanizeReconnect.version,2);assert.equal(f.storage.mechanizeReconnect.phase,'pending');
 assert.equal(f.storage.lastGrant.brokerEpoch,'broker1');
 return {...f,interrupted:JSON.parse(JSON.stringify(f.storage.mechanizeReconnect))};
}
test('interrupted v2 empty preparation recovers with sorted storage and retains the entire v2 and v1 lineage',async()=>{
 const f=await interruptedEmptyRecoveryFixture();await f.connect();f.messages.length=0;
 await f.receive({...restartQualification(),brokerEpoch:'recovered-v3',channelEpoch:'recovered-v3'});
 assert.equal(f.storage.mechanizeReconnect.version,1);assert.equal(f.storage.mechanizeReconnect.phase,'adopted');
 assert.deepEqual(JSON.parse(JSON.stringify(auditOriginal(f))),f.interrupted);
 assert.deepEqual(JSON.parse(JSON.stringify(auditOriginal(f).recovery.originalPending)),f.original);
 assert.ok(f.messages.some(x=>x.type==='executorPrepared'));assert.equal(f.state.deliveries,0);
 f.disconnect();await f.connect();f.messages.length=0;
 await f.receive({...restartQualification(),brokerEpoch:'later-v3',channelEpoch:'later-v3'});
 assert.equal(f.storage.mechanizeReconnect.history.length,1);assert.deepEqual(JSON.parse(JSON.stringify(auditOriginal(f,auditOriginal(f)))),f.interrupted);
 assert.ok(f.messages.some(x=>x.type==='executorPrepared'));
});
test('v2 recovery refuses committed or malformed lineage, fresh websites and all private or unknown barriers',async()=>{
 for(const mode of ['grantNew','appended','lineage','extra','website','unknown','private','lifecycle','sameFence']){
  const f=await interruptedEmptyRecoveryFixture();
  if(mode==='grantNew')Object.assign(f.storage.lastGrant,f.storage.mechanizeReconnect.newFence);
  if(mode==='appended'){const j=f.storage.mechanizeReconnect;j.history.push({nonce:j.nonce,oldFence:j.oldFence,newFence:j.newFence,executors:[]});}
  if(mode==='lineage')f.storage.mechanizeReconnect.recovery.originalPending.oldFence.channelEpoch='foreign';
  if(mode==='extra')f.storage.mechanizeReconnect.recovery.extra=true;
  if(mode==='website')f.state.inventoryTabs=[{id:1,url:'https://outside.example.test'}];
  const before=JSON.stringify(f.storage.mechanizeReconnect);await f.connect();f.messages.length=0;
  if(mode==='unknown')f.sessionState['browserIntent:unknown']={};
  if(mode==='private')f.sessionState.mechanizeProtectedOrigins=['https://fixture.example.test'];
  if(mode==='lifecycle')f.sessionState.mechanizeLifecycleInhibited=true;
  assert.equal(f.state.nativeConnections,4,mode);
  await f.receive({...restartQualification(),brokerEpoch:mode==='sameFence'?'broker1':'next',channelEpoch:mode==='sameFence'?'channel1':'next'});
  assert.ok(!f.messages.some(x=>x.type==='executorPrepared'),mode);assert.equal(JSON.stringify(f.storage.mechanizeReconnect),before,mode);assert.equal(f.state.deliveries,0);
 }
});
test('canonical storage comparison still refuses changed authority fields and array order',async()=>{
 for(const mode of ['fence','extra','array']){
  const f=await interruptedReconnectFixture();f.state.sortedStorage=true;f.storage.enrollment.origins.push('https://second.example.test');await f.connect();f.messages.length=0;
  if(mode==='fence')f.state.afterPendingWrite=()=>{f.storage.mechanizeReconnect.oldFence.channelEpoch='foreign';};
  if(mode==='extra')f.state.afterPendingWrite=()=>{f.storage.mechanizeReconnect.extra=true;};
  if(mode==='array')f.state.afterReconnectCommit=()=>{f.storage.enrollment.origins.reverse();};
  await f.receive({...restartQualification(),brokerEpoch:'canonical',channelEpoch:'canonical'});
  assert.ok(!f.messages.some(x=>x.type==='executorPrepared'),mode);assert.equal(f.storage.mechanizeReconnect.phase,'pending',mode);
  assert.equal(f.diagnostic().reason,mode==='array'?'scopeChanged':'journalChanged',mode);
 }
});
test('legacy pending recovery requires fresh native qualification and empty inventory, preserving the entire original record',async()=>{
 const f=await interruptedReconnectFixture();
 f.state.inventoryTabs=[{id:1,url:'chrome://extensions/'},{id:2,url:'chrome-extension://extension/options.html'}];
 await f.connect();assert.equal(f.state.nativeConnections,3);assert.deepEqual(JSON.parse(JSON.stringify(f.storage.mechanizeReconnect)),f.original);
 f.messages.length=0;
 await f.receive({...restartQualification(),brokerEpoch:'recovered-broker',channelEpoch:'recovered-channel'});
 const recovered=f.storage.mechanizeReconnect;
 assert.equal(recovered.format,'activeHandoff');assert.equal(recovered.version,1);assert.equal(recovered.phase,'adopted');assert.deepEqual(JSON.parse(JSON.stringify(auditOriginal(f,recovered))),f.original);
 assert.equal(recovered.newFence.brokerEpoch,'recovered-broker');assert.equal(recovered.history.at(-1).executors.length,0);
 assert.ok(f.messages.some(x=>x.type==='executorPrepared'));assert.equal(f.state.deliveries,0);
 f.disconnect();await f.connect();f.messages.length=0;
 await f.receive({...restartQualification(),brokerEpoch:'later-broker',channelEpoch:'later-channel'});
 assert.equal(f.storage.mechanizeReconnect.history.length,1);assert.deepEqual(JSON.parse(JSON.stringify(auditOriginal(f,auditOriginal(f)))),f.original);
});
test('pending startup refuses websites outside scope, incomplete tabs, pending navigation and malformed journals',async()=>{
 for(const mode of ['website','outsideScope','missingURL','pendingURL','incognito','discarded','unknownPage','scope','history','extra','nonce','v2Pending']){
  const f=await interruptedReconnectFixture();
  if(mode==='website'||mode==='outsideScope')f.state.inventoryTabs=[{id:7,url:mode==='website'?f.state.url:'https://outside.example.test/'}];
  if(mode==='missingURL')f.state.inventoryTabs=[{id:7}];
  if(mode==='pendingURL')f.state.inventoryTabs=[{id:7,url:'chrome://extensions/',pendingUrl:'https://fixture.example.test/'}];
  if(mode==='incognito'||mode==='discarded')f.state.inventoryTabs=[{id:7,url:'chrome://extensions/',[mode]:true}];
  if(mode==='unknownPage')f.state.inventoryTabs=[{id:7,url:'about:blank'}];
  if(mode==='scope')f.storage.mechanizeReconnect.oldFence.scopeHash='b'.repeat(64);
  if(mode==='history')f.storage.mechanizeReconnect.history=[{}];
  if(mode==='extra')f.storage.mechanizeReconnect.extra=true;
  if(mode==='nonce')f.storage.mechanizeReconnect.nonce='malformed';
  if(mode==='v2Pending')f.storage.mechanizeReconnect.version=2;
  const before=JSON.stringify(f.storage);await f.connect();assert.equal(f.state.nativeConnections,3,mode);assert.deepEqual(Array.from(f.messages.at(-1).documents),[]);await f.receive({...restartQualification(),brokerEpoch:'blocked-new',channelEpoch:'blocked-new'});assert.ok(!f.messages.some(m=>m.type==='executorPrepared'));assert.equal(f.state.deliveries,0);assert.equal(JSON.stringify(f.storage),before,mode);
 }
});
test('pending recovery retains prior executor receipt lineage and rejects a mismatched history tail',async()=>{
 for(const mismatch of [false,true]){
  const f=await interruptedReconnectFixture();
  const history=[{nonce:'e'.repeat(64),oldFence:{...grant,brokerEpoch:'prior',channelEpoch:'prior'},newFence:{...grant},executors:[{identity,receiptRevision:3,receiptCount:3}]}];
  f.storage.mechanizeReconnect.history=history;
  if(mismatch)history[0].newFence.channelEpoch='unrelated';
  const original=JSON.parse(JSON.stringify(f.storage.mechanizeReconnect));await f.connect();
  if(mismatch){assert.equal(f.state.nativeConnections,3);await f.receive({...restartQualification(),brokerEpoch:'blocked-new',channelEpoch:'blocked-new'});assert.ok(!f.messages.some(m=>m.type==='executorPrepared'));assert.deepEqual(JSON.parse(JSON.stringify(f.storage.mechanizeReconnect)),original);continue;}
  f.messages.length=0;await f.receive({...restartQualification(),brokerEpoch:'recovered',channelEpoch:'recovered'});
  assert.ok(f.messages.some(x=>x.type==='executorPrepared'));assert.equal(auditOriginal(f).history[0].executors[0].receiptCount,3);
  assert.deepEqual(JSON.parse(JSON.stringify(auditOriginal(f))),original);
 }
});
test('empty recovery refuses changed qualification, unknown browser receipts and retained private/lifecycle barriers',async()=>{
 for(const mode of ['scope','fixture','sameOldFence','unknown','unknownEffect','orphan','private','sessionPrivate','lifecycle','retirement']){
  const f=await interruptedReconnectFixture();await f.connect();f.messages.length=0;
  const qualification={...restartQualification(),brokerEpoch:'recovered',channelEpoch:'recovered'};
  if(mode==='scope')qualification.scopeHash='b'.repeat(64);
  if(mode==='fixture')qualification.fixtureOnly=true;
  if(mode==='sameOldFence')Object.assign(qualification,grant);
  if(mode==='unknown')f.sessionState['browserIntent:unknown']={};
  if(mode==='unknownEffect'){f.sessionState['browserIntent:unknown']={};f.sessionState['browserReceipt:unknown']={dispatchState:'dispatched',error:{effectState:'unknown'}};}
  if(mode==='orphan')f.sessionState['browserReceipt:unknown']={dispatchState:'unknown'};
  if(mode==='private')f.storage.mechanizeProtectedOrigins=['https://fixture.example.test'];
  if(mode==='sessionPrivate')f.sessionState.mechanizeProtectedOrigins=['https://fixture.example.test'];
  if(mode==='lifecycle')f.sessionState.mechanizeLifecycleInhibited=true;
  if(mode==='retirement')f.storage.mechanizeRetirementV1={phase:'pending'};
  await f.receive(qualification);
  assert.ok(!f.messages.some(x=>x.type==='executorPrepared'),mode);assert.deepEqual(JSON.parse(JSON.stringify(f.storage.mechanizeReconnect)),f.original,mode);
  assert.equal(f.state.deliveries,0,mode);
 }
});
test('empty recovery retains inhibition if inventory changes, storage fails or native port disappears during commit',async()=>{
 for(const mode of ['inventory','storage','port','scopeDuringCommit','privateDuringCommit','readback','setupChange']){
  const f=await interruptedReconnectFixture();await f.connect();f.messages.length=0;
  if(mode==='storage')f.state.rejectReconnectCommit=true;
  if(mode==='inventory'){const start=f.state.inventoryReads;f.state.inventoryHook=n=>{if(n>=start+3)f.state.inventoryTabs=[{id:7,url:'https://outside.example.test/'}];};}
  if(mode==='scopeDuringCommit')f.state.afterReconnectCommit=()=>{f.storage.enrollment.profileChannel='changed';};
  if(mode==='privateDuringCommit')f.state.afterReconnectCommit=()=>{f.sessionState.mechanizeProtectedOrigins=['https://fixture.example.test'];};
  if(mode==='readback')f.state.afterReconnectCommit=()=>{f.state.rejectStorageRead='lastGrant';};
  if(mode==='setupChange')f.state.afterReconnectCommit=()=>{f.state.inventoryTabs=[{id:7,url:'chrome://extensions/'}];};
  let release;if(mode==='port')f.state.blockReconnectCommit=new Promise(resolve=>release=resolve);
  const receiving=f.receive({...restartQualification(),brokerEpoch:'recovered',channelEpoch:'recovered'});
  if(mode==='port'){while(!f.state.commitEntered)await new Promise(resolve=>setImmediate(resolve));f.disconnect();release();}
  await receiving;assert.ok(!f.messages.some(x=>x.type==='executorPrepared'),mode);
  assert.equal(f.storage.mechanizeReconnect.phase,['port','readback'].includes(mode)?'adopted':'pending',mode);
  await f.verifyArchives(f.storage.mechanizeReconnect);assert.equal(f.storage.mechanizeReconnect.phase==='pending'?f.pendingReconnectValid(f.storage.mechanizeReconnect,f.storage.lastGrant):true,true,mode);
  const original=f.storage.mechanizeReconnect.format==='activeHandoff'?auditOriginal(f):f.storage.mechanizeReconnect.recovery?.originalPending||f.storage.mechanizeReconnect;
  assert.deepEqual(JSON.parse(JSON.stringify(original)),f.original,mode);assert.equal(f.state.deliveries,0,mode);
  assert.equal(f.pendingReconnectValid(f.storage.mechanizeReconnect,f.storage.lastGrant)||f.journalValid(f.storage.mechanizeReconnect,f.storage.lastGrant),true,mode);
  if(['storage','readback','setupChange','port'].includes(mode)){
   delete f.state.afterReconnectCommit;delete f.state.rejectStorageRead;f.state.rejectReconnectCommit=false;f.state.blockReconnectCommit=null;f.state.inventoryTabs=[];
   f.disconnect();await f.connect();f.messages.length=0;await f.receive({...restartQualification(),brokerEpoch:'recovered-after-'+mode,channelEpoch:'recovered-after-'+mode});assert.equal(f.messages.some(m=>m.type==='executorPrepared'),true,mode);
  }
 }
});
test('reconnect diagnostics classify exact barrier failures without releasing retained state',async()=>{
 for(const mode of ['unknownReceipts','privateProtection','lifecycle','storageFailure','busy','scopeChanged','inventoryChanged']){
  const f=await interruptedReconnectFixture();await f.connect();f.messages.length=0;
  if(mode==='unknownReceipts')f.sessionState['browserReceipt:orphan']={dispatchState:'dispatched'};
  if(mode==='privateProtection')f.sessionState.mechanizeProtectedOrigins=['https://fixture.example.test'];
  if(mode==='lifecycle')f.sessionState.mechanizeLifecycleInhibited=true;
  if(mode==='storageFailure')f.state.rejectStorageRead='mechanizeProtectedOrigins';
  if(mode==='busy')f.setActiveCommands(1);
  if(mode==='scopeChanged')f.state.afterReconnectCommit=()=>{f.storage.enrollment.profileChannel='changed';};
  if(mode==='inventoryChanged')f.state.afterReconnectCommit=()=>{f.state.inventoryTabs=[{id:1,url:'https://outside.example.test'}];};
  await f.receive({...restartQualification(),brokerEpoch:'diagnostic',channelEpoch:'diagnostic'});
  assert.equal(f.diagnostic().reason,mode,mode);
  if(['unknownReceipts','privateProtection','lifecycle','storageFailure','busy'].includes(mode))assert.equal(f.diagnostic().phase,'barriers',mode);
  assert.ok(!f.messages.some(x=>x.type==='executorPrepared'),mode);assert.equal(f.storage.mechanizeReconnect.phase,'pending',mode);
 }
});

test('real packaged content and worker complete reconnect with retained receipt and no input replay',async t=>{
 const {JSDOM}=require('jsdom'),dom=new JSDOM('<button id="save">Save</button>',{url:'https://fixture.example.test/page',runScripts:'outside-only'}),w=dom.window;
 t.after(()=>w.close());w.TextEncoder=TextEncoder;Object.defineProperty(w,'crypto',{value:require('node:crypto').webcrypto,configurable:true});w.HTMLElement.prototype.getClientRects=()=>[{width:100,height:20}];
 let listener;w.chrome={runtime:{id:'extension',onMessage:{addListener:f=>listener=f}}};
 for(const file of ['protocol.js','fingerprint.js','accessibility-provider.js','dom.js','recorder.js','secure-input.js','content.js'])w.eval(fs.readFileSync(path.join(__dirname,'..',file),'utf8'));
 const f=await fixture({debuggerAttachDelay:1100}, {enroll:false});f.state.inventoryTabs=[{id:7,url:f.state.url,title:'Public fixture'}];
 f.state.renderer=(_,message)=>new Promise(resolve=>{
  if(message.type==='brokerReconnect'&&message.phase==='adopt')w.document.body.appendChild(w.document.createElement('div'));
  listener(JSON.parse(JSON.stringify(message)),{id:'extension',url:'chrome-extension://extension/worker.js'},value=>resolve(JSON.parse(JSON.stringify(value))));
 });
 await f.receive(restartQualification());assert.ok(f.messages.some(x=>x.type==='executorPrepared'));
 const lease={id:'old-lease',generation:1},base={identity,...grant,deadlineUnixMs:Date.now()+5000};
 await f.receive({...base,requestId:'acquire-old',action:'executor.acquire',controlLease:lease});
 let clicks=0;w.document.querySelector('#save').onclick=()=>clicks++;
 const action={...base,requestId:'old-input',action:'element.press',attemptId:'c'.repeat(64),locator:{strategy:'id',value:'save',exact:true},controlLease:lease,fingerprintVersion:2};
 action.fingerprintSHA256=(await w.MechanizeFingerprint.mutationV2(action)).sha256;await f.receive(action);assert.equal(clicks,1);
 f.disconnect();await f.connect();f.messages.length=0;
 const newFence={...grant,brokerEpoch:'broker2',channelEpoch:'channel2'};
 await f.receive({...restartQualification(),...newFence,executorChallenge:'new-real-challenge'});
 assert.ok(f.messages.some(x=>x.type==='executorPrepared'&&x.executorChallenge==='new-real-challenge'));
 assert.equal(f.storage.mechanizeReconnect.history[0].executors[0].receiptRevision,1);assert.equal(clicks,1);
 assert.ok(f.storage.mechanizeReconnect.history[0].executors[0].identity.documentGeneration>1);
 assert.equal(f.storage.mechanizeReconnect.sourceInventory.kind,'eligibleDocuments');
 assert.equal(f.storage.mechanizeReconnect.sourceInventory.documents[0].documentId,identity.documentId);
 f.disconnect();await f.connect();f.messages.length=0;await f.receive({...restartQualification(),...newFence,executorChallenge:'same-epoch-challenge'});assert.ok(f.messages.some(x=>x.type==='executorPrepared'&&x.executorChallenge==='same-epoch-challenge'));
 await f.receive({...base,...newFence,requestId:'old-receipt',action:'receipt.query',attemptId:action.attemptId});
 assert.equal(f.messages.at(-1).dispatchState,'dispatched');assert.equal(f.messages.at(-1).fingerprintSHA256,action.fingerprintSHA256);assert.equal(clicks,1);
 await f.receive({...base,...newFence,requestId:'old-lease-reuse',action:'executor.acquire',controlLease:lease});assert.ok(f.messages.at(-1).error);assert.equal(clicks,1);
});

test('malformed private request IDs are rejected before renderer inspection', async () => {
  const f=await privateFixture(), probe=privateFrame({type:'credentialInspect',requestId:'a'.repeat(16)});
  for(const key of ['attemptId','controlLease','username','password']) delete probe[key];
  const before=f.state.deliveries;
  await f.receive(probe);
  assert.equal(f.state.deliveries,before);
  assert.equal(f.messages.length,0);
  assert.equal(f.storage.mechanizeProtectedOrigins,undefined);
  assert.equal(f.sessionState.mechanizeProtectedOrigins,undefined);
});


test('private inspection supports legacy and current broker correlation IDs',async()=>{
 for(const size of [32,64]) {
  const f=await privateFixture(),probe=privateFrame({type:'credentialInspect',requestId:'a'.repeat(size)});
  for(const key of ['attemptId','controlLease','username','password']) delete probe[key];
  await f.receive(probe);
  assert.equal(f.messages[0].ready,true);
  assert.equal(f.messages[0].requestId,probe.requestId);
 }
});

test('rolling correlation ID support does not accept short credential attempt IDs',async()=>{
 const f=await privateFixture(),before=f.state.deliveries;
 await f.receive(privateFrame({requestId:'a'.repeat(32),attemptId:'b'.repeat(32)}));
 assert.equal(f.state.deliveries,before);
 assert.ok(!f.messages.length || f.messages.at(-1).status==='notDispatched');
});

const privateRetireFrame=()=>({...privateSubmitFrame(),type:'credentialRetire',attemptId:'d'.repeat(64)});
test('private retirement closes exact protected tab after refused submit without renderer or secret reads',async()=>{
 const f=await privateFixture();await f.receive(privateFrame());f.state.privateReply={status:'notDispatched',retiredAuthorityQuiesced:false,controlLease:privateSubmitFrame().controlLease};
 await f.receive(privateSubmitFrame());const calls=f.state.deliveries;
 await f.receive(privateRetireFrame());const reply=f.messages.at(-1);
 assert.equal(reply.type,'credentialRetireResult');assert.equal(reply.status,'dispatched');assert.equal(f.state.removedTab,identity.tabId);assert.equal(f.state.deliveries,calls);
 assert.deepEqual(Object.keys(reply).sort(),['attemptId','identity','requestId','status','type']);
 assert.deepEqual(JSON.parse(JSON.stringify(f.storage.mechanizeProtectedOrigins)),['https://fixture.example.test']);
 const count=f.messages.length;await f.receive(command('after-retire','observe'));assert.equal(f.messages.length,count);
 await f.receive({...privateRetireFrame(),attemptId:'e'.repeat(64)});assert.equal(f.state.removals,1);
 assert.ok(!JSON.stringify([f.messages,f.storage,f.sessionState]).includes('CANARY'));
});
test('private retirement refuses successful or uncertain submit, drift, foreign lease and extra fields',async()=>{
 for(const mode of ['successful','uncertain','document','origin','lease','extra']){
  const f=await privateFixture();await f.receive(privateFrame());
  if(mode==='successful')await f.receive(privateSubmitFrame());
  if(mode==='uncertain'){f.state.privateReply={status:'unknown',retiredAuthorityQuiesced:false,controlLease:privateSubmitFrame().controlLease};await f.receive(privateSubmitFrame());}
  if(mode==='document')f.state.documentId='replacement';
  if(mode==='origin')f.state.frameURL='https://other.example.test';
  const request=privateRetireFrame();if(mode==='lease')request.controlLease={id:'foreign',generation:1};if(mode==='extra')request.value='PASSWORD-CANARY';
  await f.receive(request);assert.equal(f.state.removals||0,0,mode);
  assert.ok(!JSON.stringify(f.messages).includes('CANARY'));
 }
});
test('retirement loss or missing absence proof is unknown and cannot replay',async()=>{
 for(const mode of ['removeError','stillPresent','queryError','disconnect']){
  const f=await privateFixture();await f.receive(privateFrame());
  if(mode==='removeError')f.state.rejectRemoval=true;
  if(mode==='stillPresent')f.state.keepRemovedTab=true;
  if(mode==='queryError')f.state.rejectTabQuery=true;
  if(mode==='disconnect'){let release;f.state.blockRemoval=new Promise(r=>release=r);const count=f.messages.length;const pending=f.receive(privateRetireFrame());await new Promise(r=>setImmediate(r));f.disconnect();release();await pending;assert.equal(f.messages.length,count);}
  else {await f.receive(privateRetireFrame());assert.equal(f.messages.at(-1).status,'unknown',mode);await f.receive({...privateRetireFrame(),attemptId:'e'.repeat(64)});}
  assert.equal(f.state.removals,1,mode);assert.ok(!JSON.stringify(f.messages).includes('CANARY'));
 }
});


test('reconnect preserves origin quarantine without exposing protected documents', async () => {
 const origin='https://fixture.example.test';
 const f=await fixture({mechanizeProtectedOrigins:[origin]}, {enroll:false});
 f.storage.mechanizeProtectedOrigins=[origin];
 f.state.boundFingerprintVersion=2;
 f.state.inventoryTabs=[{id:7,url:origin+'/private',title:'SECRET-TITLE-CANARY'}];
 await f.receive(restartQualification());
 f.disconnect();await f.connect();f.messages.length=0;
 await f.receive({...restartQualification(),brokerEpoch:'broker2',channelEpoch:'channel2',executorChallenge:'fresh-challenge'});
 assert.equal(f.storage.lastGrant.brokerEpoch,'broker2');
 assert.deepEqual(f.storage.mechanizeProtectedOrigins,[origin]);
 assert.deepEqual(f.sessionState.mechanizeProtectedOrigins,[origin]);
 assert.equal(f.state.reconnectCalls,undefined);
 assert.equal(f.state.deliveries,0);
 assert.ok(f.messages.some(x=>x.type==='executorPrepared'));
 assert.ok(!JSON.stringify(f.messages).includes('SECRET-TITLE-CANARY'));
 assert.equal(f.storage.mechanizeReconnect.history[0].executors.length,0);
 // Quarantine continues to reject ordinary document control after reconnect.
 f.messages.length=0;
 await f.receive(command('blocked-after-reconnect','element.press',{brokerEpoch:'broker2',channelEpoch:'channel2'}));
 assert.equal(f.state.deliveries,0);
});


test('reconnect refuses quarantine changes during adoption without clearing protection', async () => {
 const f=await reconnectFixture();
 f.state.afterPendingWrite=()=>{f.storage.mechanizeProtectedOrigins=['https://fixture.example.test'];};
 await f.receive({...restartQualification(),brokerEpoch:'broker2',channelEpoch:'channel2',executorChallenge:'fresh-challenge'});
 assert.equal(f.storage.lastGrant.brokerEpoch,'broker1');
 assert.equal(f.storage.mechanizeReconnect.phase,'pending');
 assert.deepEqual(f.storage.mechanizeProtectedOrigins,['https://fixture.example.test']);
 assert.equal(f.diagnostic().reason,'privateProtection');
 assert.equal(f.state.deliveries,0);
 assert.ok(!f.messages.some(x=>x.type==='executorPrepared'));
});


test('durable origin quarantine survives a cleared Chrome session store on reconnect', async () => {
 const origin='https://fixture.example.test';
 const f=await fixture({}, {enroll:false});
 f.storage.mechanizeProtectedOrigins=[origin];
 f.disconnect(); await f.connect();
 await f.receive(restartQualification());
 f.disconnect(); await f.connect(); f.messages.length=0;
 await f.receive({...restartQualification(),brokerEpoch:'broker2',channelEpoch:'channel2',executorChallenge:'fresh-challenge'});
 assert.equal(f.storage.lastGrant.brokerEpoch,'broker2');
 assert.deepEqual(f.storage.mechanizeProtectedOrigins,[origin]);
 assert.equal(f.sessionState.mechanizeProtectedOrigins,undefined);
 assert.equal(f.state.deliveries,0);
 assert.ok(f.messages.some(x=>x.type==='executorPrepared'));
});


test('reconnect classifies executor and injection failures without leaking renderer errors',async()=>{
 for(const mode of ['injection','executor']) {
  const f=await reconnectFixture();
  if(mode==='injection')f.state.rejectInjection=true;else f.state.reconnectError='inspect';
  await f.receive({...restartQualification(),brokerEpoch:'broker2',channelEpoch:'channel2',executorChallenge:'diagnostic-challenge'});
  assert.equal(f.diagnostic().phase,'inspect');
  assert.equal(f.diagnostic().reason,mode==='injection'?'injectionUnavailable':'executorRefused');
  assert.equal(f.storage.lastGrant.brokerEpoch,'broker1');
  assert.equal(f.storage.mechanizeReconnect,undefined);
  assert.equal(f.state.deliveries,0);
  assert.ok(!JSON.stringify(f.messages).includes('PRIVATE_FAILURE'));
 }
});


test('Chrome injection error diagnostics redact private URL and file details',async()=>{
 for(const [message,reason] of [
  ['The extensions gallery cannot be scripted. SECRET-CANARY','restrictedBrowserPage'],
  ['Cannot access contents of url https://PRIVATE-CANARY. Missing host permission','websitePermissionMissing'],
  ['No document with id PRIVATE-CANARY','documentChanged'],
  ['Could not load file PRIVATE-CANARY','packagedExecutorUnavailable'],
  ['Error at parameter injection: PRIVATE-CANARY','injectionArgumentsRejected'],
  ['Extension context invalidated. PRIVATE-CANARY','extensionContextInvalidated'],
  ['Cannot access a fenced frame PRIVATE-CANARY','restrictedFrame'],
  ['TypeError: PRIVATE-CANARY is not a function','executorEvaluationFailed']
 ]) {
  const f=await reconnectFixture();f.state.rejectInjection=true;f.state.injectionError=message;
  await f.receive({...restartQualification(),brokerEpoch:'broker2',channelEpoch:'channel2',executorChallenge:'diagnostic-challenge'});
  assert.equal(f.diagnostic().reason,reason);
  assert.ok(!JSON.stringify(f.messages).includes('CANARY'));
  assert.equal(f.storage.mechanizeReconnect,undefined);
 }
});


test('reconnect excludes Chrome error documents and fenced frames from executor injection',async()=>{
 for(const kind of ['error','fenced']) {
  const f=await reconnectFixture();
  if(kind==='error')f.state.frameErrorOccurred=true;else f.state.frameType='fenced_frame';
  f.state.rejectInjection=true;
  await f.receive({...restartQualification(),brokerEpoch:'broker2',channelEpoch:'channel2',executorChallenge:'eligible-only'});
  assert.equal(f.storage.lastGrant.brokerEpoch,'broker2');
  assert.ok(f.messages.some(x=>x.type==='executorPrepared'));
  assert.equal(f.storage.mechanizeReconnect.history[0].executors.length,0);
  assert.equal(f.state.deliveries,0);
 }
});


test('healthy root reconnect remains usable alongside error and fenced child frames',async()=>{
 const f=await reconnectFixture();
 f.state.frameRows=[
  {frameId:0,documentId:'d1',url:f.state.url,errorOccurred:false,frameType:'outermost_frame'},
  {frameId:1,documentId:'error-child',url:f.state.url,errorOccurred:true,frameType:'sub_frame'},
  {frameId:2,documentId:'fenced-child',url:f.state.url,errorOccurred:false,frameType:'fenced_frame'}
 ];
 await f.receive({...restartQualification(),brokerEpoch:'broker2',channelEpoch:'channel2',executorChallenge:'healthy-root'});
 assert.equal(f.storage.lastGrant.brokerEpoch,'broker2');
 assert.ok(f.messages.some(x=>x.type==='executorPrepared'&&x.executorChallenge==='healthy-root'));
 assert.equal(f.storage.mechanizeReconnect.history[0].executors.length,1);
 assert.equal(f.storage.mechanizeReconnect.history[0].executors[0].identity.documentId,'d1');
 assert.deepEqual(f.state.reconnectCalls.map(x=>[x.phase,x.newBinding.identity.documentId]),[['inspect','d1'],['prepare','d1'],['adopt','d1']]);
 assert.equal(f.state.deliveries,0);
});


test('v2 protocol click crosses exact content-worker lease and retains one receipt on duplicate',async t=>{
 const {JSDOM}=require('jsdom'),dom=new JSDOM('<button id="save">Save</button>',{url:'https://fixture.example.test/page',runScripts:'outside-only'}),w=dom.window;
 t.after(()=>w.close());w.TextEncoder=TextEncoder;Object.defineProperty(w,'crypto',{value:require('node:crypto').webcrypto,configurable:true});
 const button=w.document.querySelector('#save');button.getClientRects=()=>[{width:100,height:30}];button.getBoundingClientRect=()=>({x:20,y:20,width:100,height:30});button.scrollIntoView=()=>{};w.document.elementFromPoint=()=>button;w.requestAnimationFrame=fn=>setTimeout(fn,0);
 let listener,f;w.chrome={runtime:{id:'extension',getManifest:()=>({permissions:['debugger']}),onMessage:{addListener:fn=>listener=fn},sendMessage:message=>new Promise(resolve=>{for(const fn of f.state.runtimeListeners)fn(message,{id:'extension',tab:{id:7},frameId:0,documentId:'d1'},resolve);})}};
 for(const file of ['protocol.js','fingerprint.js','accessibility-provider.js','dom.js','recorder.js','secure-input.js','content.js'])w.eval(fs.readFileSync(path.join(__dirname,'..',file),'utf8'));
 f=await fixture({}, {enroll:false});f.state.inventoryTabs=[{id:7,url:f.state.url,title:'Public fixture'}];
 f.state.renderer=(_,message)=>new Promise(resolve=>listener(JSON.parse(JSON.stringify(message)),{id:'extension',url:'chrome-extension://extension/worker.js'},value=>resolve(JSON.parse(JSON.stringify(value)))));
 await f.receive(restartQualification());
 const lease={id:'protocol-lease',generation:1},base={identity,...grant,deadlineUnixMs:Date.now()+2000};
 await f.receive({...base,requestId:'acquire-protocol',action:'executor.acquire',controlLease:lease});
 let domClicks=0;button.onclick=()=>domClicks++;
 const action={...base,requestId:'protocol-input',action:'element.press',attemptId:'c'.repeat(64),locator:{strategy:'id',value:'save',exact:true},controlLease:lease,fingerprintVersion:2};
 action.fingerprintSHA256=(await w.MechanizeFingerprint.mutationV2(action)).sha256;
 await f.receive(action);
 assert.equal(f.messages.at(-1).dispatchState,'dispatched');
 assert.equal(f.messages.at(-1).inputSemantics,'Browser protocol input v1');
 assert.equal(domClicks,0);
 assert.deepEqual(JSON.parse(JSON.stringify(f.state.activatedSetupTab)),{id:7,details:{active:true}});
 assert.deepEqual(f.state.debuggerInputs.map(x=>x.args.type),['mouseMoved','mousePressed','mouseReleased']);
 assert.equal(f.sessionState['browserProtocolInput:'+action.attemptId].state,'released');
 await f.receive({...action,requestId:'duplicate-protocol-input'});
 assert.equal(f.messages.at(-1).dispatchState,'dispatched');assert.equal(f.state.debuggerInputs.length,3);
 // Activation must not permit a click after the exact document changes.
 f.state.activationHook=()=>{f.state.documentId='replaced-during-activation';};
 const changed={...action,requestId:'activation-document-change',attemptId:'e'.repeat(64),deadlineUnixMs:Date.now()+2000};
 changed.fingerprintSHA256=(await w.MechanizeFingerprint.mutationV2(changed)).sha256;
 await f.receive(changed);
 assert.ok(f.messages.at(-1).error);
 assert.equal(f.state.debuggerInputs.length,3);

});

test('unadmitted content browser input cannot attach or post CDP',async()=>{
 const f=await fixture();let response;
 for(const listener of f.state.runtimeListeners)listener({type:'browserInputLocal',requestId:'fake',attemptId:'fake',deadlineUnixMs:Date.now()+1000,action:'click',point:{x:1,y:1}},{id:'extension',tab:{id:7},frameId:0,documentId:'d1'},r=>response=r);
 assert.equal(response.dispatchState,'notDispatched');assert.equal(f.state.debuggerAttaches,undefined);assert.equal(f.state.debuggerInputs,undefined);
});


test('clean qualified native disconnect gets one metadata reconnect without input replay',async()=>{
 const f=await fixture();const before=f.state.nativeConnections;f.disconnect();
 await new Promise(resolve=>setTimeout(resolve,1100));
 assert.equal(f.state.nativeConnections,before+1);assert.equal(f.state.deliveries,0);
 assert.equal(f.storage.lastGrant.brokerEpoch,'broker1');
});

test('unknown receipts and unqualified startup reconnect metadata without input replay',async()=>{
 const unknown=await fixture({'browserIntent:held':{}}, {enroll:false});
 const startup=await fixture({}, {enroll:false});
 const counts=[unknown.state.nativeConnections,startup.state.nativeConnections];
 unknown.disconnect();startup.disconnect();
 await new Promise(resolve=>setTimeout(resolve,1100));
 assert.deepEqual([unknown.state.nativeConnections,startup.state.nativeConnections],counts.map(n=>n+1));
 for(const f of [unknown,startup])assert.deepEqual(Array.from(f.messages.at(-1).documents),[]);
 await unknown.receive(restartQualification());assert.ok(!unknown.messages.some(m=>m.type==='executorPrepared'));assert.ok(unknown.sessionState['browserIntent:held']);
 assert.equal(unknown.state.deliveries+startup.state.deliveries,0);
});


test('lazy binding immediately publishes negotiated v2 for a newly opened document',async()=>{
 const f=await fixture({}, {enroll:false});f.state.boundFingerprintVersion=2;
 await f.receive(restartQualification());f.messages.length=0;
 const fresh={...identity,documentId:'new-document'};
 f.state.documentId=fresh.documentId;f.state.boundDynamicIdentity=true;
 f.state.inventoryTabs=[{id:7,url:f.state.url,title:'Public fixture'}];
 f.state.publicReply={requestId:'observe-new-document',identity:fresh,nodes:[],truncated:false};
 await f.receive(command('observe-new-document','observe',{identity:fresh}));
 const update=f.messages.find(x=>x.type==='documents');
 assert.equal(update.documents.length,1);assert.equal(update.documents[0].documentId,fresh.documentId);
 assert.equal(update.documents[0].mutationFingerprintVersion,2);
 assert.ok(f.messages.findIndex(x=>x.type==='documents')<f.messages.findIndex(x=>x.requestId==='observe-new-document'));
});

test('same-document status preserves private flow, reports closed states and never repeats submit',async()=>{
 const f=await privateFixture();await f.receive(privateFrame());await f.receive(privateSubmitFrame());
 for(const [index,stage] of ['pending','rejected','challenge'].entries()) {
  f.state.postSubmitStage=stage;
  const advance={...privateSubmitFrame(),type:'credentialAdvance',requestId:['d','e','f'][index].repeat(64),nextLease:{id:'next-lease',generation:2}};delete advance.fillAttemptId;
  await f.receive(advance);
  const reply=f.messages.at(-1);assert.equal(reply.stage,stage);assert.equal(reply.ready,false);assert.equal(reply.identity.documentId,identity.documentId);
  assert.equal(f.state.lastRendererMessage.type,'credentialPostSubmit');
 }
 assert.ok(!JSON.stringify(f.messages).includes('CANARY'));
 assert.equal(f.state.debuggerInputs,undefined);assert.equal(f.state.privateSubmits,1);
});

test('lost post-submit read stays pending under fresh metadata without granting access or resubmitting',async()=>{
 const f=await privateFixture();await f.receive(privateFrame());await f.receive(privateSubmitFrame());f.state.postSubmitLost=true;
 const advance={...privateSubmitFrame(),type:'credentialAdvance',requestId:'d'.repeat(64),nextLease:{id:'next-lease',generation:2}};delete advance.fillAttemptId;
 await f.receive(advance);assert.equal(f.messages.at(-1).stage,'pending');assert.equal(f.messages.at(-1).ready,false);
 assert.ok(f.state.lastPostSubmitDeadline<=Date.now()+1000);
 const before=f.messages.length;await f.receive(command('pending-read-private','observe'));assert.equal(f.messages.length,before);
 f.state.postSubmitLost=false;f.state.postSubmitStage='rejected';await f.receive({...advance,requestId:'e'.repeat(64)});
 assert.equal(f.messages.at(-1).stage,'rejected');assert.equal(f.state.privateSubmits,1);assert.ok(!JSON.stringify(f.messages).includes('CANARY'));
});
test('renderer replacement during post-submit probe retains only pending metadata',async()=>{
 for(const lost of [false,true]) {
  const f=await privateFixture();await f.receive(privateFrame());await f.receive(privateSubmitFrame());
  f.state.postSubmitLost=lost;f.state.postSubmitHook=()=>{f.state.documentId='private-next';};
  const advance={...privateSubmitFrame(),type:'credentialAdvance',requestId:'d'.repeat(64),nextLease:{id:'next-lease',generation:2}};delete advance.fillAttemptId;
  await f.receive(advance);
  const pending=f.messages.at(-1);assert.equal(pending.stage,'pending');assert.equal(pending.ready,false);assert.equal(pending.identity.documentId,identity.documentId);
  f.state.postSubmitHook=undefined;f.state.postSubmitLost=false;
  await f.receive({...advance,requestId:'e'.repeat(64)});
  assert.equal(f.messages.at(-1).identity.documentId,'private-next');assert.equal(f.messages.at(-1).ready,true);
  assert.equal(f.state.privateSubmits,1);assert.equal(f.state.debuggerInputs,undefined);assert.ok(!JSON.stringify(f.messages).includes('CANARY'));
 }
});

test('private recipient pin crosses worker-content handoff after decorative mutation without public secrets',async t=>{
 const {JSDOM}=require('jsdom');
 const dom=new JSDOM('<p id="decoration">Initial</p><form method="post"><input autocomplete="username"><input type="password" autocomplete="current-password"><button>Login</button></form>',{url:'https://fixture.example.test/login',runScripts:'outside-only'}),w=dom.window;
 t.after(()=>w.close());w.TextEncoder=TextEncoder;Object.defineProperty(w,'crypto',{value:require('node:crypto').webcrypto});w.HTMLElement.prototype.getClientRects=()=>[{width:100,height:20}];
 let listener;w.chrome={runtime:{id:'extension',onMessage:{addListener:fn=>listener=fn}}};
 for(const file of ['protocol.js','fingerprint.js','accessibility-provider.js','dom.js','recorder.js','secure-input.js','content.js'])w.eval(fs.readFileSync(path.join(__dirname,'..',file),'utf8'));
 const f=await fixture({}, {enroll:false});f.state.inventoryTabs=[{id:7,url:f.state.url,title:'Private fixture'}];
 f.state.renderer=(_,message)=>new Promise(resolve=>listener(JSON.parse(JSON.stringify(message)),{id:'extension',url:'chrome-extension://extension/worker.js'},value=>{if(message.type==='credentialInspect')f.state.probeSummary={ready:value.ready,stage:value.stage,version:value.privateCredentialProtocolVersion,keys:Object.keys(value).sort(),generation:value.identity?.documentGeneration};resolve(JSON.parse(JSON.stringify(value)));}));
 await f.receive(restartQualification());
 assert.equal(w.MechanizeSecureInput.pinRecipient(w.document,w.location.origin).stage,'pair');
 const recipientId='f'.repeat(64),probe=privateFrame({type:'credentialInspect',recipientId});for(const key of ['attemptId','controlLease','username','password'])delete probe[key];
 await f.receive(probe);assert.equal(f.messages.at(-1).ready,true,JSON.stringify({probe:f.state.probeSummary,messages:f.messages.map(m=>({type:m.type,code:m.error?.code,stage:m.stage,ready:m.ready}))}));assert.equal(f.messages.at(-1).recipientId,recipientId);assert.equal(f.messages.at(-1).privateCredentialProtocolVersion,3);
 const lease={id:'lease-private',generation:1};
 await f.receive(command('pin-acquire','executor.acquire',{attemptId:undefined,locator:undefined,controlLease:lease}));
 w.document.querySelector('#decoration').textContent='Changed decoration';await new Promise(resolve=>setImmediate(resolve));
 await f.receive({...probe,requestId:'c'.repeat(64),controlLease:lease});
 assert.equal(f.messages.at(-1).ready,true);assert.ok(f.messages.at(-1).identity.documentGeneration>identity.documentGeneration);
 await f.receive(privateFrame({recipientId,requestId:'d'.repeat(64)}));
 assert.equal(f.messages.at(-1).status,'dispatched');
 assert.equal(w.document.querySelector('[type=password]').value,'PASSWORD-CANARY');
 assert.ok(!JSON.stringify(f.messages).includes('CANARY'));assert.ok(!JSON.stringify(f.storage).includes('CANARY'));assert.ok(!JSON.stringify(f.sessionState).includes('CANARY'));
});

test('native Playwright uses exact admitted worker lease and rejects epoch, origin, and document drift',async()=>{
 for(const change of ['valid','epoch','origin','generation','lease']){
  const f=await privateFixture(true);const extra=change==='epoch'?{brokerEpoch:'foreign'}:change==='generation'?{identity:{...identity,documentGeneration:2}}:change==='lease'?{controlLease:{id:'foreign',generation:1}}:{};
  const c=await playwrightCommand(extra);const result=await playwrightNative(f,c,'open',{command:c,origin:change==='origin'?'https://foreign.test':'https://fixture.example.test'});
  assert.equal(result.result?.opened,change==='valid'?true:undefined,change+': '+JSON.stringify(result));
  if(change==='valid')await playwrightNative(f,c,'close');else assert.equal((f.state.debuggerAttaches||[]).length,0);
 }
});
test('native Playwright admits committed protected DOM and redacts extension-owned variants',async()=>{
 for(const committed of [false,true]){
  const f=await privateFixture(true);await f.receive(privateFrame());await f.receive(privateSubmitFrame());f.state.documentId='privacy-doc';
  const proof=privacyFrame();await f.receive(proof);const target=f.messages.at(-1).identity;
  if(committed)await f.receive({...proof,type:'credentialPrivacyCommit',requestId:'e'.repeat(64),identity:target});
  const c=command('playwright-read','read',{identity:target,attemptId:undefined,locator:{strategy:'id',value:'summary',exact:true},args:{attribute:'text'}});
  const opened=await playwrightNative(f,c,'open',{command:c,origin:'https://fixture.example.test'});
  assert.equal(opened.result?.opened,committed?true:undefined,JSON.stringify(opened));
  if(committed){const result=await playwrightNative(f,c,'redact',{value:'PASSWORD-CANARY '+Buffer.from('USERNAME-CANARY').toString('base64')});assert.equal(result.result.value,'[redacted]');await playwrightNative(f,c,'close');}
  assert.ok(!JSON.stringify([f.messages,f.storage,f.sessionState]).includes('CANARY'));
 }
});
test('native Playwright document drift retains original receipt and never forwards a second input',async()=>{
 const f=await privateFixture(true),c=await playwrightCommand();assert.equal((await playwrightNative(f,c,'open',{command:c,origin:'https://fixture.example.test'})).result.opened,true);
 await playwrightNative(f,c,'send',{method:'Input.dispatchMouseEvent',params:{type:'mousePressed',button:'left',buttons:1,modifiers:0,clickCount:1,x:20,y:20}});
 f.state.documentId='replacement';const result=await playwrightNative(f,c,'send',{method:'Input.dispatchMouseEvent',params:{type:'mousePressed',button:'left',buttons:1,modifiers:0,clickCount:1,x:20,y:20}});
 assert.equal(result.dispatchState,'unknown');assert.equal(f.state.debuggerInputs.filter(call=>call.method.startsWith('Input.')).length,1);
 await f.receive(command('playwright-query','receipt.query',{attemptId:c.attemptId}));assert.equal(f.messages.at(-1).dispatchState,'unknown');assert.equal(f.messages.at(-1).fingerprintSHA256,c.fingerprintSHA256);
});
test('lifecycle receipt export retains native Playwright original attempt and fingerprint',async()=>{
 const f=await privateFixture(true),c=await playwrightCommand();await playwrightNative(f,c,'open',{command:c,origin:'https://fixture.example.test'});
 await playwrightNative(f,c,'send',{method:'Input.dispatchMouseEvent',params:{type:'mousePressed',button:'left',buttons:1,modifiers:0,clickCount:1,x:20,y:20}});
 await playwrightNative(f,c,'send',{method:'Input.dispatchMouseEvent',params:{type:'mouseReleased',button:'left',buttons:0,modifiers:0,clickCount:1,x:20,y:20}});
 await playwrightNative(f,c,'receipt',{dispatchState:'dispatched',effectState:'unverified'});await playwrightNative(f,c,'close');
 f.state.renderer=async(_,message)=>({version:2,requestId:message.requestId,identity,total:0,revision:0,offset:0,nextOffset:0,truncated:false,receipts:[],readiness:{quiesced:true,controlLeaseHeld:false,recordingState:'none',recordingLastSequence:0,recordingDroppedThrough:0,recordingLeaseExpiresUnixMs:0}});
 await f.receive(command('playwright-retirement-export','executor.receipts',{type:'lifecycle',lifecycleGuardId:'retirement',attemptId:undefined,locator:undefined,args:{offset:0,limit:64}}));
 const exported=f.messages.at(-1);assert.equal(exported.total,1);assert.equal(exported.revision,1);assert.equal(exported.receipts[0].attemptId,c.attemptId);assert.equal(exported.receipts[0].fingerprintSHA256,c.fingerprintSHA256);assert.equal(exported.receipts[0].fingerprintVersion,2);
});
test('admitted semantic Playwright tracks monotonic renderer generations and preserves original receipts',async()=>{
 for(const phase of ['before','after']){
  const f=await privateFixture(true),c=await playwrightCommand();assert.equal((await playwrightNative(f,c,'open',{command:c,origin:'https://fixture.example.test'})).result.opened,true);
  if(phase==='before')f.state.rendererGeneration=2;else f.state.debuggerHook=(method,args)=>{if(method==='Input.dispatchMouseEvent'&&args.type==='mousePressed')f.state.rendererGeneration=2;};
  const sent=await playwrightNative(f,c,'send',{method:'Input.dispatchMouseEvent',params:{type:'mousePressed',button:'left',buttons:1,modifiers:0,clickCount:1,x:20,y:20}});
  assert.deepEqual(Object.keys(sent.result),[]);
  await playwrightNative(f,c,'send',{method:'Input.dispatchMouseEvent',params:{type:'mouseReleased',button:'left',buttons:0,modifiers:0,clickCount:1,x:20,y:20}});
  assert.equal((await playwrightNative(f,c,'receipt',{dispatchState:'dispatched',effectState:'unverified'})).result.persisted,true);await playwrightNative(f,c,'close');
  await f.receive(command('original-generation-query','receipt.query',{attemptId:c.attemptId}));const receipt=f.messages.find(m=>m.requestId==='original-generation-query');assert.equal(receipt.identity.documentGeneration,1);assert.equal(receipt.fingerprintSHA256,c.fingerprintSHA256);
  await new Promise(r=>setImmediate(r));assert.ok(f.messages.some(m=>m.type==='documents'&&m.documents?.some(d=>d.documentGeneration===2)));
 }
});
test('legacy worker rejects indexed locators while native relay binds them into original fingerprint',async()=>{
 const f=await privateFixture(true),c=await playwrightCommand({locator:{strategy:'role',value:'button',name:'Expand current row',exact:true,index:1,order:'document'}});
 await f.receive({...c,requestId:'indexed-legacy'});assert.equal(f.messages.at(-1).error.code,'unsupportedSelector');
 assert.equal((await playwrightNative(f,c,'open',{command:c,origin:'https://fixture.example.test'})).result.opened,true);await playwrightNative(f,c,'close');
 assert.equal(f.sessionState['playwrightAttempt:'+c.attemptId].fingerprintSHA256,c.fingerprintSHA256);
});
test('owned Playwright input never accepts a substituted renderer identity during completion',async()=>{
 const f=await privateFixture(true),c=await playwrightCommand();await playwrightNative(f,c,'open',{command:c,origin:'https://fixture.example.test'});
 await playwrightNative(f,c,'send',{method:'Input.dispatchMouseEvent',params:{type:'mousePressed',button:'left',buttons:1,modifiers:0,clickCount:1,x:20,y:20}});
 f.state.renderer=async(_,message)=>({requestId:message.requestId,identity:{...identity,documentId:'foreign',documentGeneration:2},validated:true});
 const result=await playwrightNative(f,c,'receipt',{dispatchState:'dispatched',effectState:'unverified'});assert.equal(result.dispatchState,'unknown');assert.equal(f.state.debuggerInputs.filter(call=>call.method.startsWith('Input.')).length,1);assert.equal(f.sessionState['playwrightAttempt:'+c.attemptId].receipt.identity.documentId,'d1');
});
test('semantic Playwright requires pinned safe target at the immediate input boundary',async()=>{
 for(const mode of ['unpinned','changed']){
  const f=await privateFixture(true),c=await playwrightCommand();if(mode==='unpinned')f.state.noTargetProof=true;
  await playwrightNative(f,c,'open',{command:c,origin:'https://fixture.example.test'});
  f.state.rendererGeneration=2;if(mode==='changed')f.state.targetSafe=false;
  const result=await playwrightNative(f,c,'send',{method:'Input.dispatchMouseEvent',params:{type:'mousePressed',button:'left',buttons:1,modifiers:0,clickCount:1,x:20,y:20}});
  assert.equal(result.dispatchState,'notDispatched');assert.equal(result.errorCode,mode==='unpinned'?'playwrightTargetUnpinned':'playwrightTargetChanged');assert.equal((f.state.debuggerInputs||[]).filter(call=>call.method.startsWith('Input.')).length,0);assert.ok(!f.state.playwrightJournalPhases.includes('input'));assert.equal(result.result.receipt.dispatchState,'notDispatched');assert.equal(result.result.receipt.error.code,result.errorCode);assert.equal(result.result.receipt.fingerprintSHA256,c.fingerprintSHA256);
 }
});
test('failed terminal journal write cannot attest a rejected Playwright input',async()=>{
 const f=await privateFixture(true),c=await playwrightCommand();await playwrightNative(f,c,'open',{command:c,origin:'https://fixture.example.test'});
 // Model Chrome structured-clone storage, detached from the live record.
 f.sessionState['playwrightAttempt:'+c.attemptId]=structuredClone(f.sessionState['playwrightAttempt:'+c.attemptId]);
 f.state.targetSafe=false;f.state.rejectStorageWrite=true;
 const denied=await playwrightNative(f,c,'send',{method:'Input.dispatchMouseEvent',params:{type:'mousePressed',button:'left',buttons:1,modifiers:0,clickCount:1,x:20,y:20}});
 assert.equal(denied.errorCode,'playwrightTargetChanged');assert.equal(denied.result,undefined);assert.equal(f.sessionState['playwrightAttempt:'+c.attemptId].phase,'ready');
 assert.equal((f.state.debuggerInputs||[]).filter(call=>call.method.startsWith('Input.')).length,0);
});
test('private same-document promotion survives an existing pooled debugger attachment',async t=>{
 const {JSDOM}=require('jsdom');
 const dom=new JSDOM('<form method="post"><input autocomplete="username"><input type="password" autocomplete="current-password"><button>Login</button></form>',{url:'https://fixture.example.test/login',runScripts:'outside-only'}),w=dom.window;
 t.after(()=>w.close());w.TextEncoder=TextEncoder;Object.defineProperty(w,'crypto',{value:require('node:crypto').webcrypto});w.HTMLElement.prototype.getClientRects=()=>[{width:100,height:20}];
 let listener,submits=0;w.chrome={runtime:{id:'extension',onMessage:{addListener:fn=>listener=fn}}};
 for(const file of ['protocol.js','fingerprint.js','accessibility-provider.js','dom.js','recorder.js','secure-input.js','content.js'])w.eval(fs.readFileSync(path.join(__dirname,'..',file),'utf8'));
 w.document.querySelector('form').addEventListener('submit',e=>{e.preventDefault();submits++;});
 const f=await fixture({}, {enroll:false});f.state.inventoryTabs=[{id:7,url:f.state.url,title:'Private fixture'}];
 f.state.renderer=(_,message)=>new Promise(resolve=>listener(JSON.parse(JSON.stringify(message)),{id:'extension',url:'chrome-extension://extension/worker.js'},value=>resolve(JSON.parse(JSON.stringify(value)))));
 await f.receive(restartQualification());
 const debug=await f.attachReadOnlyCDP(8);await debug.send('Runtime.enable',{},Date.now()+1000);
 const recipientId='f'.repeat(64),probe=privateFrame({type:'credentialInspect',recipientId});for(const key of ['attemptId','controlLease','username','password'])delete probe[key];
 await f.receive(probe);assert.equal(f.messages.at(-1).ready,true);
 await f.receive(command('private-integration-acquire','executor.acquire',{attemptId:undefined,locator:undefined,controlLease:{id:'lease-private',generation:1}}));
 await f.receive(privateFrame({recipientId}));assert.equal(f.messages.at(-1).status,'dispatched');
 await f.receive(privateSubmitFrame());assert.equal(f.messages.at(-1).status,'dispatched');assert.equal(submits,1);
 const advance=()=>{const request={...privateSubmitFrame(),type:'credentialAdvance',requestId:'d'.repeat(64),nextLease:{id:'next-private-lease',generation:2}};delete request.fillAttemptId;return request;};
 await f.receive(advance());assert.equal(f.messages.at(-1).stage,'pending');assert.equal(submits,1);
 w.document.body.innerHTML='<h1>USERNAME-CANARY</h1><h2>Fixture invoices</h2>';
 await f.receive(advance());assert.equal(f.messages.at(-1).stage,'unavailable');assert.equal(submits,1);
 // Reproduce the real packaged reinjection, including the existing content
 // executor and its retired-input state in this same Chrome document.
 f.state.injectionHook=details=>{for(const file of details.files)w.eval(fs.readFileSync(path.join(__dirname,'..',file),'utf8'));};
 const qualification=privacyFrame();await f.receive(qualification);const proof=f.messages.at(-1);assert.equal(proof.ready,true);assert.equal(proof.retiredAuthorityQuiesced,true);assert.equal(proof.redactionReady,true);
 await f.receive({...qualification,type:'credentialPrivacyCommit',identity:proof.identity,requestId:'e'.repeat(64)});const committed=f.messages.at(-1);assert.equal(committed.ready,true);
 await f.receive(command('private-integration-observe','observe',{identity:committed.identity,attemptId:undefined,locator:undefined}));const observed=f.messages.find(m=>m.requestId==='private-integration-observe');assert.ok(observed&&!observed.error);

 f.state.url=f.state.frameURL=w.location.href;f.state.tabStatus='complete';f.state.inventoryTabs=[{id:7,url:f.state.url,status:'complete'}];
 const scopeRequest={type:'credentialScope',requestId:'0'.repeat(64),mode:'publicRead',preparationId:'1'.repeat(64),sourceIdentity:{...committed.identity,documentId:'',documentGeneration:0},sourceOrigin:'https://fixture.example.test',loginRouteSHA256:'',...grant,deadlineUnixMs:Date.now()+4000,targetTabId:7,targetOrigin:'https://fixture.example.test'};
 await f.receive(scopeRequest);const scoped=f.messages.find(m=>m.requestId===scopeRequest.requestId);assert.ok(scoped?.ready&&scoped.publicDocument?.public,`classified post-login public scope reason=${scoped?.reason||'missing'} keys=${Object.keys(scoped||{}).join(',')}`);
 await f.receive(command('classified-integration-observe','observe',{identity:scoped.publicDocument.identity,publicRead:true,attemptId:undefined,locator:undefined}));
 const publicObservation=f.messages.find(m=>m.requestId==='classified-integration-observe');assert.ok(publicObservation&&!publicObservation.error,'classified post-login observation');
const publicLease={id:'ordinary-public-lease',generation:3};
 await f.receive(command('ordinary-integration-acquire','executor.acquire',{identity:publicObservation.identity,attemptId:undefined,locator:undefined,controlLease:publicLease}));
 const acquired=f.messages.find(m=>m.requestId==='ordinary-integration-acquire');assert.ok(acquired&&acquired.validated===true,'ordinary acquisition after committed public observe');assert.equal(acquired.controlLease.id,publicLease.id);assert.equal(acquired.controlLease.generation,publicLease.generation);
 await f.receive(command('private-integration-retire','executor.retire',{identity:acquired.identity,attemptId:undefined,locator:undefined,controlLease:publicLease}));
 const retired=f.messages.find(m=>m.requestId==='private-integration-retire');assert.ok(retired&&retired.retiredAuthorityQuiesced===true,`exact ordinary retirement after private login: ${retired?.error?.code||'missing'} message=${retired?.error?.message||'missing'} keys=${Object.keys(retired||{}).join(',')}`);

 assert.equal(submits,1);assert.equal(debug.current(),true);assert.deepEqual(f.state.debuggerAttaches.map(v=>v.tabId),[8]);assert.equal(f.state.debuggerInputs.filter(v=>v.method.startsWith('Input.')).length,0);assert.ok(!JSON.stringify([f.messages,f.storage,f.sessionState]).includes('CANARY'));
});
test('explicit reconnect retries an unqualified native port while preserving dormant origin quarantine',async()=>{
 const origin='https://fixture.example.test';
 const f=await fixture({mechanizeProtectedOrigins:[origin]},{enroll:false});
 f.storage.mechanizeProtectedOrigins=[origin];f.state.boundFingerprintVersion=2;
 await f.receive(restartQualification());
 f.disconnect();await f.connect();
 // An independently invalid scope refuses before journal preparation.
 await f.receive({...restartQualification(),brokerEpoch:'broker2',channelEpoch:'channel2',scopeHash:'b'.repeat(64)});
 assert.equal(f.messages.at(-1).error.code,'storedFenceMismatch');assert.equal(f.diagnostic().reason,'scopeChanged');
 const previous=JSON.stringify(f.storage.lastGrant),attempts=f.state.nativeConnections;
 await f.connect();assert.equal(f.state.nativeConnections,attempts+1);
 assert.equal(JSON.stringify(f.storage.lastGrant),previous);assert.equal(f.storage.mechanizeReconnect,undefined);
 await f.receive({...restartQualification(),brokerEpoch:'broker3',channelEpoch:'channel3',executorChallenge:'quarantine-retry'});
 assert.ok(f.messages.some(m=>m.type==='executorPrepared'&&m.executorChallenge==='quarantine-retry'));
 assert.deepEqual(f.storage.mechanizeProtectedOrigins,[origin]);assert.deepEqual(f.sessionState.mechanizeProtectedOrigins,[origin]);assert.equal(f.storage.mechanizeReconnect.phase,'adopted');
 assert.equal(f.state.deliveries,0);assert.equal((f.state.debuggerInputs||[]).length,0);
});
test('quarantine metadata retry still refuses every live private input and lifecycle barrier',async()=>{
 for(const barrier of ['flow','redactions','silenced','unknown','lifecycle','privatePending','admission','privacy','mutation']){
  const f=await fixture({mechanizeProtectedOrigins:['https://fixture.example.test']},{enroll:false});
  await f.receive(restartQualification());f.disconnect();await f.connect();
  await f.receive({...restartQualification(),brokerEpoch:'broker2',channelEpoch:'channel2',scopeHash:'b'.repeat(64)});
  assert.equal(f.diagnostic().reason,'scopeChanged');const count=f.state.nativeConnections,before=JSON.stringify(f.storage);
  f.reconnectBarrier(barrier);await f.connect();assert.equal(f.state.nativeConnections,count,barrier);assert.equal(JSON.stringify(f.storage),before,barrier);assert.equal(f.state.deliveries,0,barrier);
 }
});
test('stored fence attention projects only closed reconnect phase and reason on the original native channel',async()=>{
 const f=await reconnectFixture();f.state.rejectInjection=true;f.state.injectionError='Cannot access contents of https://PRIVATE-CANARY.test';const before=JSON.stringify(f.storage.lastGrant);
 await f.receive({...restartQualification(),brokerEpoch:'broker2',channelEpoch:'channel2'});
 const attention=f.messages.at(-1);assert.equal(attention.type,'attention');assert.equal(attention.error.code,'storedFenceMismatch');assert.equal(attention.reconnectPhase,'inspect');assert.equal(attention.reconnectReason,'websitePermissionMissing');
 assert.deepEqual(Object.keys(attention).sort(),['error','reconnectPhase','reconnectReason','type']);assert.equal(JSON.stringify(f.storage.lastGrant),before);assert.equal(f.state.deliveries,0);assert.ok(!JSON.stringify(attention).includes('PRIVATE-CANARY'));
});
test('reconnect projection rejects unknown metadata and leaves other attention errors unchanged',async()=>{
 const f=await fixture(),original={type:'attention',error:{code:'storedFenceMismatch',message:'Generic recovery required'}};
 for(const [phase,reason] of [['foreign-private','none'],['inspect','PRIVATE-CANARY'],['inspect',{}],[{},'none']]){f.setReconnectDiagnostic(phase,reason);assert.equal(f.reconnectAttention(original),original);}
 f.setReconnectDiagnostic('inspect','executorRefused');const other={type:'attention',error:{code:'inventoryUnavailable'}};assert.equal(f.reconnectAttention(other),other);
 const result=f.reconnectAttention(original);assert.equal(result.reconnectPhase,'inspect');assert.equal(result.reconnectReason,'executorRefused');assert.equal(result.error,original.error);
});
test('authenticated reconnect projection vocabulary matches local setup metadata exactly',async()=>{
 const f=await fixture();const source=fs.readFileSync(path.join(__dirname,'..','setup-metadata.js'),'utf8');
 const phases=JSON.parse(source.match(/const phases = (\[[^;]+\]);/)[1]),reasons=JSON.parse(source.match(/const reasons = (\[[^;]+\]);/)[1]);
 const original={type:'attention',error:{code:'storedFenceMismatch'}};
 for(const phase of phases)for(const reason of reasons){f.setReconnectDiagnostic(phase,reason);const frame=f.reconnectAttention(original);assert.equal(frame.reconnectPhase,phase);assert.equal(frame.reconnectReason,reason);}
});
const builtinNewTabFrames=()=>[
 {frameId:0,parentFrameId:-1,documentId:'builtin-new-tab',url:'chrome://new-tab-page/',errorOccurred:false,documentLifecycle:'active',frameType:'outermost_frame'},
 {frameId:1,parentFrameId:0,documentId:'builtin-new-tab-child',url:'chrome-untrusted://new-tab-page/one-google-bar?paramsencoded=',errorOccurred:false,documentLifecycle:'active',frameType:'sub_frame'}
];
test('pending recovery accepts independently verified built-in New Tab without injecting or discarding history',async()=>{
 for(const rootURL of ['chrome://newtab/','chrome://new-tab-page/']){
  const f=await interruptedReconnectFixture();f.state.inventoryTabs=[{id:11,url:'chrome://newtab/'}];f.state.frameRows=builtinNewTabFrames();f.state.frameRows[0].url=rootURL;
  const calls=f.state.nativeConnections,injections=f.state.injections;
  await f.connect();assert.equal(f.state.nativeConnections,calls+1);f.messages.length=0;
  await f.receive({...restartQualification(),brokerEpoch:'new-tab-recovery',channelEpoch:'new-tab-recovery'});
  assert.ok(f.messages.some(m=>m.type==='executorPrepared'));assert.equal(f.storage.mechanizeReconnect.phase,'adopted');assert.deepEqual(JSON.parse(JSON.stringify(auditOriginal(f))),f.original);
  assert.equal(f.state.injections,injections);assert.equal(f.state.deliveries,0);assert.equal((f.state.debuggerInputs||[]).length,0);
 }
});
test('New Tab recovery refuses overrides, foreign frames and noncanonical browser metadata',async()=>{
 for(const mode of ['extensionRoot','websiteRoot','searchRoot','thirdPartyRoot','extensionChild','websiteChild','queryTab','pathTab','fragmentTab','queryRoot','pathChild','foreignQuery','doubleQuery','fragmentChild','missingFrames','missingRoot','missingDocument','duplicateFrame','missingParent','cycle','error','fenced','cached','pending','incognito','discarded','frameAPI']){
  const f=await interruptedReconnectFixture();f.state.inventoryTabs=[{id:11,url:'chrome://newtab/'}];f.state.frameRows=builtinNewTabFrames();const frames=f.state.frameRows,tab=f.state.inventoryTabs[0];
  if(mode==='extensionRoot')frames[0].url='chrome-extension://foreign/newtab.html';if(mode==='websiteRoot')frames[0].url='https://fixture.example.test/';if(mode==='searchRoot')frames[0].url='chrome-search://local-ntp/local-ntp.html';if(mode==='thirdPartyRoot')frames[0].url='chrome://new-tab-page-third-party/';
  if(mode==='extensionChild')frames[1].url='chrome-extension://foreign/frame.html';if(mode==='websiteChild')frames[1].url='https://fixture.example.test/';
  if(mode==='queryTab')tab.url+='?custom';if(mode==='pathTab')tab.url+='custom';if(mode==='fragmentTab')tab.url+='#custom';if(mode==='queryRoot')frames[0].url+='?custom';if(mode==='pathChild')frames[1].url='chrome-untrusted://new-tab-page/custom';if(mode==='foreignQuery')frames[1].url='chrome-untrusted://new-tab-page/one-google-bar?url=https://fixture.example.test';if(mode==='doubleQuery')frames[1].url+='&paramsencoded=extra';if(mode==='fragmentChild')frames[1].url+='#fragment';
  if(mode==='missingFrames')f.state.frameRows=[];if(mode==='missingRoot')frames.shift();if(mode==='missingDocument')delete frames[0].documentId;if(mode==='duplicateFrame')frames[1].frameId=0;if(mode==='missingParent')frames[1].parentFrameId=99;if(mode==='cycle')frames[1].parentFrameId=1;
  if(mode==='error')frames[0].errorOccurred=true;if(mode==='fenced')frames[1].frameType='fenced_frame';if(mode==='cached')frames[0].documentLifecycle='cached';if(mode==='pending')tab.pendingUrl='https://fixture.example.test/';if(mode==='incognito')tab.incognito=true;if(mode==='discarded')tab.discarded=true;if(mode==='frameAPI')f.state.rejectFrameQuery=true;
  const calls=f.state.nativeConnections,before=JSON.stringify(f.storage);await f.connect();assert.equal(f.state.nativeConnections,calls+1,mode);await f.receive({...restartQualification(),brokerEpoch:'blocked-new',channelEpoch:'blocked-new'});assert.ok(!f.messages.some(m=>m.type==='executorPrepared'));assert.equal(JSON.stringify(f.storage),before,mode);assert.equal(f.diagnostic().reason,'inventoryChanged',mode);assert.equal(f.state.deliveries,0,mode);
 }
});
test('New Tab document changes during recovery preserve the interrupted journal and inhibit qualification',async()=>{
 const f=await interruptedReconnectFixture();f.state.inventoryTabs=[{id:11,url:'chrome://newtab/'}];f.state.frameRows=builtinNewTabFrames();await f.connect();f.messages.length=0;
 f.state.afterPendingWrite=()=>{f.state.frameRows[0].documentId='replaced-new-tab';};
 await f.receive({...restartQualification(),brokerEpoch:'new-tab-changed',channelEpoch:'new-tab-changed'});
 assert.equal(f.diagnostic().reason,'inventoryChanged');assert.equal(f.inventoryReason(),'inventoryDrift');assert.ok(!f.messages.some(m=>m.type==='executorPrepared'));assert.equal(f.storage.mechanizeReconnect.phase,'pending');assert.deepEqual(JSON.parse(JSON.stringify(auditOriginal(f))),f.original);assert.equal(f.storage.lastGrant.brokerEpoch,'broker1');
});
test('verified built-in New Tab never bypasses unknown receipt or lifecycle recovery barriers',async()=>{
 for(const mode of ['unknown','lifecycle','retirement']){
  const f=await interruptedReconnectFixture();f.state.inventoryTabs=[{id:11,url:'chrome://newtab/'}];f.state.frameRows=builtinNewTabFrames();await f.connect();f.messages.length=0;
  if(mode==='unknown')f.sessionState['browserIntent:retained-attempt']={};
  if(mode==='lifecycle')f.sessionState.mechanizeLifecycleInhibited=true;
  if(mode==='retirement')f.storage.mechanizeRetirementV1={phase:'intended'};
  const before=JSON.stringify(f.storage.mechanizeReconnect);
  await f.receive({...restartQualification(),brokerEpoch:'new-tab-blocked',channelEpoch:'new-tab-blocked'});
  assert.ok(!f.messages.some(m=>m.type==='executorPrepared'),mode);assert.equal(JSON.stringify(f.storage.mechanizeReconnect),before,mode);assert.equal(f.storage.lastGrant.brokerEpoch,'broker1',mode);assert.equal(f.state.deliveries,0,mode);
 }
});
async function interruptNextEmptyRecovery(f,label){
 await f.connect();f.messages.length=0;f.state.afterPendingWrite=()=>f.disconnect();
 await f.receive({...restartQualification(),brokerEpoch:label,channelEpoch:label});delete f.state.afterPendingWrite;
 assert.equal(f.storage.mechanizeReconnect.phase,'pending');return JSON.parse(JSON.stringify(f.storage.mechanizeReconnect));
}
test('produced pending v3 and further interrupted recoveries retain full lineage and dormant quarantine',async()=>{
 for(const interruptions of [2,3]){
  const f=await interruptedReconnectFixture();f.storage.mechanizeProtectedOrigins=['https://fixture.example.test'];
  const lineage=[f.original];
  for(let index=0;index<interruptions;index++)lineage.push(await interruptNextEmptyRecovery(f,'interruption-'+index));
  assert.equal(f.storage.mechanizeReconnect.version,1);assert.equal(f.storage.lastGrant.brokerEpoch,'broker1');
  await f.connect();f.messages.length=0;await f.receive({...restartQualification(),brokerEpoch:'successful-recovery',channelEpoch:'successful-recovery'});
  assert.ok(f.messages.some(m=>m.type==='executorPrepared'));assert.equal(f.storage.mechanizeReconnect.version,1);assert.equal(f.storage.mechanizeReconnect.phase,'adopted');
  let node=auditOriginal(f);
  for(const original of lineage.toReversed()){assert.deepEqual(JSON.parse(JSON.stringify(node)),original);node=node?.format==='activeHandoff'?auditOriginal(f,node):node.recovery?.originalPending;}
  assert.deepEqual(f.storage.mechanizeProtectedOrigins,['https://fixture.example.test']);assert.equal(f.state.deliveries,0);
 }
});
test('ordinary transition interrupted after an adopted recovery remains a readable recoverable pending record',async()=>{
 const f=await interruptedReconnectFixture();await f.connect();await f.receive({...restartQualification(),brokerEpoch:'first-recovery',channelEpoch:'first-recovery'});
 assert.equal(f.storage.mechanizeReconnect.version,1);const old=JSON.parse(JSON.stringify(f.storage.mechanizeReconnect));f.disconnect();
 const pending=await interruptNextEmptyRecovery(f,'ordinary-interrupted');assert.equal(pending.version,1);assert.deepEqual(pending.history,[]);assert.deepEqual(auditOriginal(f),old);
 await f.connect();f.messages.length=0;await f.receive({...restartQualification(),brokerEpoch:'after-ordinary',channelEpoch:'after-ordinary'});
 assert.ok(f.messages.some(m=>m.type==='executorPrepared'));assert.equal(f.storage.mechanizeReconnect.version,1);assert.deepEqual(JSON.parse(JSON.stringify(auditOriginal(f))),pending);
});
test('maximum valid legacy depth migrates without creating another recursive level',async()=>{
 const f=await interruptedReconnectFixture();let record=structuredClone(f.original);
 for(let version=2;version<=6;version++)record={...structuredClone(f.original),version,nonce:String(version).repeat(64),newFence:{...grant,brokerEpoch:'legacy-'+version,channelEpoch:'legacy-'+version},recovery:{kind:'emptySetupDocuments',originalPending:record}};
 f.storage.mechanizeReconnect=record;const original=JSON.stringify(record);
 await f.connect();f.messages.length=0;await f.receive({...restartQualification(),brokerEpoch:'migrated-six',channelEpoch:'migrated-six'});
 assert.ok(f.messages.some(m=>m.type==='executorPrepared'));assert.equal(f.storage.mechanizeReconnect.format,'activeHandoff');assert.equal(f.storage.mechanizeReconnect.version,1);
 assert.equal(f.storage['mechanizeReconnectAudit:'+f.storage.mechanizeReconnect.audit.digest].journalJSON,original);assert.equal(f.state.deliveries,0);
});
test('repeated interrupted handoffs recover beyond legacy depth without losing historical receipts',async()=>{
 const f=await interruptedReconnectFixture();
 delete f.storage.mechanizeReconnect.format;delete f.storage.mechanizeReconnect.recoveryFences;
 f.storage.mechanizeReconnect.history=Array.from({length:37},(_,index)=>({nonce:(1000+index).toString(16).padStart(64,'0'),oldFence:index?{...grant,brokerEpoch:'audit-'+index,channelEpoch:'audit-'+index}:{...grant,brokerEpoch:'audit-0',channelEpoch:'audit-0'},newFence:index===36?{...grant}:{...grant,brokerEpoch:'audit-'+(index+1),channelEpoch:'audit-'+(index+1)},executors:[{identity,receiptRevision:3,receiptCount:3}]}));
 f.sessionState['browserIntent:retained-fixture']={attemptId:'retained-fixture'};
 f.sessionState['browserReceipt:retained-fixture']={dispatchState:'dispatched',effectState:'dispatched'};
 const history=JSON.stringify(f.storage.mechanizeReconnect.history),receipts=JSON.stringify(f.sessionState),originals=[];
 for(let index=0;index<12;index++){
  originals.push(JSON.stringify(f.storage.mechanizeReconnect));
  await interruptNextEmptyRecovery(f,'flat-interruption-'+index);
  if(f.storage.mechanizeReconnect.newFence.brokerEpoch!=='flat-interruption-'+index)console.log(JSON.stringify({interruption:index+1,version:f.storage.mechanizeReconnect.version,historyCount:f.storage.mechanizeReconnect.history.length,diagnostic:f.diagnostic()}));
  assert.ok(f.storage.mechanizeReconnect.newFence.brokerEpoch==='flat-interruption-'+index,'every interruption must write a readable current handoff');
 }
 await f.connect();f.messages.length=0;await f.receive({...restartQualification(),brokerEpoch:'flat-success',channelEpoch:'flat-success'});
 assert.ok(f.messages.some(m=>m.type==='executorPrepared'),'a reconciled current handoff must not exhaust a lifetime recovery-depth counter');
 assert.equal(f.storage.mechanizeReconnect.format,'activeHandoff');assert.equal(f.storage.mechanizeReconnect.version,1);assert.equal(f.storage.mechanizeReconnect.history.length,1);
 const archived=Object.entries(f.storage).filter(([key])=>key.startsWith('mechanizeReconnectAudit:')).map(([,value])=>value.journalJSON);
 for(const original of originals)assert.ok(archived.includes(original),'all exact prior records remain immutable');
 assert.ok(archived.some(bytes=>JSON.stringify(JSON.parse(bytes).history)===history));
 assert.equal(JSON.stringify(f.sessionState),receipts);assert.equal(f.state.deliveries,0);assert.equal(f.state.debuggerInputs,undefined);
});
test('invalid pending lineage reports journalChanged over a metadata-only native port',async()=>{
 for(const mode of ['duplicateNonce','foreignScope','wrongVersion','foreignHistory','tooDeep','tooManyNodes','tooManyBytes']){
  const f=await interruptedEmptyRecoveryFixture();let journal=f.storage.mechanizeReconnect;
  if(mode==='duplicateNonce')journal.nonce=journal.recovery.originalPending.nonce;
  if(mode==='foreignScope')journal.recovery.originalPending.oldFence.scopeHash='b'.repeat(64);
  if(mode==='wrongVersion')journal.version=4;
  if(mode==='foreignHistory')journal.history=[{nonce:'c'.repeat(64)}];
  if(mode==='tooDeep'){for(let index=0;index<20;index++)journal={...journal,version:journal.version+1,nonce:String(index).padStart(64,'0'),recovery:{kind:'emptySetupDocuments',originalPending:journal}};f.storage.mechanizeReconnect=journal;}
  if(mode==='tooManyNodes')journal.extra=Array(32769).fill(0);
  if(mode==='tooManyBytes')journal.extra='x'.repeat(262145);
  const before=JSON.stringify(f.storage),connections=f.state.nativeConnections;await f.connect();
  assert.equal(f.state.nativeConnections,connections+1,mode);f.messages.length=0;await f.receive({...restartQualification(),brokerEpoch:'blocked',channelEpoch:'blocked'});assert.ok(!f.messages.some(m=>m.type==='executorPrepared'));assert.equal(JSON.stringify(f.storage),before,mode);assert.equal(f.diagnostic().phase,'journal',mode);assert.equal(f.diagnostic().reason,'journalChanged',mode);
 }
});
test('maximum readable lineage retains preexisting receipts and rejects a nonadjacent nonce collision',async()=>{
 const f=await interruptedReconnectFixture();
 let record=JSON.parse(JSON.stringify(f.original));record.history=[{nonce:'e'.repeat(64),oldFence:{...grant,brokerEpoch:'prior',channelEpoch:'prior'},newFence:{...grant},executors:[{identity,receiptRevision:3,receiptCount:3}]}];
 for(let version=2;version<=6;version++)record={version,phase:'pending',nonce:String(version).padStart(64,'0'),oldFence:{...record.oldFence},newFence:{...record.newFence,brokerEpoch:'lineage-'+version},history:record.history,recovery:{kind:'emptySetupDocuments',originalPending:record}};
 assert.equal(f.pendingReconnectValid(record,f.storage.lastGrant),true);assert.doesNotThrow(()=>f.reconnectCanonical(record));
 record.nonce=record.recovery.originalPending.recovery.originalPending.nonce;assert.equal(f.pendingReconnectValid(record,f.storage.lastGrant),false);
});
test('enrollment failures before pending-journal validation have closed scope diagnostics rather than idle',async()=>{
 for(const mode of ['missing','invalidScope','storageRead']){
  const f=await interruptedEmptyRecoveryFixture();await interruptNextEmptyRecovery(f,'pending-three');assert.equal(f.storage.mechanizeReconnect.version,1);
  const retained=JSON.stringify(f.storage.mechanizeReconnect),connections=f.state.nativeConnections;f.setReconnectDiagnostic('idle','none');
  if(mode==='missing')delete f.storage.enrollment;
  if(mode==='invalidScope')f.storage.enrollment.origins=['https://fixture.example.test/path'];
  if(mode==='storageRead')f.state.rejectStorageRead='enrollment';
  await f.connect();assert.equal(f.diagnostic().phase,'scope',mode);assert.equal(f.diagnostic().reason,mode==='storageRead'?'storageFailure':'scopeChanged',mode);assert.equal(f.state.nativeConnections,connections,mode);assert.equal(JSON.stringify(f.storage.mechanizeReconnect),retained,mode);assert.equal(f.state.deliveries,0,mode);
 }
});
test('missing chrome tab URL has a precise closed reason and cannot bypass pending history proof',async()=>{
 const f=await interruptedEmptyRecoveryFixture();await interruptNextEmptyRecovery(f,'pending-three-metadata');
 // tabs.query omits protected URL metadata without tabs/matching-host access.
 f.state.inventoryTabs=[{id:11,url:'chrome-extension://extension/options.html'},{id:12}];
 const before=JSON.stringify(f.storage),connections=f.state.nativeConnections;await f.connect();await f.receive({...restartQualification(),brokerEpoch:'blocked',channelEpoch:'blocked'});
 assert.equal(f.diagnostic().phase,'inventory');assert.equal(f.diagnostic().reason,'inventoryChanged');assert.equal(f.inventoryReason(),'tabURLUnavailable');assert.equal(f.state.nativeConnections,connections+1);assert.equal(JSON.stringify(f.storage),before);
 const projected=f.reconnectAttention({type:'attention',error:{code:'storedFenceMismatch'}});assert.equal(projected.reconnectInventoryReason,'tabURLUnavailable');assert.ok(!JSON.stringify(projected).includes('chrome-extension'));assert.equal(f.state.deliveries,0);
});
test('each empty-inventory rejection uses bounded static metadata rather than tab or frame values',async()=>{
 const setups={
  tabQueryUnavailable:f=>{f.state.rejectTabQuery=true;},tabListInvalid:f=>{f.state.inventoryTabs={};},tabLimitExceeded:f=>{f.state.inventoryTabs=Array(201).fill({});},tabMetadataInvalid:f=>{f.state.inventoryTabs=[null];},tabIDInvalid:f=>{f.state.inventoryTabs=[{id:-1}];},tabIDDuplicate:f=>{f.state.inventoryTabs=[{id:1,url:'chrome://extensions/'},{id:1,url:'chrome://extensions/'}];},tabURLUnavailable:f=>{f.state.inventoryTabs=[{id:1}];},tabURLInvalid:f=>{f.state.inventoryTabs=[{id:1,url:'PRIVATE_CANARY'}];},pendingNavigation:f=>{f.state.inventoryTabs=[{id:1,url:'chrome://extensions/',pendingUrl:'chrome://extensions/'}];},incognitoTab:f=>{f.state.inventoryTabs=[{id:1,url:'chrome://extensions/',incognito:true}];},discardedTab:f=>{f.state.inventoryTabs=[{id:1,url:'chrome://extensions/',discarded:true}];},nonSetupTab:f=>{f.state.inventoryTabs=[{id:1,url:'https://PRIVATE_CANARY.test'}];},
  frameQueryUnavailable:f=>{f.state.rejectFrameQuery=true;},frameListUnavailable:f=>{f.state.frameRows=[];},frameLimitExceeded:f=>{f.state.frameRows=Array(33).fill({});},frameMetadataInvalid:f=>{f.state.frameRows=[null];},frameIDInvalid:f=>{f.state.frameRows[0].frameId=-1;},frameIDDuplicate:f=>{f.state.frameRows[1].frameId=0;},frameParentInvalid:f=>{delete f.state.frameRows[0].parentFrameId;},frameDocumentUnavailable:f=>{delete f.state.frameRows[0].documentId;},builtInRootFrameError:f=>{f.state.frameRows[0].errorOccurred=true;},rootLifecycleCached:f=>{f.state.frameRows[0].documentLifecycle='cached';},rootFrameTypeFenced:f=>{f.state.frameRows[0].frameType='fenced_frame';},builtInRootURLDenied:f=>{f.state.frameRows[0].url='https://PRIVATE_CANARY.test';},frameChildURLDenied:f=>{f.state.frameRows[1].url='https://PRIVATE_CANARY.test';},frameRootMissing:f=>{f.state.frameRows.shift();},frameCycle:f=>{f.state.frameRows[1].parentFrameId=1;}
 };
 for(const [reason,setup] of Object.entries(setups)){
  const f=await fixture();f.state.inventoryTabs=[{id:1,url:'chrome://newtab/'}];f.state.frameRows=builtinNewTabFrames();setup(f);const before=JSON.stringify(f.storage);
  await assert.rejects(()=>f.emptyReconnectInventory());assert.equal(f.inventoryReason(),reason);assert.equal(f.diagnostic().reason,'inventoryChanged');assert.equal(JSON.stringify(f.storage),before);
  assert.ok(!JSON.stringify(f.reconnectAttention({type:'attention',error:{code:'storedFenceMismatch'}})).includes('PRIVATE_CANARY'));assert.equal(f.state.deliveries,0);
 }
});
async function fullReconnectHistoryFixture(){
 const f=await reconnectFixture(),history=[];
 for(let index=0;index<64;index++)history.push({nonce:(index+1).toString(16).padStart(64,'0'),oldFence:{...grant,brokerEpoch:'history-'+index,channelEpoch:'history-'+index},newFence:index===63?{...grant}:{...grant,brokerEpoch:'history-'+(index+1),channelEpoch:'history-'+(index+1)},executors:[{identity,receiptCount:3,receiptRevision:3}]});
 const tail=history.at(-1);f.storage.mechanizeReconnect={version:1,phase:'adopted',nonce:tail.nonce,oldFence:tail.oldFence,newFence:tail.newFence,history};return f;
}
const archiveKeys=f=>Object.keys(f.storage).filter(key=>key.startsWith('mechanizeReconnectArchive:'));
const auditKeys=f=>Object.keys(f.storage).filter(key=>key.startsWith('mechanizeReconnectAudit:'));
const retainedAudit=(f,bytes)=>auditKeys(f).some(key=>f.storage[key].journalJSON===bytes);
test('full adopted legacy history migrates losslessly without active history rollover',async()=>{
 const f=await fullReconnectHistoryFixture(),retained=JSON.stringify(f.storage.mechanizeReconnect);f.sessionState['browserIntent:known']={};f.sessionState['browserReceipt:known']={dispatchState:'dispatched'};const receipts=JSON.stringify(f.sessionState);
 await f.receive({...restartQualification(),brokerEpoch:'next-broker',channelEpoch:'next-channel'});
 assert.ok(f.messages.some(m=>m.type==='executorPrepared'));assert.ok(retainedAudit(f,retained));assert.equal(f.storage.mechanizeReconnect.history.length,1);assert.equal(f.storage.mechanizeReconnect.archive,undefined);assert.equal(JSON.stringify(f.sessionState),receipts);assert.equal(f.state.deliveries,0);
});
test('audit-first and pending-first interruption retain original history and resume idempotently',async()=>{
 for(const phase of ['audit','pending']){
  const f=await fullReconnectHistoryFixture(),retained=JSON.stringify(f.storage.mechanizeReconnect);let interrupted=false;
  f.state.afterStorageWrite=value=>{if(!interrupted&&(phase==='audit'?Object.keys(value).some(k=>k.startsWith('mechanizeReconnectAudit:')):value.mechanizeReconnect?.format==='activeHandoff'&&value.mechanizeReconnect.phase==='pending')){interrupted=true;f.disconnect();}};
  await f.receive({...restartQualification(),brokerEpoch:'interrupted',channelEpoch:'interrupted'});delete f.state.afterStorageWrite;
  assert.ok(retainedAudit(f,retained));assert.equal(f.storage.lastGrant.brokerEpoch,grant.brokerEpoch);
  await f.connect();f.messages.length=0;respondBindings(f);await f.receive({...restartQualification(),brokerEpoch:'resumed',channelEpoch:'resumed',reconnectBindingsVersion:1});
  assert.ok(f.messages.some(m=>m.type==='executorPrepared'),phase+JSON.stringify(f.diagnostic()));assert.ok(retainedAudit(f,retained));assert.equal(f.state.deliveries,phase==='pending'?1:0);if(f.state.deliveries)assert.equal(f.state.lastRendererMessage.action,'executor.receipts');assert.equal(f.state.debuggerInputs,undefined);
 }
});
test('immediate audit corruption absence foreign fences and bounded references deny reconnect without clearing history',async()=>{
 for(const mode of ['changed','missing','foreign','bytes','nonce','digest']){
  const f=await fullReconnectHistoryFixture();await f.receive({...restartQualification(),brokerEpoch:'first',channelEpoch:'first'});f.disconnect();const key='mechanizeReconnectAudit:'+f.storage.mechanizeReconnect.audit.digest;
  if(mode==='changed'){const record=JSON.parse(f.storage[key].journalJSON);record.history[0].executors[0].receiptCount=99;f.storage[key].journalJSON=JSON.stringify(record);}
  if(mode==='missing')delete f.storage[key];if(mode==='foreign')f.storage.mechanizeReconnect.audit.oldFence.scopeHash='b'.repeat(64);
  if(mode==='bytes')f.storage.mechanizeReconnect.audit.bytes=262145;if(mode==='nonce')f.storage.mechanizeReconnect.audit.nonce='e'.repeat(64);if(mode==='digest')f.storage.mechanizeReconnect.audit.digest='f'.repeat(64);
  const retained=JSON.stringify(f.storage),connections=f.state.nativeConnections;f.messages.length=0;await f.connect();assert.equal(f.state.nativeConnections,connections+1,mode);await f.receive({...restartQualification(),brokerEpoch:'blocked-new',channelEpoch:'blocked-new'});assert.ok(!f.messages.some(m=>m.type==='executorPrepared'));assert.equal(JSON.stringify(f.storage),retained,mode);assert.equal(f.state.deliveries,0);
 }
});
test('audit write/readback disagreement refuses before replacing active journal',async()=>{
 const f=await fullReconnectHistoryFixture(),retained=JSON.stringify(f.storage.mechanizeReconnect);f.state.afterStorageWrite=value=>{for(const key of Object.keys(value))if(key.startsWith('mechanizeReconnectAudit:'))f.storage[key]={version:1,journalJSON:'{}'};};
 await f.receive({...restartQualification(),brokerEpoch:'next',channelEpoch:'next'});assert.equal(JSON.stringify(f.storage.mechanizeReconnect),retained);const frame=f.messages.at(-1);assert.equal(frame.error.code,'storedFenceMismatch');assert.equal(frame.reconnectJournal.reason,'lineageInvalid');assert.equal(frame.reconnectJournal.historyCount,64);assert.equal(f.state.deliveries,0);
});
test('legacy history migration preserves private unknown and lifecycle inhibition',async()=>{
 for(const mode of ['flow','unknown','lifecycle']){const f=await fullReconnectHistoryFixture(),retained=JSON.stringify(f.storage);f.reconnectBarrier(mode);await f.receive({...restartQualification(),brokerEpoch:'next',channelEpoch:'next'});assert.equal(auditKeys(f).length,0);assert.equal(JSON.stringify(f.storage),retained);}
});
test('flat handoffs retain every exact predecessor across a long ordinary admission history',async()=>{
 const f=await interruptedReconnectFixture(),originals=[JSON.stringify(f.storage.mechanizeReconnect)];
 await f.connect();await f.receive({...restartQualification(),brokerEpoch:'initial-recovered',channelEpoch:'initial-recovered'});
 for(let index=0;index<128;index++){
  originals.push(JSON.stringify(f.storage.mechanizeReconnect));f.disconnect();await f.connect();f.messages.length=0;
  await f.receive({...restartQualification(),brokerEpoch:'chain-'+index,channelEpoch:'chain-'+index});assert.ok(f.messages.some(m=>m.type==='executorPrepared'),'step '+index);assert.equal(f.storage.mechanizeReconnect.history.length,1);assert.equal(f.storage.mechanizeReconnect.recoveryFences.length,1);
 }
 for(const original of originals)assert.ok(retainedAudit(f,original));
 f.disconnect();await interruptNextEmptyRecovery(f,'flat-pending');await f.connect();f.messages.length=0;await f.receive({...restartQualification(),brokerEpoch:'flat-recovered',channelEpoch:'flat-recovered'});
 assert.ok(f.messages.some(m=>m.type==='executorPrepared'));assert.equal(f.storage.mechanizeReconnect.history.length,1);assert.equal(f.state.deliveries,0);
});

test('archive byte verification budget is enforced without deleting any segment',async()=>{
 const f=await fixture(),hash=value=>require('node:crypto').createHash('sha256').update(f.reconnectCanonical(value)).digest('hex');
 let prior,ref,record,total=0,counter=10000;
 const executor={identity:{...identity,profileChannel:'p'.repeat(128),browserInstance:'b'.repeat(128),documentId:'d'.repeat(128)},receiptCount:512,receiptRevision:512};
 for(let n=1;total<=8*1024*1024;n++){
  const history=prior?[prior]:[];
  while(history.length<64){const old=history.at(-1)?.newFence||{...grant,brokerEpoch:'archive-start',channelEpoch:'archive-start'},next={...grant,brokerEpoch:'archive-'+counter,channelEpoch:'archive-'+counter};history.push({nonce:(counter++).toString(16).padStart(64,'0'),oldFence:old,newFence:next,executors:Array.from({length:6},()=>executor)});}
  const tail=history.at(-1);record={version:1,phase:'adopted',nonce:tail.nonce,oldFence:tail.oldFence,newFence:tail.newFence,history,...(ref?{archive:ref}:{})};const segment={version:1,journal:record};total+=Buffer.byteLength(f.reconnectCanonical(segment));const digest=hash(segment);f.storage['mechanizeReconnectArchive:'+digest]=segment;ref={digest,segments:n,endFence:tail.newFence,nonce:tail.nonce};prior=tail;
 }
 const active={version:1,phase:'adopted',nonce:prior.nonce,oldFence:prior.oldFence,newFence:prior.newFence,history:[prior],archive:ref},keys=archiveKeys(f).length;
 await assert.rejects(()=>f.verifyArchives(active));assert.equal(archiveKeys(f).length,keys);assert.equal(f.state.deliveries,0);assert.equal(f.diagnostic().reason,'journalChanged');
});

test('private lease refusal emits only closed exact request metadata without waiting for deadline',async()=>{
 for(const mode of ['stale','foreign','unknown','error']){
  const f=await privateFixture(),probe=privateFrame({type:'credentialInspect'});for(const key of ['attemptId','controlLease','username','password'])delete probe[key];await f.receive(probe);f.messages.length=0;
  f.state.publicReply={requestId:'retry-acquire',identity:{...identity,documentGeneration:2,...(mode==='foreign'?{documentId:'foreign'}:{})},error:{code:mode==='error'?'PRIVATE_CANARY':'staleGeneration',dispatchState:mode==='unknown'?'unknown':'notDispatched',message:'PRIVATE_CANARY'}};
  const lease={id:'lease-private',generation:1};await f.receive(command('retry-acquire','executor.acquire',{attemptId:undefined,locator:undefined,controlLease:lease}));
  assert.deepEqual(JSON.parse(JSON.stringify(f.messages.at(-1))),{requestId:'retry-acquire',identity,validated:false,controlLease:lease,errorCode:mode==='stale'?'staleGeneration':'acquisitionRejected'});assert.ok(!JSON.stringify(f.messages).includes('CANARY'));
 }
});

test('missing original committed privacy tab refuses refresh without inheriting or touching a replacement tab',async()=>{
 const f=await privateFixture();await f.receive(privateFrame());await f.receive(privateSubmitFrame());f.state.documentId='original-public';
 const qualify=privacyFrame();await f.receive(qualify);const original={...f.messages.at(-1).identity};await f.receive({...qualify,type:'credentialPrivacyCommit',identity:original});assert.equal(f.messages.at(-1).ready,true);
 const injections=f.state.injections,reads=f.state.privacyReads,deliveries=f.state.deliveries,submits=f.state.privateSubmits,retained=JSON.stringify(f.storage);
 f.state.absentTabIds=[original.tabId];f.state.inventoryTabs=[{id:8,url:'https://fixture.example.test/manual-public',title:'Synthetic manual session'}];
 await f.receive({...qualify,requestId:'8'.repeat(64),permitId:'9'.repeat(64),identity:original});
 const refusal=f.messages.at(-1);assert.equal(refusal.type,'credentialPrivacyResult');assert.equal(refusal.ready,false);assert.equal(refusal.retiredAuthorityQuiesced,false);assert.equal(refusal.redactionReady,false);assert.equal(refusal.identity.tabId,original.tabId);
 assert.equal(f.state.injections,injections);assert.equal(f.state.privacyReads,reads);assert.equal(f.state.deliveries,deliveries);assert.equal(f.state.privateSubmits,submits);assert.equal(f.state.removals,undefined);assert.equal(JSON.stringify(f.storage),retained);
 const responses=f.messages.length;await f.receive({...qualify,requestId:'7'.repeat(64),permitId:'6'.repeat(64),identity:{...original,tabId:8,documentId:'manual-public'}});assert.equal(f.messages.length,responses);assert.equal(f.state.injections,injections);assert.ok(!JSON.stringify(f.messages).includes('CANARY'));
});

const manualFrame=(type,extra={})=>({type,requestId:'a'.repeat(64),proofId:'d'.repeat(64),sourceIdentity:{...identity},...grant,deadlineUnixMs:Date.now()+7000,origin:'https://fixture.example.test',...extra});
async function manualFixture(){
 const f=await privateFixture(true);f.storage.mechanizeProtectedOrigins=['https://fixture.example.test'];f.sessionState.mechanizeProtectedOrigins=[...f.storage.mechanizeProtectedOrigins];f.disconnect();f.state.inventoryTabs=[{id:8,url:'https://fixture.example.test/manual-public'}];f.state.documentId='manual-public';await f.connect();await f.receive(restartQualification());f.messages.length=0;return f;
}
test('manual private recovery proves exact absent source then qualifies fresh redactor without input or inherited lease',async()=>{
 const f=await manualFixture(),source=manualFrame('credentialTabAbsent'),storage=JSON.stringify(f.storage),session=JSON.stringify(f.sessionState);
 await f.receive(source);assert.equal(f.messages.at(-1).absent,true);assert.equal(f.messages.at(-1).inventoryComplete,true);assert.equal(f.state.privacyReads||0,0);
 const seed={...source,type:'credentialManualPrivacy',requestId:'b'.repeat(64),username:'USERNAME-CANARY',password:'PASSWORD-CANARY'};await f.receive(seed);assert.equal(seed.username,'');assert.equal(seed.password,'');const prepared=f.messages.at(-1);assert.equal(prepared.ready,true,JSON.stringify(prepared));assert.equal(prepared.identity.tabId,8);
 const blocked=f.messages.length;await f.receive(command('manual-before-commit','observe',{identity:prepared.identity}));assert.equal(f.messages.length,blocked);
 await f.receive({...source,type:'credentialManualPrivacyCommit',requestId:'c'.repeat(64),identity:prepared.identity,permitId:source.proofId});assert.equal(f.messages.at(-1).ready,true);
 f.state.publicReply={requestId:'manual-public-read',identity:prepared.identity,value:'PASSWORD-CANARY public'};await f.receive(command('manual-public-read','observe',{identity:prepared.identity}));assert.equal(f.messages.at(-1).value,'[redacted]');
 assert.equal(f.state.privateSubmits||0,0);assert.equal(f.state.removals,undefined);assert.equal(JSON.stringify(f.storage),storage);assert.equal(JSON.stringify(f.sessionState),session);assert.ok(!JSON.stringify(f.messages).includes('CANARY'));
});
test('manual privacy refuses present source, ambiguous or unsafe candidate, missing grant and authority drift',async()=>{
 for(const mode of ['source','ambiguous','none','pending','incognito','permission','frame','unknown','lifecycle','port']){
  const f=await manualFixture(),source=manualFrame('credentialTabAbsent');
  if(mode==='source')f.state.inventoryTabs.push({id:7});
  if(mode==='unknown')f.reconnectBarrier('unknown');if(mode==='lifecycle')f.reconnectBarrier('lifecycle');
  await f.receive(source);const absent=f.messages.at(-1);
  if(['source','unknown','lifecycle'].includes(mode)){assert.equal(absent.absent,false,mode);assert.equal(f.state.privacyReads||0,0);continue;}
  assert.equal(absent.absent,true);
  if(mode==='ambiguous')f.state.inventoryTabs.push({id:9,url:f.state.inventoryTabs[0].url});
  if(mode==='none')f.state.inventoryTabs=[];
  if(mode==='pending')f.state.inventoryTabs[0].pendingUrl=f.state.inventoryTabs[0].url;
  if(mode==='incognito')f.state.inventoryTabs[0].incognito=true;
  if(mode==='permission')f.state.hostGranted=false;
  if(mode==='frame')f.state.frameURL='https://other.example.test';
  if(mode==='port'){f.disconnect();await f.connect();await f.receive(restartQualification());}
  const seed={...source,type:'credentialManualPrivacy',requestId:'b'.repeat(64),username:'USERNAME-CANARY',password:'PASSWORD-CANARY'};await f.receive(seed);assert.equal(f.messages.at(-1).ready,false,mode);assert.equal(f.state.privacyReads||0,0,mode);assert.equal(seed.username,'');assert.equal(seed.password,'');assert.ok(!JSON.stringify(f.messages).includes('CANARY'));
 }
});

test('permission revocation invalidates active authority and cannot request or silently restore website access',async()=>{
 const f=await fixture();f.state.hostGranted=false;f.state.permissionRemoved();await new Promise(r=>setImmediate(r));f.messages.length=0;
 await f.receive(restartQualification());assert.equal(f.messages.at(-1).error.code,'websiteScopeMismatch');assert.ok(!f.messages.some(m=>m.type==='executorPrepared'));
 await f.receive(command('after-revocation','element.press'));assert.equal(f.state.deliveries,0);assert.equal(f.state.permissionRequests||0,0);
 f.state.hostGranted=true;f.state.permissionAdded();await new Promise(r=>setImmediate(r));await f.receive(restartQualification());assert.ok(f.messages.some(m=>m.type==='executorPrepared'));assert.equal(f.state.permissionRequests||0,0);
});
test('completed private attempt history survives automatic metadata reconnect without blocking handoff or allowing replay',async()=>{
 const f=await privateFixture(true);await f.receive(privateFrame());assert.equal(f.privateAttemptSeen('b'.repeat(64)),true);const deliveries=f.state.deliveries;
 f.disconnect();await f.connect();assert.equal(f.privateAttemptSeen('b'.repeat(64)),true);const hello=f.messages.at(-1);assert.equal(hello.type,'hello');assert.deepEqual(Array.from(hello.documents),[]);assert.ok(!JSON.stringify(hello).includes('CANARY'));
 f.messages.length=0;await f.receive({...restartQualification(),brokerEpoch:'history-new',channelEpoch:'history-new'});assert.ok(f.messages.some(m=>m.type==='executorPrepared'));assert.equal(f.state.deliveries,deliveries);
 await f.receive({...privateFrame(),brokerEpoch:'history-new',channelEpoch:'history-new'});assert.equal(f.state.deliveries,deliveries);assert.equal(f.privateAttemptSeen('b'.repeat(64)),true);
});
test('active private and unknown gates allow only metadata attention during qualification',async()=>{
 for(const barrier of ['flow','redactions','privatePending','admission','privacy','unknown','lifecycle']){
  const f=await fixture({}, {enroll:false});f.reconnectBarrier(barrier);await f.receive(restartQualification());
  assert.ok(!f.messages.some(m=>m.type==='executorPrepared'||m.type==='documents'));assert.equal(f.state.deliveries,0);assert.equal(f.state.injections||0,0);assert.equal(f.messages.at(-1)?.type,'attention',barrier);assert.ok(!JSON.stringify(f.messages).includes('fixture-private'));
 }
});
test('scheduler persistence does not retrigger connection and disabled state cancels active authority',async()=>{
 const f=await fixture();const calls=f.state.nativeConnections;f.state.storageChanged({mechanizeConnectionRetryV1:{newValue:{}}},'local');await new Promise(r=>setImmediate(r));assert.equal(f.state.nativeConnections,calls);
 f.storage.connectionEnabled=false;f.state.storageChanged({connectionEnabled:{newValue:false}},'local');await new Promise(r=>setImmediate(r));await f.receive(command('disabled','element.press'));assert.equal(f.state.deliveries,0);assert.equal(f.state.nativeConnections,calls);
});

test('invalid stored grant cannot leak extra data into metadata hello or qualify a new executor',async()=>{
 const f=await fixture();f.disconnect();f.storage.lastGrant.extra='PRIVATE-CANARY';await f.connect();const hello=f.messages.at(-1);assert.equal(hello.type,'hello');assert.equal(hello.lastGrant,undefined);assert.ok(!JSON.stringify(hello).includes('PRIVATE-CANARY'));assert.deepEqual(Array.from(hello.documents),[]);f.messages.length=0;await f.receive(restartQualification());assert.ok(!f.messages.some(m=>m.type==='executorPrepared'));assert.equal(f.state.deliveries,0);assert.equal(f.storage.lastGrant.extra,'PRIVATE-CANARY');
});

test('focused location metadata crosses private and unknown gates without publishing protected documents',async()=>{
 for(const barrier of ['flow','redactions','privatePending','admission','privacy','unknown','lifecycle']){
  const f=await fixture({}, {enroll:false});await f.receive(restartQualification());f.messages.length=0;f.reconnectBarrier(barrier);
  f.state.focusedWindows=[{id:2,focused:true}];f.state.focusedTabs=[{id:7,windowId:2,active:true,status:'complete',url:'https://fixture.example.test/private?token=PRIVATE-CANARY'}];
  const before=JSON.stringify([f.storage,f.sessionState]);await f.receive({type:'focusedLocation',requestId:'f'.repeat(64),...grant,deadlineUnixMs:Date.now()+1500,expectedOrigin:'https://fixture.example.test'});
  assert.equal(f.messages.length,1,barrier);assert.equal(f.messages[0].matchesExpectedOrigin,true,barrier);assert.equal(f.messages[0].type,'focusedLocationResult');assert.ok(!JSON.stringify(f.messages).includes('PRIVATE-CANARY'));assert.equal(JSON.stringify([f.storage,f.sessionState]),before);assert.equal(f.state.deliveries,0);assert.equal(f.state.injections||0,0);
 }
});
test('captured credential source permits a filtered independent same-origin tab and keeps original input protected',async()=>{
 const f=await privateFixture(true),probe=privateFrame({type:'credentialInspect'});for(const k of ['attemptId','controlLease','username','password'])delete probe[k];await f.receive(probe);
 f.state.inventoryTabs=[{id:7,status:'complete',url:'https://fixture.example.test/login'},{id:8,status:'complete',url:'https://fixture.example.test/public'}];f.state.frameURL='https://fixture.example.test/login';
 const capture={type:'credentialScope',requestId:'f'.repeat(64),mode:'capture',preparationId:'d'.repeat(64),sourceIdentity:identity,sourceOrigin:'https://fixture.example.test',loginRouteSHA256:'',...grant,deadlineUnixMs:Date.now()+2000,targetTabId:0,targetOrigin:'',controlLease:{id:'lease-private',generation:1}};
 await f.receive(capture);assert.equal(f.messages.at(-1).ready,true);assert.equal(f.messages.at(-1).loginRouteSHA256.length,64);await f.receive(privateFrame());assert.equal(f.messages.at(-1).status,'dispatched');
 const other={...identity,tabId:8,documentId:'other'};f.state.documentId='other';f.state.frameURL='https://fixture.example.test/public';f.state.boundDynamicIdentity=true;
 // Fresh ordinary binding is allowed only on the independent tab. The worker
 // still sanitizes all output with retained known credential variants.
 f.state.publicReply={requestId:'scoped-public',identity:other,nodes:[{text:'USERNAME-CANARY PASSWORD-CANARY'}]};
 // Populate the existing normal document registry, never a privacy permit.
 f.registerDocument(other,'https://fixture.example.test');await f.receive(command('scoped-public','observe',{identity:other,attemptId:undefined}));
 assert.ok(!JSON.stringify(f.messages.at(-1)).includes('CANARY'));assert.equal(f.messages.at(-1).requestId,'scoped-public');const before=f.state.deliveries;await f.receive(command('source-denied','observe'));assert.equal(f.state.deliveries,before);
});
test('negotiated private inspection forwards only closed causes and diagnoses old renderer protocol',async()=>{
 for(const mode of ['oldRenderer','challenge','changed','extra','formFailure','oldBinding']){
  const f=await privateFixture(true),probe=privateFrame({type:'credentialInspect',diagnostics:true});for(const k of ['attemptId','controlLease','username','password'])delete probe[k];
  if(mode==='challenge')f.state.privateReply={ready:false,stage:'challenge',identity,privateCredentialProtocolVersion:2};
  if(mode==='formFailure'||mode==='oldBinding')f.state.privateReply={ready:false,stage:'unavailable',identity,privateCredentialProtocolVersion:2};if(mode==='oldBinding')f.state.diagnosticReason='none';
  if(mode==='changed')f.state.documentId='different';
  if(mode==='extra')f.state.privateReply={ready:false,stage:'unavailable',identity,privateCredentialProtocolVersion:2,inspectionReason:'fieldsUnavailable',value:'PRIVATE-CANARY'};
  await f.receive(probe);const r=f.messages.at(-1);assert.equal(r.ready,mode==='oldRenderer');assert.equal(r.inspectionReason,({oldRenderer:'none',challenge:'challenge',changed:'documentUnavailable',extra:'rendererProtocolUnavailable',formFailure:'noCredentialFields',oldBinding:'documentBindingOrProtectionUnavailable'})[mode]);assert.ok(!JSON.stringify(r).includes('PRIVATE-CANARY'));
 }
});

test('channel browser unknown receipt survives worker restart and cannot qualify or dispatch',async()=>{
 const saved={'browserIntent:retained-open':{action:'browser.openOrigin',fingerprint:'retained'},'browserReceipt:retained-open':{type:'browser.openOriginResult',dispatchState:'unknown',tabId:0,errorCode:'receiptUnavailable'}};
 const f=await fixture(saved,{enroll:false});await f.receive(restartQualification());
 assert.ok(!f.messages.some(m=>m.type==='executorPrepared'));assert.equal(f.state.deliveries,0);
 await f.receive(command('blocked-after-open-unknown','element.press'));
 assert.equal(f.state.deliveries,0);assert.equal(f.sessionState['browserReceipt:retained-open'].dispatchState,'unknown');
 assert.equal(f.state.permissionRequests||0,0);
});

async function manualSameTabFixture(){
 const f=await manualFixture();f.resetVolatileLeases();f.state.inventoryTabs=[{id:identity.tabId,status:'complete',url:'https://fixture.example.test/manual-public'}];
 f.state.frameRows=[{frameId:0,documentId:'manual-public',url:f.state.inventoryTabs[0].url,frameType:'outermost_frame',documentLifecycle:'active'}];return f;
}
test('manual document-absence mode pins same-tab successor, keeps legacy tab absence and publishes only redacted DOM',async()=>{
 const f=await manualSameTabFixture();await f.receive(manualFrame('credentialTabAbsent'));assert.equal(f.messages.at(-1).absent,false);
 const source=manualFrame('credentialTabAbsent',{sourceDocumentAbsence:true});await f.receive(source);assert.equal(f.messages.at(-1).absent,true,JSON.stringify(f.messages.at(-1)));
 // Another same-origin tab is irrelevant: the proof pins the source tab's successor.
 f.state.inventoryTabs.push({id:9,status:'complete',url:'https://fixture.example.test/other'});
 await f.receive({...source,type:'credentialManualPrivacy',requestId:'b'.repeat(64),username:'USERNAME-CANARY',password:'PASSWORD-CANARY'});
 const prepared=f.messages.at(-1);assert.equal(prepared.ready,true,JSON.stringify(prepared));assert.equal(prepared.identity.tabId,identity.tabId);assert.notEqual(prepared.identity.documentId,identity.documentId);
 await f.receive({...source,type:'credentialManualPrivacyCommit',requestId:'c'.repeat(64),identity:prepared.identity,permitId:source.proofId});assert.equal(f.messages.at(-1).ready,true);
 f.state.publicReply={requestId:'manual-same-read',identity:prepared.identity,value:'PASSWORD-CANARY public'};await f.receive(command('manual-same-read','observe',{identity:prepared.identity}));assert.equal(f.messages.at(-1).value,'[redacted]');assert.equal(f.state.privateSubmits||0,0);assert.ok(!JSON.stringify(f.messages).includes('CANARY'));
});
test('manual document-absence mode refuses original/SPA, unsafe inventory, authority drift and successor replacement',async()=>{
 for(const mode of ['sameDocument','pending','loading','inactive','frame','unknown','lifecycle','lease','replacementBeforeSeed','replacementBeforeCommit','downgrade']){
  const f=await manualSameTabFixture(),source=manualFrame('credentialTabAbsent',{sourceDocumentAbsence:true});
  if(mode==='sameDocument')f.state.frameRows[0].documentId=identity.documentId;
  if(mode==='pending')f.state.inventoryTabs[0].pendingUrl=f.state.inventoryTabs[0].url;
  if(mode==='loading')f.state.inventoryTabs[0].status='loading';
  if(mode==='inactive')f.state.frameRows[0].documentLifecycle='prerender';
  if(mode==='frame')f.state.frameRows[0].frameType='sub_frame';
  if(['unknown','lifecycle'].includes(mode))f.reconnectBarrier(mode);if(mode==='lease')f.seedVolatileLease();
  await f.receive(source);
  if(!['replacementBeforeSeed','replacementBeforeCommit','downgrade'].includes(mode)){assert.equal(f.messages.at(-1).absent,false,mode);assert.equal(f.state.privacyReads||0,0);continue;}
  assert.equal(f.messages.at(-1).absent,true,mode);
  if(mode==='replacementBeforeSeed')f.state.frameRows[0].documentId='replacement';
  const seed={...source,type:'credentialManualPrivacy',requestId:'b'.repeat(64),username:'USERNAME-CANARY',password:'PASSWORD-CANARY'};
  if(mode==='downgrade')delete seed.sourceDocumentAbsence;
  await f.receive(seed);
  if(mode!=='replacementBeforeCommit'){assert.equal(f.messages.at(-1).ready,false,mode);continue;}
  const prepared=f.messages.at(-1);assert.equal(prepared.ready,true);f.state.frameRows[0].documentId='replacement';
  await f.receive({...source,type:'credentialManualPrivacyCommit',requestId:'c'.repeat(64),identity:prepared.identity,permitId:source.proofId});assert.equal(f.messages.at(-1).ready,false);
 }
});

function activationStatusFixtureData(){
 const attemptId='b'.repeat(64),origin='https://fixture.example.test',fingerprint=require('node:crypto').createHash('sha256').update(JSON.stringify(['mechanize-browser-activate-tab-v1','p1','b1',attemptId,origin,7,grant.brokerEpoch,grant.channelEpoch,grant.scopeHash])).digest('hex');
 const request={type:'browser.activationStatus',requestId:'c'.repeat(64),attemptId,...grant,deadlineUnixMs:Date.now()+2000,originalBrokerEpoch:grant.brokerEpoch,originalChannelEpoch:grant.channelEpoch,originalScopeHash:grant.scopeHash,origin,tabId:7,fingerprintSHA256:fingerprint};
 const saved={['browserIntent:'+attemptId]:{action:'browser.activateTab',fingerprintVersion:1,fingerprint,...grant},['browserReceipt:'+attemptId]:{type:'browser.activateTabResult',requestId:'d'.repeat(64),attemptId,...grant,dispatchState:'unknown',tabId:0,errorCode:'activationUnavailable'}};
 return {request,saved};
}
test('visibility proof holds mutation lane, retains unknown, and cannot exempt unrelated input uncertainty',async()=>{
 const {request,saved}=activationStatusFixtureData(),f=await fixture(),before=JSON.stringify(saved);await f.receive({...desktopQualification(),fixtureOnly:false});Object.assign(f.sessionState,saved);
 let unblock;f.state.blockSessionRead=new Promise(r=>unblock=r);
 const status=f.receive(request);await new Promise(r=>setTimeout(r,5));
 await f.receive(command('racing-read','observe',{attemptId:undefined}));
 assert.equal(f.messages.at(-1).error.code,'mutationBusy');assert.equal(f.state.deliveries,0);
 f.state.blockSessionRead=null;unblock();await status;
 assert.equal(f.messages.at(-1).quiescent,true);assert.equal(f.unknownCount(),1);assert.equal(f.domUnknown(),false);assert.equal(JSON.stringify(saved),before);
 await f.receive(command('reused-visibility-id','element.press',{attemptId:request.attemptId,controlLease:{id:'test-lease',generation:1}}));assert.equal(f.messages.at(-1).error.code,'attemptConflict');assert.equal(f.state.deliveries,0);
 f.reconnectBarrier('unknown');assert.equal(f.domUnknown(),true);
});
test('pending input or missing restart journal never proves visibility quiescence',async()=>{
 for(const mode of ['pending','missing','private','lifecycle']){
  const {request,saved}=activationStatusFixtureData(),f=await fixture();await f.receive({...desktopQualification(),fixtureOnly:false});if(mode!=='missing')Object.assign(f.sessionState,saved);
  if(mode==='pending')f.reconnectBarrier('mutation');if(mode==='private')f.reconnectBarrier('privatePending');if(mode==='lifecycle')f.reconnectBarrier('lifecycle');
  await f.receive(request);assert.equal(f.messages.at(-1).quiescent,false,mode);assert.equal(f.state.deliveries,0);
 }
});

 test('reconnect document limit reports a finite inventory reason without adopting',async()=>{
 const f=await reconnectFixture();f.state.frameCount=201;
 const before=JSON.stringify(f.storage.lastGrant);
 await f.receive({...restartQualification(),brokerEpoch:'limit-broker',channelEpoch:'limit-channel'});
 const result=f.messages.at(-1);
 assert.equal(result.error.code,'storedFenceMismatch');
 assert.equal(result.reconnectPhase,'inventory');
 assert.equal(result.reconnectReason,'inventoryChanged');
 assert.equal(result.reconnectInventoryReason,'frameLimitExceeded');
 assert.equal(JSON.stringify(f.storage.lastGrant),before);
 assert.equal(f.state.deliveries,0);
 assert.ok(!f.messages.some(x=>x.type==='executorPrepared'));
});

test('reconnect supports the full normal inventory limit and retains adoption proofs',async()=>{
 for(const count of [65,200]) {
  const f=await reconnectFixture();f.state.frameCount=count;f.state.boundDynamicIdentity=true;
  await f.receive({...restartQualification(),brokerEpoch:'large-broker',channelEpoch:'large-channel'});
  assert.equal(f.storage.lastGrant.brokerEpoch,'large-broker',JSON.stringify(f.messages.at(-1)));
  assert.equal(f.storage.mechanizeReconnect.phase,'adopted');
  assert.equal(f.storage.mechanizeReconnect.history.at(-1).executors.length,count);
  assert.equal(f.state.reconnectCalls.length,count*3);
  assert.ok(f.messages.some(x=>x.type==='executorPrepared'));
  f.disconnect();await f.connect();f.messages.length=0;
  await f.receive({...restartQualification(),brokerEpoch:'large-broker-next',channelEpoch:'large-channel-next'});
  assert.equal(f.storage.lastGrant.brokerEpoch,'large-broker-next');
  assert.equal(f.storage.mechanizeReconnect.history.at(-1).executors.length,count);
  assert.ok(f.messages.some(x=>x.type==='executorPrepared'));
 }
});


test('fresh native qualification is queued behind predecessor reads and stale completion cannot poison it',async()=>{
 for(const lateFailure of [false,true]){
 const f=await reconnectFixture();let release;f.state.blockSessionRead=new Promise((resolve,reject)=>release=()=>lateFailure?reject(Error('PRIVATE read error')):resolve());
 const old=f.receive({...restartQualification(),brokerEpoch:'old-flight',channelEpoch:'old-flight'});
 while(f.diagnostic().phase!=='barriers')await new Promise(resolve=>setImmediate(resolve));
 await new Promise(resolve=>setImmediate(resolve));f.disconnect();delete f.state.blockSessionRead;await f.connect();f.messages.length=0;
 await f.receive({...restartQualification(),brokerEpoch:'fresh-flight',channelEpoch:'fresh-flight',executorChallenge:'fresh-owner'});
 assert.ok(f.messages.some(m=>m.type==='attention'&&m.error?.code==='executorNotQuiescent'));
 assert.ok(!f.messages.some(m=>m.type==='executorPrepared'));
 release();await old;
 for(let n=0;n<100&&!f.messages.some(m=>m.type==='executorPrepared');n++)await new Promise(resolve=>setImmediate(resolve));
 assert.ok(f.messages.some(m=>m.type==='executorPrepared'&&m.executorChallenge==='fresh-owner'));
 assert.equal(f.storage.lastGrant.brokerEpoch,'fresh-flight');assert.equal(f.storage.mechanizeReconnect.history.length,1);
 const prepared=f.messages.findIndex(m=>m.type==='executorPrepared');await new Promise(resolve=>setImmediate(resolve));
 assert.ok(!f.messages.slice(prepared+1).some(m=>m.type==='attention'));assert.equal(f.state.deliveries,0);
 assert.equal(JSON.stringify(f.messages).includes('PRIVATE'),false);
 }
});


test('closed queued port cannot qualify and only the latest owner adopts after predecessor drains',async()=>{
 const f=await reconnectFixture();let release;f.state.blockSessionRead=new Promise(resolve=>release=resolve);
 const old=f.receive({...restartQualification(),brokerEpoch:'old-flight',channelEpoch:'old-flight'});
 while(f.diagnostic().phase!=='barriers')await new Promise(resolve=>setImmediate(resolve));
 await new Promise(resolve=>setImmediate(resolve));f.disconnect();delete f.state.blockSessionRead;await f.connect();
 await f.receive({...restartQualification(),brokerEpoch:'closed-flight',channelEpoch:'closed-flight',executorChallenge:'closed-owner'});
 f.disconnect();await f.connect();f.messages.length=0;
 await f.receive({...restartQualification(),brokerEpoch:'latest-flight',channelEpoch:'latest-flight',executorChallenge:'latest-owner'});
 release();await old;
 for(let n=0;n<100&&!f.messages.some(m=>m.type==='executorPrepared');n++)await new Promise(resolve=>setImmediate(resolve));
 assert.deepEqual(f.messages.filter(m=>m.type==='executorPrepared').map(m=>m.executorChallenge),['latest-owner']);
 assert.equal(f.storage.lastGrant.brokerEpoch,'latest-flight');assert.equal(f.storage.mechanizeReconnect.history.length,1);assert.equal(f.state.deliveries,0);
});


test('qualification deadline reports hanging injection while retaining lane and rejects late completion',async t=>{
 t.mock.timers.enable({apis:['setTimeout','Date']});
 const f=await reconnectFixture();let release;f.state.blockInjection=new Promise(resolve=>release=resolve);
 const old=f.receive({...restartQualification(),brokerEpoch:'expired-flight',channelEpoch:'expired-flight'});
 for(let n=0;n<100&&f.diagnostic().phase!=='inspect';n++)await new Promise(resolve=>setImmediate(resolve));
 assert.equal(f.diagnostic().phase,'inspect');await new Promise(resolve=>setImmediate(resolve));
 t.mock.timers.tick(10001);await new Promise(resolve=>setImmediate(resolve));
 assert.ok(f.messages.some(m=>m.type==='attention'&&m.reconnectPhase==='inspect'&&m.reconnectReason==='deadline'));
 assert.ok(!f.messages.some(m=>m.type==='executorPrepared'));assert.equal(f.storage.lastGrant.brokerEpoch,'broker1');assert.equal(f.state.deliveries,0);
 f.disconnect();delete f.state.blockInjection;await f.connect();f.messages.length=0;
 await f.receive({...restartQualification(),brokerEpoch:'replacement-flight',channelEpoch:'replacement-flight',executorChallenge:'replacement-owner'});
 assert.ok(f.messages.some(m=>m.error?.code==='executorNotQuiescent'));
 assert.ok(!f.messages.some(m=>m.type==='executorPrepared'));
 release();await old;
 for(let n=0;n<100&&!f.messages.some(m=>m.type==='executorPrepared');n++)await new Promise(resolve=>setImmediate(resolve));
 assert.deepEqual(f.messages.filter(m=>m.type==='executorPrepared').map(m=>m.executorChallenge),['replacement-owner']);
 assert.equal(f.storage.lastGrant.brokerEpoch,'replacement-flight');assert.equal(f.state.deliveries,0);
 assert.equal(f.state.reconnectCalls.filter(m=>m.newBinding.brokerEpoch==='expired-flight').length,0);
});


test('expired same-port injection cannot bind or replace its deadline with a generic error',async t=>{
 t.mock.timers.enable({apis:['setTimeout','Date']});
 const f=await fixture({}, {enroll:false});f.state.inventoryTabs=[{id:7,url:f.state.url}];f.state.boundFingerprintVersion=2;
 let release;f.state.blockInjection=new Promise(resolve=>release=resolve);
 const pending=f.receive(restartQualification());
 for(let n=0;n<100&&f.diagnostic().phase!=='inspect';n++)await new Promise(resolve=>setImmediate(resolve));
 assert.equal(f.diagnostic().phase,'inspect');await new Promise(resolve=>setImmediate(resolve));t.mock.timers.tick(10001);
 release();await pending;
 assert.equal(f.messages.at(-1).error.code,'storedFenceMismatch');assert.equal(f.messages.at(-1).reconnectReason,'deadline');
 assert.equal(f.state.binds||0,0);assert.equal(f.storage.lastGrant,undefined);assert.equal(f.state.deliveries,0);assert.ok(!f.messages.some(m=>m.type==='executorPrepared'));
});

function controllerPortFixture() {
 const events={},outward=[];
 const port={name:'mechanize-controller-v1',sender:{url:'https://shell.fixture.test/app',origin:'https://shell.fixture.test',frameId:0,tab:{id:8},documentId:'controller-document'},
  onMessage:{addListener:f=>events.message=f},onDisconnect:{addListener:f=>events.disconnect=f},postMessage:m=>outward.push(m),disconnect(){port.disconnected=true;events.disconnect?.();}};
 return {port,events,outward};
}
async function failedExecutorControllerFixture() {
 const f=await fixture({}, {enroll:false});
 f.state.inventoryTabs=[{id:7,url:f.state.url}];f.state.rejectBind=true;
 const qualified={...desktopQualification(),fixtureOnly:false};
 await f.receive(qualified);
 assert.equal(f.messages.some(m=>m.type==='executorPrepared'),false);
 assert.equal(f.messages.some(m=>m.type==='controllerSync'&&m.scopeHash===grant.scopeHash),true);
 f.nativeMessage({type:'controllerPolicy',enabled:true,origins:['https://shell.fixture.test'],...grant});
 const page=controllerPortFixture();f.state.controllerConnect(page.port);
 const open=f.messages.find(m=>m.type==='controllerOpen');assert.ok(open);
 f.nativeMessage({type:'controllerApproval',sessionId:open.sessionId,...grant});await new Promise(r=>setImmediate(r));
 assert.equal(page.outward.at(-1).type,'approved');
 return {f,page,qualified,open};
}
test('controller metadata uses process fence while executor is unavailable without renderer work',async()=>{
 const {f,page,qualified}=await failedExecutorControllerFixture();
 const before={injections:f.state.injections,deliveries:f.state.deliveries,binds:f.state.binds};
 for(const [requestId,operation] of [['initialize','initialize'],['catalog','tools/list'],['status','connection.status']]) {
  await page.events.message({type:'request',requestId,operation,deadlineUnixMs:Date.now()+1000});
  const request=f.messages.at(-1);assert.equal(request.type,'controllerRequest');assert.equal(request.operation,operation);
  if(operation==='initialize') f.nativeMessage({type:'controllerResult',requestId:request.requestId,result:{protocolVersion:'2025-11-25',capabilities:{tools:{}},serverInfo:{name:'mechanize',version:'fixture'}}});
  if(operation==='tools/list') f.nativeMessage({type:'controllerResult',requestId:request.requestId,result:{tools:[]}});
  if(operation==='connection.status') f.nativeMessage({type:'controllerResult',requestId:request.requestId,ready:false});
  assert.equal(page.outward.at(-1).requestId,requestId);assert.equal(page.outward.at(-1).error,undefined);
 }
 assert.deepEqual({injections:f.state.injections,deliveries:f.state.deliveries,binds:f.state.binds},before);
 await f.receive(command('controller-no-executor','observe'));assert.equal(f.messages.at(-1).error.code,'notEnrolled');assert.equal(f.state.deliveries,0);
 // Same process fence retry may fail again; the original controller session survives.
 await f.receive(qualified);assert.equal(page.port.disconnected,undefined);
 f.nativeMessage({type:'controllerPolicy',enabled:true,origins:['https://shell.fixture.test'],...grant});
 await page.events.message({type:'request',requestId:'same-fence',operation:'tools/list',deadlineUnixMs:Date.now()+1000});
 assert.equal(f.messages.at(-1).operation,'tools/list');assert.equal(page.port.disconnected,undefined);
 await f.receive({...qualified,channelEpoch:'replacement-channel'});assert.equal(page.port.disconnected,true);
});
test('controller process fence cannot be supplied by fixture enrollment or unqualified acknowledgements',async()=>{
 for(const fields of [{type:'enrolled'}, {type:'processQualified',scopeQualified:false,fixtureOnly:false}, {type:'processQualified',scopeQualified:true,fixtureOnly:true}]) {
  const f=await fixture({}, {enroll:false});await f.receive({...grant,...fields});
  assert.equal(f.messages.some(m=>m.type==='controllerSync'),false);
  f.nativeMessage({type:'controllerPolicy',enabled:true,origins:['https://shell.fixture.test'],...grant});
  const page=controllerPortFixture();f.state.controllerConnect(page.port);
  assert.equal(page.outward.at(-1).type,'setupRefused');assert.equal(f.messages.some(m=>m.type==='controllerOpen'),false);
  page.events.message?.({type:'setupRefusedAck'});
 }
});
test('process-qualified discovery retains private silencing and unknown execution barriers',async()=>{
 const {f,page}=await failedExecutorControllerFixture();
 f.reconnectBarrier('admission');
 const count=f.messages.length;
 await page.events.message({type:'request',requestId:'private-metadata',operation:'initialize',deadlineUnixMs:Date.now()+100});
 assert.equal(f.messages.length,count,'private discovery must not bypass the established private lane');
 f.disconnect();assert.equal(page.port.disconnected,true);
 const unknown=await fixture({'browserIntent:old':{action:'element.press',attemptId:'old'}} ,{enroll:false});
 await unknown.receive({...desktopQualification(),fixtureOnly:false});
 assert.equal(unknown.unknownCount(),1);
 await unknown.receive(command('unknown-still-held','element.press'));assert.equal(unknown.state.deliveries,0);assert.equal(unknown.unknownCount(),1);
});

async function legacyCurrentReconnectFixture(t,rows=[],options={}){
 const {JSDOM}=require('jsdom'),w=new JSDOM('<button id="public">Public</button>',{url:'https://fixture.example.test/page',runScripts:'outside-only'}).window;t.after(()=>w.close());
 w.TextEncoder=TextEncoder;Object.defineProperty(w,'crypto',{value:require('node:crypto').webcrypto,configurable:true});w.HTMLElement.prototype.getClientRects=()=>[{width:10,height:10}];
 let listener;w.chrome={runtime:{id:'extension',onMessage:{addListener:f=>listener=f}}};
 for(const file of ['protocol.js','fingerprint.js','accessibility-provider.js','dom.js','recorder.js','secure-input.js','content.js'])w.eval(fs.readFileSync(path.join(__dirname,'..',file),'utf8'));
 const f=await interruptedReconnectFixture();await f.connect();f.messages.length=0;
 f.state.inventoryTabs=[{id:7,url:'https://fixture.example.test/page'}];
 f.state.frameRows=[{frameId:0,parentFrameId:-1,documentId:'successor',url:'https://fixture.example.test/page',documentLifecycle:'active',frameType:'outermost_frame'}];
 f.state.renderer=(_,message)=>new Promise(resolve=>listener(JSON.parse(JSON.stringify(message)),{id:'extension',url:'chrome-extension://extension/worker.js'},value=>resolve(JSON.parse(JSON.stringify(value)))));
 f.state.nativePost=message=>{
  if(message.type==='reconnectBindings'){
   const digest=require('node:crypto').createHash('sha256').update(JSON.stringify(message.pending)).digest('hex');
   queueMicrotask(()=>f.receive({type:'reconnectBindingsResult',requestId:message.requestId,pendingDigest:options.badDigest?'0'.repeat(64):digest,bindingsDigest:require('node:crypto').createHash('sha256').update(JSON.stringify(rows)).digest('hex'),total:rows.length,offset:0,nextOffset:rows.length,bindings:rows}));
  }
  if(message.type==='reconnectBindingsDone'&&message.complete)queueMicrotask(()=>f.receive({type:'reconnectBindingsCommitReady',requestId:message.requestId,complete:options.releaseRefused!==true}));
 };
 return{...f,w,run:()=>f.receive({...restartQualification(),brokerEpoch:'recover-current',channelEpoch:'recover-current',reconnectBindingsVersion:1})};
}
test('active handoff cannot hide missing or UNKNOWN still-live old-epoch receipts outside its candidate fences',async t=>{
 for(const state of ['dispatched','unknown']){
  const row={identity:{...identity,documentId:'successor'},fence:{...grant,brokerEpoch:'omitted-old',channelEpoch:'omitted-old'},attemptId:'8'.repeat(64),fingerprintSHA256:'9'.repeat(64),dispatchState:state};
  const f=await legacyCurrentReconnectFixture(t,[row]),old=f.storage.mechanizeReconnect;
  f.storage.mechanizeReconnect={format:'activeHandoff',version:1,phase:'pending',nonce:old.nonce,oldFence:old.oldFence,newFence:old.newFence,history:[],recoveryFences:[old.newFence],sourceInventory:old.sourceInventory};
  assert.ok(!f.storage.mechanizeReconnect.recoveryFences.some(fence=>fence.brokerEpoch===row.fence.brokerEpoch));
  const before=JSON.stringify(f.storage.mechanizeReconnect),receipt=JSON.stringify(row);await f.run();
  assert.ok(f.messages.some(m=>m.type==='reconnectBindings'));assert.ok(!f.messages.some(m=>m.type==='executorPrepared'));
  assert.equal(JSON.stringify(f.storage.mechanizeReconnect),before);assert.equal(JSON.stringify(row),receipt);assert.equal(f.state.deliveries,0);assert.equal(f.state.debuggerInputs,undefined);
 }
});
test('complete native binding snapshot recovers legacy pending with an independently absent source and ordinary live successor',async t=>{
 const row={identity:{...identity,documentId:'original-absent'},fence:grant,attemptId:'8'.repeat(64),fingerprintSHA256:'9'.repeat(64),dispatchState:'unknown'};
 const f=await legacyCurrentReconnectFixture(t,[row]);const original=JSON.stringify(f.storage.mechanizeReconnect);await f.run();
 assert.ok(f.messages.some(x=>x.type==='executorPrepared'),JSON.stringify(f.diagnostic()));
 assert.equal(f.storage.mechanizeReconnect.phase,'adopted');assert.equal(f.storage.mechanizeReconnect.format,'activeHandoff');
 assert.equal(JSON.stringify(auditOriginal(f)),original);
 assert.ok(f.messages.some(x=>x.type==='reconnectBindingsDone'&&x.complete));assert.equal(f.state.deliveries,0);assert.equal(f.state.permissionRequests||0,0);
});
test('legacy current recovery denies missing live receipt, changed snapshot, private renderer and original frozen executor',async t=>{
 for(const mode of ['missingReceipt','digest','inactive','private','frozen']){
  const row={identity:{...identity,documentId:'successor'},fence:grant,attemptId:'8'.repeat(64),fingerprintSHA256:'9'.repeat(64),dispatchState:'dispatched'};
  const f=await legacyCurrentReconnectFixture(t,mode==='missingReceipt'?[row]:[],{badDigest:mode==='digest'});const before=JSON.stringify(f.storage.mechanizeReconnect);
  if(mode==='inactive')f.state.frameRows[0].documentLifecycle='cached';
  if(mode==='private')f.reconnectBarrier('privatePending');
  if(mode==='frozen'){
   const request={type:'brokerReconnect',phase:'prepare',nonce:'7'.repeat(64),deadlineUnixMs:Date.now()+5000,oldFence:grant,newBinding:{identity:{...identity,documentId:'successor'},brokerEpoch:'partial',channelEpoch:'partial',scopeHash:grant.scopeHash,leaseRequired:true,mutationFingerprintVersion:2}};
   assert.equal((await f.state.renderer(7,request)).phase,'prepared');
  }
  await f.run();assert.ok(!f.messages.some(x=>x.type==='executorPrepared'),mode);assert.equal(JSON.stringify(f.storage.mechanizeReconnect),before,mode);assert.equal(f.state.deliveries,0,mode);
 }
});

test('lost final binding acknowledgement preserves recoverable pending lineage without publishing a grant',async t=>{
 const f=await legacyCurrentReconnectFixture(t,[],{releaseRefused:true}),original=JSON.stringify(f.storage.mechanizeReconnect),old=JSON.stringify(f.storage.lastGrant);await f.run();
 assert.ok(!f.messages.some(x=>x.type==='executorPrepared'));assert.equal(f.storage.mechanizeReconnect.phase,'pending');assert.equal(JSON.stringify(auditOriginal(f)),original);assert.equal(JSON.stringify(f.storage.lastGrant),old);await f.verifyArchives(f.storage.mechanizeReconnect);assert.equal(f.pendingReconnectValid(f.storage.mechanizeReconnect,f.storage.lastGrant),true);assert.equal(f.state.deliveries,0);
});

test('opaque active children remain in census metadata without receiving executable authority',async t=>{
 for(const url of ['about:blank','about:srcdoc','data:text/html,PRIVATE_CANARY','blob:https://fixture.example.test/fixture-opaque','chrome-extension://foreign/child.html']){
  const f=await legacyCurrentReconnectFixture(t);f.state.frameRows.push({frameId:1,parentFrameId:0,documentId:'opaque-child',url,documentLifecycle:'active',frameType:'sub_frame'});
  const messages=[];const receive=f.state.renderer;f.state.renderer=(tab,message)=>{messages.push(message);return receive(tab,message);};
  await f.run();assert.ok(f.messages.some(m=>m.type==='executorPrepared'),url);assert.ok(messages.every(m=>(m.newBinding?.identity||m.identity)?.frameId===0));
  assert.ok(f.messages.filter(m=>m.type==='documents').every(m=>m.documents.every(d=>d.frameId===0)));assert.equal(f.state.deliveries,0);assert.ok(!JSON.stringify(f.messages).includes('PRIVATE_CANARY'));
 }
});
test('a retained original document in another tab or opaque child is never classified absent',async t=>{
 for(const mode of ['opaqueKnown','opaqueUnknown','movedRoot']){
  const row={identity:{...identity,tabId:mode==='movedRoot'?99:7,documentId:mode==='movedRoot'?'successor':'original-in-child'},fence:grant,attemptId:'8'.repeat(64),fingerprintSHA256:'9'.repeat(64),dispatchState:mode==='opaqueUnknown'?'unknown':'dispatched'};
  const f=await legacyCurrentReconnectFixture(t,[row]);if(mode!=='movedRoot')f.state.frameRows.push({frameId:1,parentFrameId:0,documentId:'original-in-child',url:'about:blank',documentLifecycle:'active',frameType:'sub_frame'});
  const before=JSON.stringify(f.storage.mechanizeReconnect);await f.run();assert.ok(!f.messages.some(m=>m.type==='executorPrepared'),mode);assert.equal(JSON.stringify(f.storage.mechanizeReconnect),before);assert.equal(f.state.deliveries,0);
  const diagnostic=f.messages.find(m=>m.type==='attention'&&m.reconnectRecovery)?.reconnectRecovery;assert.equal(diagnostic?.unavailableExecutors,1,mode);assert.equal(diagnostic?.unknownLiveReceipts,mode==='opaqueUnknown'?1:0,mode);
 }
});
test('current census diagnoses exact root and child predicates without exporting URL values',async t=>{
 for(const mode of ['rootFrameURLInvalid','childFrameURLInvalid','rootFrameUserinfoDenied','childFrameUserinfoDenied','rootFrameSchemeDenied','rootFrameOriginNotGranted','childFrameOriginNotGranted','rootTabOriginMismatch','frameParentInvalid']){
  const f=await legacyCurrentReconnectFixture(t);let frame=f.state.frameRows[0];
  if(mode.startsWith('child')){frame={frameId:1,parentFrameId:0,documentId:'child',url:'https://fixture.example.test/child',documentLifecycle:'active',frameType:'sub_frame'};f.state.frameRows.push(frame);}
  if(mode.endsWith('URLInvalid'))frame.url='PRIVATE_CANARY';else if(mode.endsWith('UserinfoDenied'))frame.url='https://user:PRIVATE_CANARY@fixture.example.test/';else if(mode==='rootFrameSchemeDenied')frame.url='about:blank';else if(mode.endsWith('OriginNotGranted'))frame.url='https://private-canary.example.test/';else if(mode==='frameParentInvalid')frame.parentFrameId=1;else{f.storage.enrollment.origins.push('https://other.example.test');frame.url='https://other.example.test/';}
  await f.run();assert.ok(!f.messages.some(m=>m.type==='executorPrepared'),mode);assert.equal(f.inventoryReason(),mode);assert.equal(f.state.deliveries,0);assert.ok(!JSON.stringify(f.messages.filter(m=>m.type==='attention')).includes('PRIVATE_CANARY'));
 }
});

test('pending writer reserves native envelope budget and accepts readable lineages above 128 KiB',async()=>{
 const f=await interruptedReconnectFixture(),pending=JSON.parse(JSON.stringify(f.storage.mechanizeReconnect));
 const rows=Array.from({length:200},(_,i)=>({identity:{...identity,tabId:i+1,documentId:String(i).padStart(128,'d')},receiptRevision:0,receiptCount:0}));
 const scope=grant.scopeHash,prior=i=>({brokerEpoch:'history-'+i,channelEpoch:'history-'+i,scopeHash:scope});
 pending.history=Array.from({length:3},(_,i)=>({nonce:(100+i).toString(16).padStart(64,'0'),oldFence:prior(i),newFence:i===2?pending.oldFence:prior(i+1),executors:rows}));
 assert.equal(f.pendingReconnectValid(pending,f.storage.lastGrant),true);assert.ok(Buffer.byteLength(JSON.stringify(pending))>128*1024);assert.doesNotThrow(()=>f.pendingWireBound(pending));
 const before=JSON.stringify(f.storage.mechanizeReconnect);
 assert.throws(()=>f.pendingWireBound({padding:'x'.repeat(256*1024-32)}));assert.equal(JSON.stringify(f.storage.mechanizeReconnect),before);
});

test('failed child frames remain non-executable metadata and preserve exact source-presence decisions',async t=>{
 for(const mode of ['unrelated','sourcePresent','identityUnknownEmpty','identityUnknownAbsentSource','rootError']){
  const row={identity:{...identity,documentId:mode==='sourcePresent'?'failed-child':'absent-original'},fence:grant,attemptId:'8'.repeat(64),fingerprintSHA256:'9'.repeat(64),dispatchState:'dispatched'};
  const f=await legacyCurrentReconnectFixture(t,['sourcePresent','identityUnknownAbsentSource'].includes(mode)?[row]:[]);
  if(mode==='rootError')f.state.frameRows[0].errorOccurred=true;
  else f.state.frameRows.push({frameId:1,parentFrameId:0,...(mode.startsWith('identityUnknown')?{}:{documentId:'failed-child'}),url:'chrome-error://chromewebdata/PRIVATE_CANARY',documentLifecycle:'active',frameType:'sub_frame',errorOccurred:true});
  const before=JSON.stringify(f.storage.mechanizeReconnect),messages=[],renderer=f.state.renderer;f.state.renderer=(tab,message)=>{messages.push(message);return renderer(tab,message);};await f.run();
  const accepted=['unrelated','identityUnknownEmpty'].includes(mode);assert.equal(f.messages.some(m=>m.type==='executorPrepared'),accepted,mode);assert.equal(f.state.deliveries,0,mode);assert.ok(messages.every(m=>(m.newBinding?.identity||m.identity)?.frameId===0),mode);
  if(!accepted)assert.equal(JSON.stringify(f.storage.mechanizeReconnect),before,mode);
  if(mode==='rootError')assert.equal(f.inventoryReason(),'rootFrameError');
  if(mode==='identityUnknownAbsentSource')assert.equal(f.inventoryReason(),'childSourceIdentityUnavailable');
  if(mode==='sourcePresent')assert.equal(f.messages.find(m=>m.type==='attention'&&m.reconnectRecovery)?.reconnectRecovery.unavailableExecutors,1);
  assert.ok(!JSON.stringify(f.messages).includes('PRIVATE_CANARY'));
 }
});

test('failed built-in New Tab child requires full binding census and never hides a retained source',async t=>{
 for(const mode of ['absent','sourcePresent','opaqueAbsent','opaquePresent','foreignURL','missingIdentity','rootError','legacyPeer']){
  const row={identity:{...identity,documentId:'builtin-new-tab-child'},fence:grant,attemptId:'8'.repeat(64),fingerprintSHA256:'9'.repeat(64),dispatchState:'dispatched'};
  const f=await legacyCurrentReconnectFixture(t,['sourcePresent','opaquePresent'].includes(mode)?[row]:[]);f.state.inventoryTabs=[{id:11,url:'chrome://newtab/'}];f.state.framesByTab={11:builtinNewTabFrames()};const frames=f.state.framesByTab[11];frames[1].errorOccurred=true;
  if(mode.startsWith('opaque')){frames[1].url='about:blank';frames[1].errorOccurred=false;}
  if(mode==='foreignURL')frames[1].url='https://PRIVATE_CANARY.test/';if(mode==='missingIdentity')delete frames[1].documentId;if(mode==='rootError')frames[0].errorOccurred=true;
  const before=JSON.stringify(f.storage.mechanizeReconnect);
  if(mode==='legacyPeer')await f.receive({...restartQualification(),brokerEpoch:'recover-current',channelEpoch:'recover-current'});else await f.run();
  assert.equal(f.messages.some(m=>m.type==='executorPrepared'),['absent','opaqueAbsent'].includes(mode),mode);
  if(['absent','opaqueAbsent'].includes(mode)){assert.ok(f.messages.some(m=>m.type==='reconnectBindings'));assert.equal(f.storage.mechanizeReconnect.format,'activeHandoff');assert.equal(JSON.stringify(auditOriginal(f)),before);}
  else assert.equal(JSON.stringify(f.storage.mechanizeReconnect),before,mode);
  if(['sourcePresent','opaquePresent'].includes(mode))assert.equal(f.messages.find(m=>m.type==='attention'&&m.reconnectRecovery)?.reconnectRecovery.unavailableExecutors,1);
  if(mode==='rootError')assert.equal(f.inventoryReason(),'builtInRootFrameError');
  assert.equal(f.state.deliveries,0);assert.ok(!JSON.stringify(f.messages).includes('PRIVATE_CANARY'));
 }
});


test('scoped public read keeps private holder and unknown journal without publishing input documents',async()=>{
 const f=await fixture();await f.receive({...desktopQualification(),fixtureOnly:false});
 f.state.url=f.state.frameURL='https://fixture.example.test/history';f.state.tabStatus='complete';f.state.inventoryTabs=[{id:7,url:f.state.url,status:'complete'}];
 f.reconnectBarrier('admission');f.reconnectBarrier('redactions');f.reconnectBarrier('unknown');
 const before=f.publicReadCounts(),journal=JSON.stringify(f.sessionState),digest=require('node:crypto').createHash('sha256').update(f.state.url).digest('hex');let readCalls=0,privateMessages=0;
 f.state.renderer=async(_tab,m)=>{
  if(m.type==='credentialPublicScope'){privateMessages++;assert.deepEqual(JSON.parse(JSON.stringify(m.redactions)),['fixture-private']);assert.equal(m.identity.documentGeneration,0);return {requestId:m.requestId,publicDocument:{version:1,identity:{...identity},routeSHA256:digest,public:true}};}
  readCalls++;return {requestId:m.requestId,identity:{...identity},nodes:[{name:'History'},{name:'fixture-private'}],truncated:false};
 };
 const request={type:'credentialScope',requestId:'e'.repeat(64),mode:'publicRead',preparationId:'0'.repeat(64),sourceIdentity:{...identity,documentId:'',documentGeneration:0},sourceOrigin:'https://fixture.example.test',loginRouteSHA256:'',...grant,deadlineUnixMs:Date.now()+4000,targetTabId:7,targetOrigin:'https://fixture.example.test'};
 await f.receive(request);assert.equal(f.messages.at(-1).ready,true);assert.equal(f.messages.at(-1).publicDocument.public,true);
 const read={publicRead:true,requestId:'public-read',action:'observe',identity,...grant,deadlineUnixMs:Date.now()+3000,args:{limit:10}};
 await f.receive(read);const result=f.messages.at(-1);assert.equal(result.requestId,read.requestId);assert.equal(result.error,undefined);assert.ok(JSON.stringify(result).includes('History'));assert.ok(!JSON.stringify(result).includes('fixture-private'));
 const after=f.publicReadCounts();assert.equal(after.documents,before.documents);assert.equal(after.leases,before.leases);assert.equal(after.privateAdmission,true);assert.equal(after.unknown,before.unknown);assert.equal(JSON.stringify(f.sessionState),journal);assert.equal(privateMessages,1);assert.equal(readCalls,1);
 await f.receive({...read,requestId:'mutation',action:'element.press',attemptId:'must-not-replay',locator:{strategy:'id',value:'button'}});assert.equal(readCalls,1);
 f.state.frameURL=f.state.url='https://fixture.example.test/login';await f.receive({...read,requestId:'changed-route'});assert.equal(f.messages.at(-1).error.code,'secureDocumentRequired');assert.equal(readCalls,1);
});

test('scoped public read refuses foreign fences, changed generation and expired proof before exposing payload',async()=>{
 for(const mode of ['fence','generation','expired','changedRoot']){
  const f=await fixture();await f.receive({...desktopQualification(),fixtureOnly:false});f.state.url=f.state.frameURL='https://fixture.example.test/history';f.state.tabStatus='complete';f.state.inventoryTabs=[{id:7,url:f.state.url,status:'complete'}];
  const digest=require('node:crypto').createHash('sha256').update(f.state.url).digest('hex');let reads=0;
  f.state.renderer=async(_tab,m)=>m.type==='credentialPublicScope'?{requestId:m.requestId,publicDocument:{version:1,identity:{...identity},routeSHA256:digest,public:true}}:(reads++,{requestId:m.requestId,identity:{...identity,documentGeneration:mode==='generation'?2:1},nodes:[{name:'MUST-NOT-EXPORT'}]});
  await f.receive({type:'credentialScope',requestId:'e'.repeat(64),mode:'publicRead',preparationId:'0'.repeat(64),sourceIdentity:{...identity,documentId:'',documentGeneration:0},sourceOrigin:'https://fixture.example.test',loginRouteSHA256:'',...grant,deadlineUnixMs:Date.now()+4000,targetTabId:7,targetOrigin:'https://fixture.example.test'});assert.equal(f.messages.at(-1).ready,true);
  const read={publicRead:true,requestId:'read-'+mode,action:'observe',identity,...grant,deadlineUnixMs:Date.now()+3000};if(mode==='fence')read.channelEpoch='foreign';if(mode==='expired')read.deadlineUnixMs=Date.now()-1;if(mode==='changedRoot')f.state.documentId='new-root';
  await f.receive(read);assert.equal(f.messages.at(-1).error.code,'secureDocumentRequired',mode);assert.ok(!JSON.stringify(f.messages.at(-1)).includes('MUST-NOT-EXPORT'));assert.equal(reads,mode==='generation'?1:0);
 }
});


test('missing tabs URL uses exact Chrome-owned frame metadata only in complete recovery',async t=>{
 for(const mode of ['absent','rootPresent','childPresent','foreignRoot','missingIdentity','cycle','rootError']){
  const row={identity:{...identity,documentId:mode==='childPresent'?'internal-child':'internal-root'},fence:grant,attemptId:'8'.repeat(64),fingerprintSHA256:'9'.repeat(64),dispatchState:'dispatched'};
  const f=await legacyCurrentReconnectFixture(t,['rootPresent','childPresent'].includes(mode)?[row]:[]);
  f.state.inventoryTabs=[{id:11,status:'complete'}];
  const frames=[{frameId:0,parentFrameId:-1,documentId:'internal-root',documentLifecycle:'active',frameType:'outermost_frame',url:'chrome://extensions/?PRIVATE_CANARY'}, {frameId:1,parentFrameId:0,documentId:'internal-child',documentLifecycle:'active',frameType:'sub_frame',url:'about:blank',errorOccurred:true}];
  if(mode==='foreignRoot')frames[0].url='https://PRIVATE_CANARY.test/';if(mode==='missingIdentity')delete frames[1].documentId;if(mode==='cycle')frames[1].parentFrameId=1;if(mode==='rootError')frames[0].errorOccurred=true;
  f.state.framesByTab={11:frames};const original=JSON.stringify(f.storage.mechanizeReconnect);await f.run();
  assert.equal(f.messages.some(m=>m.type==='executorPrepared'),mode==='absent',mode);
  if(mode==='absent'){assert.equal(f.storage.mechanizeReconnect.format,'activeHandoff');assert.equal(JSON.stringify(auditOriginal(f)),original);}
  else assert.equal(JSON.stringify(f.storage.mechanizeReconnect),original,mode);
  if(['rootPresent','childPresent'].includes(mode))assert.equal(f.messages.find(m=>m.reconnectRecovery)?.reconnectRecovery.unavailableExecutors,1);
  assert.equal(f.state.deliveries,0);assert.equal(f.state.permissionRequests||0,0);assert.ok(!JSON.stringify(f.messages).includes('PRIVATE_CANARY'));
 }
});
test('tab closure coalesces one idle failed-inventory handshake retry without clearing journal or input barriers',async t=>{
 for(const mode of ['idle','unknown','privatePending','flow','privacy','lifecycle','mutation']){
  const f=await legacyCurrentReconnectFixture(t,[]);f.state.inventoryTabs=[{id:11}];await f.run();
  assert.equal(f.inventoryReason(),'tabURLUnavailable');
  f.sessionState['terminal-fixture-receipt']={attemptId:'retained-original',dispatchState:'unknown'};
  const connections=f.state.nativeConnections,original=JSON.stringify(f.storage.mechanizeReconnect),receipts=JSON.stringify(f.sessionState);
  if(mode!=='idle')f.reconnectBarrier(mode);
  f.state.inventoryTabs=[];
  for(let i=0;i<3;i++)for(const listener of f.state.removedListeners)listener(11);
  await new Promise(resolve=>setTimeout(resolve,140));
  assert.equal(f.state.nativeConnections,connections+(mode==='idle'?1:0),mode);
  assert.equal(JSON.stringify(f.storage.mechanizeReconnect),original,mode);assert.equal(JSON.stringify(f.sessionState),receipts,mode);assert.equal(f.state.deliveries,0);assert.equal(f.state.permissionRequests||0,0);
 }
});

test('reconnect lifecycle and frame-type refusals distinguish only closed root and child metadata',async t=>{
 for(const root of [true,false])for(const [field,value,suffix] of [['documentLifecycle',undefined,'LifecycleMissing'],['documentLifecycle','prerender','LifecyclePrerender'],['documentLifecycle','cached','LifecycleCached'],['documentLifecycle','pending_deletion','LifecyclePendingDeletion'],['documentLifecycle','PRIVATE_CANARY','LifecycleInvalid'],['frameType',undefined,'FrameTypeMissing'],['frameType','fenced_frame','FrameTypeFenced'],['frameType','PRIVATE_CANARY','FrameTypeInvalid']]){
  if(!root&&['prerender','cached','fenced_frame'].includes(value))continue;
  const f=await legacyCurrentReconnectFixture(t,[]);f.state.inventoryTabs=[{id:11,status:'complete'}];
  const frames=[{frameId:0,parentFrameId:-1,documentId:'internal-root',documentLifecycle:'active',frameType:'outermost_frame',url:'chrome://extensions/'},{frameId:1,parentFrameId:0,documentId:'internal-child',documentLifecycle:'active',frameType:'sub_frame',url:'about:blank'}];
  frames[root?0:1][field]=value;f.state.framesByTab={11:frames};const original=JSON.stringify(f.storage.mechanizeReconnect);await f.run();
  assert.equal(f.inventoryReason(),(root?'root':'child')+suffix);assert.equal(f.messages.some(m=>m.type==='executorPrepared'),false);assert.equal(JSON.stringify(f.storage.mechanizeReconnect),original);assert.equal(f.state.deliveries,0);assert.ok(!JSON.stringify(f.messages).includes('PRIVATE_CANARY'));
 }
});

test('inactive identified child stays in complete census and never becomes a source absence proof',async t=>{
 for(const lifecycle of ['prerender','cached'])for(const kind of ['internal','newtab','web'])for(const state of ['absent','unknown','dispatched']){
  const row={identity:{...identity,documentId:'dormant-child'},fence:grant,attemptId:'8'.repeat(64),fingerprintSHA256:'9'.repeat(64),dispatchState:state==='absent'?'dispatched':state};
  const f=await legacyCurrentReconnectFixture(t,state==='absent'?[]:[row]);
  if(kind==='internal'){f.state.inventoryTabs=[{id:11,status:'complete'}];f.state.framesByTab={11:[{frameId:0,parentFrameId:-1,documentId:'internal-root',url:'chrome://extensions/',frameType:'outermost_frame',documentLifecycle:'active'},{frameId:1,parentFrameId:0,documentId:'dormant-child',url:'about:blank',frameType:'sub_frame',documentLifecycle:lifecycle}]};}
  else if(kind==='newtab'){f.state.inventoryTabs=[{id:11,url:'chrome://newtab/'}];f.state.frameRows=builtinNewTabFrames();Object.assign(f.state.frameRows[1],{documentId:'dormant-child',documentLifecycle:lifecycle});}
  else f.state.frameRows.push({frameId:1,parentFrameId:0,documentId:'dormant-child',url:'https://fixture.example.test/hidden',frameType:'sub_frame',documentLifecycle:lifecycle});
  const original=JSON.stringify(f.storage.mechanizeReconnect);const injected=[];f.state.injectionHook=d=>injected.push(...d.target.documentIds);await f.run();
  assert.equal(f.messages.some(m=>m.type==='executorPrepared'),state==='absent',kind+':'+lifecycle+':'+state);
  assert.equal(injected.includes('dormant-child'),false);assert.equal(f.state.deliveries,0);
  assert.equal(JSON.stringify(state==='absent'?auditOriginal(f):f.storage.mechanizeReconnect),original);
  if(state!=='absent'){const a=f.messages.find(m=>m.reconnectRecovery);assert.equal(a.reconnectRecovery.unavailableExecutors,1);if(state==='unknown')assert.equal(a.reconnectRecovery.unknownLiveReceipts,1);}
 }
});
test('same document reactivation never restores a suspended renderer lease or rewrites receipts',async()=>{
 for(const lifecycle of ['prerender','cached']){
  const f=await fixture();f.registerDocument(identity,'https://fixture.example.test');f.seedVolatileLease();
  f.state.inventoryTabs=[{id:7,url:'https://fixture.example.test/page'}];f.state.frameRows=[{frameId:0,parentFrameId:-1,documentId:'d1',url:f.state.frameURL,frameType:'outermost_frame',documentLifecycle:lifecycle}];
  f.sessionState['retained-terminal']={dispatchState:'unknown',attemptId:'original'};const original=JSON.stringify(f.sessionState);
  assert.equal((await f.inventory()).documents.length,0);const injections=f.state.injections||0,deliveries=f.state.deliveries;
  await f.receive(command('inactive-read','observe'));assert.equal(f.messages.at(-1).error.code,'documentDenied');assert.equal(f.state.injections||0,injections);
  f.state.frameRows[0].documentLifecycle='active';assert.equal((await f.inventory()).documents.length,1);
  await f.receive(command('old-input','element.press',{controlLease:{id:'held',generation:1}}));assert.equal(f.messages.at(-1).error.code,'staleAuthority');
  await f.receive(command('old-acquire','executor.acquire',{attemptId:undefined,locator:undefined,controlLease:{id:'held',generation:1}}));assert.equal(f.messages.at(-1).error.code,'staleAuthority');assert.equal(f.state.deliveries,deliveries);
  f.state.publicReply={error:{code:'staleAuthority',dispatchState:'notDispatched'}};
  await f.receive(command('wrong-retire','executor.retire',{controlLease:{id:'foreign',generation:1}}));assert.equal(f.messages.at(-1).error.code,'staleAuthority');delete f.state.publicReply;
  await f.receive(command('still-suspended','executor.acquire',{attemptId:undefined,locator:undefined,controlLease:{id:'held',generation:1}}));assert.equal(f.messages.at(-1).error.code,'staleAuthority');
  await f.receive(command('old-retire','executor.retire',{controlLease:{id:'held',generation:1}}));assert.equal(f.messages.at(-1).error,undefined);
  await f.receive(command('fresh-acquire','executor.acquire',{attemptId:undefined,locator:undefined,controlLease:{id:'fresh',generation:2}}));assert.equal(f.messages.at(-1).validated,true);
  assert.equal(JSON.stringify(f.sessionState),original);
 }
});

test('identified fenced children are non-executable census entries and never erase matching old outcomes',async t=>{
 for(const lifecycle of ['active','prerender','cached'])for(const kind of ['internal','newtab','web'])for(const state of ['absent','unknown','dispatched']){
  const row={identity:{...identity,documentId:'fenced-child'},fence:grant,attemptId:'8'.repeat(64),fingerprintSHA256:'9'.repeat(64),dispatchState:state==='absent'?'dispatched':state};
  const f=await legacyCurrentReconnectFixture(t,state==='absent'?[]:[row]);
  const child={frameId:1,parentFrameId:0,documentId:'fenced-child',frameType:'fenced_frame',documentLifecycle:lifecycle};
  if(kind==='internal'){f.state.inventoryTabs=[{id:11,status:'complete'}];f.state.framesByTab={11:[{frameId:0,parentFrameId:-1,documentId:'internal-root',url:'chrome://extensions/',frameType:'outermost_frame',documentLifecycle:'active'},child]};}
  else if(kind==='newtab'){f.state.inventoryTabs=[{id:11,url:'chrome://newtab/'}];f.state.frameRows=[builtinNewTabFrames()[0],child];}
  else f.state.frameRows.push(child);
  const original=JSON.stringify(f.storage.mechanizeReconnect),injected=[];f.state.injectionHook=d=>injected.push(...d.target.documentIds);await f.run();
  assert.equal(f.messages.some(m=>m.type==='executorPrepared'),state==='absent',kind+':'+lifecycle+':'+state);assert.equal(injected.includes('fenced-child'),false);assert.equal(f.state.deliveries,0);
  assert.equal(JSON.stringify(state==='absent'?auditOriginal(f):f.storage.mechanizeReconnect),original);
  if(state!=='absent'){const a=f.messages.find(m=>m.reconnectRecovery);assert.equal(a.reconnectRecovery.unavailableExecutors,1);if(state==='unknown')assert.equal(a.reconnectRecovery.unknownLiveReceipts,1);}
 }
});
test('fenced child metadata requires exact identity and rejects conflicting parent trees; direct attach cannot inject it',async t=>{
 for(const mode of ['missingID','cycle','outermost','invalid']){
  const f=await legacyCurrentReconnectFixture(t,[]),child={frameId:1,parentFrameId:0,documentId:'fenced-child',frameType:'fenced_frame',documentLifecycle:'prerender'};
  if(mode==='missingID')delete child.documentId;if(mode==='cycle')child.parentFrameId=1;if(mode==='outermost')child.frameType='outermost_frame';if(mode==='invalid')child.frameType='PRIVATE_CANARY';
  f.state.frameRows.push(child);const original=JSON.stringify(f.storage.mechanizeReconnect);await f.run();assert.equal(f.messages.some(m=>m.type==='executorPrepared'),false);assert.equal(JSON.stringify(f.storage.mechanizeReconnect),original);assert.equal(f.state.deliveries,0);assert.ok(!JSON.stringify(f.messages).includes('PRIVATE_CANARY'));
  if(mode==='outermost')assert.equal(f.inventoryReason(),'inactiveRootParentDenied');if(mode==='invalid')assert.equal(f.inventoryReason(),'childFrameTypeInvalid');
 }
 const f=await fixture();f.state.frameRows=[{frameId:0,parentFrameId:-1,documentId:'d1',url:f.state.frameURL,documentLifecycle:'active',frameType:'outermost_frame'},{frameId:1,parentFrameId:0,documentId:'fenced-child',url:f.state.frameURL,documentLifecycle:'active',frameType:'fenced_frame'}];
 f.state.inventoryTabs=[{id:7,url:f.state.url}];const snapshot=await f.inventory();assert.equal(snapshot.documents.some(d=>d.documentId==='fenced-child'),false);
 await f.receive(command('fenced-read','observe',{identity:{...identity,frameId:1,documentId:'fenced-child'}}));assert.equal(f.messages.at(-1).error.code,'documentDenied');assert.equal(f.state.injections||0,0);assert.equal(f.state.deliveries,0);
});

test('prerender and cached outermost forests retain every source identity without granting descendant execution',async t=>{
 for(const lifecycle of ['prerender','cached'])for(const kind of ['internal','newtab','web'])for(const source of ['absent','root','descendant','unknown']){
  const row={identity:{...identity,documentId:source==='descendant'?'forest-descendant':'forest-root'},fence:grant,attemptId:'8'.repeat(64),fingerprintSHA256:'9'.repeat(64),dispatchState:source==='unknown'?'unknown':'dispatched'};
  const f=await legacyCurrentReconnectFixture(t,source==='absent'?[]:[row]);
  const extra=[{frameId:5,parentFrameId:-1,documentId:'forest-root',frameType:'outermost_frame',documentLifecycle:lifecycle,url:'https://fixture.example.test/PRIVATE_CANARY'},{frameId:6,parentFrameId:5,parentDocumentId:'forest-root',documentId:'forest-descendant',frameType:'sub_frame',documentLifecycle:'active',url:'https://fixture.example.test/PRIVATE_CANARY'}];
  if(kind==='internal'){f.state.inventoryTabs=[{id:11,status:'complete'}];f.state.framesByTab={11:[{frameId:0,parentFrameId:-1,documentId:'internal-root',url:'chrome://extensions/',frameType:'outermost_frame',documentLifecycle:'active'},...extra]};}
  else if(kind==='newtab'){f.state.inventoryTabs=[{id:11,url:'chrome://newtab/'}];f.state.frameRows=[builtinNewTabFrames()[0],...extra];}
  else f.state.frameRows.push(...extra);
  const original=JSON.stringify(f.storage.mechanizeReconnect),injected=[];f.state.injectionHook=d=>injected.push(...d.target.documentIds);await f.run();
  assert.equal(f.messages.some(m=>m.type==='executorPrepared'),source==='absent',kind+':'+lifecycle+':'+source);assert.equal(injected.some(id=>['forest-root','forest-descendant'].includes(id)),false);assert.equal(f.state.deliveries,0);
  assert.equal(JSON.stringify(source==='absent'?auditOriginal(f):f.storage.mechanizeReconnect),original);assert.ok(!JSON.stringify(f.messages).includes('PRIVATE_CANARY'));
  if(source!=='absent'){const a=f.messages.find(m=>m.reconnectRecovery);assert.equal(a.reconnectRecovery.unavailableExecutors,1);if(source==='unknown')assert.equal(a.reconnectRecovery.unknownLiveReceipts,1);}
 }
});
test('inactive forest rejects conflicting parentage, aliases and unqualified independent roots',async t=>{
 for(const mode of ['active','rootParent','rootParentDoc','wrongParentDoc','cycle','duplicateDoc','missingDoc']){
  const f=await legacyCurrentReconnectFixture(t,[]),root={frameId:5,parentFrameId:-1,documentId:'forest-root',frameType:'outermost_frame',documentLifecycle:'prerender',url:'https://fixture.example.test/root'},child={frameId:6,parentFrameId:5,parentDocumentId:'forest-root',documentId:'forest-child',frameType:'sub_frame',documentLifecycle:'active',url:'https://fixture.example.test/child'};
  if(mode==='active')root.documentLifecycle='active';if(mode==='rootParent')root.parentFrameId=0;if(mode==='rootParentDoc')root.parentDocumentId='foreign';if(mode==='wrongParentDoc')child.parentDocumentId='foreign';if(mode==='cycle')child.parentFrameId=6;if(mode==='duplicateDoc')child.documentId=root.documentId;if(mode==='missingDoc')delete root.documentId;
  f.state.frameRows.push(root,child);const before=JSON.stringify(f.storage.mechanizeReconnect);await f.run();assert.equal(f.messages.some(m=>m.type==='executorPrepared'),false,mode);assert.equal(JSON.stringify(f.storage.mechanizeReconnect),before);assert.equal(f.state.deliveries,0);
 }
});
test('activation from an inactive outermost forest cannot resurrect a same-document lease under frame alias zero',async()=>{
 for(const source of ['root','descendant']){
  const f=await fixture();f.registerDocument(identity,'https://fixture.example.test');f.seedVolatileLease();f.state.inventoryTabs=[{id:7,url:f.state.url}];
  f.state.frameRows=[{frameId:0,parentFrameId:-1,documentId:'main-page',url:f.state.frameURL,frameType:'outermost_frame',documentLifecycle:'active'},{frameId:5,parentFrameId:-1,documentId:source==='root'?'d1':'forest-root',url:f.state.frameURL,frameType:'outermost_frame',documentLifecycle:'prerender'},{frameId:6,parentFrameId:5,documentId:source==='root'?'forest-child':'d1',url:f.state.frameURL,frameType:'sub_frame',documentLifecycle:'active'}];
  f.sessionState['retained-terminal']={dispatchState:'unknown',attemptId:'original'};const history=JSON.stringify(f.sessionState);const inventory=await f.inventory();assert.equal(inventory.documents.length,1);assert.equal(inventory.documents[0].documentId,'main-page');
  await f.receive(command('forest-read','observe',{identity:{...identity,frameId:source==='root'?5:6}}));assert.equal(f.messages.at(-1).error.code,'documentDenied');assert.equal(f.state.injections||0,0);
  f.state.frameRows=[{frameId:0,parentFrameId:-1,documentId:'d1',url:f.state.frameURL,frameType:'outermost_frame',documentLifecycle:'active'}];assert.equal((await f.inventory()).documents[0].documentId,'d1');
  await f.receive(command('alias-old','element.press',{controlLease:{id:'held',generation:1}}));assert.equal(f.messages.at(-1).error.code,'staleAuthority');assert.equal(f.state.deliveries,0);
  assert.equal(JSON.stringify(f.sessionState),history);
 }
});

test('navigation away and sameDoc BFCache return cannot reacquire the old lease under primary frame alias',async()=>{
 const f=await fixture();f.registerDocument(identity,'https://fixture.example.test');f.seedVolatileLease();
 f.sessionState['retained-terminal']={dispatchState:'unknown',attemptId:'original'};const before=JSON.stringify(f.sessionState);
 f.state.inventoryTabs=[{id:7,url:f.state.url}];f.state.frameRows=[{frameId:0,parentFrameId:-1,documentId:'new-page',url:f.state.frameURL,frameType:'outermost_frame',documentLifecycle:'active'}];
 for(const listener of f.state.committedListeners)listener({tabId:7,frameId:0,documentId:'new-page',documentLifecycle:'active',frameType:'outermost_frame'});await new Promise(r=>setImmediate(r));
 f.state.frameRows[0].documentId='d1';for(const listener of f.state.committedListeners)listener({tabId:7,frameId:0,documentId:'d1',documentLifecycle:'active',frameType:'outermost_frame'});await new Promise(r=>setImmediate(r));
 await f.receive(command('restored-old-lease','executor.acquire',{attemptId:undefined,locator:undefined,controlLease:{id:'held',generation:1}}));assert.equal(f.messages.at(-1).error.code,'staleAuthority');assert.equal(f.state.deliveries,0);assert.equal(JSON.stringify(f.sessionState),before);
});

test('version two pending recovery with thirty-six history rows distinguishes bounded metadata from input recovery',async t=>{
 for(const perEntry of [1,12,24]){
  const f=await legacyCurrentReconnectFixture(t,[]),history=[];
  for(let index=0;index<36;index++)history.push({nonce:(index+100).toString(16).padStart(64,'0'),oldFence:{...grant,brokerEpoch:'history-'+index,channelEpoch:'history-'+index},newFence:index===35?{...grant}:{...grant,brokerEpoch:'history-'+(index+1),channelEpoch:'history-'+(index+1)},executors:Array.from({length:perEntry},(_,n)=>({identity:{...identity,tabId:n+20,documentId:'source-'+n},receiptCount:3,receiptRevision:3}))});
  history[0].executors=[];
  const original={version:1,phase:'pending',nonce:'c'.repeat(64),oldFence:history[0].oldFence,newFence:{...grant,brokerEpoch:'original-uncommitted',channelEpoch:'original-uncommitted'},history:[]};
  const record={version:2,phase:'pending',nonce:'d'.repeat(64),oldFence:{...grant},newFence:{...grant,brokerEpoch:'second-uncommitted',channelEpoch:'second-uncommitted'},history,recovery:{kind:'emptySetupDocuments',originalPending:original}};
  assert.equal(f.pendingReconnectValid(record,f.storage.lastGrant),true);f.storage.mechanizeReconnect=record;
  const before=JSON.stringify(record);await f.run();const prepared=f.messages.some(m=>m.type==='executorPrepared');
  console.log(JSON.stringify({fixture:'synthetic-v2-history36',perEntry,bytes:before.length,prepared,phase:f.diagnostic().phase,reason:f.diagnostic().reason}));
  assert.equal(prepared,true);assert.equal(f.state.deliveries,0);
  const ref=f.storage.mechanizeReconnect.audit;
  if(ref){assert.equal(ref.bytes,before.length);assert.equal(f.storage['mechanizeReconnectAudit:'+ref.digest].journalJSON,before);assert.equal(require('node:crypto').createHash('sha256').update(before).digest('hex'),ref.digest);}
  else assert.equal(JSON.stringify(auditOriginal(f)),before);
 }
});

async function largePendingReconnectFixture(t){
 const perEntry=24;
  const f=await legacyCurrentReconnectFixture(t,[]),history=[];
  for(let index=0;index<36;index++)history.push({nonce:(index+100).toString(16).padStart(64,'0'),oldFence:{...grant,brokerEpoch:'history-'+index,channelEpoch:'history-'+index},newFence:index===35?{...grant}:{...grant,brokerEpoch:'history-'+(index+1),channelEpoch:'history-'+(index+1)},executors:Array.from({length:perEntry},(_,n)=>({identity:{...identity,tabId:n+20,documentId:'source-'+n},receiptCount:3,receiptRevision:3}))});
  history[0].executors=[];
  const original={version:1,phase:'pending',nonce:'c'.repeat(64),oldFence:history[0].oldFence,newFence:{...grant,brokerEpoch:'original-uncommitted',channelEpoch:'original-uncommitted'},history:[]};
  const record={version:2,phase:'pending',nonce:'d'.repeat(64),oldFence:{...grant},newFence:{...grant,brokerEpoch:'second-uncommitted',channelEpoch:'second-uncommitted'},history,recovery:{kind:'emptySetupDocuments',originalPending:original}};
 f.storage.mechanizeReconnect=record;return f;
}

test('archived pending predecessor is append-only and crash-safe before the current-record CAS',async t=>{
 for(const mode of ['archiveDisconnect','archiveLostAck','pendingDisconnect','tamper','missing','recordChanged']){
  const f=await largePendingReconnectFixture(t),original=JSON.stringify(f.storage.mechanizeReconnect);let injected=false;
  f.state.afterStorageWrite=value=>{
   const key=Object.keys(value).find(k=>k.startsWith('mechanizeReconnectAudit:'));
   if(injected)return;
   if(key){
    assert.equal(JSON.stringify(f.storage.mechanizeReconnect),original);injected=true;
    if(mode==='archiveDisconnect')f.disconnect();if(mode==='archiveLostAck')throw Error('PRIVATE_CANARY');
    if(mode==='tamper')f.storage[key].journalJSON+=' ';if(mode==='missing')delete f.storage[key];if(mode==='recordChanged')f.storage.mechanizeReconnect={...f.storage.mechanizeReconnect,nonce:'e'.repeat(64)};
    if(mode==='pendingDisconnect')injected=false;
   } else if(mode==='pendingDisconnect'&&value.mechanizeReconnect?.audit){injected=true;f.disconnect();}
  };
  await f.run();delete f.state.afterStorageWrite;
  assert.equal(f.messages.some(m=>m.type==='executorPrepared'),false,mode);assert.equal(f.state.deliveries,0);assert.ok(!JSON.stringify(f.messages).includes('PRIVATE_CANARY'));
  if(mode==='pendingDisconnect'){assert.ok(f.storage.mechanizeReconnect.audit);}
  else if(mode==='recordChanged')assert.equal(f.storage.mechanizeReconnect.nonce,'e'.repeat(64));
  else assert.equal(JSON.stringify(f.storage.mechanizeReconnect),original);
  if(['archiveDisconnect','archiveLostAck','pendingDisconnect'].includes(mode)){
   const archiveKeys=Object.keys(f.storage).filter(k=>k.startsWith('mechanizeReconnectAudit:')),saved=Object.fromEntries(archiveKeys.map(k=>[k,JSON.stringify(f.storage[k])]));
   f.disconnect();await f.connect();f.messages.length=0;await f.run();assert.equal(f.messages.some(m=>m.type==='executorPrepared'),true,mode);assert.equal(f.state.deliveries,0);for(const k of archiveKeys)assert.equal(JSON.stringify(f.storage[k]),saved[k]);
  }
 }
});
test('missing or tampered committed pending archive blocks fresh qualification without modifying current journal',async t=>{
 for(const mode of ['missing','tamper','refBytes','refVersion','refFence']){
  const f=await largePendingReconnectFixture(t);await f.run();assert.ok(f.messages.some(m=>m.type==='executorPrepared'));
  const ref=f.storage.mechanizeReconnect.audit,key='mechanizeReconnectAudit:'+ref.digest;
  if(mode==='missing')delete f.storage[key];if(mode==='tamper')f.storage[key].journalJSON+=' ';if(mode==='refBytes')ref.bytes++;if(mode==='refVersion')ref.version--;if(mode==='refFence')ref.oldFence.scopeHash='0'.repeat(64);
  const before=JSON.stringify(f.storage),injections=f.state.injections;f.disconnect();await f.connect();f.messages.length=0;await f.run();
  assert.equal(f.messages.some(m=>m.type==='executorPrepared'),false,mode);assert.equal(JSON.stringify(f.storage),before);assert.equal(f.state.injections,injections);assert.equal(f.state.deliveries,0);
 }
});
test('native reconnect binding refusal has a closed snapshot reason rather than a journal CAS claim',async t=>{
 const f=await legacyCurrentReconnectFixture(t,[]);f.state.nativePost=m=>{if(m.type==='reconnectBindings')queueMicrotask(()=>f.receive({type:'reconnectBindingsFailure',requestId:m.requestId,reason:'historyUnavailable'}));};
 const before=JSON.stringify(f.storage);await f.run();const attention=f.messages.find(m=>m.reconnectJournal);assert.equal(attention.reconnectJournal.reason,'bindingSnapshotUnavailable');assert.equal(JSON.stringify(f.storage),before);assert.equal(f.state.deliveries,0);
});

test('commit failure never restores pending over a changed current record',async()=>{
 const f=await interruptedReconnectFixture();await f.connect();f.messages.length=0;let changed;
 f.state.afterReconnectCommit=()=>{f.storage.mechanizeReconnect={...f.storage.mechanizeReconnect,nonce:'f'.repeat(64)};changed=JSON.stringify(f.storage.mechanizeReconnect);};
 await f.receive({...restartQualification(),brokerEpoch:'foreign-record',channelEpoch:'foreign-record'});
 assert.equal(f.messages.some(m=>m.type==='executorPrepared'),false);assert.equal(JSON.stringify(f.storage.mechanizeReconnect),changed);assert.equal(f.storage.mechanizeReconnect.nonce,'f'.repeat(64));assert.equal(f.state.deliveries,0);
});
test('malformed binding generations never enter the executor identity map',async()=>{
 for(const generation of [-1,0,1.5,'2',Number.MAX_SAFE_INTEGER+1])for(const route of ['attach','qualify']){
  const f=await fixture();f.state.renderer=async(_tab,message)=>message.type==='bind'?{identity:{...identity,documentGeneration:generation},mutationFingerprintVersion:2}:{error:{code:'fixture-unexpected'}};
  if(route==='attach')await f.receive(command('bad-generation','observe'));
  else{f.state.inventoryTabs=[{id:7,url:f.state.url}];await f.receive({...desktopQualification(),fixtureOnly:false});}
  assert.equal(f.messages.at(-1).error.code,'executorBindingFailed',route+':'+generation);assert.equal(f.publicReadCounts().documents,0);assert.equal(f.state.deliveries,0);assert.equal(f.messages.some(m=>m.type==='executorPrepared'),false);
 }
});
test('boolean journal validators neither throw nor mutate closed diagnostic state on budget failure',async()=>{
 const f=await fixture();f.setReconnectDiagnostic('inventory','inventoryChanged');const before=JSON.stringify(f.diagnostic());
 for(const value of [{extra:'x'.repeat(262145)},{extra:Array(32769).fill(1)},{archive:{extra:'x'.repeat(262145)}}]){
  assert.equal(f.pendingReconnectValid(value,grant),false);assert.equal(f.journalValid(value,grant),false);assert.equal(JSON.stringify(f.diagnostic()),before);
 }
});

test('ordinary reconnect rechecks archived pending ancestry after commit without publishing a grant on tamper',async t=>{
 const f=await largePendingReconnectFixture(t);await f.run();assert.ok(f.messages.some(m=>m.type==='executorPrepared'));
 const ref=f.storage.mechanizeReconnect.audit,key='mechanizeReconnectAudit:'+ref.digest;
 f.disconnect();await f.connect();f.messages.length=0;f.state.afterReconnectCommit=()=>{f.storage[key].journalJSON+=' ';};
 await f.receive({...restartQualification(),brokerEpoch:'archive-followup',channelEpoch:'archive-followup',reconnectBindingsVersion:1});
 assert.equal(f.messages.some(m=>m.type==='executorPrepared'),false);const attention=f.messages.find(m=>m.error?.code==='storedFenceMismatch');assert.ok(attention);assert.equal(attention.reconnectPhase,'commit');assert.equal(f.state.deliveries,0);
});
test('storage key reordering preserves archived pending bytes and reuses its verified orphan',async t=>{
 const f=await largePendingReconnectFixture(t);f.state.sortedStorage=true;const original=JSON.stringify(sortedStorageValue(f.storage.mechanizeReconnect));let writes=0;
 f.state.afterStorageWrite=value=>{if(Object.keys(value).some(k=>k.startsWith('mechanizeReconnectAudit:'))){writes++;f.disconnect();}};
 await f.run();assert.equal(writes,1);const key=Object.keys(f.storage).find(k=>k.startsWith('mechanizeReconnectAudit:'));assert.equal(f.storage[key].journalJSON,original);
 delete f.state.afterStorageWrite;await f.connect();f.messages.length=0;await f.run();assert.equal(f.messages.some(m=>m.type==='executorPrepared'),true);assert.equal(Object.keys(f.storage).filter(k=>k.startsWith('mechanizeReconnectAudit:')).length,1);assert.equal(f.storage[key].journalJSON,original);assert.equal(f.state.deliveries,0);
});

test('ordinary reconnect archives a carried embedded predecessor when fresh inventory exceeds the record budget',async()=>{
 const f=await reconnectFixture();let record,original;
 for(let perEntry=1;perEntry<=30;perEntry++){
  const history=Array.from({length:36},(_,i)=>({nonce:(100+i).toString(16).padStart(64,'0'),oldFence:{...grant,brokerEpoch:'carry-'+i,channelEpoch:'carry-'+i},newFence:i===35?{...grant}:{...grant,brokerEpoch:'carry-'+(i+1),channelEpoch:'carry-'+(i+1)},executors:Array.from({length:perEntry},(_,n)=>({identity:{...identity,tabId:n+20,documentId:'carried-original-'+n},receiptCount:3,receiptRevision:3}))}));
  const predecessor={version:1,phase:'pending',nonce:'c'.repeat(64),oldFence:history[29].newFence,newFence:{...grant,brokerEpoch:'carry-abandoned',channelEpoch:'carry-abandoned'},history:history.slice(0,30)};
  const tail=history.at(-1),candidate={version:2,phase:'adopted',nonce:tail.nonce,oldFence:tail.oldFence,newFence:tail.newFence,history,recovery:{kind:'verifiedCurrentDocuments',originalPending:predecessor}};
  if(JSON.stringify(candidate).length<245000){record=candidate;original=JSON.stringify(candidate);}else break;
 }
 assert.ok(JSON.stringify(record).length>225000);assert.equal(f.journalValid(record,f.storage.lastGrant),true);f.storage.mechanizeReconnect=record;f.state.frameCount=200;
 await f.receive({...restartQualification(),brokerEpoch:'carry-next',channelEpoch:'carry-next'});
 assert.equal(f.messages.some(m=>m.type==='executorPrepared'),true,JSON.stringify(f.diagnostic()));const ref=f.storage.mechanizeReconnect.audit;assert.ok(ref);assert.equal(f.storage['mechanizeReconnectAudit:'+ref.digest].journalJSON,original);assert.equal(f.state.deliveries,0);
});
test('cold pending archive cache resolves afresh and missing references never terminate nonce proof silently',async t=>{
 const f=await largePendingReconnectFixture(t);await f.run();const current=f.storage.mechanizeReconnect,ref=current.audit;
 assert.equal(f.journalValid(current,f.storage.lastGrant),false,'qualification end must discard the cache');
 await f.verifyArchives(current);assert.equal(f.journalValid(current,f.storage.lastGrant),true);
 delete f.storage['mechanizeReconnectAudit:'+ref.digest];await assert.rejects(()=>f.verifyArchives(current));assert.equal(f.journalValid(current,f.storage.lastGrant),false);assert.equal(f.state.deliveries,0);
});
test('blocked archive read obeys qualification deadline without publishing input or overwriting history',async t=>{
 t.mock.timers.enable({apis:['setTimeout','Date'],now:Date.now()});
 const f=await largePendingReconnectFixture(t);await f.run();f.disconnect();await f.connect();f.messages.length=0;
 const original=JSON.stringify(f.storage.mechanizeReconnect),ref=f.storage.mechanizeReconnect.audit;let release;
 f.state.blockStorageReadKey='mechanizeReconnectAudit:'+ref.digest;f.state.blockStorageRead=new Promise(r=>release=r);
 const pending=f.receive({...restartQualification(),brokerEpoch:'blocked-archive',channelEpoch:'blocked-archive',reconnectBindingsVersion:1});for(let i=0;i<20;i++)await new Promise(r=>setImmediate(r));
 t.mock.timers.tick(10001);await new Promise(r=>setImmediate(r));
 assert.ok(f.messages.some(m=>m.type==='attention'&&m.reconnectReason==='deadline'));
 release();await pending;
 assert.equal(f.messages.some(m=>m.type==='executorPrepared'),false);assert.equal(JSON.stringify(f.storage.mechanizeReconnect),original);assert.equal(f.state.deliveries,0);
});

test('explicit read-proof routing cannot trap ordinary control validation with stale generation or expiry',async()=>{
 for(const mode of ['generation','expiry']){
  const f=await fixture();f.state.url=f.state.frameURL='https://fixture.example.test/public';f.state.tabStatus='complete';f.state.inventoryTabs=[{id:7,url:f.state.url,status:'complete'}];
  const digest=require('node:crypto').createHash('sha256').update(f.state.url).digest('hex');let metadata=0;
  f.state.renderer=async(_tab,m)=>{
   assert.equal(Object.hasOwn(m,'publicRead'),false,'worker routing marker must not reach renderer');
   if(m.type==='bind')return {identity:{...identity},mutationFingerprintVersion:2};
   if(m.type==='credentialPublicScope')return {requestId:m.requestId,publicDocument:{version:1,identity:{...identity,documentGeneration:5},routeSHA256:digest,public:true}};
   if(m.action==='executor.validate'){metadata++;return {requestId:m.requestId,identity:{...identity,documentGeneration:6},validated:true};}
   if(m.action==='executor.acquire')return {requestId:m.requestId,identity:{...identity,documentGeneration:6},controlLease:m.controlLease,validated:true};
   throw Error('unexpected operation');
  };
  await f.receive({...desktopQualification(),fixtureOnly:false});f.messages.length=0;
  await f.receive({type:'credentialScope',requestId:'e'.repeat(64),mode:'publicRead',preparationId:'0'.repeat(64),sourceIdentity:{...identity,documentId:'',documentGeneration:0},sourceOrigin:'https://fixture.example.test',loginRouteSHA256:'',...grant,deadlineUnixMs:Date.now()+4000,targetTabId:7,targetOrigin:'https://fixture.example.test'});assert.equal(f.messages.at(-1).ready,true);
  if(mode==='expiry')f.expirePublicReads();
  await f.receive({publicRead:true,requestId:'marked-stale-'+mode,action:'executor.validate',identity:{...identity,documentGeneration:5},...grant,deadlineUnixMs:Date.now()+3000});assert.equal(f.messages.at(-1).error.code,'secureDocumentRequired');const prior=metadata;
  await f.receive({requestId:'ordinary-validate-'+mode,action:'executor.validate',identity,...grant,deadlineUnixMs:Date.now()+3000});assert.equal(f.messages.at(-1).validated,true);assert.equal(f.messages.at(-1).identity.documentGeneration,6);assert.equal(metadata,prior+1);
  await f.receive({requestId:'ordinary-acquire-'+mode,action:'executor.acquire',identity:{...identity,documentGeneration:6},controlLease:{id:'fresh-control',generation:1},...grant,deadlineUnixMs:Date.now()+3000});assert.equal(f.messages.at(-1).validated,true);assert.equal(f.publicReadCounts().leases,1);assert.equal(f.state.deliveries,0);
 }
});
test('explicit read marker cannot authorize absent proof, mutation, or leased command',async()=>{
 const f=await fixture();const before=f.state.deliveries;
 for(const extra of [{publicRead:true},{publicRead:false},{publicRead:'true'},{publicRead:true,action:'element.press',attemptId:'not-input',locator:{strategy:'id',value:'x'}},{publicRead:true,controlLease:{id:'not-allowed',generation:1}}]){
  await f.receive({requestId:'marked-'+Math.random(),action:'executor.validate',identity,...grant,deadlineUnixMs:Date.now()+3000,...extra});assert.equal(f.messages.at(-1).error.code,'secureDocumentRequired');
 }
 assert.equal(f.state.deliveries,before);assert.equal(f.publicReadCounts().leases,0);assert.equal(f.state.injections||0,0);
});

async function publicProofFixture(change=()=>{}){
 const f=await fixture();f.state.url=f.state.frameURL='https://fixture.example.test/public';f.state.tabStatus='complete';f.state.inventoryTabs=[{id:7,url:f.state.url,status:'complete'}];
 f.state.renderer=async()=>({identity:{...identity},mutationFingerprintVersion:2});await f.receive({...desktopQualification(),fixtureOnly:false});f.messages.length=0;
 const proof={version:1,identity:{...identity},public:true,routeSHA256:require('node:crypto').createHash('sha256').update(f.state.url).digest('hex')};change(proof);
 f.state.renderer=async(_tab,m)=>{assert.equal(m.type,'credentialPublicScope');return {requestId:m.requestId,publicDocument:proof};};
 return {f,request:{type:'credentialScope',requestId:'e'.repeat(64),mode:'publicRead',preparationId:'0'.repeat(64),sourceIdentity:{...identity,documentId:'',documentGeneration:0},sourceOrigin:'https://fixture.example.test',loginRouteSHA256:'',...grant,deadlineUnixMs:Date.now()+4000,targetTabId:7,targetOrigin:'https://fixture.example.test'}};
}
test('production public proof validator rejects malformed renderer proofs before scope insertion',async()=>{
 const changes={extra:p=>p.extra='PRIVATE_CANARY',version:p=>p.version=2,notPublic:p=>p.public=false,hash:p=>p.routeSHA256='bad',wrongRoute:p=>p.routeSHA256='0'.repeat(64),profile:p=>p.identity.profileChannel='foreign',browser:p=>p.identity.browserInstance='foreign',tab:p=>p.identity.tabId=8,frame:p=>p.identity.frameId=1,document:p=>p.identity.documentId='foreign',extraIdentity:p=>p.identity.extra=true};
 for(const generation of [0,-1,1.5,'1',Number.MAX_SAFE_INTEGER+1])changes['generation'+generation]=p=>p.identity.documentGeneration=generation;
 for(const [name,change]of Object.entries(changes)){
  const {f,request}=await publicProofFixture(change);await f.receive(request);
  assert.equal(f.messages.at(-1).ready,false,name);assert.equal(f.publicReadCounts().publicReads,0,name);assert.equal(f.publicReadCounts().documents,1);assert.equal(f.publicReadCounts().leases,0);assert.equal(f.state.deliveries,0);assert.ok(!JSON.stringify(f.messages).includes('PRIVATE_CANARY'));
 }
 const {f,request}=await publicProofFixture();await f.receive(request);assert.equal(f.messages.at(-1).ready,true);assert.equal(f.publicReadCounts().publicReads,1);assert.equal(f.publicReadCounts().leases,0);
});
test('public read scope capacity prunes only expired or predecessor-port proofs',async()=>{
 for(const mode of ['expired','foreignPort','active']){
  const {f,request}=await publicProofFixture();f.seedPublicReads(mode);assert.equal(f.publicReadCounts().publicReads,200);await f.receive(request);
  assert.equal(f.publicReadCounts().publicReads,mode==='active'?200:1,mode);assert.equal(f.messages.some(m=>m.type==='credentialScopeResult'&&m.ready),mode!=='active',mode);assert.equal(f.publicReadCounts().leases,0);assert.equal(f.state.deliveries,0);
 }
});

async function shippedBindingFixture(t,privateOrigin=false){
 const {JSDOM}=require('jsdom');
 const w=new JSDOM(privateOrigin?'<form method="post"><input autocomplete="username"><input type="password" autocomplete="current-password"><button>Login</button></form>':'<button id="save">Fixture</button>',{url:'https://fixture.example.test/login',runScripts:'outside-only'}).window;
 t.after(()=>w.close());w.TextEncoder=TextEncoder;Object.defineProperty(w,'crypto',{value:require('node:crypto').webcrypto});w.HTMLElement.prototype.getClientRects=()=>[{width:100,height:20}];
 let listener;w.chrome={runtime:{id:'extension',onMessage:{addListener:fn=>listener=fn}}};
 for(const file of ['protocol.js','fingerprint.js','accessibility-provider.js','dom.js','recorder.js','secure-input.js','content.js'])w.eval(fs.readFileSync(path.join(__dirname,'..',file),'utf8'));
 const f=await fixture(privateOrigin?{mechanizeProtectedOrigins:['https://fixture.example.test']}:{},{enroll:false});
 f.state.boundBindings=[];f.state.renderer=(_,message)=>new Promise(resolve=>{if(message.type==='bind')f.state.boundBindings.push(structuredClone(message.binding));listener(JSON.parse(JSON.stringify(message)),{id:'extension',url:'chrome-extension://extension/worker.js'},value=>resolve(JSON.parse(JSON.stringify(value))));});
 // Qualify an empty browser first; the later tab uses the on-demand bind path.
 await f.receive(restartQualification());f.messages.length=0;
 f.state.inventoryTabs=[{id:7,url:f.state.url,title:'Public fixture'}];
 return {f,w,send:message=>new Promise(resolve=>listener(message,{id:'extension'},resolve))};
}
test('on-demand public binding keeps qualified trust shape across same-fence enrollment with shipped content',async t=>{
 const {f,w,send}=await shippedBindingFixture(t);let clicks=0;w.document.querySelector('button').onclick=()=>clicks++;
 await f.receive(command('shape-observe','observe',{attemptId:undefined}));
 const first=f.state.boundBindings[0];assert.equal(first.trustScope,'desktop');assert.equal(first.scopeQualified,true);assert.equal(first.profileQualified,false);
 const lease={id:'shape-lease',generation:1};
 assert.equal((await send(command('shape-acquire','executor.acquire',{attemptId:undefined,locator:undefined,controlLease:lease}))).validated,true);
 f.messages.length=0;await f.receive(restartQualification());
 assert.ok(f.messages.some(message=>message.type==='executorPrepared'),JSON.stringify(f.messages.map(m=>({type:m.type,code:m.error?.code}))));
 const after=f.state.boundBindings.at(-1);for(const key of Object.keys(first))assert.deepEqual(key==='identity'?Object.fromEntries(Object.keys(identity).map(k=>[k,after.identity[k]])):after[key],first[key]);
 assert.equal((await send(command('shape-validate','executor.validate',{attemptId:undefined,locator:undefined,controlLease:lease}))).validated,true);
 assert.equal((await send({type:'bind',binding:{...first,channelEpoch:'foreign'}})).error.code,'executorNotQuiescent');assert.equal(clicks,0);assert.equal(f.state.debuggerInputs,undefined);
});
test('private candidate binding derives trust only from grant and cannot rebind through private protection',async t=>{
 const {f,w,send}=await shippedBindingFixture(t,true);
 const probe=privateFrame({type:'credentialInspect',recipientId:'f'.repeat(64)});for(const key of ['attemptId','controlLease','username','password'])delete probe[key];
 await f.receive(probe);assert.equal(f.messages.at(-1).ready,true);
 const first=f.state.boundBindings[0];assert.equal(first.trustScope,'desktop');assert.equal(first.scopeQualified,true);assert.equal(first.profileQualified,false);
 assert.equal((await send({type:'bind',binding:{...first}})).error,undefined);
 const before=f.state.boundBindings.length;await f.receive({...probe,requestId:'e'.repeat(64),trustScope:'desktop',scopeQualified:true,profileQualified:false});assert.equal(f.state.boundBindings.length,before);
 // A retained private continuation is an actual input guard, not binding metadata.
 const bindingCommand={type:'credentialManualPrivacyBind',requestId:'a'.repeat(64),identity,...grant,deadlineUnixMs:Date.now()+5000,origin:w.location.origin,permitId:'b'.repeat(64),redactions:w.MechanizeSecureInput.redactionVariants(['PRIVATE-FIXTURE-CANARY'])};
 const bound=await send(bindingCommand);assert.equal(bound.ready,false);
 const refused=await send({type:'bind',binding:first});assert.equal(refused.error.code,'secureDocumentRequired');
 assert.equal(w.document.querySelector('[type=password]').value,'');assert.equal(f.state.debuggerInputs,undefined);
 assert.ok(!JSON.stringify(f.messages).includes('CANARY'));
});
test('legacy enrollment keeps its original bind shape without inventing trust metadata',async()=>{
 const f=await fixture();let sent;
 f.state.renderer=async(_,message)=>{sent=message;return message.type==='bind'?{identity,mutationFingerprintVersion:1}:{requestId:message.requestId,identity,validated:true};};
 await f.receive(command('legacy-shape','executor.validate',{attemptId:undefined,locator:undefined}));
 // Use a fresh document so the next read records the actual on-demand bind.
 const bindings=[];f.state.documentId='legacy-second';f.state.renderer=async(_,message)=>{if(message.type==='bind'){bindings.push(message.binding);return {identity:message.binding.identity,mutationFingerprintVersion:1};}return {requestId:message.requestId,identity:message.identity,validated:true};};
 await f.receive(command('legacy-second-read','executor.validate',{identity:{...identity,documentId:'legacy-second'},attemptId:undefined,locator:undefined}));
 assert.equal(bindings.length,1);for(const key of ['trustScope','scopeQualified','profileQualified'])assert.equal(Object.hasOwn(bindings[0],key),false);
 assert.equal(f.state.debuggerInputs,undefined);
});

test('unrelated discarded tab is scoped metadata and never wakes during complete legacy recovery',async t=>{
 for(const frameMode of ['empty','known','unavailable']){
  const row={identity:{...identity,documentId:'old-absent'},fence:grant,attemptId:'8'.repeat(64),fingerprintSHA256:'9'.repeat(64),dispatchState:'unknown'};
  const f=await legacyCurrentReconnectFixture(t,[row]);const original=JSON.stringify(f.storage.mechanizeReconnect);
  f.state.inventoryTabs.unshift({id:11,discarded:true,url:'https://fixture.example.test/discarded?PRIVATE_CANARY'});
  f.state.framesByTab={11:frameMode==='known'?[{frameId:0,parentFrameId:-1,documentId:'discarded-doc',url:'https://fixture.example.test/discarded',frameType:'outermost_frame',documentLifecycle:'cached'}]:[]};
  if(frameMode==='unavailable')f.state.framesByTab[11]=null;
  const sent=[];const renderer=f.state.renderer;f.state.renderer=(tab,message)=>{sent.push(tab);return renderer(tab,message);};
  await f.run();assert.ok(f.messages.some(m=>m.type==='executorPrepared'),JSON.stringify(f.diagnostic()));
  assert.equal(JSON.stringify(auditOriginal(f)),original);assert.ok(sent.every(tab=>tab===7));
  assert.ok(f.messages.filter(m=>m.type==='documents').every(m=>m.documents.every(d=>d.tabId===7)));
  assert.equal(f.state.createdSetupTabs||0,0);assert.equal(f.state.activatedSetupTab,undefined);assert.equal(f.state.deliveries,0);assert.equal(f.state.debuggerInputs,undefined);assert.ok(!JSON.stringify(f.messages).includes('PRIVATE_CANARY'));
 }
});
test('discarded owner scope keeps terminal UNKNOWN and private source barriers without rewriting journal',async t=>{
 for(const mode of ['notDispatched','dispatched','unknown','movedDocument','private','privateMoved']){
  const row={identity:{...identity,tabId:mode==='movedDocument'?99:11,documentId:'discarded-doc'},fence:grant,attemptId:'8'.repeat(64),fingerprintSHA256:'9'.repeat(64),dispatchState:mode==='unknown'?'unknown':mode==='notDispatched'?'notDispatched':'dispatched'};
  const f=await legacyCurrentReconnectFixture(t,mode.startsWith('private')?[]:[row]);
  f.state.inventoryTabs.unshift({id:11,discarded:true,url:'https://fixture.example.test/login'});f.state.framesByTab={11:['movedDocument','privateMoved'].includes(mode)?[{frameId:0,parentFrameId:-1,documentId:mode==='privateMoved'?'private-source':'discarded-doc',frameType:'outermost_frame',documentLifecycle:'cached',url:'https://fixture.example.test/login'}]:[]};
  if(mode.startsWith('private')){
   const route='https://fixture.example.test/login';f.storage.mechanizeCredentialScopesV1={version:1,records:[{preparationId:'c'.repeat(64),identity:{...identity,tabId:mode==='privateMoved'?99:11,documentId:'private-source'},origin:'https://fixture.example.test',loginRoute:route,loginRouteSHA256:require('node:crypto').createHash('sha256').update(route).digest('hex'),retired:false}]};f.disconnect();await f.connect();f.messages.length=0;
  }
  const original=JSON.stringify(f.storage.mechanizeReconnect);await f.run();assert.ok(!f.messages.some(m=>m.type==='executorPrepared'),mode);assert.equal(JSON.stringify(f.storage.mechanizeReconnect),original);
  const counts=f.messages.find(m=>m.reconnectRecovery)?.reconnectRecovery;assert.equal(counts?.unavailableExecutors,1,mode);assert.equal(counts.privateSources,mode.startsWith('private')?1:0);assert.equal(counts.unknownLiveReceipts,mode==='unknown'?1:0);assert.equal(f.state.deliveries,0);
 }
});
test('discarded reactivation during recovery prevents publication and ordinary admission cannot wake tab',async t=>{
 const f=await legacyCurrentReconnectFixture(t);f.state.inventoryTabs.push({id:11,discarded:true,url:'https://fixture.example.test/parked'});f.state.framesByTab={11:[]};
 const renderer=f.state.renderer;f.state.renderer=(tab,message)=>{if(message.type==='brokerReconnect'&&message.phase==='prepare')f.state.inventoryTabs[1].discarded=false;return renderer(tab,message);};
 await f.run();assert.ok(!f.messages.some(m=>m.type==='executorPrepared'));assert.equal(f.state.deliveries,0);assert.equal(f.state.activatedSetupTab,undefined);
 const ordinary=await privateFixture(true);ordinary.state.tabDiscarded=true;const before=ordinary.state.deliveries;
 await ordinary.receive(command('discarded-observe','observe',{attemptId:undefined}));assert.equal(ordinary.messages.at(-1).error.code,'documentDenied');assert.equal(ordinary.state.deliveries,before);
 ordinary.state.tabDiscarded=false;await ordinary.receive(command('old-lease-after-wake','executor.acquire',{attemptId:undefined,locator:undefined,controlLease:{id:'lease-private',generation:1}}));assert.equal(ordinary.messages.at(-1).error.code,'staleAuthority');assert.equal(ordinary.state.deliveries,before);
});
test('discarded private inspector refuses before packaged injection and malformed flag never becomes eligibility',async t=>{
 const {f}=await shippedBindingFixture(t,true);f.state.tabDiscarded=true;
 const probe=privateFrame({type:'credentialInspect',diagnostics:true});for(const key of ['attemptId','controlLease','username','password'])delete probe[key];
 const injections=f.state.injections||0;await f.receive(probe);assert.equal(f.messages.at(-1).ready,false);assert.equal(f.messages.at(-1).inspectionReason,'documentUnavailable');assert.equal(f.state.injections||0,injections);assert.equal(f.state.boundBindings.length,0);assert.equal(f.state.deliveries,0);
 const invalid=await legacyCurrentReconnectFixture(t);invalid.state.inventoryTabs.unshift({id:11,url:'https://fixture.example.test/parked',discarded:'true'});const original=JSON.stringify(invalid.storage.mechanizeReconnect);await invalid.run();assert.ok(!invalid.messages.some(m=>m.type==='executorPrepared'));assert.equal(invalid.inventoryReason(),'tabMetadataInvalid');assert.equal(JSON.stringify(invalid.storage.mechanizeReconnect),original);
});

test('reconnect consumes durable Playwright terminal proof after extension session storage is cleared',async t=>{
 const row={identity:{...identity,documentId:'successor'},fence:grant,attemptId:'8'.repeat(64),fingerprintSHA256:'9'.repeat(64),dispatchState:'dispatched'};
 const f=await legacyCurrentReconnectFixture(t,[row]);
 const record={phase:'done',requestId:'original-pw',attemptId:row.attemptId,identity:row.identity,controlLease:{id:'original-lease',generation:1},...grant,fingerprintSHA256:row.fingerprintSHA256};
 record.receipt={requestId:record.requestId,attemptId:record.attemptId,identity:record.identity,controlLease:record.controlLease,fingerprintVersion:2,fingerprintSHA256:record.fingerprintSHA256,dispatchState:'dispatched',effectState:'unverified',inputSemantics:'Local Playwright over scoped extension CDP'};
 f.storage.mechanizePlaywrightJournalV1={version:1,records:{[record.attemptId]:record}};
 for(const key of Object.keys(f.sessionState))if(key.startsWith('playwrightAttempt:'))delete f.sessionState[key];
 const before=JSON.stringify(f.storage.mechanizePlaywrightJournalV1);await f.run();
 assert.ok(f.messages.some(m=>m.type==='executorPrepared'),JSON.stringify(f.diagnostic()));assert.equal(JSON.stringify(f.storage.mechanizePlaywrightJournalV1),before);assert.equal(f.state.deliveries,0);assert.equal(f.unknownCount(),0);
});
test('missing live receipt source correlation hashes exact stable identity without exposing it on native attention',async t=>{
 const row={identity:{...identity,documentId:'successor'},fence:grant,attemptId:'8'.repeat(64),fingerprintSHA256:'9'.repeat(64),dispatchState:'dispatched'};
 const f=await legacyCurrentReconnectFixture(t,[row]);await f.run();
 const expected=require('node:crypto').createHash('sha256').update(JSON.stringify(['mechanize.reconnect.missing-document.v1','p1','b1',7,0,'successor'])).digest('hex');
 assert.deepEqual(JSON.parse(JSON.stringify(f.missingReceiptSources())),{version:1,count:1,hashes:[expected],truncated:false});
 const attention=f.messages.find(m=>m.type==='attention'&&m.reconnectRecovery);assert.equal(attention.reconnectRecovery.missingLiveReceipts,1);assert.equal(Object.hasOwn(attention,'missingReceiptSources'),false);assert.ok(!JSON.stringify(attention).includes(expected));assert.equal(f.state.deliveries,0);f.disconnect();assert.equal(f.missingReceiptSources(),null);
});

async function missingSourceRetryFixture(t){
 const row={identity:{...identity,documentId:'successor'},fence:grant,attemptId:'8'.repeat(64),fingerprintSHA256:'9'.repeat(64),dispatchState:'dispatched'};
 const rows=[row],f=await legacyCurrentReconnectFixture(t,rows);await f.run();
 assert.equal(f.messages.find(m=>m.reconnectRecovery)?.reconnectRecovery.missingLiveReceipts,1);
 f.retryRows=rows;f.autoQualification=()=>f.run();
 const post=f.state.nativePost;f.state.nativePost=message=>{post(message);if(message.type==='hello')queueMicrotask(()=>f.autoQualification());};
 return f;
}
const sourceCommitted=(f,event)=>{for(const listener of f.state.committedListeners||[])listener(event);};
const waitRetry=async(f,predicate)=>{for(let n=0;n<100&&!predicate();n++)await new Promise(r=>setTimeout(r,10));assert.ok(predicate(),JSON.stringify(f.diagnostic()));};
test('missing receipt source navigation requests one full proof and qualifies only after original document absence',async t=>{
 for(const removed of [false,true]){
  const f=await missingSourceRetryFixture(t),oldJournal=JSON.stringify(f.storage.mechanizeReconnect),before=f.state.nativeConnections;
  f.state.frameRows[0].documentId='fresh-public';
  if(removed){f.state.inventoryTabs=[{id:8,url:'https://fixture.example.test/page'}];for(const listener of f.state.removedListeners||[])listener(7);}
  else for(let n=0;n<20;n++)sourceCommitted(f,{tabId:7,frameId:0,documentId:'fresh-public'});
  await waitRetry(f,()=>f.messages.some(m=>m.type==='executorPrepared'));
  assert.equal(f.state.nativeConnections,before+1);assert.equal(f.state.deliveries,0);assert.equal(f.state.permissionRequests||0,0);assert.equal(f.state.activatedSetupTab,undefined);assert.equal(f.state.createdSetupTabs||0,0);assert.equal(f.state.debuggerInputs,undefined);
  assert.equal(JSON.stringify(auditOriginal(f)),oldJournal);
 }
});
test('missing receipt retry cannot turn a source-change notification into absence proof or a retry storm',async t=>{
 const f=await missingSourceRetryFixture(t),before=f.state.nativeConnections,original=JSON.stringify(f.storage.mechanizeReconnect);
 // The notification alone is insufficient: independent census still has source.
 const event={tabId:7,frameId:0,documentId:'not-in-browser-census'};
 for(let n=0;n<20;n++)sourceCommitted(f,event);
 await waitRetry(f,()=>f.state.nativeConnections===before+1&&f.missingReceiptSources()!==null);
 assert.ok(!f.messages.some(m=>m.type==='executorPrepared'));assert.equal(JSON.stringify(f.storage.mechanizeReconnect),original);
 for(let n=0;n<20;n++)sourceCommitted(f,event);await new Promise(r=>setTimeout(r,140));assert.equal(f.state.nativeConnections,before+1);assert.equal(f.state.deliveries,0);
});
test('missing source retry ignores unchanged unrelated private UNKNOWN and busy state',async t=>{
 for(const mode of ['same','unrelated','subframe','malformed','privatePending','unknown','mutation','busy','lifecycle']){
  const f=await missingSourceRetryFixture(t),before=f.state.nativeConnections,original=JSON.stringify(f.storage.mechanizeReconnect);
  if(['privatePending','unknown','mutation','lifecycle'].includes(mode))f.reconnectBarrier(mode);if(mode==='busy')f.setActiveCommands(1);
  const event={tabId:mode==='unrelated'?99:7,frameId:mode==='subframe'?1:0,documentId:mode==='same'?'successor':mode==='malformed'?null:'changed'};
  sourceCommitted(f,event);await new Promise(r=>setTimeout(r,140));assert.equal(f.state.nativeConnections,before,mode);assert.equal(JSON.stringify(f.storage.mechanizeReconnect),original);assert.equal(f.state.deliveries,0);assert.equal(f.state.permissionRequests||0,0);
 }
});
test('missing source retry rechecks quiescence after its coalescing delay',async t=>{
 const f=await missingSourceRetryFixture(t),before=f.state.nativeConnections,original=JSON.stringify(f.storage.mechanizeReconnect);
 sourceCommitted(f,{tabId:7,frameId:0,documentId:'changed'});f.reconnectBarrier('privatePending');
 await new Promise(r=>setTimeout(r,150));assert.equal(f.state.nativeConnections,before);assert.equal(JSON.stringify(f.storage.mechanizeReconnect),original);assert.equal(f.state.deliveries,0);
});
test('successful authenticated recovery renews the event budget across two episodes without resetting history',async t=>{
 const f=await missingSourceRetryFixture(t);f.seedRecoveryEvents(199);const original=JSON.stringify(f.storage.mechanizeReconnect);
 f.state.frameRows[0].documentId='first-recovered';sourceCommitted(f,{tabId:7,frameId:0,documentId:'first-recovered'});
 await waitRetry(f,()=>f.messages.some(m=>m.type==='executorPrepared'));assert.equal(f.recoveryEventCount(),0);assert.equal(JSON.stringify(auditOriginal(f)),original);
 const first=structuredClone(f.storage.mechanizeReconnect),firstHistory=JSON.stringify(first.history);
 // A separate document/attempt and genuine failed commit create the next
 // pending recovery episode on the SAME worker, preserving its history.
 const second=await shippedBindingFixture(t);f.state.renderer=second.f.state.renderer;f.state.frameRows[0].documentId='second-source';
 f.retryRows.push({identity:{...identity,documentId:'second-source'},fence:{brokerEpoch:'second-broker',channelEpoch:'second-channel',scopeHash:grant.scopeHash},attemptId:'6'.repeat(64),fingerprintSHA256:'7'.repeat(64),dispatchState:'dispatched'});
 f.state.rejectReconnectCommit=true;f.autoQualification=()=>f.receive({...restartQualification(),brokerEpoch:'second-broker',channelEpoch:'second-channel',reconnectBindingsVersion:1});f.messages.length=0;f.disconnect();await f.connect();
 await waitRetry(f,()=>f.storage.mechanizeReconnect.phase==='pending'&&f.messages.some(m=>m.type==='attention'));
 assert.equal(f.recoveryEventCount(),0);f.state.rejectReconnectCommit=false;
 f.autoQualification=()=>f.receive({...restartQualification(),brokerEpoch:'third-broker',channelEpoch:'third-channel',reconnectBindingsVersion:1});f.messages.length=0;f.disconnect();await f.connect();
 await waitRetry(f,()=>f.missingReceiptSources()?.count===1);assert.ok(!f.messages.some(m=>m.type==='executorPrepared'));
 const pending=JSON.stringify(f.storage.mechanizeReconnect),third=await shippedBindingFixture(t);f.state.renderer=third.f.state.renderer;f.state.frameRows[0].documentId='second-recovered';const before=f.state.nativeConnections;
 sourceCommitted(f,{tabId:7,frameId:0,documentId:'second-recovered'});await waitRetry(f,()=>f.messages.some(m=>m.type==='executorPrepared'));
 assert.equal(f.state.nativeConnections,before+1);assert.equal(f.recoveryEventCount(),0);assert.equal(JSON.stringify(auditOriginal(f)),pending);assert.ok(auditKeys(f).some(key=>JSON.stringify(JSON.parse(f.storage[key].journalJSON).history)===firstHistory));assert.equal(f.state.deliveries,0);assert.equal(f.state.permissionRequests||0,0);
});

test('adoption refusals expose finite existing causes while retaining pending lineage and no input',async()=>{
 for(const mode of ['shape','identity','generation','receipt','inventory']){
  const f=await reconnectFixture(),priorGrant=JSON.stringify(f.storage.lastGrant);
  f.state.renderer=async(_tab,message)=>{
   if(message.type!=='brokerReconnect')throw Error('fixture unsupported');
   const response={nonce:message.nonce,phase:message.phase==='inspect'?'inspected':message.phase==='prepare'?'prepared':'adopted',identity:{...message.newBinding.identity,documentGeneration:2},...(message.phase==='inspect'?{version:1}:{receiptRevision:0,receiptCount:0,quiescent:true})};
   if(message.phase==='adopt'){if(mode==='shape')response.nonce='PRIVATE_CANARY';if(mode==='identity')response.identity.documentId='PRIVATE_CANARY';if(mode==='generation')response.identity.documentGeneration=1;if(mode==='receipt')response.receiptRevision=response.receiptCount=1;if(mode==='inventory')f.state.inventoryTabs=[];}
   return response;
  };
  await f.receive({...restartQualification(),brokerEpoch:'adopt-test',channelEpoch:'adopt-test'});
  const attention=f.messages.find(m=>m.type==='attention'&&m.error?.code==='storedFenceMismatch');assert.equal(attention.reconnectPhase,'adopt',mode);assert.equal(attention.reconnectReason,({shape:'executorRefused',identity:'documentChanged',generation:'documentChanged',receipt:'unknownReceipts',inventory:'inventoryChanged'})[mode]);if(mode==='inventory')assert.equal(attention.reconnectInventoryReason,'inventoryDrift');
  assert.ok(!JSON.stringify(attention).includes('PRIVATE_CANARY'));assert.equal(f.storage.mechanizeReconnect.phase,'pending');assert.deepEqual(Array.from(f.storage.mechanizeReconnect.history),[]);assert.equal(JSON.stringify(f.storage.lastGrant),priorGrant);assert.ok(!f.messages.some(m=>m.type==='executorPrepared'));assert.equal(f.state.deliveries,0);
 }
});
test('committed adoption capacity archives completed prefix before renderer handoff',async()=>{
 const f=await reconnectFixture();let record;
 for(let per=16;per<=25;per++){
  const history=Array.from({length:36},(_,i)=>({nonce:(100+i).toString(16).padStart(64,'0'),oldFence:{...grant,brokerEpoch:'h'+i,channelEpoch:'h'+i},newFence:i===35?{...grant}:{...grant,brokerEpoch:'h'+(i+1),channelEpoch:'h'+(i+1)},executors:Array.from({length:per},(_,n)=>({identity:{...identity,tabId:n+20,documentId:'fixture-'+n+'x'.repeat(80)},receiptRevision:3,receiptCount:3}))}));
  const tail=history.at(-1),candidate={version:1,phase:'adopted',nonce:tail.nonce,oldFence:tail.oldFence,newFence:tail.newFence,history};
  if(JSON.stringify(candidate).length>200000&&JSON.stringify(candidate).length<215000){record=candidate;break;}
 }
 assert.ok(record);assert.equal(f.journalValid(record,f.storage.lastGrant),true);f.storage.mechanizeReconnect=record;f.state.frameCount=200;
 const original=JSON.stringify(record),priorGrant=JSON.stringify(f.storage.lastGrant);await f.receive({...restartQualification(),brokerEpoch:'budget-next',channelEpoch:'budget-next'});
 assert.ok(f.messages.some(m=>m.type==='executorPrepared'),JSON.stringify(f.diagnostic()));assert.ok(retainedAudit(f,original));assert.equal(f.storage.mechanizeReconnect.history.length,1);assert.equal(f.state.deliveries,0);assert.notEqual(JSON.stringify(f.storage.lastGrant),priorGrant);
});

async function metadataActivationFixture(){
 const f=await fixture({}, {enroll:false});f.state.inventoryTabs=[{id:7,url:f.state.url}];f.state.rejectBind=true;
 await f.receive({...restartQualification(),fixtureOnly:false});assert.ok(!f.messages.some(m=>m.type==='executorPrepared'));assert.equal(f.messages.at(-1).error.code,'executorBindingFailed');
 f.state.tabMetadata={windowId:9,status:'complete',active:false};f.messages.length=0;
 return f;
}
const metadataActivationRequest=()=>({type:'browser.activateTab',requestId:'a'.repeat(64),attemptId:'b'.repeat(64),origin:'https://fixture.example.test',tabId:7,...grant,deadlineUnixMs:Date.now()+2000});
test('exact tab activation uses authenticated metadata fence without executor and keeps open-origin closed',async()=>{
 const f=await metadataActivationFixture(),request=metadataActivationRequest(),before={injections:f.state.injections,deliveries:f.state.deliveries,binds:f.state.binds};
 f.reconnectBarrier('flow'); // Dormant private flow is not active credential input.
 await f.receive(request);assert.equal(f.messages.at(-1).dispatchState,'dispatched');assert.equal(f.messages.at(-1).tabId,7);assert.equal(f.state.tabUpdates,1);assert.equal(f.state.windowUpdates,1);
 await f.receive({...request,requestId:'c'.repeat(64)});assert.equal(f.messages.at(-1).dispatchState,'dispatched');assert.equal(f.state.tabUpdates,1);assert.equal(f.state.windowUpdates,1);
 const count=f.messages.length;await f.receive({type:'browser.openOrigin',requestId:'d'.repeat(64),attemptId:'e'.repeat(64),origin:request.origin,...grant,deadlineUnixMs:Date.now()+2000});assert.equal(f.messages.length,count);assert.equal(f.state.createdSetupTabs||0,0);
 assert.deepEqual({injections:f.state.injections,deliveries:f.state.deliveries,binds:f.state.binds},before);assert.ok(!f.messages.some(m=>m.type==='executorPrepared'));assert.equal(f.state.permissionRequests||0,0);
});
test('metadata activation retains private UNKNOWN active-work and exact-origin guards',async()=>{
 for(const mode of ['privatePending','admission','unknown','mutation','lifecycle','setup','foreignOrigin','permission','foreignFence']){
  const f=await metadataActivationFixture(),request=metadataActivationRequest();
  if(['privatePending','admission','unknown','mutation','lifecycle'].includes(mode))f.reconnectBarrier(mode);if(mode==='setup')f.setActiveCommands(1);if(mode==='foreignOrigin')f.state.url='https://foreign.invalid';if(mode==='permission')f.state.hostGranted=false;if(mode==='foreignFence')request.channelEpoch='foreign';
  const before=f.state.deliveries;await f.receive(request);assert.equal(f.state.tabUpdates||0,0,mode);assert.equal(f.state.windowUpdates||0,0,mode);assert.equal(f.state.deliveries,before);assert.ok(!f.messages.some(m=>m.dispatchState==='dispatched'),mode);
 }
});
test('metadata activation cannot borrow forged qualification or continue across a replaced port',async()=>{
 for(const fields of [{fixtureOnly:true},{profileQualified:true},{scopeQualified:false},{trustScope:'foreign'},{executorQualified:true},{executorChallenge:''}]){
  const f=await fixture({}, {enroll:false});await f.receive({...restartQualification(),...fields});f.state.tabMetadata={windowId:9,status:'complete',active:false};await f.receive(metadataActivationRequest());assert.equal(f.state.tabUpdates||0,0);
 }
 const f=await metadataActivationFixture();f.state.activationHook=()=>f.disconnect();await f.receive(metadataActivationRequest());assert.equal(f.state.tabUpdates,1);assert.equal(f.state.windowUpdates||0,0);assert.equal(f.sessionState['browserReceipt:'+'b'.repeat(64)].dispatchState,'unknown');assert.ok(!f.messages.some(m=>m.dispatchState==='dispatched'));assert.equal(f.state.deliveries,0);
});

async function pending49HistoryFixture(t){
 const absent={identity:{...identity,documentId:'retained-unknown-absent'},fence:grant,attemptId:'8'.repeat(64),fingerprintSHA256:'9'.repeat(64),dispatchState:'unknown'};
 const f=await legacyCurrentReconnectFixture(t,[absent]);let history;
 for(let per=10;per<30;per++){
  const candidate=Array.from({length:49},(_,index)=>({nonce:(100+index).toString(16).padStart(64,'0'),oldFence:{...grant,brokerEpoch:'history-'+index,channelEpoch:'history-'+index},newFence:index===48?{...grant}:{...grant,brokerEpoch:'history-'+(index+1),channelEpoch:'history-'+(index+1)},executors:index===0?[]:Array.from({length:per},(_,n)=>({identity:{...identity,tabId:20+n,documentId:'historical-'+n+'x'.repeat(80)},receiptCount:3,receiptRevision:3}))}));
  if(JSON.stringify(candidate).length>205000&&JSON.stringify(candidate).length<225000){history=candidate;break;}
 }
 assert.ok(history);
 let original={version:1,phase:'pending',nonce:'c'.repeat(64),oldFence:history[0].oldFence,newFence:{...grant,brokerEpoch:'initial-uncommitted',channelEpoch:'initial-uncommitted'},history:[]};
 for(let version=2;version<=4;version++){
  let recovery={kind:version===2?'emptySetupDocuments':'verifiedCurrentDocuments',originalPending:original};
  if(version>2){const pendingJSON=JSON.stringify(original),digest=require('node:crypto').createHash('sha256').update(pendingJSON).digest('hex');f.storage['mechanizeReconnectPendingArchive:'+digest]={version:1,pendingJSON};recovery={kind:'verifiedCurrentDocuments',originalPendingRef:{digest,bytes:Buffer.byteLength(pendingJSON),version:original.version,nonce:original.nonce,oldFence:original.oldFence,newFence:original.newFence}};}
  original={version,phase:'pending',nonce:(20+version).toString(16).repeat(32),oldFence:{...grant},newFence:{...grant,brokerEpoch:'uncommitted-'+version,channelEpoch:'uncommitted-'+version},history,recovery};
 }
 f.storage.mechanizeReconnect=original;await f.verifyArchives(original);assert.equal(f.pendingReconnectValid(original,f.storage.lastGrant),true);
 f.state.frameRows=Array.from({length:200},(_,n)=>({frameId:n,parentFrameId:n?0:-1,documentId:'live-'+n,url:'https://fixture.example.test/page',frameType:n?'sub_frame':'outermost_frame',documentLifecycle:'active'}));
 f.state.renderer=async(_tab,message)=>{if(message.type==='brokerReconnect')return {nonce:message.nonce,phase:message.phase==='inspect'?'inspected':message.phase==='prepare'?'prepared':'adopted',identity:{...message.newBinding.identity},...(message.phase==='inspect'?{version:1}:{quiescent:true,receiptCount:0,receiptRevision:0})};if(message.action==='executor.receipts')return {error:{code:'notEnrolled'}};throw Error('unexpected input');};
 return {...f,originalJSON:JSON.stringify(original),retainedUnknown:absent};
}
test('pending v4 history49 compacts losslessly before handoff and retains original pending and UNKNOWN',async t=>{
 const f=await pending49HistoryFixture(t);let historyArchivedBeforePrepare=false;const receive=f.state.renderer;
 f.state.renderer=(tab,message)=>{if(message.type==='brokerReconnect'&&message.phase==='prepare'){assert.ok(retainedAudit(f,f.originalJSON));historyArchivedBeforePrepare=true;}return receive(tab,message);};
 await f.run();assert.ok(f.messages.some(m=>m.type==='executorPrepared'),JSON.stringify(f.diagnostic()));assert.equal(historyArchivedBeforePrepare,true);assert.equal(f.storage.mechanizeReconnect.history.length,1);
 const ref=f.storage.mechanizeReconnect.audit;assert.equal(f.storage['mechanizeReconnectAudit:'+ref.digest].journalJSON,f.originalJSON);assert.equal(ref.version,4);
 const prefix=auditOriginal(f);assert.equal(prefix.phase,'pending');assert.equal(prefix.history.length,49);assert.deepEqual(prefix,JSON.parse(f.originalJSON));assert.equal(f.retainedUnknown.dispatchState,'unknown');assert.equal(f.state.deliveries,0);await f.verifyArchives(f.storage.mechanizeReconnect);
});
test('pending main-history archive tamper missing order and current-record races never publish authority',async t=>{
 for(const mode of ['tamper','missing','order','currentRace']){
  const f=await pending49HistoryFixture(t),beforeGrant=JSON.stringify(f.storage.lastGrant);let changed,handled=false;
  f.state.afterStorageWrite=value=>{const key=Object.keys(value).find(k=>k.startsWith('mechanizeReconnectAudit:'));if(!key||handled)return;handled=true;f.storage[key]=structuredClone(f.storage[key]); // Chrome storage detaches persisted values.
   if(mode==='tamper'){const journal=JSON.parse(f.storage[key].journalJSON);journal.history[0].nonce='f'.repeat(64);f.storage[key].journalJSON=JSON.stringify(journal);}if(mode==='missing')delete f.storage[key];if(mode==='order'){const journal=JSON.parse(f.storage[key].journalJSON);journal.history.reverse();f.storage[key].journalJSON=JSON.stringify(journal);}if(mode==='currentRace'){f.storage.mechanizeReconnect={...f.storage.mechanizeReconnect,nonce:'f'.repeat(64)};changed=JSON.stringify(f.storage.mechanizeReconnect);}
  };
  await f.run();assert.equal(handled,true);assert.ok(!f.messages.some(m=>m.type==='executorPrepared'),mode);assert.equal(JSON.stringify(f.storage.lastGrant),beforeGrant);assert.equal(JSON.stringify(f.storage.mechanizeReconnect),mode==='currentRace'?changed:f.originalJSON);assert.equal(f.state.deliveries,0);
 }
});

test('failed archive graph verification clears prior and partially loaded proof caches',async t=>{
 const f=await pending49HistoryFixture(t);await f.run();
 assert.ok(f.messages.some(m=>m.type==='executorPrepared'));
 const current=f.storage.mechanizeReconnect;
 for(const mode of ['canonicalBudget','loadedArchiveBoundary']){
  await f.verifyArchives(current);assert.equal(f.journalValid(current,f.storage.lastGrant),true);
  const invalid=structuredClone(current);
  if(mode==='canonicalBudget')invalid.oversized='x'.repeat(300000);
  else invalid.audit.nonce='f'.repeat(64);
  await assert.rejects(()=>f.verifyArchives(invalid));
  assert.equal(f.journalValid(current,f.storage.lastGrant),false,mode);
  assert.equal(f.state.deliveries,0);
 }
 await f.verifyArchives(current);assert.equal(f.journalValid(current,f.storage.lastGrant),true);
});

test('fresh tab inventory uses authenticated setup metadata despite invalid history private UNKNOWN and lifecycle barriers',async()=>{
 const f=await metadataActivationFixture();f.storage.mechanizeReconnect={invalid:'PRIVATE-CANARY'};
 f.state.inventoryTabs=[{id:7,url:'https://fixture.example.test/public?PRIVATE-CANARY',title:'PRIVATE-CANARY',incognito:false,discarded:false,status:'complete'}];
 for(const kind of ['flow','redactions','unknown','lifecycle','privatePending','admission','privacy','mutation'])f.reconnectBarrier(kind);f.setActiveCommands(1);
 const before={local:JSON.stringify(f.storage),session:JSON.stringify(f.sessionState),counts:JSON.stringify(f.publicReadCounts()),inputs:f.state.deliveries,injections:f.state.injections,binds:f.state.binds};
 const q={type:'tabInventory',requestId:'a'.repeat(64),expectedOrigin:'https://fixture.example.test',...grant,deadlineUnixMs:Date.now()+1000};
 await f.receive(q);const r=f.messages.at(-1);assert.equal(r.type,'tabInventoryResult');assert.equal(r.complete,true);assert.equal(r.reason,'none');assert.deepEqual([...r.tabIds],[7]);assert.ok(!JSON.stringify(r).includes('PRIVATE-CANARY'));
 assert.equal(JSON.stringify(f.storage),before.local);assert.equal(JSON.stringify(f.sessionState),before.session);assert.equal(JSON.stringify(f.publicReadCounts()),before.counts);assert.equal(f.state.deliveries,before.inputs);assert.equal(f.state.injections,before.injections);assert.equal(f.state.binds,before.binds);assert.equal(f.state.tabUpdates||0,0);assert.equal(f.state.permissionRequests||0,0);assert.ok(!f.messages.some(m=>m.type==='executorPrepared'));
 for(const override of [{scopeHash:'e'.repeat(64)},{expectedOrigin:'https://foreign.test'},{deadlineUnixMs:Date.now()-1}]){await f.receive({...q,...override});const rejected=f.messages.at(-1);assert.equal(rejected.complete,false);assert.equal(rejected.tabIds.length,0);assert.ok(['permissionUnavailable','authorityChanged'].includes(rejected.reason));}
 f.state.hostGranted=false;await f.receive(q);assert.equal(f.messages.at(-1).reason,'permissionUnavailable');
});
test('tab inventory advertises its own capability and drops results for a replaced native port',async()=>{
 const f=await metadataActivationFixture();f.disconnect();await f.connect();assert.equal(f.messages.find(m=>m.type==='hello').tabInventoryVersion,1);
 await f.receive({...restartQualification(),fixtureOnly:false});f.messages.length=0;
 f.state.blockStorageReadKey='enrollment';let release;f.state.blockStorageRead=new Promise(resolve=>{release=resolve;});
 const pending=f.receive({type:'tabInventory',requestId:'b'.repeat(64),expectedOrigin:'https://fixture.example.test',...grant,deadlineUnixMs:Date.now()+1000});
 await new Promise(resolve=>setImmediate(resolve));f.disconnect();release();await pending;
 assert.ok(!f.messages.some(m=>m.type==='tabInventoryResult'));assert.equal(f.state.deliveries,0);
});

// Test-first native maintenance contract. Production support is deliberately
// absent until the native admission and persisted outcome contract is reviewed.
const extensionReloadRequest=()=>({type:'extension.reload',requestId:'a'.repeat(64),attemptId:'b'.repeat(64),expectedVersion:'0.1.0',...grant,deadlineUnixMs:Date.now()+1000});
test('extension reload maintenance persists one original intent before reload and never replays it',async()=>{
 const f=await metadataActivationFixture(),q=extensionReloadRequest();
 f.storage.mechanizeReconnect={retained:'historical-unknown'};f.sessionState.originalReceipt={dispatchState:'unknown'};
 for(const kind of ['flow','privacy','redactions','unknown'])f.reconnectBarrier(kind);
 const history=JSON.stringify(f.storage.mechanizeReconnect),receipt=JSON.stringify(f.sessionState.originalReceipt),before=f.publicReadCounts();
 f.state.reloadHook=()=>assert.ok(JSON.stringify(f.storage).includes(q.attemptId),'original durable maintenance intent must precede runtime.reload');
 await f.receive(q);assert.equal(f.state.reloads,1);assert.equal(f.messages.at(-1).type,'extension.reloadResult');assert.equal(f.messages.at(-1).dispatchState,'unknown');
 await f.receive({...q,requestId:'c'.repeat(64)});assert.equal(f.state.reloads,1,'same original attempt cannot reload twice');
 assert.equal(JSON.stringify(f.storage.mechanizeReconnect),history);assert.equal(JSON.stringify(f.sessionState.originalReceipt),receipt);assert.equal(f.publicReadCounts().unknown,before.unknown);assert.equal(f.state.deliveries,0);assert.equal(f.state.createdSetupTabs||0,0);assert.equal(f.state.permissionRequests||0,0);
});
test('extension reload maintenance refuses actual active work with a finite no-dispatch result',async()=>{
 for(const mode of ['privatePending','mutation','browserInput','setup']){
  const f=await metadataActivationFixture();if(mode==='setup')f.setActiveCommands(1);else f.reconnectBarrier(mode);
  const before=JSON.stringify(f.storage);await f.receive(extensionReloadRequest());const r=f.messages.at(-1);
  assert.equal(r?.type,'extension.reloadResult',mode);assert.equal(r.dispatchState,'notDispatched');assert.equal(r.reason,'busy');assert.equal(f.state.reloads||0,0);assert.equal(JSON.stringify(f.storage),before);assert.equal(f.state.deliveries,0);
 }
});
test('extension reload maintenance cannot cross lost intent persistence authority or deadline',async()=>{
 for(const mode of ['storage','fence','deadline']){
  const f=await metadataActivationFixture(),q=extensionReloadRequest();if(mode==='storage')f.state.rejectStorageWrite=true;if(mode==='fence')q.channelEpoch='foreign';if(mode==='deadline')q.deadlineUnixMs=Date.now()-1;
  await f.receive(q);const r=f.messages.at(-1);assert.equal(r?.type,'extension.reloadResult',mode);assert.equal(r.dispatchState,mode==='storage'?'unknown':'notDispatched');assert.ok(['receiptUnavailable','authorityChanged'].includes(r.reason));assert.equal(f.state.reloads||0,0);assert.equal(f.state.deliveries,0);
 }
});
test('extension reload maintenance gates new native renderer dispatch while its intent write is pending',async()=>{
 const f=await metadataActivationFixture();let release;f.state.blockStorageWrite=new Promise(resolve=>{release=resolve;});
 const original=f.receive(extensionReloadRequest());await new Promise(resolve=>setImmediate(resolve));
 await f.receive(command('racing-input'));assert.equal(f.state.deliveries,0);assert.equal(f.messages.at(-1).error.code,'executorNotQuiescent');assert.equal(f.messages.at(-1).error.dispatchState,'notDispatched');
 release();await original;assert.equal(f.state.reloads,1);assert.equal(f.state.deliveries,0);
});

test('native hello advertises bounded DOM select separately from fingerprint and Playwright versions',async()=>{
 const f=await metadataActivationFixture();f.disconnect();await f.connect();
 const hello=f.messages.find(m=>m.type==='hello');assert.equal(hello.selectOptionVersion,1);assert.equal(hello.privacySourceRetirementVersion,1);assert.equal(hello.workerBuild,33);
 assert.equal(hello.checkOptionVersion,undefined);assert.equal(hello.uncheckOptionVersion,undefined);assert.equal(f.state.deliveries,0);
});

async function promotedPrivacyFixture(){
 const f=await privateFixture();await f.receive(privateFrame());await f.receive(privateSubmitFrame());
 f.state.documentId='public-successor';f.state.frameURL=f.state.url='https://fixture.example.test/public';
 f.state.frameRows=[{frameId:0,parentFrameId:-1,documentId:'public-successor',documentLifecycle:'active',frameType:'outermost_frame',url:f.state.url,errorOccurred:false}];
 // Real navigation drops A's volatile executor/lease map before promotion.
 for(const listener of f.state.committedListeners)listener({tabId:7,frameId:0,documentId:'public-successor'});
 const proof=privacyFrame();await f.receive(proof);assert.equal(f.messages.at(-1).ready,true);
 const successor={...f.messages.at(-1).identity};await f.receive({...proof,type:'credentialPrivacyCommit',identity:successor});assert.equal(f.messages.at(-1).ready,true);
 const retire={type:'credentialScope',requestId:'8'.repeat(64),mode:'retire',preparationId:'d'.repeat(64),sourceIdentity:identity,sourceOrigin:'https://fixture.example.test',loginRouteSHA256:'',...grant,deadlineUnixMs:Date.now()+3000,targetTabId:0,targetOrigin:''};
 return {f,successor,proof,retire};
}
const sourceRetirementProof=()=>({candidates:[{submitAttemptId:'b'.repeat(64),controlLease:{id:'lease-private',generation:1}},{submitAttemptId:'c'.repeat(64),controlLease:{id:'lease-private',generation:1}}]});
test('automatic privacy source retirement releases only original capability and keeps successor redaction',async()=>{
 const {f,successor,proof,retire}=await promotedPrivacyFixture();assert.deepEqual(JSON.parse(JSON.stringify(f.privacyState().source)),identity);
 const before={deliveries:f.state.deliveries,submits:f.state.privateSubmits,unknown:f.unknownCount(),receipts:JSON.stringify(f.sessionState)};
 const storedBefore=JSON.stringify(f.storage);await f.receive({...retire,mode:'absent'});assert.equal(f.messages.at(-1).ready,true);assert.equal(f.privacyState().hasPrivacy,true);assert.equal(JSON.stringify(f.storage),storedBefore);
 await f.receive(retire);assert.equal(f.messages.at(-1).ready,true);assert.equal(f.privacyState().hasPrivacy,false);assert.equal(f.privacyState().redacted,'[redacted]');assert.equal(f.privacyState().silenced,false);
 assert.equal(f.state.deliveries,before.deliveries);assert.equal(f.state.privateSubmits,before.submits);assert.equal(f.unknownCount(),before.unknown);assert.equal(JSON.stringify(f.sessionState),before.receipts);
 // A delayed old private frame must neither poison the port nor replace state.
 await f.receive({...proof,type:'credentialPrivacyVerify',identity:successor});assert.equal(f.privacyState().silenced,false);
 await f.receive(privateFrame());assert.equal(f.privacyState().silenced,false);assert.equal(f.state.deliveries,before.deliveries);
 f.state.boundDynamicIdentity=true;f.state.boundFingerprintVersion=2;f.state.privateReply={ready:false,stage:'challenge',privateCredentialProtocolVersion:2,identity:successor};
 const inspect={type:'credentialInspect',requestId:'9'.repeat(64),identity:successor,...grant,deadlineUnixMs:Date.now()+1000,origin:'https://fixture.example.test'};
 await f.receive(inspect);assert.equal(f.messages.at(-1).type,'credentialInspectResult');assert.equal(f.messages.at(-1).stage,'challenge');assert.equal(f.state.deliveries,before.deliveries+1);
 assert.ok(!JSON.stringify(f.messages).includes('CANARY'));
});
test('legacy automatic privacy requires one exact confirmed submit and lease correlation',async()=>{
 for(const mode of ['valid','missing','wrongAttempt','wrongLease','duplicate','extra','foreignDocument','sourcePresent','activeLease']){
  const {f,successor,retire}=await promotedPrivacyFixture();f.privacyLegacy();let proof=sourceRetirementProof();
  if(mode==='wrongAttempt')proof.candidates[1].submitAttemptId='e'.repeat(64);
  if(mode==='wrongLease')proof.candidates[1].controlLease.generation=2;
  if(mode==='duplicate')proof.candidates.push({...proof.candidates[1]});
  if(mode==='extra')proof.candidates[1].value='PRIVATE-CANARY';
  if(mode==='foreignDocument')retire.sourceIdentity={...identity,tabId:8};
  if(mode==='sourcePresent')f.state.frameRows.push({frameId:1,parentFrameId:0,documentId:identity.documentId,documentLifecycle:'cached',frameType:'sub_frame',url:'https://fixture.example.test/login'});
  if(mode==='activeLease'){const lease={id:'successor-control',generation:2};f.state.publicReply={requestId:'successor-acquire',identity:successor,validated:true,controlLease:lease};await f.receive(command('successor-acquire','executor.acquire',{identity:successor,attemptId:undefined,locator:undefined,controlLease:lease}));assert.equal(f.messages.at(-1).validated,true);delete f.state.publicReply;}
  const before={deliveries:f.state.deliveries,storage:JSON.stringify(f.storage),session:JSON.stringify(f.sessionState)};
  await f.receive({...retire,mode:'absent',...(mode==='missing'?{}:{retirementProof:proof})});assert.equal(f.messages.at(-1).ready,mode==='valid',mode);assert.equal(f.privacyState().hasPrivacy,true,mode);assert.equal(JSON.stringify(f.storage),before.storage,mode);
  await f.receive({...retire,...(mode==='missing'?{}:{retirementProof:proof})});const result=f.messages.at(-1);
  assert.equal(result.type,'credentialScopeResult',mode);assert.equal(result.ready,mode==='valid',mode);assert.equal(f.privacyState().hasPrivacy,mode!=='valid',mode);
  assert.equal(f.state.deliveries,before.deliveries,mode);assert.equal(JSON.stringify(f.sessionState),before.session,mode);if(mode!=='valid')assert.equal(JSON.stringify(f.storage),before.storage,mode);
  assert.equal(f.privacyState().redacted,'[redacted]',mode);assert.ok(!JSON.stringify(result).includes('CANARY'));
 }
});

test('legacy old-port privacy may retire under new authenticated fence only with exact durable pair',async()=>{
 for(const mode of ['valid','missing','mismatch','oldFence','inFlight']){
  const {f,retire}=await promotedPrivacyFixture();f.privacyLegacy();const restore=f.keepLegacyPrivacy();
  // Model historical retained capability, not current close behavior (which
  // clears volatile privacy state). The port itself is genuinely replaced.
  f.disconnect();restore();await f.connect();const next={...restartQualification(),brokerEpoch:'new-broker',channelEpoch:'new-channel',executorChallenge:'new-proof'};await f.receive(next);
  assert.equal(f.privacyState().hasPrivacy,true);assert.equal(f.privacyState().currentPort,false);assert.equal(f.privacyState().grantPresent,false);
  let proof=sourceRetirementProof();if(mode==='mismatch')proof.candidates[1].controlLease.id='other-source';
  const request={...retire,brokerEpoch:next.brokerEpoch,channelEpoch:next.channelEpoch,...(mode==='missing'?{}:{retirementProof:proof})};if(mode==='oldFence')Object.assign(request,grant);if(mode==='inFlight')f.reconnectBarrier('privatePending');
  const before={messages:f.messages.length,deliveries:f.state.deliveries,storage:JSON.stringify(f.storage),session:JSON.stringify(f.sessionState)};
  await f.receive({...request,mode:'absent'});assert.equal(f.privacyState().hasPrivacy,true);assert.equal(f.privacyState().currentPort,false);assert.equal(JSON.stringify(f.storage),before.storage);
  if(mode!=='oldFence')assert.equal(f.messages.at(-1).ready,mode==='valid',mode);else assert.equal(f.messages.length,before.messages);
  await f.receive(request);assert.equal(f.privacyState().hasPrivacy,mode!=='valid',mode);assert.equal(f.privacyState().grantPresent,false);assert.equal(f.state.deliveries,before.deliveries);assert.equal(JSON.stringify(f.sessionState),before.session);
  if(mode!=='valid')assert.equal(JSON.stringify(f.storage),before.storage);
  const replies=f.messages.length;f.nativeMessage(privateFrame(),0);await new Promise(resolve=>setImmediate(resolve));assert.equal(f.messages.length,replies);assert.equal(f.state.deliveries,before.deliveries);
  assert.equal(f.privacyState().redacted,'[redacted]');assert.ok(!f.messages.slice(before.messages).some(x=>x.type==='executorPrepared'));
 }
});

test('actual worker navigation preserves original finalization but cannot grant replacement document access',async()=>{
 for(const mode of ['valid','reconnect','lifecycle']){
  const f=await privateFixture(true),c=await playwrightCommand();await playwrightNative(f,c,'open',{command:c,origin:'https://fixture.example.test'});
  await playwrightNative(f,c,'send',{method:'Input.dispatchMouseEvent',params:{type:'mousePressed',button:'left',buttons:1,modifiers:0,clickCount:1,x:20,y:20}});
  await playwrightNative(f,c,'send',{method:'Input.dispatchMouseEvent',params:{type:'mouseReleased',button:'left',buttons:0,modifiers:0,clickCount:1,x:20,y:20}});
  f.state.documentId='new-document';for(const listener of f.state.committedListeners)listener({tabId:7,frameId:0,documentId:'new-document'});
  const inputs=f.state.debuggerInputs.length,held=JSON.stringify(f.storage.mechanizePlaywrightJournalV1);
  const denied=await playwrightNative(f,c,'send',{method:'Runtime.callFunctionOn',params:{}});assert.equal(denied.errorCode,'playwrightAuthorityChanged');assert.equal(f.state.debuggerInputs.length,inputs);assert.equal(JSON.stringify(f.storage.mechanizePlaywrightJournalV1),held);
  if(mode==='reconnect'){f.disconnect();await f.connect();}
  if(mode==='lifecycle')f.reconnectBarrier('lifecycle');
  const result=await playwrightNative(f,c,'receipt',{dispatchState:'dispatched',effectState:'unverified'});
  if(mode==='valid'){assert.equal(result.result.persisted,true);assert.equal(f.storage.mechanizePlaywrightJournalV1.records[c.attemptId].receipt.dispatchState,'dispatched');assert.equal(f.publicReadCounts().leases,0);}else{assert.ok(result.errorCode);assert.notEqual(f.storage.mechanizePlaywrightJournalV1.records[c.attemptId].receipt?.dispatchState,'dispatched');}
  assert.equal(f.state.debuggerInputs.length,inputs);
 }
});

test('existing executor retirement can prove known navigation source absent without a new DOM authority',async()=>{
 for(const mode of ['valid','sourcePresent','unknown','lease','fence']){
  const f=await privateFixture(true),c=await playwrightCommand();await playwrightNative(f,c,'open',{command:c,origin:'https://fixture.example.test'});
  await playwrightNative(f,c,'send',{method:'Input.dispatchMouseEvent',params:{type:'mousePressed',button:'left',buttons:1,modifiers:0,clickCount:1,x:20,y:20}});
  if(mode==='unknown')await playwrightNative(f,c,'send',{method:'Input.dispatchMouseEvent',params:{type:'mousePressed',button:'left',buttons:1,modifiers:0,clickCount:1,x:20,y:20}});
  else {await playwrightNative(f,c,'send',{method:'Input.dispatchMouseEvent',params:{type:'mouseReleased',button:'left',buttons:0,modifiers:0,clickCount:1,x:20,y:20}});await playwrightNative(f,c,'receipt',{dispatchState:'dispatched',effectState:'unverified'});await playwrightNative(f,c,'close');}
  f.state.documentId='retirement-successor';f.state.frameRows=[{frameId:0,parentFrameId:-1,documentId:f.state.documentId,url:f.state.frameURL,documentLifecycle:'active',frameType:'outermost_frame'}];
  if(mode==='sourcePresent')f.state.frameRows.push({frameId:1,parentFrameId:0,documentId:identity.documentId,url:f.state.frameURL,documentLifecycle:'cached',frameType:'sub_frame'});
  for(const listener of f.state.committedListeners)listener({tabId:7,frameId:0,documentId:f.state.documentId});
  const before={journal:JSON.stringify(f.storage.mechanizePlaywrightJournalV1),input:f.state.debuggerInputs.length,deliveries:f.state.deliveries};
  const retire=command('known-source-retire','executor.retire',{attemptId:undefined,locator:undefined,controlLease:{...c.controlLease},...(mode==='fence'?{channelEpoch:'foreign'}:{})});if(mode==='lease')retire.controlLease.id='foreign';
  await f.receive(retire);const result=f.messages.find(m=>m.requestId===retire.requestId);assert.ok(result,mode);assert.equal(result.retiredAuthorityQuiesced,mode==='valid'?true:undefined,mode);
  if(mode==='valid'){assert.deepEqual(JSON.parse(JSON.stringify(result.controlLease)),c.controlLease);assert.equal(result.identity.documentId,identity.documentId);assert.equal(f.state.deliveries,before.deliveries);}
  assert.equal(JSON.stringify(f.storage.mechanizePlaywrightJournalV1),before.journal,mode);assert.equal(f.state.debuggerInputs.length,before.input,mode);
 }
});
