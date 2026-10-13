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
    tabs: {async sendMessage() { return {validated: true, identity}; }, async update(tabId, changes) { state.updates++; state.listenersBeforeDispatch = completed.size > 0; state.committed = true; if(!state.suppressCompletion)for (const f of completed) f({tabId, frameId: 0}); }, async get() { return state.keepOldDocument ? {id:7,active:true,title:'Source',url:'https://fixture.example.test/start',pendingUrl:state.pendingURL} : {id: 7, active: true, title: 'Cases', url: state.redirect ? 'https://untrusted.example.test' : 'https://fixture.example.test/next'}; }},
    webNavigation: {onCompleted: {addListener: f => completed.add(f), removeListener: f => completed.delete(f)}, onErrorOccurred: {addListener: f => failed.add(f), removeListener: f => failed.delete(f)}, async getAllFrames() { return state.keepOldDocument ? [{frameId:0,documentId:'doc1',url:'https://fixture.example.test/start'}] : [{frameId: 0, documentId: state.committed ? 'doc2' : 'doc1', url: state.redirect ? 'https://untrusted.example.test' : 'https://fixture.example.test/next'}]; }}
  };
  const context = vm.createContext({chrome, TextEncoder, URL, Date, setTimeout, clearTimeout, crypto: require('node:crypto').webcrypto});
  for (const file of ['protocol.js', 'fingerprint.js', 'browser.js']) vm.runInContext(fs.readFileSync(path.join(__dirname, '..', file), 'utf8'), context);
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
test('all websites permits an explicit new public destination without changing receipt safeguards', async () => {
  const f=fixture(); f.enrollment={allWebsites:true,origins:[]};
  const c=command('browser.navigate',{args:{url:'https://another.example.test/next'}});
  const receipt=await f.api.execute(c,f.enrollment);
  assert.equal(receipt.ready,true);assert.equal(f.state.updates,1);
  await f.api.execute({...c,requestId:'r2'},f.enrollment);assert.equal(f.state.updates,1);
  const unsafe=fixture();unsafe.enrollment={allWebsites:true,origins:[]};
  await assert.rejects(unsafe.api.execute(command('browser.navigate',{args:{url:'file:///private/fixture'}}),unsafe.enrollment),e=>e.code==='originDenied');
  assert.equal(unsafe.state.updates,0);
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

test('protected origins deny non-root destinations, redirected metadata and old unsafe receipts',async()=>{
  const denied=new Set(['https://untrusted.example.test']),f=fixture();f.enrollment={allWebsites:true,origins:[]};
  await assert.rejects(f.api.execute(command('browser.navigate',{args:{url:'https://untrusted.example.test/private'}}),f.enrollment,denied),e=>e.code==='originDenied');
  assert.equal(f.state.updates,0);
  const update=f.context.chrome.tabs.update;f.context.chrome.tabs.update=async(...args)=>{await update(...args);f.state.redirect=true;};
  const result=await f.api.execute(command(),f.enrollment,denied);
  assert.equal(result.error.code,'redirectOriginDenied');assert.equal(result.newDocument,undefined);
  assert.ok(!JSON.stringify(f.state.stored).includes('Cases'));
  const cached=fixture();await cached.api.execute(command(),cached.enrollment);
  const before=JSON.stringify(cached.state.stored);
  await assert.rejects(cached.api.query(command('receipt.query'),new Set(['https://fixture.example.test'])),e=>e.code==='secureDocumentRequired');
  assert.equal(JSON.stringify(cached.state.stored),before);
});

test('explicit protected HTTPS root navigation retains quarantine and exports identity without reading title',async()=>{
 const f=fixture(),origin='https://protected.example.test',protectedOrigins=new Set([origin]);
 f.enrollment={allWebsites:true,origins:[]};
 f.context.chrome.tabs.get=async()=>({id:7,active:true,url:origin+'/',get title(){throw Error('TITLE-CANARY must not be read');}});
 f.context.chrome.webNavigation.getAllFrames=async()=>[{frameId:0,documentId:f.state.committed?'doc2':'doc1',url:f.state.committed?origin+'/':'https://fixture.example.test/'}];
 const c=command('browser.navigate',{args:{url:origin+'/'}});
 const r=await f.api.execute(c,f.enrollment,protectedOrigins);
 assert.equal(r.dispatchState,'dispatched');assert.equal(r.ready,true);assert.equal(r.newDocument.origin,origin);assert.equal(r.newDocument.title,'');assert.equal(r.newDocument.titleTruncated,false);
 assert.equal(protectedOrigins.has(origin),true);assert.ok(!JSON.stringify(f.state.stored).includes('CANARY'));
 const cached=await f.api.query({...c,requestId:'query'},protectedOrigins);assert.equal(cached.privateTarget,true);assert.equal(f.state.updates,1);
 f.state.stored['browserReceipt:a1'].newDocument.title='PRIVATE-CANARY';
 await assert.rejects(f.api.query(c,protectedOrigins),e=>e.code==='secureDocumentRequired');
});
test('v2 navigation binds fingerprint and requires exact prior renderer retirement',async()=>{
 const f=fixture();const original=f.context.chrome.tabs.sendMessage;let retired=false;
 f.context.chrome.tabs.sendMessage=async(tab,m)=>{if(m.action==='executor.retire'){retired=true;return {identity,retiredAuthorityQuiesced:true,controlLease:m.controlLease}}return original(tab,m)};
 const c=command('browser.navigate',{scopeHash:'a'.repeat(64),locator:null,controlLease:{id:'lease1',generation:1},fingerprintVersion:2});
 c.fingerprintSHA256=(await f.context.MechanizeFingerprint.mutationV2(c)).sha256;
 const result=await f.api.execute(c,f.enrollment);
 assert.equal(retired,true);assert.equal(f.state.updates,1);assert.equal(result.retiredAuthorityQuiesced,true);assert.equal(result.fingerprintSHA256,c.fingerprintSHA256);
 await f.api.execute({...c,requestId:'repeat'},f.enrollment);assert.equal(f.state.updates,1);
});
test('v2 navigation never dispatches without retirement proof or matching fingerprint',async()=>{
 for(const invalidHash of [false,true]){
  const f=fixture();const c=command('browser.navigate',{scopeHash:'a'.repeat(64),locator:null,controlLease:{id:'lease1',generation:1},fingerprintVersion:2});
  c.fingerprintSHA256=invalidHash?'b'.repeat(64):(await f.context.MechanizeFingerprint.mutationV2(c)).sha256;
  await assert.rejects(f.api.execute(c,f.enrollment));assert.equal(f.state.updates,0);
 }
});

test('navigation returns a bounded receipt before its action deadline when loading continues',async()=>{
 const f=fixture();f.state.suppressCompletion=true;let observationWait;
 f.context.setTimeout=(fn,ms)=>{observationWait=ms;return setTimeout(fn,0);};
 const c=command('browser.navigate',{deadlineUnixMs:Date.now()+3000});
 const r=await f.api.execute(c,f.enrollment);
 assert.ok(observationWait<=1000,'readiness waited through dispatch deadline');
 assert.ok(observationWait<=c.deadlineUnixMs-Date.now()-200,'no reply budget retained');
 assert.equal(r.dispatchState,'dispatched');assert.equal(r.ready,false);assert.equal(r.newDocument.documentId,'doc2');
 assert.equal(f.state.updates,1);
 const saved=await f.api.query({...c,requestId:'new-read-request'});
 assert.equal(saved.dispatchState,'dispatched');assert.equal(f.state.updates,1);
});

test('pending protected navigation does not classify the old source as a denied redirect',async()=>{
 const f=fixture(),origin='https://private.fixture.test';
 f.state.suppressCompletion=true;f.state.keepOldDocument=true;f.state.pendingURL=origin+'/';
 f.context.setTimeout=(fn)=>setTimeout(fn,0);
 const c=command('browser.navigate',{args:{url:origin},deadlineUnixMs:Date.now()+3000});
 const r=await f.api.execute(c,{origins:['https://fixture.example.test',origin]},new Set([origin]));
 assert.equal(r.dispatchState,'dispatched');assert.equal(r.ready,false);assert.equal(r.error,undefined);assert.equal(r.newDocument,undefined);assert.equal(r.privateTarget,true);
 assert.equal(f.state.updates,1);assert.ok(!JSON.stringify(f.state.stored).includes('Source'));
});

test('pending navigation never grants a document and still refuses a foreign pending URL',async()=>{
 for(const foreign of [false,true]){
  const f=fixture();f.state.suppressCompletion=true;f.state.keepOldDocument=true;f.state.pendingURL=foreign?'https://foreign.invalid/':'https://fixture.example.test/next';
  f.context.setTimeout=(fn)=>setTimeout(fn,0);
  const r=await f.api.execute(command('browser.navigate',{deadlineUnixMs:Date.now()+3000}),f.enrollment);
  assert.equal(r.newDocument,undefined);assert.equal(r.ready,false);
  assert.equal(r.error?.code,foreign?'redirectOriginDenied':undefined);assert.equal(f.state.updates,1);
 }
});

test('target-bound v2 lost browser ACK permits another tab but keeps legacy and same-tab successor blocked',async()=>{
 const f=fixture();f.state.keepOldDocument=true;
 const make=async(tab,attempt,doc='doc1')=>{
  const c=command('browser.activate',{scopeHash:'a'.repeat(64),identity:{...identity,tabId:tab,documentId:doc},attemptId:attempt,args:undefined,fingerprintVersion:2,controlLease:{id:'lease-'+tab,generation:1}});
  c.fingerprintSHA256=(await f.context.MechanizeFingerprint.mutationV2(c)).sha256;return c;
 };
 const a=await make(7,'a'.repeat(64)),originalUpdate=f.context.chrome.tabs.update;
 f.context.chrome.tabs.update=async(...args)=>{await originalUpdate(...args);throw Error('fixture lost original browser ACK');};
 await assert.rejects(()=>f.api.execute(a,f.enrollment));
 f.context.chrome.tabs.update=originalUpdate;
 const before=JSON.stringify(f.state.stored['browserIntent:'+a.attemptId]);
 const b=await make(8,'b'.repeat(64));
 assert.equal((await f.api.execute(b,f.enrollment)).dispatchState,'dispatched');
 assert.equal(f.state.updates,2);
 assert.equal(JSON.stringify(f.state.stored['browserIntent:'+a.attemptId]),before);
 assert.equal((await f.api.execute({...a,requestId:'query-original'},f.enrollment)).dispatchState,'unknown');
 assert.equal(f.state.updates,2,'original input must not replay');
 const successor=await make(7,'c'.repeat(64),'successor');
 await assert.rejects(()=>f.api.execute(successor,f.enrollment),e=>e.code==='unknownEffect');
 delete f.state.stored['browserIntent:'+a.attemptId].controlLease;
 const other=await make(9,'e'.repeat(64));
 await assert.rejects(()=>f.api.execute(other,f.enrollment),e=>e.code==='unknownEffect');
 assert.equal(f.state.updates,2,'legacy unbound uncertainty must remain conservative');
});
