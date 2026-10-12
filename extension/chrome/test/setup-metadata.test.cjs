const {test} = require('node:test');
const assert = require('node:assert/strict');
const vm = require('node:vm');
const fs = require('node:fs');
const path = require('node:path');
const crypto = require('node:crypto');
function fixture() {
  const local = {enrollment:{profileChannel:'fixture',browserInstance:'browser'},privateCanary:'synthetic-private-value'};
  const session = {}, state = {activeCommands:0,unknownAttempts:0,mutationBusy:false,lifecycleInhibited:false,nativeConnected:false,executorQualified:false};
  let listener, changed, reads=0; const calls={tabs:0,writes:0};
  const chrome={storage:{onChanged:{addListener(fn){changed=fn;}},local:{async getBytesInUse(){return JSON.stringify(local).length;},async get(){reads++;return JSON.parse(JSON.stringify(local));},async set(){calls.writes++;throw Error('must not write');}},session:{async get(){return {...session};}}},
    runtime:{id:'a'.repeat(32),getManifest(){return{version:'0.1.0'};},getURL(p){return `chrome-extension://${this.id}/${p}`;},onMessage:{addListener(fn){listener=fn;}}},tabs:{query(){calls.tabs++;throw Error('must not inspect websites');}}};
  const context=vm.createContext({chrome,crypto:crypto.webcrypto,TextEncoder,Date,URL});
  vm.runInContext(fs.readFileSync(path.join(__dirname,'..','setup-metadata.js'),'utf8'),context);
  const api=context.MechanizeSetupMetadata;
  return {api,local,session,state,chrome,calls,changed:()=>changed(),reads:()=>reads,install(){api.installLocal(()=>state);},send(message,sender){return new Promise(resolve=>{const accepted=listener(message,sender,resolve);if(!accepted)resolve(undefined);});}};
}
test('metadata without native or website connection exposes only digest and state',async()=>{
  const f=fixture(),result=await f.api.snapshot(()=>f.state);
  assert.equal(result.extensionId,'a'.repeat(32));assert.equal(result.storageScope,'extension-local-v1');assert.match(result.storageSHA256,/^[a-f0-9]{64}$/);
  assert.equal(result.nativeConnected,false);assert.equal(result.executorQualified,false);assert.equal(result.loadedDirectoryAvailable,false);
  assert.equal(JSON.stringify(result).includes('synthetic-private'),false);assert.equal(JSON.stringify(result).includes('enrollment'),false);
  assert.deepEqual(f.calls,{tabs:0,writes:0});assert.equal(f.reads(),2);
  const again=await f.api.snapshot(()=>f.state);assert.equal(again.storageSHA256,result.storageSHA256);
});
test('persistent digest excludes ephemeral session but retains unknown and lifecycle barriers',async()=>{
  const f=fixture(),before=await f.api.snapshot(()=>f.state);
  f.session['browserIntent:fixture']={privateValue:'must-not-export'};f.session.mechanizeLifecycleInhibited=true;
  const after=await f.api.snapshot(()=>f.state);
  assert.equal(before.storageSHA256,after.storageSHA256);assert.equal(after.unknownAttempts,1);assert.equal(after.lifecycleInhibited,true);
  assert.equal(JSON.stringify(after).includes('must-not-export'),false);
  f.session['browserReceipt:fixture']={};
  assert.equal((await f.api.snapshot(()=>f.state)).unknownAttempts,1);
  f.session['browserReceipt:fixture']={dispatchState:'notDispatched'};
  assert.equal((await f.api.snapshot(()=>f.state)).unknownAttempts,0);
});
test('storage changes and oversized state refuse metadata',async()=>{
  const f=fixture();let count=0;f.chrome.storage.local.get=async()=>{if(++count===2)f.local.privateCanary='changed';return {...f.local};};
  await assert.rejects(f.api.snapshot(()=>f.state));
  const g=fixture();g.chrome.storage.local.getBytesInUse=async()=>1024*1024+1;await assert.rejects(g.api.snapshot(()=>g.state));assert.equal(g.reads(),0);
});
test('setup channel requires exact fresh nonce/fence and does not need website grant',async()=>{
  const f=fixture(),fence={brokerEpoch:'b',channelEpoch:'c',scopeHash:'d'.repeat(64)};
  const request={type:'setupMetadata',requestId:'1'.repeat(64),nonce:'2'.repeat(64),...fence,deadlineUnixMs:Date.now()+5000};
  const result=await f.api.respond(request,fence,()=>f.state);assert.equal(result.nonce,request.nonce);assert.equal(result.metadata.executorQualified,false);
  for(const changed of [{nonce:'bad'},{scopeHash:'e'.repeat(64)},{deadlineUnixMs:Date.now()-1},{nativeHuman:true}])await assert.rejects(f.api.respond({...request,...changed},fence,()=>f.state));
  assert.deepEqual(f.calls,{tabs:0,writes:0});
});
test('local projection is restricted to exact top-level own options page',async()=>{
  const f=fixture();f.install();const sender={id:'a'.repeat(32),url:`chrome-extension://${'a'.repeat(32)}/options.html`,origin:`chrome-extension://${'a'.repeat(32)}`,frameId:0,tab:{id:2}};
  const good=await f.send({type:'setupMetadataLocal'},sender);assert.ok(good.metadata.storageSHA256);
  for(const changed of [{origin:'https://website.test'},{frameId:1},{id:'b'.repeat(32)},{url:'chrome://extensions'},{tab:{id:-1}}])assert.equal(await f.send({type:'setupMetadataLocal'},{...sender,...changed}),undefined);
  assert.equal(await f.send({type:'setupMetadataLocal',origin:'https://website.test'},sender),undefined);
});
test('local errors never reflect storage exception contents',async()=>{
  const f=fixture();f.install();f.chrome.storage.local.get=async()=>{throw Error('private-credential-canary');};
  const response=await f.send({type:'setupMetadataLocal'},{id:'a'.repeat(32),url:`chrome-extension://${'a'.repeat(32)}/options.html`,origin:`chrome-extension://${'a'.repeat(32)}`,frameId:0,tab:{id:1}});
  assert.equal(response.error,'setupMetadataUnavailable');assert.equal(JSON.stringify(response).includes('canary'),false);
});
test('connection diagnostics expose only fixed barriers and never modify retained state',async()=>{
 const f=fixture(),before=JSON.stringify(f.local);
 const state={phase:'barriers',reason:'none',privatePending:false,lifecyclePending:false,privateCanary:'must-not-export'};
 f.api.installLocal(()=>f.state,()=>state);
 f.local.mechanizeProtectedOrigins=['https://synthetic-private.test'];
 f.local.mechanizeReconnect={phase:'pending',nonce:'private-nonce',receipts:['private-receipt']};
 f.local.mechanizeRetirementV1={privateCanary:'private-retirement'};
 const sender={id:'a'.repeat(32),url:`chrome-extension://${'a'.repeat(32)}/options.html`,origin:`chrome-extension://${'a'.repeat(32)}`,frameId:0,tab:{id:1}};
 const retained=JSON.stringify(f.local),reply=await f.send({type:'connectionDiagnosticsLocal'},sender);
 assert.deepEqual(JSON.parse(JSON.stringify(reply)),{diagnostics:{version:3,journalVersion:-1,grantRelation:'unavailable',phase:'barriers',reason:'none',credentialProtection:true,lifecyclePending:false,retirementPending:true,reconnectJournal:'pending'}});
 assert.equal(JSON.stringify(reply).includes('private'),false);
 assert.equal(JSON.stringify(f.local),retained);assert.notEqual(retained,before);
 assert.deepEqual(f.calls,{tabs:0,writes:0});
 for(const version of [1,2,3,4,5,6,7]){f.local.mechanizeReconnect.version=version;const result=await f.send({type:'connectionDiagnosticsLocal'},sender);assert.equal(result.diagnostics.journalVersion,version<=6?version:-1);}
 for(const changed of [{origin:'https://website.test'},{frameId:1},{url:'chrome://extensions'},{id:'b'.repeat(32)}])assert.equal(await f.send({type:'connectionDiagnosticsLocal'},{...sender,...changed}),undefined);
 assert.equal(await f.send({type:'connectionDiagnosticsLocal',key:'privateCanary'},sender),undefined);
 state.phase='private-error-text';
 assert.deepEqual(JSON.parse(JSON.stringify(await f.send({type:'connectionDiagnosticsLocal'},sender))),{error:'connectionDiagnosticsUnavailable'});
});
test('inventory diagnostics project only the closed optional subreason for inventory failures',async()=>{
 const f=fixture(),state={phase:'inventory',reason:'inventoryChanged',inventoryReason:'tabURLUnavailable',privatePending:false,lifecyclePending:false};f.api.installLocal(()=>f.state,()=>state);
 const sender={id:'a'.repeat(32),url:`chrome-extension://${'a'.repeat(32)}/options.html`,origin:`chrome-extension://${'a'.repeat(32)}`,frameId:0,tab:{id:1}};
 for(const reason of f.api.INVENTORY_REASONS){state.inventoryReason=reason;assert.equal((await f.send({type:'connectionDiagnosticsLocal'},sender)).diagnostics.inventoryReason,reason);}
 state.inventoryReason='PRIVATE_CANARY';assert.equal(Object.hasOwn((await f.send({type:'connectionDiagnosticsLocal'},sender)).diagnostics,'inventoryReason'),false);
 state.inventoryReason='tabURLUnavailable';state.reason='none';assert.equal(Object.hasOwn((await f.send({type:'connectionDiagnosticsLocal'},sender)).diagnostics,'inventoryReason'),false);assert.deepEqual(f.calls,{tabs:0,writes:0});
});
test('own Options diagnostics expose bounded missing source hashes only in the original receipt-failure phase',async()=>{
 const f=fixture(),state={phase:'inspect',reason:'unknownReceipts',privatePending:false,lifecyclePending:false,missingReceiptSources:{version:1,count:1,hashes:['a'.repeat(64)],truncated:false}};f.api.installLocal(()=>f.state,()=>state);
 const sender={id:'a'.repeat(32),url:`chrome-extension://${'a'.repeat(32)}/options.html`,origin:`chrome-extension://${'a'.repeat(32)}`,frameId:0,tab:{id:2}};
 assert.deepEqual(JSON.parse(JSON.stringify((await f.send({type:'connectionDiagnosticsLocal'},sender)).diagnostics.missingReceiptSources)),state.missingReceiptSources);
 for(const bad of [{...state.missingReceiptSources,documentId:'PRIVATE_CANARY'},{...state.missingReceiptSources,hashes:['PRIVATE_CANARY']},{...state.missingReceiptSources,truncated:true},{...state.missingReceiptSources,count:201},{...state.missingReceiptSources,hashes:['a'.repeat(64),'a'.repeat(64)],count:2}]){state.missingReceiptSources=bad;const reply=await f.send({type:'connectionDiagnosticsLocal'},sender);assert.equal(reply.error,'connectionDiagnosticsUnavailable');assert.ok(!JSON.stringify(reply).includes('PRIVATE_CANARY'));}
 state.missingReceiptSources={version:1,count:1,hashes:['a'.repeat(64)],truncated:false};state.phase='inventory';assert.equal((await f.send({type:'connectionDiagnosticsLocal'},sender)).error,'connectionDiagnosticsUnavailable');assert.equal(await f.send({type:'connectionDiagnosticsLocal'},{...sender,url:'https://public.test'}),undefined);assert.deepEqual(f.calls,{tabs:0,writes:0});
});
