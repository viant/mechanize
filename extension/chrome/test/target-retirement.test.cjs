const test=require('node:test'),assert=require('node:assert/strict'),crypto=require('node:crypto');
const {identity,grant,command,fixture,privateFixture,playwrightNative,playwrightCommand}=require('./worker-fixture.cjs');
const hash=v=>crypto.createHash('sha256').update(JSON.stringify(v)).digest('hex');
async function unknownFixture(){
 const f=await privateFixture(true),c=await playwrightCommand({attemptId:'d'.repeat(64)});
 await playwrightNative(f,c,'open',{command:c,origin:'https://fixture.example.test'});
 await playwrightNative(f,c,'send',{method:'Input.dispatchMouseEvent',params:{type:'mousePressed',button:'left',buttons:1,modifiers:0,clickCount:1,x:20,y:20}});
 await playwrightNative(f,c,'send',{method:'Input.dispatchMouseEvent',params:{type:'mousePressed',button:'left',buttons:1,modifiers:0,clickCount:1,x:20,y:20}});
 assert.equal(f.storage.mechanizePlaywrightJournalV1.records[c.attemptId].receipt.dispatchState,'unknown');
 return {f,c};
}
const retire=(c,fence=grant)=>command('retire-original','executor.retire',{attemptId:c.attemptId,locator:undefined,controlLease:c.controlLease,fingerprintVersion:2,fingerprintSHA256:c.fingerprintSHA256,...fence});
test('exact tab and CDP target death retires only active hazard, retaining UNKNOWN audit and replay denial',async()=>{
 const {f,c}=await unknownFixture(),before=JSON.stringify(f.storage.mechanizePlaywrightJournalV1),inputs=f.state.debuggerInputs.length;
 f.state.inventoryTabs=[];
 await f.receive(retire(c));const result=f.messages.at(-1);assert.equal(result.retiredAuthorityQuiesced,true,JSON.stringify(result));assert.equal(result.dispatchState,'unknown');assert.equal(f.unknownCount(),0);
 assert.equal(JSON.stringify(f.storage.mechanizePlaywrightJournalV1),before);assert.equal(f.state.debuggerInputs.length,inputs);
 const row=await f.playwrightQuery({...c,action:'receipt.query'});assert.equal(row.dispatchState,'unknown');
 const page=await f.playwrightExport(command('export-audit','executor.receipts',{attemptId:undefined,locator:undefined,args:{offset:0,limit:64}}));assert.equal(page.readiness,null);assert.equal(page.receipts[0].dispatchState,'unknown');
 const replay=await playwrightNative(f,c,'open',{command:c,origin:'https://fixture.example.test'});assert.ok(replay.errorCode);assert.equal(f.state.debuggerInputs.length,inputs);
 f.disconnect();assert.equal(f.unknownCount(),1,'port loss rearms the hazard');assert.equal(JSON.stringify(f.storage.mechanizePlaywrightJournalV1),before);
});
test('target retirement rejects live ambiguous foreign active and late metadata without input or receipt edits',async t=>{
 for(const mode of ['liveTab','liveTarget','ambiguousTarget','duplicateTarget','failedCensus','wrongLease','wrongHash','wrongDocument','wrongFence','expired','private','input','targetDrift','portChange'])await t.test(mode,async()=>{
  const {f,c}=await unknownFixture();f.state.inventoryTabs=[];let r=retire(c);
  if(mode==='liveTab')f.state.inventoryTabs=[{id:7}];
  if(mode==='liveTarget')f.state.debuggerTargets=[{id:'old-target',type:'page',tabId:7}];
  if(mode==='ambiguousTarget')f.state.debuggerTargets=[{id:'unowned-page',type:'page'}];
  if(mode==='duplicateTarget')f.state.debuggerTargets=[{id:'same',type:'worker'},{id:'same',type:'worker'}];
  if(mode==='failedCensus')f.state.rejectTargets=true;
  if(mode==='wrongLease')r.controlLease={id:'foreign',generation:1};
  if(mode==='wrongHash')r.fingerprintSHA256='f'.repeat(64);
  if(mode==='wrongDocument')r.identity={...identity,documentId:'other'};
  if(mode==='wrongFence')r.channelEpoch='foreign';
  if(mode==='expired')r.deadlineUnixMs=Date.now()-1;
  if(mode==='private')f.reconnectBarrier('privatePending');
  if(mode==='input')f.reconnectBarrier('browserInput');
  if(mode==='targetDrift')f.state.targetHook=()=>{if(f.state.targetQueries>1)f.state.debuggerTargets=[{id:'late-target',type:'page',tabId:7}];};
  if(mode==='portChange')f.state.targetHook=()=>f.disconnect();
  const before=JSON.stringify(f.storage),inputs=f.state.debuggerInputs.length;
  await f.receive(r);assert.notEqual(f.messages.at(-1)?.retiredAuthorityQuiesced,true);assert.equal(f.unknownCount(),1);assert.equal(JSON.stringify(f.storage),before);assert.equal(f.state.debuggerInputs.length,inputs);
 });
});
async function restartUnknown(){
 const original=await unknownFixture(),before=JSON.stringify(original.f.storage.mechanizePlaywrightJournalV1);
 original.f.disconnect();
 const f=await fixture({}, {enroll:false,localState:structuredClone(original.f.storage)});
 f.state.inventoryTabs=[{id:8,url:'https://fixture.example.test/fresh'}];
 f.state.framesByTab={8:[{frameId:0,parentFrameId:-1,documentId:'fresh-document',url:'https://fixture.example.test/fresh',frameType:'outermost_frame',documentLifecycle:'active'}]};
 f.state.emptyRendererReceipts=true;f.state.reconnectSupported=true;f.state.boundFingerprintVersion=2;f.state.boundDynamicIdentity=true;
 return {f,c:original.c,before};
}
function snapshotResponder(f,c,next,{refuse=false}={}){
 const rows=[{attemptId:c.attemptId,identity:c.identity,fence:grant,fingerprintSHA256:c.fingerprintSHA256,dispatchState:'unknown',controlLease:c.controlLease}];
 f.state.nativePost=m=>{
  if(m.type==='reconnectBindings')queueMicrotask(()=>f.nativeMessage({type:'reconnectBindingsResult',requestId:m.requestId,pendingDigest:hash(m.pending),bindingsDigest:hash(rows),total:1,offset:0,nextOffset:1,bindings:rows}));
  if(m.type==='reconnectBindingsDone'&&m.complete)queueMicrotask(async()=>{
   if(!refuse)await f.receive(retire(c,next));
   f.nativeMessage({type:'reconnectBindingsCommitReady',requestId:m.requestId,complete:!refuse});
  });
 };
}
test('reload reconnect snapshots original UNKNOWN then retires dead target before fresh qualification and input',async()=>{
 const {f,c,before}=await restartUnknown();assert.equal(f.unknownCount(),1);
 const next={...grant,brokerEpoch:'broker2',channelEpoch:'channel2'};snapshotResponder(f,c,next);
 await f.receive({type:'processQualified',...next,trustScope:'desktop',scopeQualified:true,profileQualified:false,fixtureOnly:false,executorChallenge:'new-challenge',mutationFingerprintVersion:2,reconnectBindingsVersion:1});
 assert.ok(f.messages.some(m=>m.type==='executorPrepared'),JSON.stringify(f.messages));assert.equal(f.unknownCount(),0);assert.equal(JSON.stringify(f.storage.mechanizePlaywrightJournalV1),before);
 const fresh={...identity,tabId:8,documentId:'fresh-document'},lease={id:'fresh-lease',generation:2};
 // The exact fresh document needs a separate ordinary lease. Retirement itself
 // supplied no renderer capability or input.
 f.state.publicReply={requestId:'fresh-acquire',identity:fresh,validated:true,controlLease:lease};
 await f.receive(command('fresh-acquire','executor.acquire',{...next,identity:fresh,attemptId:undefined,locator:undefined,controlLease:lease}));delete f.state.publicReply;
 assert.equal(f.messages.at(-1).validated,true);
 const input=command('fresh-select','element.select',{...next,identity:fresh,attemptId:'e'.repeat(64),locator:{strategy:'id',value:'color',exact:true},controlLease:lease,args:{value:'blue'},fingerprintVersion:2});input.fingerprintSHA256=(await require('../fingerprint.js').mutationV2(input)).sha256;
 f.state.publicReply={requestId:input.requestId,identity:fresh,attemptId:input.attemptId,dispatchState:'dispatched',effectState:'unverified'};const deliveries=f.state.deliveries;await f.receive(input);delete f.state.publicReply;assert.equal(f.messages.at(-1).dispatchState,'dispatched',JSON.stringify(f.messages.at(-1)));assert.equal(f.state.deliveries,deliveries+1);
 assert.equal(JSON.stringify(f.storage.mechanizePlaywrightJournalV1),before);assert.equal(f.state.debuggerInputs,undefined);assert.ok(f.state.targetQueries>=4);
 f.disconnect();assert.equal(f.unknownCount(),1);assert.equal(JSON.stringify(f.storage.mechanizePlaywrightJournalV1),before);
});
test('snapshot refusal or surviving original target cannot publish executor or clear UNKNOWN',async t=>{
 for(const mode of ['liveTab','liveTarget','refused','differentHazard'])await t.test(mode,async()=>{
  const {f,c,before}=await restartUnknown(),next={...grant,brokerEpoch:'broker2',channelEpoch:'channel2'};
  if(mode==='liveTab')f.state.inventoryTabs.push({id:7,url:'https://fixture.example.test/old'});
  if(mode==='liveTarget')f.state.debuggerTargets=[{id:'old-target',type:'page',tabId:7}];
  if(mode==='differentHazard')f.reconnectBarrier('unknown');
  snapshotResponder(f,c,next,{refuse:mode==='refused'});
  await f.receive({type:'processQualified',...next,trustScope:'desktop',scopeQualified:true,profileQualified:false,fixtureOnly:false,executorChallenge:'new-challenge',mutationFingerprintVersion:2,reconnectBindingsVersion:1});
  assert.ok(!f.messages.some(m=>m.type==='executorPrepared'));assert.ok(f.unknownCount()>0);assert.equal(JSON.stringify(f.storage.mechanizePlaywrightJournalV1),before);assert.equal(f.state.debuggerInputs,undefined);
 });
});
module.exports={unknownFixture,restartUnknown,snapshotResponder,retire};

test('same-fence qualification retires independently absent UNKNOWN target without requiring ready inventory',async t=>{
 for(const journal of ['initial','adopted'])await t.test(journal,async()=>{
 const {f,c}=await unknownFixture(),before=JSON.stringify(f.storage.mechanizePlaywrightJournalV1),inputs=f.state.debuggerInputs.length;
 if(journal==='adopted'){
  const prior={...grant,brokerEpoch:'prior-broker',channelEpoch:'prior-channel'},nonce='a'.repeat(64);
  f.storage.mechanizeReconnect={version:1,phase:'adopted',nonce,oldFence:prior,newFence:grant,history:[{nonce,oldFence:prior,newFence:grant,executors:[]}]};
 }
 const originalJournal=JSON.stringify(f.storage.mechanizeReconnect);
 f.state.inventoryTabs=[];
 snapshotResponder(f,c,grant);
 await f.receive({type:'processQualified',...grant,fixtureOnly:false,profileQualified:true,scopeQualified:true,executorQualified:false,executorChallenge:'same-fence-challenge',mutationFingerprintVersion:2,reconnectBindingsVersion:1});
 assert.ok(f.messages.some(m=>m.type==='executorPrepared'),'same-fence retained UNKNOWN stranded independent absent-target proof '+JSON.stringify(f.messages.map(m=>({type:m.type,code:m.error?.code,phase:m.reconnectPhase,reason:m.reconnectReason}))));
 assert.equal(f.unknownCount(),0);assert.equal(JSON.stringify(f.storage.mechanizePlaywrightJournalV1),before);assert.equal(JSON.stringify(f.storage.mechanizeReconnect),originalJournal);assert.equal(f.state.debuggerInputs.length,inputs);
 });
});
test('same-fence retirement refuses live replacement ambiguous and unbound target hazards',async t=>{
 for(const mode of ['liveTab','replacementTab','liveTarget','ambiguousTarget','failedCensus','malformedCensus','unbound','refused'])await t.test(mode,async()=>{
 const {f,c}=await unknownFixture(),before=JSON.stringify(f.storage.mechanizePlaywrightJournalV1),journal=JSON.stringify(f.storage.mechanizeReconnect),inputs=f.state.debuggerInputs.length;
 f.state.inventoryTabs=[];
 if(mode==='liveTab'||mode==='replacementTab')f.state.inventoryTabs=[{id:7,url:'https://fixture.example.test/replacement'}];
 if(mode==='liveTarget')f.state.debuggerTargets=[{id:'old-target',type:'page',tabId:7}];
 if(mode==='ambiguousTarget')f.state.debuggerTargets=[{id:'opaque-target',type:'page'}];
 if(mode==='failedCensus')f.state.rejectTargets=true;
 if(mode==='malformedCensus')f.state.debuggerTargets='invalid';
 if(mode==='unbound')f.reconnectBarrier('unknown');
 snapshotResponder(f,c,grant,{refuse:mode==='refused'});
 await f.receive({type:'processQualified',...grant,fixtureOnly:false,profileQualified:true,scopeQualified:true,executorQualified:false,executorChallenge:'same-fence-challenge',mutationFingerprintVersion:2,reconnectBindingsVersion:1});
 assert.ok(!f.messages.some(m=>m.type==='executorPrepared'));assert.ok(f.unknownCount()>0);assert.equal(JSON.stringify(f.storage.mechanizePlaywrightJournalV1),before);assert.equal(JSON.stringify(f.storage.mechanizeReconnect),journal);assert.equal(f.state.debuggerInputs.length,inputs);
 });
});
