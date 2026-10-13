const test=require('node:test'),assert=require('node:assert/strict'),crypto=require('node:crypto');
const {grant,fixture,privateFixture,command}=require('./worker-fixture.cjs');
const {restartUnknown,retire}=require('./target-retirement-fixture.cjs');
const hash=v=>crypto.createHash('sha256').update(JSON.stringify(v)).digest('hex');
const qualification=next=>({type:'processQualified',...next,trustScope:'desktop',scopeQualified:true,profileQualified:false,fixtureOnly:false,executorChallenge:'replacement-challenge',mutationFingerprintVersion:2,reconnectBindingsVersion:1});
function responder(f,c,next,mode){
 const rows=[{attemptId:c.attemptId,identity:c.identity,fence:grant,fingerprintSHA256:c.fingerprintSHA256,dispatchState:'unknown',controlLease:c.controlLease}];
 f.state.nativePost=m=>{
  if(m.type==='reconnectBindings')queueMicrotask(()=>f.nativeMessage({type:'reconnectBindingsResult',requestId:m.requestId,pendingDigest:hash(m.pending),bindingsDigest:hash(rows),total:1,offset:0,nextOffset:1,bindings:rows}));
  if(m.type==='reconnectBindingsDone'&&m.complete)queueMicrotask(async()=>{
   if(mode!=='refusedACK')await f.receive(retire(c,next));
   f.nativeMessage({type:'reconnectBindingsCommitReady',requestId:m.requestId,complete:mode!=='refusedACK'});
  });
 };
}
test('same-broker fresh channel fence automatically re-establishes retired historical UNKNOWN after worker restart',async()=>{
 const {f,c,before}=await restartUnknown({retireBeforeReload:true}),next={...grant,channelEpoch:'replacement-channel'};
 assert.equal(f.unknownCount(),1);
 responder(f,c,next);
 await f.receive(qualification(next));
 assert.ok(f.messages.some(m=>m.type==='executorPrepared'));
 assert.equal(f.unknownCount(),0);
 assert.equal(JSON.stringify(f.storage.mechanizePlaywrightJournalV1),before);
 assert.equal(f.state.debuggerInputs,undefined);
});
test('same-broker replacement still refuses live targets failed ACK malformed census and unbound uncertainty',async t=>{
 for(const mode of ['liveTab','refusedACK','malformedCensus','unbound'])await t.test(mode,async()=>{
  const {f,c,before}=await restartUnknown({retireBeforeReload:true}),next={...grant,channelEpoch:'replacement-channel'};
  if(mode==='liveTab')f.state.inventoryTabs.push({id:7,url:'https://fixture.example.test/old'});
  if(mode==='malformedCensus')f.state.debuggerTargets=[{id:'target',type:'page',tabId:'malformed'}];
  if(mode==='unbound')f.reconnectBarrier('unknown');
  responder(f,c,next,mode);
  await f.receive(qualification(next));
  assert.ok(!f.messages.some(m=>m.type==='executorPrepared'));
  assert.ok(f.unknownCount()>0);
  assert.equal(JSON.stringify(f.storage.mechanizePlaywrightJournalV1),before);
  assert.equal(f.state.debuggerInputs,undefined);
 });
});
test('healthy worker restart on same broker rebinds under fresh channel epoch without input',async()=>{
 const original=await privateFixture(true),storage=structuredClone(original.storage);
 original.disconnect();
 const f=await fixture({}, {enroll:false,localState:storage});
 f.state.inventoryTabs=[{id:7,url:f.state.url}];f.state.reconnectSupported=true;f.state.emptyRendererReceipts=true;f.state.boundFingerprintVersion=2;f.state.boundDynamicIdentity=true;
 await f.receive({...qualification({...grant,channelEpoch:'replacement-channel'}),reconnectBindingsVersion:undefined});
 assert.ok(f.messages.some(m=>m.type==='executorPrepared'));
 assert.equal(f.unknownCount(),0);
 assert.equal(f.state.debuggerInputs,undefined);
 assert.equal(f.state.freshInputs,undefined);
});
