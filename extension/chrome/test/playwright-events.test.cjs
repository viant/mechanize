const {test}=require('node:test');
const assert=require('node:assert/strict');
const {pathToFileURL}=require('node:url');
const path=require('node:path');
const {fixture,burst,drain}=require('./fixtures/playwright-event-burst.cjs');
const required=[
 'Runtime.executionContextCreated','Runtime.executionContextDestroyed','Runtime.executionContextsCleared',
 'Page.frameNavigated','Page.frameAttached','Page.frameDetached','Page.lifecycleEvent',
 'Page.loadEventFired','Page.domContentEventFired','Page.frameStoppedLoading',
 'Page.javascriptDialogOpening','Page.javascriptDialogClosed','Inspector.detached','Inspector.targetCrashed',
];
test('extension root event policy exactly matches the sidecar page events',async()=>{
 const f=await fixture();
 try{
  const {pageEvents}=await import(pathToFileURL(path.resolve(__dirname,'../../../browser/playwright/relay.mjs')).href);
  assert.deepEqual([...f.context.MechanizePlaywrightRelay.rootEvents],pageEvents);
  assert.deepEqual([...f.context.MechanizePlaywrightRelay.rootEvents],required);
  assert.equal(Object.isFrozen(f.context.MechanizePlaywrightRelay.rootEvents),true);
 }finally{await f.close();}
});
test('unused root bursts perform no current checks or native forwarding and leave commands usable',async()=>{
 const {counters}=await burst();
 assert.deepEqual(counters,{burst:512,eventChecks:0,unrelatedForwarded:0,requiredForwarded:1,commandSucceeded:true});
});
test('all required root events retain params while child and foreign tab events do not reach current checks',async()=>{
 const f=await fixture();
 try{
  const before=f.state.checks;
  for(const method of required){f.emit(method,{fixture:method},{tabId:8});f.emit(method,{fixture:method},{tabId:7,sessionId:'foreign-child'});}
  for(const method of ['Target.attachedToTarget','Network.requestWillBeSent','Log.entryAdded','Runtime.consoleAPICalled'])f.emit(method,{fixture:method});
  await drain();assert.equal(f.state.checks,before);assert.equal(f.eventFrames().length,0);
  for(const method of required)f.emit(method,{fixture:method});
  await drain();assert.equal(f.state.checks-before,required.length);
  assert.deepEqual(f.eventFrames().map(e=>[e.method,e.params]),required.map(method=>[method,{fixture:method}]));
 }finally{await f.close();}
});
test('required events still recheck dynamic authority and revoked commands fail before CDP',async()=>{
 const f=await fixture();
 try{
  f.state.allowed=false;const before=f.state.checks,commands=f.commands.length;
  f.emit('Page.lifecycleEvent',{frameId:'fixture-root'});await drain();
  assert.equal(f.state.checks,before+1);assert.equal(f.eventFrames().length,0);
  assert.equal((await f.send('send',{method:'Runtime.getProperties',params:{objectId:'fixture'}})).errorCode,'playwrightAuthorityChanged');
  assert.equal(f.commands.length,commands);
 }finally{await f.close();}
});
test('closed relay, detach and stale epoch suppress later events; invalidation and port loss suppress pending results',async()=>{
 for(const mode of ['invalidate','close','detach','epoch','port']){
  const f=await fixture();let release;
  try{
   if(mode==='close')await f.close();
   if(mode==='detach')f.detach();
   if(mode==='epoch')f.context.MechanizeCDP.invalidate(f.api);
   f.state.pending=new Promise(resolve=>{release=resolve;});
   f.emit('Page.lifecycleEvent',{frameId:'fixture-root'});
   if(mode==='invalidate')f.worker.invalidate();
   if(mode==='port')f.state.port={postMessage:()=>{throw Error('Foreign port must not receive an event');}};
   release();await drain();
   assert.equal(f.eventFrames().length,0,mode);
   if(['detach','epoch'].includes(mode)){
    const before=f.state.checks;f.emit('Page.lifecycleEvent',{});await drain();assert.equal(f.state.checks,before);
    const commands=f.commands.length;
    assert.ok((await f.send('send',{method:'Runtime.getProperties',params:{objectId:'fixture'}})).errorCode);assert.equal(f.commands.length,commands);
   }
  }finally{release?.();f.state.pending=undefined;await f.close();}
 }
});
