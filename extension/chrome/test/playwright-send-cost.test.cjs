const {test}=require('node:test');
const assert=require('node:assert/strict');
const {readFixture,call,delay,measure}=require('./fixtures/playwright-send-cost.cjs');
const {privateFixture,playwrightCommand,playwrightNative}=require('./worker-fixture.cjs');
function revoke(f,mode){
 if(mode==='origin')f.state.url='https://changed.invalid/page';
 if(mode==='document')f.state.documentId='replacement-document';
 if(mode==='config')f.storage.enrollment.origins=[];
 if(mode==='privacy')f.reconnectBarrier('privatePending');
 if(mode==='navigation'){f.state.documentId='replacement-document';for(const listener of f.state.committedListeners)listener({tabId:7,frameId:0,documentId:'replacement-document',url:f.state.frameURL});}
}
const cdpCount=f=>(f.state.debuggerInputs||[]).length;
test('joined read sends perform exactly three full current checks across 20 deterministic-cost samples',async()=>{
 const counters=await measure();
 assert.deepEqual(counters.fullChecksPerRead,Array(20).fill(3));
 assert.equal(counters.totalFullChecks,60);assert.equal(counters.totalChargedCurrentCostMs,300);
});
test('joined origin privacy document and config revocation before read prevents CDP',async()=>{
 for(const mode of ['origin','privacy','document','config','navigation']){
  const x=await readFixture();
  try{const before=cdpCount(x.f);revoke(x.f,mode);const result=await x.send();assert.ok(result.errorCode,mode);assert.equal(result.dispatchState,'notDispatched');assert.equal(cdpCount(x.f),before,mode);}
  finally{await x.close();}
 }
});
test('joined revocation during an asynchronous read withholds CDP result data',async()=>{
 for(const mode of ['origin','privacy','document','config','navigation']){
  const x=await readFixture();let release;
  try{
   let entered;const dispatched=new Promise(resolve=>{entered=resolve;});
   const sendCommand=x.f.chrome.debugger.sendCommand;
   x.f.chrome.debugger.sendCommand=async(...args)=>{
    if(args[1]!=='Runtime.getProperties')return sendCommand(...args);
    await sendCommand(...args);entered();await new Promise(resolve=>{release=resolve;});
    return {result:{value:'WITHHELD_GENERIC_RESULT'}};
   };
   const pending=x.send();await dispatched;revoke(x.f,mode);release();const result=await pending;
   assert.ok(result.errorCode,mode);assert.equal(result.dispatchState,'notDispatched');
   assert.ok(!JSON.stringify(x.f.messages).includes('WITHHELD_GENERIC_RESULT'),mode);
  }finally{release?.();await x.close();}
 }
});
test('worker envelope replay method budget and retired-session checks survive consolidation',async()=>{
 for(const mode of ['method','params','budget','identity','deadline','replay','invalidate']){
  const x=await readFixture();
  try{
   const before=cdpCount(x.f);let result;
   if(mode==='method')result=await x.send('Browser.getVersion',{});
   if(mode==='params')result=await x.send('Emulation.setFocusEmulationEnabled',{enabled:false});
   if(mode==='budget')result=await x.send('Runtime.evaluate',{expression:'x'.repeat(512*1024)});
   if(mode==='replay'){
    assert.ok(!(await x.send()).errorCode);const requestId='cost-'+x.f.state.costWireSequence;
    const replies=x.f.messages.filter(m=>m.type==='playwright.result'&&m.requestId===requestId).length;
    x.f.nativeMessage({type:'playwright.send',requestId,relayId:'cost-relay',deadlineUnixMs:x.command.deadlineUnixMs,method:'Runtime.getProperties',params:{objectId:'fixture-public-object'}});
    while(x.f.messages.filter(m=>m.type==='playwright.result'&&m.requestId===requestId).length===replies)await delay(1);
    result=x.f.messages.filter(m=>m.type==='playwright.result'&&m.requestId===requestId).at(-1);
    assert.equal(result.errorCode,'playwrightRequestReplay');assert.equal(cdpCount(x.f),before+1);continue;
   }
   if(mode==='identity')result=await call(x.f,x.command,'send',{method:'Runtime.getProperties',params:{},identity:{}});
   if(mode==='deadline')result=await call(x.f,{...x.command,deadlineUnixMs:Date.now()-1},'send',{method:'Runtime.getProperties',params:{}});
   if(mode==='invalidate'){x.f.disconnect();await delay(2);assert.equal(cdpCount(x.f),before);continue;}
   assert.ok(result.errorCode,mode);assert.equal(cdpCount(x.f),before,mode);
  }finally{if(mode!=='invalidate')await x.close();}
 }
});
test('joined original input retains fresh pinned guard and journal-before-dispatch behavior',async()=>{
 for(const mode of ['valid','unpinned','changed','duringGuard','afterJournal']){
  const f=await privateFixture(true),c=await playwrightCommand();
  if(mode==='unpinned')f.state.noTargetProof=true;
  try{
   assert.equal((await playwrightNative(f,c,'open',{command:c,origin:'https://fixture.example.test'})).result.opened,true);
   if(mode==='changed')f.state.targetSafe=false;
   if(mode==='duringGuard'){const send=f.chrome.debugger.sendCommand;f.chrome.debugger.sendCommand=async(...args)=>{const result=await send(...args);if(args[2]?.functionDeclaration===require('../playwright-target.js').boundarySource)f.state.url='https://changed.invalid';return result;};}
   if(mode==='afterJournal')f.state.afterStorageWrite=values=>{if(values.mechanizePlaywrightJournalV1?.records[c.attemptId]?.phase==='input')f.state.url='https://changed.invalid';};
   const before=f.state.playwrightFullChecks;
   const result=await playwrightNative(f,c,'send',{method:'Input.dispatchMouseEvent',params:{type:'mousePressed',button:'left',buttons:1,modifiers:0,clickCount:1,x:20,y:20}});
   const inputs=(f.state.debuggerInputs||[]).filter(v=>v.method.startsWith('Input.'));
   if(mode==='valid'){
    assert.ok(result.result);assert.equal(inputs.length,1);assert.ok(f.state.playwrightFullChecks-before>=10);assert.ok(f.state.playwrightJournalPhases.includes('input'));
    await playwrightNative(f,c,'send',{method:'Input.dispatchMouseEvent',params:{type:'mouseReleased',button:'left',buttons:0,modifiers:0,clickCount:1,x:20,y:20}});
    assert.equal((await playwrightNative(f,c,'receipt',{dispatchState:'dispatched',effectState:'unverified'})).result.persisted,true);
   }else{
    assert.ok(result.errorCode,mode);assert.equal(inputs.length,0,mode);assert.equal(result.result.receipt.dispatchState,'notDispatched');
    if(mode!=='afterJournal')assert.ok(!f.state.playwrightJournalPhases.includes('input'));
   }
  }finally{await playwrightNative(f,c,'close');}
 }
});
