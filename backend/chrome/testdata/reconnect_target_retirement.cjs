// The shipped worker reloads with its real persisted UNKNOWN journal. Chrome
// APIs are inert adapters; all native protocol messages travel to the Go broker.
const readline=require('node:readline'),assert=require('node:assert/strict'),crypto=require('node:crypto');
const {restartUnknown}=require('../../../extension/chrome/test/target-retirement-fixture.cjs');
let f,before,ready=false;
const write=v=>process.stdout.write(JSON.stringify(v)+'\n');
readline.createInterface({input:process.stdin}).on('line',async line=>{
 try {
  const m=JSON.parse(line);
  if(m.type==='fixture.start'){
   const restarted=await restartUnknown({attemptId:m.attemptId});f=restarted.f;before=restarted.before;
   let hello;f.disconnect();f.state.nativePost=m=>{if(m.type==='hello')hello=m;else write(m)};await f.connect();
   for(let n=0;n<100&&!hello;n++)await new Promise(r=>setTimeout(r,5));assert.ok(hello);f.state.nativePost=write;
   // Supply no fake reconnect replies: Go owns the entire native exchange.
   f.state.renderer=async(_,message)=>{
    if(message.type==='brokerReconnect'){
     const current=message.newBinding.identity;
     if(message.phase==='inspect')return {nonce:message.nonce,phase:'inspected',version:1,identity:current};
     return {nonce:message.nonce,phase:message.phase==='prepare'?'prepared':'adopted',identity:current,receiptRevision:0,receiptCount:0,quiescent:true};
    }
    if(message.type==='bind')return {identity:message.binding.identity,mutationFingerprintVersion:2};
    if(message.action==='executor.receipts')return {version:2,requestId:message.requestId,identity:message.identity,total:0,revision:0,offset:0,nextOffset:0,truncated:false,receipts:[],readiness:{recording:false}};
    if(message.action==='executor.validate')return {requestId:message.requestId,identity:message.identity,validated:true};
    if(message.action==='executor.acquire')return {requestId:message.requestId,identity:message.identity,validated:true,controlLease:message.controlLease};
    if(message.action==='element.select'){f.state.freshInputs=(f.state.freshInputs||0)+1;return {requestId:message.requestId,identity:message.identity,attemptId:message.attemptId,fingerprintVersion:message.fingerprintVersion,fingerprintSHA256:message.fingerprintSHA256,controlLease:message.controlLease,dispatchState:'dispatched',effectState:'unverified'};}
    if(message.action==='executor.retire')return {requestId:message.requestId,identity:message.identity,retiredAuthorityQuiesced:true,controlLease:message.controlLease};
    throw Error('unsupported inert renderer boundary');
   };
   ready=true;
   write({type:'fixture.ready',original:restarted.c,hello});return;
  }
  if(!ready)throw Error('fixture not ready');
  if(m.type==='fixture.finish'){
   assert.equal(JSON.stringify(f.storage.mechanizePlaywrightJournalV1),before);assert.equal(f.state.freshInputs,1);assert.equal(f.state.debuggerInputs,undefined);
   write({type:'fixture.finished',journalUnchanged:true,freshInputs:1,deathCensusChecks:f.state.targetQueries});return;
  }
  f.nativeMessage(m);
 }catch(_){write({type:'fixture.failed'});process.exitCode=1;}
});
