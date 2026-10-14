// Joined real worker.js + playwright-worker + relay + CDP modules.
// Existing generic native/renderer API fixture; no real browser or native host.
const {privateFixture,identity,grant}=require('../worker-fixture.cjs');
const {performance}=require('node:perf_hooks');
const delay=ms=>new Promise(resolve=>setTimeout(resolve,ms));
async function call(f,c,type,extra={}){
 const requestId='cost-'+(f.state.costWireSequence=(f.state.costWireSequence||0)+1);
 f.nativeMessage({type:'playwright.'+type,requestId,relayId:'cost-relay',deadlineUnixMs:c.deadlineUnixMs,...extra});
 const deadline=Date.now()+5000;
 while(Date.now()<deadline){const reply=f.messages.find(m=>m.type==='playwright.result'&&m.requestId===requestId);if(reply)return reply;await delay(1);}
 throw Error('Generic cost fixture reply missing');
}
async function readFixture(){
 const f=await privateFixture(true);
 const command={requestId:'generic-cost-read',action:'read',identity:{...identity},...grant,deadlineUnixMs:Date.now()+10000,locator:{strategy:'id',value:'public-result',exact:true},args:{attribute:'text'}};
 const opened=await call(f,command,'open',{command,origin:'https://fixture.example.test'});
 if(!opened.result?.opened)throw Error('Generic cost fixture did not open');
 return{f,command,send:(method='Runtime.getProperties',params={objectId:'fixture-public-object'})=>call(f,command,'send',{method,params}),close:()=>call(f,command,'close')};
}
async function measure(){
 const x=await readFixture(),samples=[],costMs=5;
 try{
  x.f.state.playwrightCurrentCostMs=costMs;
  for(let n=0;n<20;n++){
   const before=x.f.state.playwrightFullChecks,start=performance.now();
   const result=await x.send();
   if(result.errorCode)throw Error('Generic measured read failed');
   const fullChecks=x.f.state.playwrightFullChecks-before;
   samples.push({sample:n+1,fullChecks,chargedCurrentCostMs:fullChecks*costMs,elapsedMs:Math.round((performance.now()-start)*1000)/1000});
  }
  return {samples:20,costPerCurrentMs:costMs,fullChecksPerRead:samples.map(s=>s.fullChecks),totalFullChecks:samples.reduce((n,s)=>n+s.fullChecks,0),totalChargedCurrentCostMs:samples.reduce((n,s)=>n+s.chargedCurrentCostMs,0),measurements:samples};
 }finally{x.f.state.playwrightCurrentCostMs=0;await x.close();}
}
module.exports={call,readFixture,measure,delay};
if(require.main===module)measure().then(v=>process.stdout.write(JSON.stringify(v)+'\n')).catch(()=>{process.stderr.write('Generic send cost fixture failed\n');process.exitCode=1;});
