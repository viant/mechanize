// Generic transport-only fixture: real extension modules, no browser/profile.
const vm=require('node:vm');
const fs=require('node:fs');
const path=require('node:path');
const identity={profileChannel:'fixture',browserInstance:'isolated',tabId:7,frameId:0,documentId:'root-document',documentGeneration:1};
const drain=()=>new Promise(resolve=>setImmediate(resolve));
async function fixture(){
 const events=new Set(),detaches=new Set(),sent=[],commands=[],saved={};
 const state={allowed:true,checks:0,busy:false,frames:0};
 const context=vm.createContext({TextEncoder,Date,URL,setTimeout,clearTimeout,crypto:require('node:crypto').webcrypto});
 for(const name of ['protocol','fingerprint','cdp-transport','playwright-target','playwright-relay','playwright-worker'])vm.runInContext(fs.readFileSync(path.join(__dirname,'../..',name+'.js'),'utf8'),context);
 const store={get:async key=>key===null?structuredClone(saved):{[key]:structuredClone(saved[key])},set:async value=>Object.assign(saved,structuredClone(value)),setAccessLevel:async()=>{}};
 const api={debugger:{onEvent:{addListener:fn=>events.add(fn)},onDetach:{addListener:fn=>detaches.add(fn)},attach:async()=>{},sendCommand:async(target,method,params)=>{commands.push({target,method,params});return{};}},webNavigation:{getAllFrames:async()=>{state.frames++;return[{frameId:0,documentId:state.documentId||identity.documentId,url:'https://fixture.test'}];}},storage:{local:store,session:store}};
 state.port={postMessage:value=>sent.push(JSON.parse(JSON.stringify(value)))};
 const originalPort=state.port;
 const worker=context.MechanizePlaywrightWorker.create(api,{port:()=>state.port,current:async()=>{state.checks++;if(state.pending)await state.pending;return state.allowed;},acquire:()=>{state.busy=true;},release:()=>{state.busy=false;},unknown:()=>{},redact:value=>value});
 const command={requestId:'generic-read',action:'read',identity,brokerEpoch:'fixture-broker',channelEpoch:'fixture-channel',scopeHash:'a'.repeat(64),deadlineUnixMs:Date.now()+10000,locator:{strategy:'id',value:'public-result',exact:true},args:{attribute:'text'}};
 let sequence=0;
 const send=async(type,extra={})=>{await worker.receive({type:'playwright.'+type,requestId:'wire-'+ ++sequence,relayId:'fixture-relay',deadlineUnixMs:command.deadlineUnixMs,...extra},originalPort);return sent.at(-1);};
 const emit=(method,params={},source={tabId:identity.tabId})=>{for(const fn of events)fn(source,method,params);};
 await send('open',{command,origin:'https://fixture.test'});
 if(!sent.at(-1)?.result?.opened)throw Error('Generic relay fixture failed to open');
 return {context,api,worker,state,identity,sent,commands,send,emit,drain,close:()=>send('close'),eventFrames:()=>sent.filter(frame=>frame.type==='playwright.event'),detach:()=>{for(const fn of detaches)fn({tabId:identity.tabId},'target_closed');}};
}
async function burst(){
 const f=await fixture(),before=f.state.checks;
 try{
  for(let n=0;n<512;n++)f.emit(n%2?'Network.dataReceived':'Log.entryAdded',{fixtureSequence:n});
  await drain();
  const unrelated=f.eventFrames(),eventChecks=f.state.checks-before;
  f.emit('Page.lifecycleEvent',{frameId:'fixture-root',name:'DOMContentLoaded'});await drain();
  const result=await f.send('send',{method:'Runtime.getProperties',params:{objectId:'fixture-public-object'}});
  return {unrelated,required:f.eventFrames().filter(frame=>frame.method==='Page.lifecycleEvent'),counters:{burst:512,eventChecks,unrelatedForwarded:unrelated.length,requiredForwarded:f.eventFrames().length-unrelated.length,commandSucceeded:!result.errorCode}};
 }finally{await f.close();}
}
module.exports={fixture,burst,drain};
if(require.main===module)burst().then(result=>process.stdout.write(JSON.stringify(result)+'\n')).catch(()=>{process.stderr.write('Generic event fixture failed\n');process.exitCode=1;});
