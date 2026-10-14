import {test} from 'node:test';
import assert from 'node:assert/strict';
import {chromium} from 'playwright-core';
import {createScopedRelay} from '../relay.mjs';
import {PlaywrightEngine} from '../engine.mjs';

async function fixture(send=async()=>({}),deadline=Date.now()+2000){
 const order=[],frames=[];let sends=0;
 const relay=await createScopedRelay({origin:'https://fixture.test',current:async()=>true,onEvent:()=>()=>order.push('unsubscribe'),close:async()=>order.push('adapterClose'),send:async(method,...args)=>{if(method==='Page.getFrameTree')return {frameTree:{frame:{id:'fixture-root'}}};sends++;return send(method,...args);}},{deadlineUnixMs:deadline});
 relay.transport.onmessage=frame=>{frames.push(frame);order.push(frame.error?'error':'result');};
 relay.transport.onclose=()=>order.push('close');
 relay.transport.send({id:1,method:'Target.attachToTarget',params:{targetId:'fixture-root'}});
 await new Promise(resolve=>setImmediate(resolve));
 const sessionId=frames.find(frame=>frame.id===1).result.sessionId;
 return {relay,frames,order,sends:()=>sends,send:(id=2)=>relay.transport.send({id,sessionId,method:'Runtime.callFunctionOn',params:{}}),sendInput:()=>relay.transport.send({id:4,sessionId,method:'Input.dispatchMouseEvent',params:{type:'mousePressed',x:10,y:10}})};
}
const drain=()=>new Promise(resolve=>setImmediate(resolve));
for(const code of ['playwrightTargetDenied','playwrightDocumentChanged','playwrightCDPDenied'])test('first closed relay failure survives disconnect: '+code,async()=>{
 const f=await fixture(async()=>{throw Object.assign(Error('PRIVATE_CANARY'),{code});});
 try{
  f.relay.beginMutation();f.send();f.sendInput();f.send(3);await drain();await drain();
  assert.equal(f.frames.filter(frame=>frame.error).length,1);
  assert.deepEqual(f.relay.failure(),{code,stage:'relay.send'});
  assert.equal(f.frames.find(frame=>frame.id===2).error.message,'Scoped Playwright relay unavailable');
  assert.equal(f.sends(),1);assert.equal(f.order.filter(value=>value==='close').length,1);
  assert.ok(f.order.indexOf('error')<f.order.indexOf('close'));assert.ok(!JSON.stringify(f.frames).includes('PRIVATE_CANARY'));
  await f.relay.close();assert.equal(f.order.filter(value=>value==='adapterClose').length,1);
 }finally{await f.relay.close();}
});
test('unexpected relay errors collapse to a fixed code with no private values',async()=>{
 const f=await fixture(async()=>{throw Object.assign(Error('PRIVATE_CANARY'),{code:'playwrightPRIVATE_CANARY'});});
 try{f.send();await drain();assert.deepEqual(f.relay.failure(),{code:'playwrightUnavailable',stage:'relay.send'});assert.ok(!JSON.stringify([f.frames,f.relay.failure()]).includes('PRIVATE_CANARY'));}finally{await f.relay.close();}
});
test('successful response remains unchanged and explicit close is idempotent',async()=>{
 const f=await fixture(async()=>({result:{value:42}}));
 f.send();await drain();assert.deepEqual(f.frames.find(frame=>frame.id===2).result,{result:{value:42}});assert.equal(f.relay.failure(),undefined);
 await Promise.all([f.relay.close(),f.relay.close()]);assert.equal(f.order.filter(value=>value==='close').length,1);assert.equal(f.order.filter(value=>value==='adapterClose').length,1);
});
test('deadline preserves its fixed closed code and stage',async()=>{
 const f=await fixture(async()=>({}),Date.now()+25);
 await new Promise(resolve=>setTimeout(resolve,40));assert.deepEqual(f.relay.failure(),{code:'playwrightDeadline',stage:'relay.deadline'});await f.relay.close();
});
test('engine projects the remembered closed code after disconnect without replay',async()=>{
 const original=chromium.connectOverCDP;
 // A deterministic transport-only connection fixture: no browser/CDP endpoint.
 chromium.connectOverCDP=async transport=>{
  let seq=0;const pending=new Map();
  transport.onmessage=frame=>{const held=pending.get(frame.id);if(!held)return;pending.delete(frame.id);frame.error?held.reject(Error('PRIVATE_CANARY')):held.resolve(frame.result);};
  transport.onclose=()=>{for(const held of pending.values())held.reject(Error('PRIVATE_CANARY'));pending.clear();};
  const send=(method,params={},sessionId)=>new Promise((resolve,reject)=>{const id=++seq;pending.set(id,{resolve,reject});transport.send({id,method,params,...(sessionId?{sessionId}:{})});});
  const attached=await send('Target.attachToTarget',{targetId:'fixture-root'});
  await send('Runtime.callFunctionOn',{},attached.sessionId);
  const element={evaluate:async()=>true,textContent:async()=>'Generic public result'};
  return {contexts:()=>[{pages:()=>[{url:()=>'https://fixture.test',setDefaultTimeout(){},locator:()=>({count:async()=>1,elementHandle:async()=>element})}]}]};
 };
 try{
  for(const code of ['playwrightTargetDenied','playwrightPRIVATE_CANARY',null]){
   let calls=0,closes=0;const identity={profileChannel:'fixture',browserInstance:'isolated',tabId:1,frameId:0,documentId:'document',documentGeneration:1};
   const host={admit:async()=>({identity,origin:'https://fixture.test',brokerEpoch:'broker',channelEpoch:'channel',scopeHash:'a'.repeat(64),privateQuarantined:false}),current:async()=>true,openRelay:async()=>({current:async()=>true,onEvent:()=>()=>{},close:async()=>{closes++;},send:async method=>{if(method==='Page.getFrameTree')return {frameTree:{frame:{id:'fixture-root'}}};calls++;if(code===null)return {result:{value:42}};throw Object.assign(Error('PRIVATE_CANARY'),{code});}}),commitIntent:async()=>{throw Error('No input allowed');},persistReceipt:async()=>{throw Error('No input allowed');},redact:async value=>value};
   const result=await new PlaywrightEngine(host).execute({requestId:'original-request',action:'read',identity,brokerEpoch:'broker',channelEpoch:'channel',scopeHash:'a'.repeat(64),deadlineUnixMs:Date.now()+2000,locator:{strategy:'id',value:'public-result',exact:true},args:{attribute:'text'}});
   assert.equal(result.requestId,'original-request');assert.equal(result.errorCode,code===null?undefined:code==='playwrightTargetDenied'?code:'playwrightUnavailable');if(code===null)assert.equal(result.value,'Generic public result');assert.equal(result.dispatchState,'notDispatched');assert.equal(result.effectState,'none');assert.equal(calls,1);assert.equal(closes,1);assert.ok(!JSON.stringify(result).includes('PRIVATE_CANARY'));
  }
 }finally{chromium.connectOverCDP=original;}
});
