const {test}=require('node:test');const assert=require('node:assert/strict');
require('../cdp-transport.js');
const {create}=require('../browser-input.js');
const target={tabId:7,frameId:0,documentId:'doc'};
function fixture(){const calls=[];const api={webNavigation:{getAllFrames:async()=>[{frameId:0,documentId:'doc'}]},debugger:{onDetach:{addListener(){}},attach:async(...x)=>calls.push(['attach',...x]),sendCommand:async(...x)=>calls.push(x)}};return {api,calls,input:create(api)};}
test('closed browser click posts one move down up without exposing page data',async()=>{const f=fixture();const r=await f.input.click(target,{x:20,y:30},Date.now()+1000,()=>true);assert.equal(r.dispatchState,'dispatched');assert.deepEqual(f.calls.slice(1).map(c=>c[2].type),['mouseMoved','mousePressed','mouseReleased']);assert.ok(!f.calls.some(c=>/Runtime|Network|DOM/.test(c[1])));});
test('changed document or denied authority prevents every browser input event',async()=>{for(const mode of ['document','authority']){const f=fixture();if(mode==='document')f.api.webNavigation.getAllFrames=async()=>[{frameId:0,documentId:'other'}];const r=await f.input.click(target,{x:20,y:30},Date.now()+1000,()=>mode!=='authority');assert.equal(r.dispatchState,'notDispatched');assert.equal(f.calls.length,0);}});
test('input admission distinguishes target deadline and authority without posting input',async()=>{for(const [recipient,deadline,admit,code] of [[{...target,frameId:1},Date.now()+1000,()=>true,'browserInputTargetDenied'],[target,Date.now()-1,()=>true,'browserInputDeadlineDenied'],[target,Date.now()+1000,()=>false,'browserInputAuthorityChanged']]){const f=fixture(),r=await f.input.click(recipient,{x:1,y:1},deadline,admit);assert.equal(r.errorCode,code);assert.equal(r.dispatchState,'notDispatched');assert.equal(f.calls.length,0);}});
test('timeout after dispatch inhibits replay and does not echo CDP errors',async()=>{const f=fixture();f.api.debugger.sendCommand=async()=>{throw Error('PASSWORD-CANARY')};const r=await f.input.click(target,{x:20,y:30},Date.now()+1000,()=>true);assert.equal(r.dispatchState,'unknown');assert.ok(!JSON.stringify(r).includes('CANARY'));await assert.rejects(f.input.click(target,{x:20,y:30},Date.now()+1000,()=>true),e=>e.code==='browserInputInhibited');assert.equal(f.calls.length,1);});
test('closed key route rejects arbitrary text and only posts matching down/up',async()=>{const f=fixture();let r=await f.input.key(target,'SECRET-CANARY',Date.now()+1000,()=>true);assert.equal(r.dispatchState,'notDispatched');r=await f.input.key(target,'Return',Date.now()+1000,()=>true);assert.equal(r.dispatchState,'dispatched');assert.deepEqual(f.calls.slice(1).map(c=>c[2].type),['rawKeyDown','keyUp']);assert.ok(!JSON.stringify(f.calls).includes('CANARY'));});

test('pointer timeout identifies only the closed input phase and retains unknown fence',async()=>{
 for(const [type,code] of [['mouseMoved','browserInputMouseMoveTimeout'],['mousePressed','browserInputMousePressTimeout'],['mouseReleased','browserInputMouseReleaseTimeout']]){
  const f=fixture();
  f.api.debugger.sendCommand=async(_,method,args)=>{if(args.type===type)return new Promise(()=>{});return {};};
  const r=await f.input.click(target,{x:20,y:30},Date.now()+30,()=>true);
  assert.equal(r.dispatchState,'unknown');assert.equal(r.errorCode,code);
  await assert.rejects(f.input.click(target,{x:20,y:30},Date.now()+1000,()=>true),e=>e.code==='browserInputInhibited');
 }
});
