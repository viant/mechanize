const {test}=require('node:test');
const assert=require('node:assert/strict');
const {create}=require('../cdp-transport.js');
function fixture(){
 const calls=[]; let detached,event;
 const api={debugger:{onDetach:{addListener(f){detached=f;}},onEvent:{addListener(f){event=f;}},attach:async()=>{calls.push('attach');},detach:async()=>{calls.push('detach');},sendCommand:async(...args)=>{calls.push(args);return {ok:true};}}};
 return {api,calls,transport:create(api,method=>method==='Input.dispatchMouseEvent'),detach:(tabId,reason)=>detached({tabId},reason),event:(tabId,method,params,sessionId)=>event({tabId,...(sessionId===undefined?{}:{sessionId})},method,params)};
}
test('CDP sessions reuse attachments and reject stale sessions after detach',async()=>{
 const f=fixture(),a=await f.transport.attach(7,Date.now()+1000),b=await f.transport.attach(7,Date.now()+1000);
 assert.equal(a.generation,b.generation);assert.equal(f.calls.filter(x=>x==='attach').length,1);
 f.detach(7,'target_closed');
 const c=await f.transport.attach(7,Date.now()+1000);assert.notEqual(c.generation,a.generation);
 await assert.rejects(a.send('Input.dispatchMouseEvent',{},Date.now()+1000),e=>e.code==='cdpDetached');
});
test('CDP detach rejects pending command immediately and user cancellation stops all tabs',async()=>{
 const f=fixture(),a=await f.transport.attach(7,Date.now()+1000),b=await f.transport.attach(8,Date.now()+1000);
 f.api.debugger.sendCommand=()=>new Promise(()=>{});
 const pending=a.send('Input.dispatchMouseEvent',{},Date.now()+1000);
 f.detach(7,'canceled_by_user');
 await assert.rejects(pending,e=>e.code==='cdpDetached'&&e.dispatchState==='unknown');
 assert.equal(b.current(),false);
 await assert.rejects(f.transport.attach(8,Date.now()+1000),e=>e.code==='cdpDenied');
});
test('late debugger attach is detached and cannot resurrect expired session',async()=>{
 const f=fixture();let finish;
 f.api.debugger.attach=()=>new Promise(resolve=>{finish=resolve;});
 await assert.rejects(f.transport.attach(7,Date.now()+15),e=>e.code==='cdpTimeout');
 await assert.rejects(f.transport.attach(7,Date.now()+1000),e=>e.code==='cdpAttachPending');
 finish();await new Promise(resolve=>setImmediate(resolve));
 assert.ok(f.calls.includes('detach'));
});
test('CDP policy and attached child ownership are enforced without echoing errors',async()=>{
 const f=fixture(),a=await f.transport.attach(7,Date.now()+1000);
 await assert.rejects(a.send('Runtime.evaluate',{expression:'SECRET'},Date.now()+1000),e=>e.code==='cdpDenied'&&!e.message.includes('SECRET'));
 await assert.rejects(a.send('Input.dispatchMouseEvent',{},Date.now()+1000,'foreign'),e=>e.code==='cdpDenied');
 f.event(7,'Target.attachedToTarget',{sessionId:'child'});
 await a.send('Input.dispatchMouseEvent',{},Date.now()+1000,'child');
 assert.deepEqual(f.calls.at(-1)[0],{tabId:7,sessionId:'child'});
 f.api.debugger.sendCommand=()=>Promise.reject(Error('SECRET'));
 await assert.rejects(a.send('Input.dispatchMouseEvent',{},Date.now()+1000),e=>e.code==='cdpUnavailable'&&!e.message.includes('SECRET'));
});
test('independent adapters share one attachment without broadening narrow method policy',async()=>{
 const f=fixture(),playwright=create(f.api,method=>['Runtime.evaluate','Input.dispatchMouseEvent'].includes(method));
 const [input,wide]=await Promise.all([f.transport.attach(7,Date.now()+1000),playwright.attach(7,Date.now()+1000)]);
 assert.equal(f.calls.filter(v=>v==='attach').length,1);
 await wide.send('Runtime.evaluate',{expression:'public'},Date.now()+1000);
 await assert.rejects(input.send('Runtime.evaluate',{},Date.now()+1000),e=>e.code==='cdpDenied');
 await input.send('Input.dispatchMouseEvent',{},Date.now()+1000);
});
test('authority epoch invalidates both adapters while preserving native attachment for new authority',async()=>{
 const f=fixture(),wide=create(f.api,()=>true),a=await f.transport.attach(7,Date.now()+1000),b=await wide.attach(7,Date.now()+1000);
 f.api.debugger.sendCommand=()=>new Promise(()=>{});const pending=a.send('Input.dispatchMouseEvent',{},Date.now()+1000);
 require('../cdp-transport.js').invalidate(f.api);
 await assert.rejects(pending,e=>e.code==='cdpDetached'&&e.dispatchState==='unknown');assert.equal(a.current(),false);assert.equal(b.current(),false);
 const c=await wide.attach(7,Date.now()+1000);assert.equal(c.current(),true);assert.equal(f.calls.filter(v=>v==='attach').length,1);assert.ok(!f.calls.includes('detach'));
});
test('user cancellation stops reattachment through every adapter and newer authority epochs',async()=>{
 const f=fixture(),wide=create(f.api,()=>true);await f.transport.attach(7,Date.now()+1000);await wide.attach(8,Date.now()+1000);f.detach(7,'canceled_by_user');
 require('../cdp-transport.js').invalidate(f.api);
 await assert.rejects(wide.attach(7,Date.now()+1000),e=>e.code==='cdpDenied');await assert.rejects(f.transport.attach(8,Date.now()+1000),e=>e.code==='cdpDenied');
});
test('epoch change during shared attachment cannot authorize the prior waiter',async()=>{
 const f=fixture();let complete;f.api.debugger.attach=()=>new Promise(resolve=>complete=resolve);
 const before=f.transport.attach(7,Date.now()+1000);await new Promise(r=>setImmediate(r));require('../cdp-transport.js').invalidate(f.api);
 await assert.rejects(before,e=>e.code==='cdpDetached');const wide=create(f.api,()=>true),after=wide.attach(7,Date.now()+1000);complete();assert.equal((await after).current(),true);assert.ok(!f.calls.includes('detach'));
});
test('packaged BrowserInput and Playwright relay switch through the same owned attachment',async()=>{
 const f=fixture(),identity={profileChannel:'p',browserInstance:'b',tabId:7,frameId:0,documentId:'d',documentGeneration:1};
 f.api.webNavigation={getAllFrames:async()=>[{frameId:0,documentId:'d',url:'https://fixture.test'}]};
 const input=require('../browser-input.js').create(f.api),playwright=require('../playwright-relay.js').create(f.api,()=>true);
 assert.equal((await input.click(identity,{x:10,y:10},Date.now()+1000,()=>true)).dispatchState,'dispatched');
 const session=await playwright.open({identity,origin:'https://fixture.test',command:{action:'read'}},Date.now()+1000);
 await session.send('Runtime.evaluate',{expression:'1'},Date.now()+500);session.close();
 assert.equal((await input.click(identity,{x:10,y:10},Date.now()+1000,()=>true)).dispatchState,'dispatched');
 assert.equal(f.calls.filter(v=>v==='attach').length,1);assert.ok(!f.calls.includes('detach'));
});
test('new consumer receives only real live execution contexts on repeated Runtime enable',async()=>{
 const f=fixture(),wide=create(f.api,()=>true),first=await wide.attach(7,Date.now()+1000),one=[],two=[];
 first.onEvent(e=>one.push(e));f.event(7,'Runtime.executionContextCreated',{context:{id:11,origin:'https://fixture.test',name:'',auxData:{frameId:'root'}}});
 const second=await wide.attach(7,Date.now()+1000);second.onEvent(e=>two.push(e));await second.send('Runtime.enable',{},Date.now()+1000);
 assert.equal(two.length,1);assert.equal(two[0].params.context.id,11);assert.equal(one.length,1);
 await second.send('Runtime.enable',{},Date.now()+1000);assert.equal(two.length,1);
 f.event(7,'Runtime.executionContextDestroyed',{executionContextId:11});const third=await wide.attach(7,Date.now()+1000),three=[];third.onEvent(e=>three.push(e));await third.send('Runtime.enable',{},Date.now()+1000);assert.equal(three.length,0);
});
test('context cache clears on navigation, context reset, epoch and detach',async()=>{
 for(const mode of ['navigation','reset','epoch','detach']){
  const f=fixture(),wide=create(f.api,()=>true);await wide.attach(7,Date.now()+1000);f.event(7,'Runtime.executionContextCreated',{context:{id:1,auxData:{frameId:'old'}}});
  if(mode==='navigation')f.event(7,'Page.frameNavigated',{frame:{id:'new'}});if(mode==='reset')f.event(7,'Runtime.executionContextsCleared',{});if(mode==='epoch')require('../cdp-transport.js').invalidate(f.api);if(mode==='detach')f.detach(7,'target_closed');
  const fresh=await wide.attach(7,Date.now()+1000),events=[];fresh.onEvent(e=>events.push(e));await fresh.send('Runtime.enable',{},Date.now()+1000);assert.equal(events.length,0,mode);
 }
});
test('new epoch requests fresh runtime context events instead of reusing old context IDs',async()=>{
 const f=fixture(),wide=create(f.api,()=>true),before=await wide.attach(7,Date.now()+1000);before.onEvent(()=>{});await before.send('Runtime.enable',{},Date.now()+1000);f.event(7,'Runtime.executionContextCreated',{context:{id:1,auxData:{frameId:'root'}}});
 require('../cdp-transport.js').invalidate(f.api);const fresh=await wide.attach(7,Date.now()+1000),events=[];fresh.onEvent(e=>events.push(e));
 f.api.debugger.sendCommand=async(_,method)=>{f.calls.push(method);if(method==='Runtime.enable')f.event(7,'Runtime.executionContextCreated',{context:{id:2,auxData:{frameId:'root'}}});return{};};
 await fresh.send('Runtime.enable',{},Date.now()+1000);assert.deepEqual(f.calls.slice(-2),['Runtime.disable','Runtime.enable']);assert.deepEqual(events.map(e=>e.params.context.id),[2]);assert.equal(f.calls.filter(v=>v==='attach').length,1);
});
test('root consumer context replay excludes child-session and destroyed unique contexts',async()=>{
 const f=fixture(),wide=create(f.api,()=>true);await wide.attach(7,Date.now()+1000);
 f.event(7,'Runtime.executionContextCreated',{context:{id:1,auxData:{frameId:'foreign'}}},'child');
 f.event(7,'Runtime.executionContextCreated',{context:{id:2,uniqueId:'dead-context',auxData:{frameId:'root'}}});
 f.event(7,'Runtime.executionContextDestroyed',{executionContextUniqueId:'dead-context'});
 const fresh=await wide.attach(7,Date.now()+1000),events=[];fresh.onEvent(e=>events.push(e));await fresh.send('Runtime.enable',{},Date.now()+1000);assert.equal(events.length,0);
});

test('drain evidence survives logical timeout invalidation and replacement until original Chrome call settles',async()=>{
 for(const mode of ['timeout','invalidate','replace']){
  const f=fixture(),session=await f.transport.attach(7,Date.now()+1000);let finish;
  f.api.debugger.sendCommand=()=>new Promise(resolve=>{finish=resolve;});
  const pending=session.send('Input.dispatchMouseEvent',{},Date.now()+20);
  const transport=require('../cdp-transport.js');assert.equal(transport.idle(f.api),false);
  if(mode==='invalidate')transport.invalidate(f.api);
  if(mode==='replace'){f.detach(7,'target_closed');await f.transport.attach(7,Date.now()+1000);}
  await assert.rejects(pending);assert.equal(transport.idle(f.api),false,mode);
  finish({});await new Promise(resolve=>setImmediate(resolve));assert.equal(transport.idle(f.api),true,mode);
 }
});
