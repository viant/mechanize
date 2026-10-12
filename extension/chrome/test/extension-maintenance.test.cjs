const {test}=require('node:test'),assert=require('node:assert/strict'),vm=require('node:vm'),fs=require('node:fs'),path=require('node:path');
const fence={brokerEpoch:'broker',channelEpoch:'channel',scopeHash:'a'.repeat(64)};
const request=(extra={})=>({type:'extension.reload',requestId:'b'.repeat(64),attemptId:'c'.repeat(64),expectedVersion:'0.1.70',...fence,deadlineUnixMs:Date.now()+1000,...extra});
function fixture(saved={}){
 const state={saved,reloads:0,held:false,busy:false,current:true,version:'0.1.70',writes:0};
 const api={runtime:{getManifest:()=>({version:state.version}),reload(){state.reloads++;state.onReload?.();}},storage:{local:{async setAccessLevel(v){assert.equal(v.accessLevel,'TRUSTED_CONTEXTS');},async get(){await state.onRead?.();return structuredClone(state.saved);},async set(v){state.writes++;await state.beforeWrite?.();Object.assign(state.saved,structuredClone(v));await state.afterWrite?.();}}}};
 const context=vm.createContext({crypto:require('node:crypto').webcrypto,Uint8Array,TextEncoder,Date,setTimeout,clearTimeout});vm.runInContext(fs.readFileSync(path.join(__dirname,'..','extension-maintenance.js'),'utf8'),context);
 const make=()=>context.MechanizeExtensionMaintenance.create(api,{config:()=>({profileChannel:'profile',browserInstance:'browser'}),busy:()=>state.busy,hold:v=>{state.held=v;}});
 const module=make();return {state,make,send:(q=request(),m=module,f=fence)=>m.handle(q,f,()=>state.current),key:context.MechanizeExtensionMaintenance.KEY};
}
test('maintenance reload stores exact payload-free intent and reports desired version only after a new boot',async()=>{
 const f=fixture(),q=request();f.state.onReload=()=>{assert.equal(f.state.saved[f.key].records[q.attemptId].dispatchState,'unknown');};
 const r=await f.send(q);assert.equal(r.dispatchState,'unknown');assert.equal(f.state.reloads,1);assert.equal(f.state.held,true);
 const original=JSON.stringify(f.state.saved);const sameBoot=await f.send({...q,type:'extension.reloadStatus'});assert.equal(sameBoot.reason,'reloadUnconfirmed');assert.equal(sameBoot.bootChanged,false);
 const newBoot=f.make(),newFence={...fence,brokerEpoch:'new-broker',channelEpoch:'new-channel'};
 const observed=await f.send({...q,...newFence,type:'extension.reloadStatus'},newBoot,newFence);assert.equal(observed.available,true);assert.equal(observed.reason,'none');assert.equal(observed.bootChanged,true);assert.equal(observed.matchesExpectedVersion,true);assert.equal(observed.dispatchState,'unknown');
 await f.send({...q,...newFence},newBoot,newFence);assert.equal(f.state.reloads,1);assert.equal(JSON.stringify(f.state.saved),original);
 f.state.version='0.1.69';const mismatch=await f.send({...q,...newFence,type:'extension.reloadStatus'},newBoot,newFence);assert.equal(mismatch.reason,'versionMismatch');assert.equal(mismatch.matchesExpectedVersion,false);assert.equal(f.state.reloads,1);
 assert.deepEqual(Object.keys(f.state.saved[f.key].records[q.attemptId]).sort(),['attemptId','expectedVersion','profileChannel','browserInstance','brokerEpoch','channelEpoch','scopeHash','bootId','dispatchState'].sort());
});
test('maintenance holds admission across persistence and rejects concurrent distinct attempts',async()=>{
 const f=fixture();let entered,release;const started=new Promise(r=>entered=r),held=new Promise(r=>release=r);f.state.beforeWrite=async()=>{entered();await held;};
 const first=f.send();await started;assert.equal(f.state.held,true);
 const second=await f.send(request({attemptId:'d'.repeat(64)}));assert.equal(second.reason,'busy');assert.equal(second.dispatchState,'notDispatched');assert.equal(f.state.writes,1);
 release();await first;assert.equal(f.state.reloads,1);
});
test('lost write ACK deadline and authority change never retry reload or discard uncertain intent',async()=>{
 for(const mode of ['lostAck','deadline','authority']){
  const f=fixture(),q=request({deadlineUnixMs:Date.now()+50});f.state.afterWrite=async()=>{if(mode==='lostAck')throw Error('PRIVATE-CANARY');if(mode==='deadline')await new Promise(r=>setTimeout(r,70));if(mode==='authority')f.state.current=false;};
  const result=await f.send(q);assert.equal(result.dispatchState,'unknown');assert.equal(f.state.reloads,0);assert.equal(f.state.held,true);assert.ok(!JSON.stringify(result).includes('CANARY'));
  f.state.current=true;f.state.afterWrite=null;const next=f.make();await f.send({...q,deadlineUnixMs:Date.now()+1000},next);assert.equal(f.state.reloads,0);assert.equal(f.state.saved[f.key].records[q.attemptId].dispatchState,'unknown');
 }
});
test('maintenance rejects malformed foreign conflicting and missing records without fabricated dispatch proof',async()=>{
 const f=fixture();assert.equal(await f.send(request({extensionId:'foreign'})),null);assert.equal(f.state.writes,0);
 const missing=await f.send(request({type:'extension.reloadStatus'}));assert.equal(missing.reason,'notFound');assert.equal(missing.dispatchState,'unknown');assert.equal(missing.available,false);
 await f.send();const before=JSON.stringify(f.state.saved);
 const conflict=await f.send(request({expectedVersion:'0.1.71'}));assert.equal(conflict.reason,'attemptConflict');assert.equal(f.state.reloads,1);assert.equal(JSON.stringify(f.state.saved),before);
 const other=f.make(),foreign={...fence,scopeHash:'f'.repeat(64)};assert.equal((await f.send(request({...foreign,type:'extension.reloadStatus'}),other,foreign)).reason,'attemptConflict');
 f.state.saved[f.key].records['c'.repeat(64)].secret='PRIVATE-CANARY';const corrupt=await f.send(request({type:'extension.reloadStatus'}),other);assert.equal(corrupt.reason,'receiptUnavailable');assert.ok(!JSON.stringify(corrupt).includes('CANARY'));
});
test('maintenance capacity and readback uncertainty never evict or reload',async()=>{
 const f=fixture();await f.send();const record=f.state.saved[f.key].records['c'.repeat(64)];
 f.state.saved[f.key].records=Object.fromEntries(Array.from({length:512},(_,n)=>{const attemptId=n.toString(16).padStart(64,'0');return[attemptId,{...record,attemptId}];}));
 const before=JSON.stringify(f.state.saved),result=await f.send(request({attemptId:'d'.repeat(64)}),f.make());
 assert.equal(result.reason,'receiptCapacity');assert.equal(result.dispatchState,'notDispatched');assert.equal(JSON.stringify(f.state.saved),before);assert.equal(f.state.reloads,1);
 const g=fixture();g.state.afterWrite=()=>{g.state.saved[g.key].records['c'.repeat(64)].bootId='e'.repeat(64);};
 const uncertain=await g.send();assert.equal(uncertain.dispatchState,'unknown');assert.equal(uncertain.reason,'receiptUnavailable');assert.equal(g.state.reloads,0);assert.equal(g.state.held,true);
});
