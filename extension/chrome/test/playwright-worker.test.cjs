const {test}=require('node:test');
const assert=require('node:assert/strict');
const vm=require('node:vm');const fs=require('node:fs');const path=require('node:path');
const identity={profileChannel:'profile',browserInstance:'browser',tabId:7,frameId:0,documentId:'document',documentGeneration:1};
async function fixture(saved={},local={}){
 const sent=[],inputs=[],unknown=new Set();const state={current:true,busy:false,port:{postMessage:v=>sent.push(v)}};
 const context=vm.createContext({TextEncoder,Date,URL,setTimeout,clearTimeout,crypto:require('node:crypto').webcrypto});
 for(const name of ['protocol','fingerprint','playwright-worker'])vm.runInContext(fs.readFileSync(path.join(__dirname,'..',name+'.js'),'utf8'),context);
 context.MechanizePlaywrightRelay={create:(_,authorize)=>({open:async binding=>{if(!await authorize(binding))throw Error();const validate=async()=>{state.validations=(state.validations||0)+1;if(state.denyValidation||!await authorize(binding))throw Object.assign(Error(),{code:'playwrightAuthorityChanged',dispatchState:'notDispatched'});};return{onEvent:()=>()=>{},close(){},validate,send:async(method,params)=>{state.beforeSend?.();await validate();inputs.push({method,params,phase:saved['playwrightAttempt:attempt']?.phase});if(state.inputLost)throw Error('PASSWORD-CANARY');return{};}};}})};
 const api={tabs:{get:async()=>state.tab||{id:7,windowId:9,title:'DO-NOT-EXPORT',url:'https://fixture.test/private'}},windows:{get:async()=>{state.windowLookedUp=true;if(state.dropAfterWindow)state.current=false;return state.window||{id:9,type:'normal',state:'normal',left:10,top:30,width:1000,height:700,title:'DO-NOT-EXPORT'};}},storage:{local:{setAccessLevel:async level=>{assert.deepEqual(JSON.parse(JSON.stringify(level)),{accessLevel:'TRUSTED_CONTEXTS'});if(state.failAccess)throw Error();state.accessCalls=(state.accessCalls||0)+1;if(state.blockAccess)await state.blockAccess;state.trusted=true;},get:async key=>{assert.equal(state.trusted,true);return {[key]:structuredClone(local[key])};},set:async value=>{assert.equal(state.trusted,true);if(state.failLocal)throw Error();Object.assign(local,structuredClone(value));if(state.lostLocalAck){state.lostLocalAck=false;throw Error();}}},session:{get:async()=>structuredClone(saved),set:async v=>{if(state.failStore)throw Error();Object.assign(saved,structuredClone(v));}}}};
 const worker=context.MechanizePlaywrightWorker.create(api,{port:()=>state.port,current:()=>state.current,acquire(){if(state.busy)throw Error();state.busy=true;},release(){state.busy=false;},unknown:(id,v)=>v?unknown.add(id):unknown.delete(id),redact:v=>v.replaceAll('PASSWORD-CANARY','[REDACTED]')});
 const command={requestId:'command',action:'element.press',identity,brokerEpoch:'broker',channelEpoch:'channel',scopeHash:'a'.repeat(64),deadlineUnixMs:Date.now()+10000,locator:{strategy:'id',value:'save',exact:true},attemptId:'attempt',controlLease:{id:'lease',generation:1},fingerprintVersion:2};
 command.fingerprintSHA256=(await context.MechanizeFingerprint.mutationV2(command)).sha256;
 let sequence=0;const send=async(type,extra={})=>{await worker.receive({type:'playwright.'+type,requestId:'request'+ ++sequence,relayId:'relay',deadlineUnixMs:command.deadlineUnixMs,...extra},state.port);return sent.at(-1);};
 return{worker,state,saved,local,inputs,unknown,command,sent,send,open:()=>send('open',{command,origin:'https://fixture.test'})};
}
test('native worker validates sealed fingerprint and closed envelope before debugger work',async()=>{
 for(const mode of ['fingerprint','extra','identity']){const f=await fixture();if(mode==='fingerprint')f.command.fingerprintSHA256='0'.repeat(64);if(mode==='extra')f.command.extra=true;if(mode==='identity')f.command.identity={...identity,frameId:2};const result=await f.open();assert.ok(result.errorCode);assert.equal(f.inputs.length,0);assert.equal(f.state.busy,false);}
});
test('journal precedes actual input; stored receipt reconciles original attempt and forbids replay',async()=>{
 const f=await fixture();assert.equal((await f.open()).result.opened,true);
 await f.send('send',{method:'Input.dispatchMouseEvent',params:{type:'mouseMoved',x:1,y:1}});assert.equal(f.saved['playwrightAttempt:attempt'].phase,'ready');
 await f.send('send',{method:'Input.dispatchMouseEvent',params:{type:'mousePressed',x:1,y:1}});assert.equal(f.inputs.at(-1).phase,'input');
 assert.equal((await f.send('receipt',{dispatchState:'dispatched',effectState:'unverified'})).result.persisted,true);
 await f.send('close');assert.equal(f.state.busy,false);
 const r=await f.worker.query({...f.command,requestId:'query'});assert.equal(r.dispatchState,'dispatched');assert.equal(r.fingerprintSHA256,f.command.fingerprintSHA256);
 assert.ok((await f.open()).errorCode);assert.equal(f.inputs.length,2);
 assert.ok(!JSON.stringify(f.saved).includes('save'));
});
test('unknown actual input survives restart and cannot become a confirmed receipt or replay',async()=>{
 const f=await fixture();await f.open();f.state.inputLost=true;
 assert.equal((await f.send('send',{method:'Input.dispatchMouseEvent',params:{type:'mousePressed',x:1,y:1}})).dispatchState,'unknown');
 assert.equal(f.unknown.has('attempt'),true);assert.equal(f.saved['playwrightAttempt:attempt'].receipt.dispatchState,'unknown');
 const restored=await fixture(f.saved);await restored.worker.recover();assert.equal(restored.unknown.has('attempt'),true);
 assert.equal((await restored.worker.query(restored.command)).dispatchState,'unknown');assert.ok((await restored.open()).errorCode);assert.equal(restored.inputs.length,0);
 await assert.rejects(()=>restored.worker.query({...restored.command,identity:{...identity,documentGeneration:2}}));
});
test('authority drift before input retains no-dispatch while drift after input retains unknown',async()=>{
 for(const actual of [false,true]){const f=await fixture();await f.open();await f.send('send',{method:'Input.dispatchMouseEvent',params:{type:actual?'mousePressed':'mouseMoved',x:1,y:1}});f.state.current=false;const result=await f.send('redact',{value:'PASSWORD-CANARY'});assert.equal(result.dispatchState,actual?'unknown':'notDispatched');assert.equal(f.saved['playwrightAttempt:attempt'].receipt.dispatchState,actual?'unknown':'notDispatched');assert.ok(!JSON.stringify(f.sent).includes('PASSWORD-CANARY'));}
});
test('redaction is extension-owned and receipt ack requires persistence',async()=>{
 const f=await fixture();await f.open();assert.equal((await f.send('redact',{value:'PASSWORD-CANARY'})).result.value,'[REDACTED]');
 await f.send('send',{method:'Input.insertText',params:{text:'public'}});f.state.failStore=true;
 assert.equal((await f.send('receipt',{dispatchState:'dispatched',effectState:'unverified'})).dispatchState,'unknown');assert.equal(f.unknown.has('attempt'),true);
});
test('restart distinguishes retained readiness work from actual input',async()=>{
 for(const phase of ['ready','input']){const f=await fixture();await f.open();const record={...f.saved['playwrightAttempt:attempt'],phase};await f.send('close');const restored=await fixture({'playwrightAttempt:attempt':record});await restored.worker.recover();assert.equal((await restored.worker.query(restored.command)).dispatchState,phase==='input'?'unknown':'notDispatched');}
});
test('private CDP envelope allows pinned engine source but enforces complete 512 KiB budget',async()=>{
 const f=await fixture();await f.open();const accepted=await f.send('send',{method:'Runtime.evaluate',params:{expression:'x'.repeat(343077)}});assert.deepEqual(Object.keys(accepted.result),[]);
 const denied=await f.send('send',{method:'Runtime.evaluate',params:{expression:'x'.repeat(512*1024)}});assert.equal(denied.errorCode,'playwrightEnvelopeDenied');assert.equal(f.inputs.length,1);
});
test('lost authority on replacement port cannot emit a late native reply',async()=>{
 const f=await fixture();await f.open();const original=f.state.port;const before=f.sent.length;f.state.port={postMessage:()=>{throw Error('must not route old relay to new port');}};
 await f.worker.receive({type:'playwright.close',requestId:'replacement',relayId:'relay',deadlineUnixMs:f.command.deadlineUnixMs},original);
 assert.equal(f.sent.length,before);assert.equal(f.saved['playwrightAttempt:attempt'].receipt.dispatchState,'notDispatched');
});
test('a relay cannot dispatch a second business input or an unmatched release',async()=>{
 const f=await fixture();await f.open();await f.send('send',{method:'Input.insertText',params:{text:'public'}});const denied=await f.send('send',{method:'Input.insertText',params:{text:'public'}});assert.equal(denied.errorCode,'playwrightInputReplay');assert.equal(f.inputs.length,1);assert.equal(denied.dispatchState,'unknown');
 const g=await fixture();await g.open();const release=await g.send('send',{method:'Input.dispatchMouseEvent',params:{type:'mouseReleased'}});assert.equal(release.errorCode,'playwrightInputSequenceDenied');assert.equal(g.inputs.length,0);
});
test('lifecycle export combines renderer and original worker fingerprints with stable pagination',async()=>{
 const f=await fixture();await f.open();await f.send('send',{method:'Input.insertText',params:{text:'public'}});await f.send('receipt',{dispatchState:'dispatched',effectState:'unverified'});await f.send('close');
 const rendererRows=Array.from({length:65},(_,n)=>({attemptId:'renderer-'+String(n).padStart(3,'0'),fingerprintVersion:2,fingerprintSHA256:'b'.repeat(64),dispatchState:'dispatched',effectState:'unverified'}));
 const readiness={quiesced:true,controlLeaseHeld:false,recordingState:'none',recordingLastSequence:0,recordingDroppedThrough:0,recordingLeaseExpiresUnixMs:0};
 const read=async c=>({version:2,requestId:c.requestId,identity,total:65,revision:65,offset:c.args.offset,nextOffset:Math.min(65,c.args.offset+64),truncated:c.args.offset+64<65,receipts:rendererRows.slice(c.args.offset,c.args.offset+64),readiness});
 const first=await f.worker.exportReceipts({...f.command,action:'executor.receipts',args:{offset:0,limit:64}},read);assert.equal(first.total,66);assert.equal(first.revision,66);assert.equal(first.receipts[0].attemptId,'attempt');assert.equal(first.receipts[0].fingerprintSHA256,f.command.fingerprintSHA256);
 const last=await f.worker.exportReceipts({...f.command,action:'executor.receipts',args:{offset:64,limit:64,expectedRevision:66}},read);assert.equal(last.receipts.length,2);assert.equal(last.truncated,false);
 await assert.rejects(()=>f.worker.exportReceipts({...f.command,args:{offset:64,limit:64,expectedRevision:65}},read),e=>e.code==='receiptRevisionMismatch');
});
test('lifecycle export rejects unknown history and renderer snapshot changes',async()=>{
 const f=await fixture();await f.open();await f.send('send',{method:'Input.insertText',params:{text:'public'}});await f.send('close');
 await assert.rejects(()=>f.worker.exportReceipts({...f.command,args:{offset:0,limit:64}},()=>{throw Error('renderer must not be queried for unknown history');}),e=>e.code==='receiptExportUnavailable');
 const g=await fixture();await g.open();await g.send('close');
 await assert.rejects(()=>g.worker.exportReceipts({...g.command,args:{offset:0,limit:64}},async c=>({version:2,requestId:c.requestId,identity,total:1,revision:1,offset:0,nextOffset:0,truncated:true,receipts:[],readiness:{}})),e=>e.code==='receiptSnapshotChanged');
});

test('read preparation validates once while physical input validates before journaling and at dispatch',async()=>{
 const f=await fixture();await f.open();await f.send('send',{method:'Runtime.getProperties',params:{objectId:'fixture'}});assert.equal(f.state.validations,1);assert.equal(f.saved['playwrightAttempt:attempt'].phase,'ready');
 await f.send('send',{method:'Input.dispatchMouseEvent',params:{type:'mousePressed',x:1,y:1}});assert.equal(f.state.validations,3);assert.equal(f.inputs.at(-1).phase,'input');await f.send('close');
 const denied=await fixture();await denied.open();denied.state.denyValidation=true;const refused=await denied.send('send',{method:'Input.dispatchMouseEvent',params:{type:'mousePressed',x:1,y:1}});assert.equal(refused.dispatchState,'notDispatched');assert.equal(denied.inputs.length,0);assert.equal(denied.saved['playwrightAttempt:attempt'].receipt.dispatchState,'notDispatched');
 const revoked=await fixture();await revoked.open();revoked.state.beforeSend=()=>{revoked.state.current=false;};assert.equal((await revoked.send('send',{method:'Runtime.getProperties',params:{objectId:'fixture'}})).dispatchState,'notDispatched');assert.equal(revoked.inputs.length,0);
});


test('requested badge metadata contains only exact target window geometry',async()=>{
 const f=await fixture();const result=await f.send('open',{command:f.command,origin:'https://fixture.test',controlBadge:true});
 assert.deepEqual(JSON.parse(JSON.stringify(result.result)),{opened:true,controlBadgeWindow:{x:10,y:30,width:1000,height:700}});
 assert.ok(!JSON.stringify(result).includes('DO-NOT-EXPORT'));assert.equal(f.inputs.length,0);await f.send('close');
});
test('legacy broker receives unchanged open acknowledgement without window lookup',async()=>{
 const f=await fixture();assert.deepEqual(JSON.parse(JSON.stringify((await f.open()).result)),{opened:true});assert.equal(f.state.windowLookedUp,undefined);await f.send('close');
});
test('ambiguous unavailable minimized or mismatched windows never produce a badge target',async()=>{
 for(const window of [{id:10,type:'normal',state:'normal',left:0,top:0,width:1000,height:700},{id:9,type:'normal',state:'minimized',left:0,top:0,width:1000,height:700},{id:9,type:'popup',state:'normal',left:0,top:0,width:1000,height:700},{id:9,type:'normal',state:'normal',left:Infinity,top:0,width:1000,height:700}]){
  const f=await fixture();f.state.window=window;const result=await f.send('open',{command:f.command,origin:'https://fixture.test',controlBadge:true});assert.deepEqual(JSON.parse(JSON.stringify(result.result)),{opened:true});await f.send('close');
 }
});
test('badge metadata does not survive authority loss during window lookup',async()=>{
 const f=await fixture();f.state.dropAfterWindow=true;const result=await f.send('open',{command:f.command,origin:'https://fixture.test',controlBadge:true});assert.equal(result.errorCode,'playwrightAuthorityChanged');assert.equal(result.result?.opened,undefined);assert.equal(result.result?.controlBadgeWindow,undefined);assert.equal(result.result?.receipt?.dispatchState,'notDispatched');assert.equal(f.inputs.length,0);
});

test('durable terminal receipts survive extension reload with session cleared and never repeat input',async()=>{
 for(const dispatch of ['dispatched','notDispatched','unknown']){
  const f=await fixture();await f.open();
  if(dispatch!=='notDispatched')await f.send('send',{method:'Input.insertText',params:{text:'PUBLIC-PAYLOAD-CANARY'}});
  if(dispatch==='unknown')await f.send('close');else{await f.send('receipt',{dispatchState:dispatch,effectState:dispatch==='dispatched'?'unverified':'none'});await f.send('close');}
  const before=JSON.stringify(f.local),restored=await fixture({},structuredClone(f.local));await restored.worker.recover();
  assert.equal((await restored.worker.query(restored.command)).dispatchState,dispatch);
  assert.equal(restored.unknown.has('attempt'),dispatch==='unknown');assert.ok((await restored.open()).errorCode);assert.equal(restored.inputs.length,0);assert.equal(JSON.stringify(restored.local),before);
  assert.ok(!before.includes('PUBLIC-PAYLOAD-CANARY'));assert.ok(!before.includes('save'));assert.ok(!before.includes('https://'));
 }
});
test('durable interrupted readiness/input keeps original uncertainty across update without inventing a missing receipt',async()=>{
 for(const phase of ['ready','input']){
  const f=await fixture();await f.open();if(phase==='input')await f.send('send',{method:'Input.insertText',params:{text:'PUBLIC-CANARY'}});
  const restored=await fixture({},structuredClone(f.local));await restored.worker.recover();
  assert.equal((await restored.worker.query(restored.command)).dispatchState,phase==='ready'?'notDispatched':'unknown');assert.ok((await restored.open()).errorCode);assert.equal(restored.inputs.length,0);
  await f.send('close');
 }
 const missing=await fixture();await missing.worker.recover();assert.equal(await missing.worker.query(missing.command),null);assert.deepEqual(missing.local,{});
});
test('journal migration copies exact legacy metadata and rejects conflicting terminal receipts or untrusted payloads',async()=>{
 const f=await fixture();await f.open();await f.send('close');const legacy=structuredClone(f.saved),local=structuredClone(f.local);
 const migrated=await fixture(legacy,{});await migrated.worker.recover();assert.deepEqual(migrated.local,local);
 for(const mode of ['conflict','payload','receiptPayload','fingerprint','unsupportedAccess']){
  const old=structuredClone(legacy),stored=structuredClone(local),record=stored.mechanizePlaywrightJournalV1.records.attempt;
  if(mode==='conflict')old['playwrightAttempt:attempt'].receipt.error.code='playwrightUnavailable';
  if(mode==='payload')record.value='SECRET-CANARY';if(mode==='receiptPayload')record.receipt.content='SECRET-CANARY';if(mode==='fingerprint')record.receipt.fingerprintSHA256='b'.repeat(64);
  const bad=await fixture(old,stored);if(mode==='unsupportedAccess')bad.state.failAccess=true;
  const before=JSON.stringify(bad.local);await assert.rejects(()=>bad.worker.recover());assert.ok((await bad.open()).errorCode);assert.equal(bad.inputs.length,0);assert.equal(JSON.stringify(bad.local),before);
 }
});
test('journal capacity refuses new admission without evicting originals and local failure forbids input',async()=>{
 const original=await fixture();await original.open();const record=original.local.mechanizePlaywrightJournalV1.records.attempt;await original.send('close');
 const records={};for(let n=0;n<512;n++){const next=structuredClone(record);next.attemptId='retained-'+n;records[next.attemptId]=next;}
 const f=await fixture({},{mechanizePlaywrightJournalV1:{version:1,records}}),before=JSON.stringify(f.local);
 assert.equal((await f.open()).errorCode,'playwrightReceiptCapacity');assert.equal(f.inputs.length,0);assert.equal(JSON.stringify(f.local),before);
 const failed=await fixture();failed.state.failLocal=true;assert.ok((await failed.open()).errorCode);assert.equal(failed.inputs.length,0);assert.deepEqual(failed.local,{});
 const oversized=structuredClone(records);for(const r of Object.values(oversized)){for(const k of ['profileChannel','browserInstance','documentId'])r.identity[k]='x'.repeat(128);r.requestId='r'.repeat(128);r.controlLease.id='l'.repeat(128);r.brokerEpoch='b'.repeat(128);r.channelEpoch='c'.repeat(128);}
 const large=await fixture({},{mechanizePlaywrightJournalV1:{version:1,records:oversized}});await assert.rejects(()=>large.worker.recover());assert.equal(large.inputs.length,0);
});
test('lost terminal local acknowledgement is immutable and queryable without overwriting or replay',async()=>{
 const f=await fixture();await f.open();await f.send('send',{method:'Input.insertText',params:{text:'PUBLIC-CANARY'}});f.state.lostLocalAck=true;
 const result=await f.send('receipt',{dispatchState:'dispatched',effectState:'unverified'});assert.equal(result.result.persisted,true);await f.send('close');
 const restored=await fixture({},structuredClone(f.local));await restored.worker.recover();assert.equal((await restored.worker.query(restored.command)).dispatchState,'dispatched');assert.ok((await restored.open()).errorCode);assert.equal(restored.inputs.length,0);
});
test('journal initialization is shared and no storage or input proceeds before trusted-context restriction',async()=>{
 const f=await fixture();let release;f.state.blockAccess=new Promise(resolve=>release=resolve);
 const recovering=f.worker.recover(),query=f.worker.query(f.command),opening=f.open();
 await new Promise(resolve=>setImmediate(resolve));assert.equal(f.inputs.length,0);assert.deepEqual(f.local,{});assert.equal(f.state.trusted,undefined);release();
 await recovering;await query;assert.equal((await opening).result.opened,true);assert.equal(f.state.accessCalls,1);await f.send('close');
});
