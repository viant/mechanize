const {test}=require('node:test');
const assert=require('node:assert/strict');
const fs=require('node:fs'),path=require('node:path');
const {webcrypto}=require('node:crypto');
const {JSDOM}=require('jsdom');
const identity={profileChannel:'profile1',browserInstance:'browser1',tabId:7,frameId:0,documentId:'doc1',documentGeneration:1};
const lease={id:'lease1',generation:1};
function fixture(){
 const dom=new JSDOM('<button id="save">Save</button>',{url:'https://fixture.test',runScripts:'outside-only'}),w=dom.window,listeners=[];
 w.TextEncoder=TextEncoder;Object.defineProperty(w,'crypto',{value:webcrypto,configurable:true});w.HTMLElement.prototype.getClientRects=()=>[{width:100,height:20}];
 w.chrome={runtime:{id:'fixture',onMessage:{addListener:f=>listeners.push(f)}}};
 for(const file of ['protocol.js','fingerprint.js','accessibility-provider.js','dom.js','recorder.js','secure-input.js','content.js'])w.eval(fs.readFileSync(path.join(__dirname,'..',file),'utf8'));
 const binding={identity,brokerEpoch:'broker1',channelEpoch:'channel1',scopeHash:'a'.repeat(64),leaseRequired:true,mutationFingerprintVersion:2};
 const send=(m,s={id:'fixture',url:'chrome-extension://fixture/worker.js'})=>new Promise(resolve=>listeners[0](m,s,resolve));
 const command=(action,extra={},b=binding)=>({requestId:'request1',action,identity:b.identity,brokerEpoch:b.brokerEpoch,channelEpoch:b.channelEpoch,scopeHash:b.scopeHash,deadlineUnixMs:Date.now()+5000,...extra});
 const ready=async()=>{await send({type:'bind',binding});await send(command('executor.acquire',{controlLease:lease}));};
 const request=()=>({type:'brokerReconnect',phase:'prepare',nonce:'b'.repeat(64),deadlineUnixMs:Date.now()+5000,oldFence:{brokerEpoch:binding.brokerEpoch,channelEpoch:binding.channelEpoch,scopeHash:binding.scopeHash},newBinding:{...binding,identity:{...identity},brokerEpoch:'broker2',channelEpoch:'channel2'}});
 const mutation=async()=>{const m=command('element.press',{attemptId:'c'.repeat(64),locator:{strategy:'id',value:'save',exact:true},controlLease:lease,fingerprintVersion:2});m.fingerprintSHA256=(await w.MechanizeFingerprint.mutationV2(m)).sha256;return m;};
 return{w,send,binding,command,ready,request,mutation,close:()=>w.close()};
}
test('reconnect retires exact lease and preserves known receipts without replay',async t=>{
 const f=fixture();t.after(f.close);await f.ready();let clicks=0;f.w.document.querySelector('#save').onclick=()=>clicks++;
 const mutation=await f.mutation();assert.equal((await f.send(mutation)).dispatchState,'dispatched');
 const request=f.request(),prepared=await f.send(request);assert.equal(prepared.phase,'prepared');assert.equal(prepared.receiptRevision,1);assert.equal(prepared.receiptCount,1);
 assert.deepEqual(Object.keys(prepared).sort(),['identity','nonce','phase','quiescent','receiptCount','receiptRevision']);
 assert.equal((await f.send(f.command('executor.acquire',{controlLease:{id:'lease2',generation:2}}))).error.code,'executorQuiesced');
 assert.ok((await f.send({...request,phase:'adopt',receiptRevision:2})).error);
 const adopted=await f.send({...request,phase:'adopt',receiptRevision:1});assert.equal(adopted.phase,'adopted');assert.equal(adopted.receiptCount,1);assert.equal(clicks,1);
 assert.ok((await f.send({...request,phase:'adopt',receiptRevision:1})).error);
 assert.ok((await f.send(f.command('executor.acquire',{controlLease:lease},request.newBinding))).error);
 assert.equal((await f.send(f.command('executor.acquire',{controlLease:{id:'lease2',generation:2}},request.newBinding))).validated,true);
 const queried=await f.send(f.command('receipt.query',{attemptId:mutation.attemptId},request.newBinding));assert.equal(queried.fingerprintSHA256,mutation.fingerprintSHA256);assert.equal(clicks,1);
 assert.ok((await f.send(f.command('observe'))).error);
});
test('quiesced adoption accepts monotonic decoration generation and requires a fresh lease',async t=>{
 for(const bound of [false,true]){const f=fixture();t.after(f.close);if(bound)await f.ready();const request=f.request(),first=await f.send(request);assert.equal(first.phase,'prepared');
  f.w.document.body.appendChild(f.w.document.createElement('div'));
  const result=await f.send({...request,phase:'adopt',receiptRevision:0});assert.equal(result.phase,'adopted');assert.ok(result.identity.documentGeneration>first.identity.documentGeneration);
  const current={...request.newBinding,identity:result.identity};
  assert.ok((await f.send(f.command('executor.acquire',{controlLease:lease},request.newBinding))).error);
  if(bound)assert.ok((await f.send(f.command('executor.acquire',{controlLease:lease},current))).error);
  assert.equal((await f.send(f.command('executor.acquire',{controlLease:{id:'fresh-lease',generation:2}},current))).validated,true);
 }
});
test('closed reconnect rejects foreign sender, fields, scope, fingerprint and stale fence',async t=>{
 for(const mode of ['tab','url','extra','scope','version','leaseRequired','oldFence','identity','expired','farDeadline']){
  const f=fixture();t.after(f.close);await f.ready();const request=f.request();let sender={id:'fixture'};
  if(mode==='tab')sender.tab=null;else if(mode==='url')sender.url='chrome-extension://fixture/options.html';else if(mode==='extra')request.approved=true;else if(mode==='scope')request.newBinding.scopeHash='d'.repeat(64);else if(mode==='version')request.newBinding.mutationFingerprintVersion=1;else if(mode==='leaseRequired')request.newBinding.leaseRequired=false;else if(mode==='oldFence')request.oldFence.brokerEpoch='wrong';else if(mode==='identity')request.newBinding.identity.documentId='other';else if(mode==='expired')request.deadlineUnixMs=Date.now()-1;else request.deadlineUnixMs=Date.now()+20000;
  assert.ok((await f.send(request,sender)).error,mode);
  assert.equal((await f.send(f.command('executor.validate',{controlLease:lease}))).validated,true,mode);
 }
});
test('prior lifecycle quiescence, recording history and unknown receipts cannot be cleared',async t=>{
 for(const mode of ['quiesced','recording','unknown']){const f=fixture();t.after(f.close);await f.ready();
  if(mode==='quiesced')await f.send(f.command('executor.quiesce'));
  else if(mode==='recording'){await f.send(f.command('record.start',{args:{recordingId:'record1',leaseExpiresUnixMs:Date.now()+5000}}));await f.send(f.command('record.stop',{args:{recordingId:'record1'}}));}
  else {f.w.MechanizeDOM.act=()=>({dispatchState:'unknown',effectState:'unknown'});await f.send(await f.mutation());}
  assert.ok((await f.send(f.request())).error,mode);
 }
});
test('pending async fingerprint prevents prepare and cannot dispatch behind reconnect',async t=>{
 const f=fixture();t.after(f.close);await f.ready();const command=await f.mutation();let release,entered;const wait=new Promise(r=>release=r),started=new Promise(r=>entered=r);
 Object.defineProperty(f.w,'crypto',{value:{subtle:{digest:async(...args)=>{entered();await wait;return webcrypto.subtle.digest(...args);}}},configurable:true});
 const pending=f.send(command);await started;assert.ok((await f.send(f.request())).error);release();await pending;
 assert.equal((await f.send(f.request())).phase,'prepared');
});
test('private continuation and committed redaction state remain quarantined across reconnect',async t=>{
 for(const mode of ['private','redaction']){const f=fixture();t.after(f.close);const message={type:mode==='private'?'credentialBind':'credentialPrivacyBind',requestId:'f'.repeat(64),identity,...{brokerEpoch:f.binding.brokerEpoch,channelEpoch:f.binding.channelEpoch,scopeHash:f.binding.scopeHash},deadlineUnixMs:Date.now()+5000,origin:'https://fixture.test'};
  if(mode==='private')message.controlLease=lease;else{message.permitId='e'.repeat(64);message.redactions=f.w.MechanizeSecureInput.redactionVariants(['SYNTHETIC-PRIVATE']);}
  await f.send(message);if(mode==='redaction'){delete message.redactions;message.type='credentialPrivacyCommit';await f.send(message);}
  assert.ok((await f.send(f.request())).error,mode);
 }
});
test('inspect is closed and read-only and cannot clear existing quiescence',async t=>{
 const f=fixture();t.after(f.close);await f.ready();const request=f.request();
 const inspected=await f.send({...request,phase:'inspect'});assert.deepEqual(Object.keys(inspected).sort(),['identity','nonce','phase','version']);assert.equal(inspected.phase,'inspected');
 assert.equal((await f.send(f.command('executor.validate',{controlLease:lease}))).validated,true);
 assert.equal((await f.send(request)).phase,'prepared');assert.ok((await f.send({...request,phase:'inspect'})).error);
 assert.equal((await f.send({...request,phase:'adopt',receiptRevision:0})).phase,'adopted');
});
test('adopt rejects changed binding, deadline, receipt revision and repeated nonce without clearing barrier',async t=>{
 for(const mode of ['binding','deadline','expired','revision']){const f=fixture();t.after(f.close);await f.ready();const request=f.request();assert.equal((await f.send(request)).phase,'prepared');
  const adopt={...request,phase:'adopt',receiptRevision:0};if(mode==='binding')adopt.newBinding={...request.newBinding,channelEpoch:'substitution'};else if(mode==='deadline')adopt.deadlineUnixMs++;else if(mode==='expired')f.w.Date.now=()=>request.deadlineUnixMs+1;else adopt.receiptRevision++;
  assert.ok((await f.send(adopt)).error,mode);assert.equal((await f.send(f.command('executor.validate',{controlLease:lease}))).error.code,'executorQuiesced');
 }
 const f=fixture();t.after(f.close);const first=f.request();await f.send(first);await f.send({...first,phase:'adopt',receiptRevision:0});
 const replay={...first,oldFence:{brokerEpoch:'broker2',channelEpoch:'channel2',scopeHash:first.oldFence.scopeHash},newBinding:{...first.newBinding,brokerEpoch:'broker3',channelEpoch:'channel3'}};
 assert.ok((await f.send(replay)).error);
});
test('production nine-key binding reconnects with unchanged qualified desktop/profile metadata',async t=>{
 for(const scope of ['desktop','profile']){
  const f=fixture();t.after(f.close);const original={...f.binding,trustScope:scope,scopeQualified:true,profileQualified:scope==='profile'};
  assert.equal((await f.send({type:'bind',binding:original})).mutationFingerprintVersion,2);
  const request=f.request();assert.equal((await f.send({...request,phase:'inspect'})).phase,'inspected');
  assert.equal((await f.send(request)).phase,'prepared');assert.equal((await f.send({...request,phase:'adopt',receiptRevision:0})).phase,'adopted');
  assert.equal((await f.send({type:'bind',binding:{...original,...request.newBinding}})).mutationFingerprintVersion,2);
 }
});
test('legacy binding requires exact qualified trust fields and new binding remains closed six-key',async t=>{
 for(const mode of ['scope','unqualified','profileMismatch','missing','extra','newExtra']){
  const f=fixture();t.after(f.close);const original={...f.binding,trustScope:'desktop',scopeQualified:true,profileQualified:false};
  if(mode==='scope')original.trustScope='other';else if(mode==='unqualified')original.scopeQualified=false;else if(mode==='profileMismatch')original.profileQualified=true;else if(mode==='missing')delete original.profileQualified;else if(mode==='extra')original.extra=true;
  await f.send({type:'bind',binding:original});const request=f.request();if(mode==='newExtra')request.newBinding.trustScope='desktop';
  assert.ok((await f.send({...request,phase:'inspect'})).error,mode);assert.ok((await f.send(request)).error,mode);
 }
});
test('equivalent binding ignores inventory display changes but retains every authority field',async t=>{
 const f=fixture();t.after(f.close);
 await f.send({type:'bind',binding:{...f.binding,identity:{...identity,origin:'https://fixture.test',title:'Before',titleTruncated:false,mutationFingerprintVersion:1}}});
 const equivalent={...f.binding,identity:{...identity,title:'After',mutationFingerprintVersion:2}};
 assert.equal((await f.send({type:'bind',binding:equivalent})).mutationFingerprintVersion,2);
 for(const changed of [{...equivalent,channelEpoch:'foreign'},{...equivalent,leaseRequired:false},{...equivalent,identity:{...equivalent.identity,documentId:'foreign'}},{...equivalent,identity:{...equivalent.identity,extraAuthority:true}}]){
  assert.equal((await f.send({type:'bind',binding:changed})).error.code,'executorNotQuiescent');
 }
});

test('same-fence legacy trust metadata upgrade preserves lease fingerprint UNKNOWN receipt and replay guard',async t=>{
 const f=fixture();t.after(f.close);await f.ready();
 let attempts=0;f.w.MechanizeDOM.act=()=>{attempts++;throw Error('PRIVATE-CANARY');};
 const command=await f.mutation(),before=(await f.w.MechanizeFingerprint.mutationV2(command)).sha256;
 const failed=await f.send(command);assert.equal(failed.error.dispatchState,'unknown');
 const prior=await f.send(f.command('receipt.query',{attemptId:command.attemptId}));
 const upgraded={...f.binding,trustScope:'desktop',scopeQualified:true,profileQualified:false};
 const result=await f.send({type:'bind',binding:upgraded});assert.equal(result.error,undefined);
 assert.equal((await f.w.MechanizeFingerprint.mutationV2(command)).sha256,before);
 assert.equal((await f.send(f.command('executor.validate',{controlLease:lease}))).validated,true);
 assert.deepEqual(await f.send(f.command('receipt.query',{attemptId:command.attemptId})),prior);
 assert.equal((await f.send(command)).error.dispatchState,'unknown');assert.equal(attempts,1);
 assert.ok(!JSON.stringify(result).includes('CANARY'));
 for(const changed of [{...upgraded,trustScope:'profile',profileQualified:true},{...upgraded,channelEpoch:'foreign'},{...upgraded,scopeHash:'c'.repeat(64)},{...upgraded,identity:{...identity,documentId:'foreign'}},{...f.binding}])assert.equal((await f.send({type:'bind',binding:changed})).error.code,'executorNotQuiescent');
});
test('additive trust migration rejects invalid metadata foreign sender and pending fingerprint before input',async t=>{
 for(const mode of ['scope','partial','profile','extra','foreignSender','changedFence','changedIdentity','pending']){
  const f=fixture();t.after(f.close);await f.ready();let calls=0;f.w.MechanizeDOM.act=()=>{calls++;throw Error('PRIVATE-CANARY');};
  const next={...f.binding,trustScope:'desktop',scopeQualified:true,profileQualified:false};let sender;
  if(mode==='scope')next.scopeQualified=false;if(mode==='partial')delete next.profileQualified;if(mode==='profile')next.profileQualified=true;if(mode==='extra')next.extra=true;if(mode==='foreignSender')sender={id:'fixture',tab:{id:7}};if(mode==='changedFence')next.brokerEpoch='foreign';if(mode==='changedIdentity')next.identity={...identity,documentId:'foreign'};
  let release,pending;
  if(mode==='pending'){const command=await f.mutation(),real=f.w.MechanizeFingerprint.mutationV2;f.w.MechanizeFingerprint={...f.w.MechanizeFingerprint,mutationV2:()=>new Promise(resolve=>{release=async()=>resolve(await real(command));})};pending=f.send(command);await new Promise(r=>setImmediate(r));}
  assert.equal((await f.send({type:'bind',binding:next},sender)).error.code,'executorNotQuiescent',mode);assert.equal(calls,0);
  if(pending){await release();await pending;assert.equal(calls,1);}
 }
});
test('legacy private-protected renderer refuses additive trust metadata without clearing privacy',async t=>{
 const f=fixture();t.after(f.close);await f.send({type:'bind',binding:f.binding});
 f.w.document.body.innerHTML='<form><input type="password"><button>Login</button></form>';
 const request={type:'credentialManualPrivacyBind',requestId:'a'.repeat(64),identity,brokerEpoch:f.binding.brokerEpoch,channelEpoch:f.binding.channelEpoch,scopeHash:f.binding.scopeHash,deadlineUnixMs:Date.now()+5000,origin:f.w.location.origin,permitId:'d'.repeat(64),redactions:f.w.MechanizeSecureInput.redactionVariants(['PRIVATE-CANARY'])};
 assert.equal((await f.send(request)).ready,false);
 assert.equal((await f.send({type:'bind',binding:{...f.binding,trustScope:'desktop',scopeQualified:true,profileQualified:false}})).error.code,'secureDocumentRequired');
 assert.equal((await f.send(f.command('observe'))).error.code,'secureDocumentRequired');assert.equal(f.w.document.querySelector('input').value,'');
});
