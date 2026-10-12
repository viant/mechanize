const {test}=require('node:test');const assert=require('node:assert/strict');const fs=require('node:fs');const path=require('node:path');const {JSDOM}=require('jsdom');
const identity={profileChannel:'p1',browserInstance:'b1',tabId:7,frameId:0,documentId:'d1',documentGeneration:1};
const binding={identity,brokerEpoch:'broker1',channelEpoch:'channel1',scopeHash:'scope1',leaseRequired:true};
function fixture(body,bind=true){
 const dom=new JSDOM(body||'<form method="post"><label>Login<input autocomplete="username"></label><label>Password<input type="password" autocomplete="current-password"></label><button>Login</button></form>',{url:'https://fixture.example.test',runScripts:'outside-only'}),w=dom.window;let listener;
 Object.defineProperty(w,'crypto',{value:require('node:crypto').webcrypto});w.TextEncoder=TextEncoder;w.HTMLElement.prototype.getClientRects=()=>[{width:100,height:20}];
 w.chrome={runtime:{id:'fixture',onMessage:{addListener:f=>listener=f}}};
 for(const file of ['protocol.js','fingerprint.js','accessibility-provider.js','dom.js','recorder.js','secure-input.js','content.js'])w.eval(fs.readFileSync(path.join(__dirname,'..',file),'utf8'));
 const send=(message,sender={id:'fixture'})=>{let result;listener(message,sender,value=>result=JSON.parse(JSON.stringify(value)));return result;};
 if(bind)send({type:'bind',binding});
 const frame=extra=>({type:'credentialDelivery',requestId:'a'.repeat(64),attemptId:'b'.repeat(64),...binding,deadlineUnixMs:Date.now()+5000,origin:w.location.origin,controlLease:{id:'lease1',generation:1},username:'USERNAME-CANARY',password:'PASSWORD-CANARY',...extra});
 const command=(action,extra={})=>({requestId:'ordinary',action,identity,brokerEpoch:binding.brokerEpoch,channelEpoch:binding.channelEpoch,scopeHash:binding.scopeHash,deadlineUnixMs:Date.now()+5000,...extra});
 const cleanFrame=extra=>{const f=frame(extra);delete f.leaseRequired;return f;};
 return{w,send,sendAsync:(message)=>new Promise(resolve=>listener(message,{id:'fixture'},value=>resolve(JSON.parse(JSON.stringify(value))))),frame:cleanFrame,command,close:()=>w.close(),acquire(){return send(command('executor.acquire',{controlLease:{id:'lease1',generation:1}}));}};
}
test('private inspect and acquire bypass no ordinary credential observation',t=>{
 const f=fixture();t.after(f.close);const probe=f.frame({type:'credentialInspect'});for(const k of ['attemptId','controlLease','username','password'])delete probe[k];
 const inspected=f.send(probe);assert.equal(inspected.ready,true);assert.deepEqual(Object.keys(inspected).sort(),['identity','privateCredentialProtocolVersion','ready','stage']);
 assert.equal(f.send(f.command('observe')).error.code,'secureDocumentRequired');assert.equal(f.acquire().validated,true);
 const result=f.send(f.frame());assert.deepEqual(result,{status:'dispatched'});assert.equal(f.w.document.querySelector('[type=password]').value,'PASSWORD-CANARY');
 assert.ok(!JSON.stringify(inspected).includes('CANARY'));assert.ok(!JSON.stringify(result).includes('CANARY'));
});

test('same-document submit status is private and promotion needs retired input plus explicit redaction commit',t=>{
 const f=fixture();t.after(f.close);let submits=0;
 f.w.document.querySelector('form').addEventListener('submit',e=>{e.preventDefault();submits++;});
 f.acquire();assert.equal(f.send(f.frame()).status,'dispatched');
 const submit=f.frame({type:'credentialSubmit',attemptId:'c'.repeat(64),fillAttemptId:'b'.repeat(64)});
 delete submit.username;delete submit.password;
 assert.equal(f.send(submit).status,'dispatched');
 const probe={...submit,type:'credentialPostSubmit'};delete probe.fillAttemptId;
 assert.equal(f.send(probe).stage,'pending');assert.equal(f.send(probe).stage,'pending');assert.equal(submits,1);
 f.w.document.querySelector('form').remove();
 f.w.document.body.innerHTML='<h1>USERNAME-CANARY</h1><h2>Invoices</h2>';
 assert.equal(f.send(probe).stage,'unavailable');
 assert.equal(f.send(f.command('observe')).error.code,'secureDocumentRequired');
 const bind={type:'credentialPrivacyBind',requestId:'d'.repeat(64),identity,brokerEpoch:binding.brokerEpoch,channelEpoch:binding.channelEpoch,scopeHash:binding.scopeHash,deadlineUnixMs:Date.now()+5000,origin:f.w.location.origin,permitId:'e'.repeat(64),redactions:f.w.MechanizeSecureInput.redactionVariants(['USERNAME-CANARY','PASSWORD-CANARY'])};
 const bound=f.send(bind);assert.equal(bound.ready,true);assert.equal(bound.privateInputRetired,true);
 assert.equal(f.send(f.command('observe')).error.code,'secureDocumentRequired');
 const commit={...bind,type:'credentialPrivacyCommit'};delete commit.redactions;
 assert.equal(f.send(commit).ready,true);
 const observed=f.send(f.command('observe'));
 assert.ok(!JSON.stringify(observed).includes('CANARY'));assert.ok(JSON.stringify(observed).includes('Invoices'));assert.equal(submits,1);
});
test('missing lease foreign sender stale generation and added selector never write',t=>{
 for(const variant of ['lease','sender','generation','selector']){
  const f=fixture();t.after(f.close);if(variant!=='lease')f.acquire();const frame=f.frame();
  if(variant==='generation')frame.identity={...identity,documentGeneration:99};if(variant==='selector')frame.selector='#private';
  const result=f.send(frame,variant==='sender'?{id:'fixture',tab:{id:8}}:undefined);
  assert.deepEqual(result,{status:'notDispatched'});assert.equal(f.w.document.querySelector('[type=password]').value,'');
 }
});
test('delivery preserves quarantine after password controls removed and never exports receipts',t=>{
 const f=fixture();t.after(f.close);f.acquire();assert.equal(f.send(f.frame()).status,'dispatched');
 f.w.document.body.innerHTML='<main>PRIVATE ACCOUNT CANARY</main>';
 for(const action of ['observe','executor.receipts','record.events','receipt.query']){
  const result=f.send(f.command(action));assert.equal(result.error.code,'secureDocumentRequired');assert.ok(!JSON.stringify(result).includes('CANARY'));
 }
});
test('page drift after first write becomes only unknown scalar',t=>{
 {
  const f=fixture();t.after(f.close);f.acquire();
  // The real receiver handles errors internally; induce page-handler navigation
  // after the first write to exercise its dispatched-unknown boundary.
  f.w.document.querySelector('[autocomplete=username]').addEventListener('input',()=>f.w.document.querySelector('[type=password]').remove());
  const result=f.send(f.frame());assert.deepEqual(result,{status:'unknown'});assert.ok(!JSON.stringify(result).includes('CANARY'));
 }
});
test('fresh inspector requires held lease and unchanged DOM generation',t=>{
 for(const mode of ['ready','wrongLease','changedGeneration','absentLease']){
  const f=fixture();t.after(f.close);if(mode!=='absentLease')f.acquire();
  const probe=f.frame({type:'credentialInspect'});for(const key of ['attemptId','username','password'])delete probe[key];
  if(mode==='wrongLease')probe.controlLease={id:'other',generation:1};
  if(mode==='changedGeneration')f.w.document.body.setAttribute('data-changed','yes');
  const result=f.send(probe);assert.equal(result.ready,mode==='ready');
  assert.deepEqual(Object.keys(result).sort(),['identity','privateCredentialProtocolVersion','ready','stage']);assert.equal(f.w.document.querySelector('[type=password]').value,'');
 }
});

test('redaction covers credential raw and common encodings while preserving safe structured text',t=>{
 const f=fixture('<p>History</p>',false);t.after(f.close);
 const variants=f.w.MechanizeSecureInput.redactionVariants(['u<& name','sensitive-password']);
 for(const encoded of ['u<& name','u%3C%26%20name','u&lt;&amp; name',Buffer.from('sensitive-password').toString('base64'),'SENSITIVE-PASSWORD']){
 const result=f.w.MechanizeSecureInput.redact({text:'prefix '+encoded+' suffix',safe:'Invoice 123.45',nested:[{value:encoded}]},variants);
 assert.equal(result.text,'[redacted]');assert.equal(result.nested[0].value,'[redacted]');assert.equal(result.safe,'Invoice 123.45');
 }
});
test('login binder requires explicit commit then uses field redaction without blocking the page',t=>{
 const f=fixture('<h1 id="username">USERNAME-CANARY</h1><input type="hidden" name="csrf-token" value="session-token"><h2>Invoice 123.45</h2><button id="safe">Open details</button>',false);t.after(f.close);
 const redactions=f.w.MechanizeSecureInput.redactionVariants(['USERNAME-CANARY','PASSWORD-CANARY']);
 const request={type:'credentialPrivacyBind',requestId:'a'.repeat(64),identity,...{brokerEpoch:binding.brokerEpoch,channelEpoch:binding.channelEpoch,scopeHash:binding.scopeHash},deadlineUnixMs:Date.now()+5000,origin:f.w.location.origin,permitId:'b'.repeat(64),redactions};
 const bound=f.send(request);assert.equal(bound.ready,true);assert.equal(bound.redactionReady,true);assert.equal(bound.privateInputRetired,true);
 assert.equal(f.send(f.command('observe')).error.code,'secureDocumentRequired');
 const commit={...request,type:'credentialPrivacyCommit'};delete commit.redactions;assert.equal(f.send(commit).ready,true);
 const observed=f.send(f.command('observe'));assert.ok(!JSON.stringify(observed).includes('CANARY'));assert.ok(JSON.stringify(observed).includes('123.45'));
 const input=f.w.document.createElement('input');input.type='password';input.value='NEW-PASSWORD-CANARY';f.w.document.body.append(input);
 const after=f.send(f.command('observe'));assert.equal(after.error,undefined);assert.ok(!JSON.stringify(after).includes('CANARY'));assert.ok(JSON.stringify(after).includes('[redacted]'));assert.ok(JSON.stringify(after).includes('123.45'));
});

test('qualified redacted DOM permits an ordinary v2 click while retaining private input retirement',async t=>{
 const f=fixture('<h1>USERNAME-CANARY</h1><button id="details">Open details</button>',false);t.after(f.close);let clicks=0;
 f.w.document.querySelector('#details').addEventListener('click',()=>clicks++);
 const scopeHash='a'.repeat(64),request={type:'credentialPrivacyBind',requestId:'a'.repeat(64),identity,brokerEpoch:binding.brokerEpoch,channelEpoch:binding.channelEpoch,scopeHash,deadlineUnixMs:Date.now()+5000,origin:f.w.location.origin,permitId:'b'.repeat(64),redactions:f.w.MechanizeSecureInput.redactionVariants(['USERNAME-CANARY','PASSWORD-CANARY'])};
 assert.equal(f.send(request).ready,true);const commit={...request,type:'credentialPrivacyCommit'};delete commit.redactions;assert.equal(f.send(commit).ready,true);
 const lease={id:'ordinary-safe-lease',generation:2};assert.equal(f.send(f.command('executor.acquire',{scopeHash,controlLease:lease})).validated,true);
 const command=f.command('element.press',{scopeHash,controlLease:lease,attemptId:'c'.repeat(64),locator:{strategy:'id',value:'details',exact:true},fingerprintVersion:2});
 command.fingerprintSHA256=(await f.w.MechanizeFingerprint.mutationV2(command)).sha256;
 const result=await f.sendAsync(command);assert.equal(result.dispatchState,'dispatched');assert.equal(clicks,1);assert.ok(!JSON.stringify(result).includes('CANARY'));
 const proof=f.send({...commit,type:'credentialPrivacyInspect',requestId:'d'.repeat(64)});assert.equal(proof.ready,true);assert.equal(proof.privateInputRetired,true);assert.equal(proof.redactionReady,true);
});

test('private DOM redaction happens before bounded text truncation',t=>{
 const secret='long-private-'+ 'X'.repeat(300),f=fixture(`<h1>${secret}</h1><h2>Safe amount 42</h2>`,false);t.after(f.close);
 const request={type:'credentialPrivacyBind',requestId:'a'.repeat(64),identity,brokerEpoch:binding.brokerEpoch,channelEpoch:binding.channelEpoch,scopeHash:binding.scopeHash,deadlineUnixMs:Date.now()+5000,origin:f.w.location.origin,permitId:'b'.repeat(64),redactions:f.w.MechanizeSecureInput.redactionVariants(['username-fixture',secret])};
 assert.equal(f.send(request).ready,true);delete request.redactions;request.type='credentialPrivacyCommit';assert.equal(f.send(request).ready,true);
 const snapshot=JSON.stringify(f.send(f.command('observe')));assert.ok(!snapshot.includes('long-private'));assert.ok(snapshot.includes('Safe amount 42'));
});

test('unrelated DOM updates invalidate whole-page generation before credential delivery',async t=>{
 const f=fixture('<p id="decoration">Initial</p><form method="post"><label>Login<input autocomplete="username"></label><label>Password<input type="password" autocomplete="current-password"></label><button>Login</button></form>');t.after(f.close);
 const probe=f.frame({type:'credentialInspect'});for(const key of ['attemptId','controlLease','username','password'])delete probe[key];
 const initial=f.send(probe);assert.equal(initial.ready,true);assert.equal(f.acquire().validated,true);
 const fresh={...probe,identity:{...initial.identity},controlLease:{id:'lease1',generation:1}};
 assert.equal(f.send(fresh).ready,true);
 f.w.document.querySelector('#decoration').textContent='Updated marketing text';
 await new Promise(resolve=>setImmediate(resolve));
 const refused=f.send(fresh);
 assert.equal(refused.ready,false);assert.ok(refused.identity.documentGeneration>initial.identity.documentGeneration);
 assert.equal(f.w.document.querySelector('[autocomplete=username]').value,'');
 assert.equal(f.w.document.querySelector('[type=password]').value,'');
 assert.ok(!JSON.stringify(refused).includes('CANARY'));
});

test('pinned recipient permits unrelated DOM drift but refuses replaced input before any write',async t=>{
 for(const changed of [false,true]){
  const f=fixture('<p id="decoration">Initial</p><form method="post"><input autocomplete="username"><input type="password" autocomplete="current-password"><button>Login</button></form>');t.after(f.close);
  const recipientId='f'.repeat(64),probe=f.frame({type:'credentialInspect',recipientId});for(const key of ['attemptId','controlLease','username','password'])delete probe[key];
  const initial=f.send(probe);assert.equal(initial.ready,true);assert.equal(initial.privateCredentialProtocolVersion,3);assert.equal(initial.recipientId,recipientId);
  assert.equal(f.acquire().validated,true);
  const fresh={...probe,controlLease:{id:'lease1',generation:1}};
  f.w.document.querySelector('#decoration').textContent='Updated decoration';
  if(changed){const input=f.w.document.querySelector('[autocomplete=username]');input.replaceWith(input.cloneNode(true));}
  await new Promise(resolve=>setImmediate(resolve));
  const checked=f.send(fresh);assert.equal(checked.ready,!changed);assert.ok(checked.identity.documentGeneration>initial.identity.documentGeneration);
  const filled=f.send(f.frame({recipientId}));
  assert.equal(filled.status,changed?'notDispatched':'dispatched');
  assert.equal(f.w.document.querySelector('[type=password]').value,changed?'':'PASSWORD-CANARY');
  assert.ok(!JSON.stringify(checked).includes('CANARY'));
 }
});

test('recipient nonce cannot authorize another form or legacy generation bypass',async t=>{
 for(const mode of ['wrongNonce','unissuedNonce','legacy']){
  const f=fixture();t.after(f.close);
  const recipientId='f'.repeat(64),probe=f.frame({type:'credentialInspect',recipientId});for(const key of ['attemptId','controlLease','username','password'])delete probe[key];
  if(mode!=='unissuedNonce')assert.equal(f.send(probe).ready,true);
  f.acquire();f.w.document.body.append(f.w.document.createElement('p'));await new Promise(resolve=>setImmediate(resolve));
  const frame=mode==='legacy'?f.frame():f.frame({recipientId:mode==='wrongNonce'?'e'.repeat(64):recipientId});
  assert.equal(f.send(frame).status,'notDispatched');assert.equal(f.w.document.querySelector('[type=password]').value,'');
 }
});

test('pinned fill permits the same submitter to enable after input without accepting recipient drift',t=>{
 for(const mode of ['enable','actionChange','replaceButton','enableBeforeDelivery']){
  const f=fixture('<form method="post"><input autocomplete="username"><input type="password" autocomplete="current-password"><button disabled aria-disabled="true">Login</button></form>');t.after(f.close);
  const recipientId='f'.repeat(64),probe=f.frame({type:'credentialInspect',recipientId});for(const key of ['attemptId','controlLease','username','password'])delete probe[key];
  assert.equal(f.send(probe).ready,true);assert.equal(f.acquire().validated,true);
  if(mode==='enableBeforeDelivery'){
   const button=f.w.document.querySelector('button');button.disabled=false;button.setAttribute('aria-disabled','false');
  }
  f.w.document.querySelector('[autocomplete=username]').addEventListener('input',()=>{
   const button=f.w.document.querySelector('button');button.disabled=false;button.setAttribute('aria-disabled','false');
   if(mode==='actionChange')button.setAttribute('formaction','/different-recipient');
   if(mode==='replaceButton')button.replaceWith(button.cloneNode(true));
  });
  const result=f.send(f.frame({recipientId}));
  assert.equal(result.status,mode==='enable'?'dispatched':mode==='enableBeforeDelivery'?'notDispatched':'unknown');
  assert.equal(f.w.document.querySelector('[type=password]').value,mode==='enable'?'PASSWORD-CANARY':'');
  assert.ok(!JSON.stringify(result).includes('CANARY'));
 }
});
test('post-submit outer validation failures cannot impersonate a privacy candidate',t=>{
 const f=fixture();t.after(f.close);let submits=0;
 f.w.document.querySelector('form').addEventListener('submit',event=>{event.preventDefault();submits++;});
 f.acquire();assert.equal(f.send(f.frame()).status,'dispatched');
 const submit=f.frame({type:'credentialSubmit',attemptId:'c'.repeat(64),fillAttemptId:'b'.repeat(64)});delete submit.username;delete submit.password;
 assert.equal(f.send(submit).status,'dispatched');assert.equal(submits,1);
 f.w.document.body.innerHTML='<h1>USERNAME-CANARY</h1><h2>Fixture invoices</h2>';
 const probe={...submit,type:'credentialPostSubmit'};delete probe.fillAttemptId;
 assert.equal(f.send(probe).stage,'unavailable'); // A validated readiness proof.
 for(const mode of ['foreignFence','retiredLease','foreignSender','expired']){
  const invalid=structuredClone(probe);let sender;
  if(mode==='foreignFence')invalid.channelEpoch='foreign-channel';
  if(mode==='retiredLease')invalid.controlLease={id:'foreign-lease',generation:1};
  if(mode==='foreignSender')sender={id:'fixture',tab:{id:7}};
  if(mode==='expired')invalid.deadlineUnixMs=Date.now()-1;
  const result=f.send(invalid,sender);assert.equal(result.stage,'pending',mode);assert.equal(result.ready,false);assert.equal(result.privateCredentialProtocolVersion,2);assert.ok(!JSON.stringify(result).includes('CANARY'));assert.equal(submits,1);
 }
 assert.equal(f.send(probe).stage,'unavailable');assert.equal(submits,1);
 assert.equal(f.send(f.command('observe')).error.code,'secureDocumentRequired');
});
test('committed same-document redactor refresh needs no login submit and still requires a new explicit commit',t=>{
 const f=fixture('<h1>USERNAME-CANARY</h1><h2>Public fixture</h2>',false);t.after(f.close);
 const request={type:'credentialPrivacyBind',requestId:'a'.repeat(64),identity,brokerEpoch:binding.brokerEpoch,channelEpoch:binding.channelEpoch,scopeHash:binding.scopeHash,deadlineUnixMs:Date.now()+5000,origin:f.w.location.origin,permitId:'b'.repeat(64),redactions:f.w.MechanizeSecureInput.redactionVariants(['USERNAME-CANARY','PASSWORD-CANARY'])};
 assert.equal(f.send(request).ready,true);const commit={...request,type:'credentialPrivacyCommit'};delete commit.redactions;assert.equal(f.send(commit).ready,true);
 const refresh={...request,requestId:'c'.repeat(64),permitId:'d'.repeat(64)};assert.equal(f.send(refresh).ready,true);assert.equal(f.send(f.command('observe')).error.code,'secureDocumentRequired');
 const renewed={...refresh,type:'credentialPrivacyCommit'};delete renewed.redactions;assert.equal(f.send(renewed).ready,true);assert.ok(!JSON.stringify(f.send(f.command('observe'))).includes('CANARY'));
 for(const changed of [{channelEpoch:'foreign'},{redactions:['replacement-redactor']},{origin:'https://foreign.example.test'}])assert.equal(f.send({...refresh,...changed,permitId:'e'.repeat(64)}).ready,false);
});
test('returning login fields never qualify as a committed public redactor refresh',t=>{
 const f=fixture('<h2>Public fixture</h2>',false);t.after(f.close);
 const request={type:'credentialPrivacyBind',requestId:'a'.repeat(64),identity,brokerEpoch:binding.brokerEpoch,channelEpoch:binding.channelEpoch,scopeHash:binding.scopeHash,deadlineUnixMs:Date.now()+5000,origin:f.w.location.origin,permitId:'b'.repeat(64),redactions:f.w.MechanizeSecureInput.redactionVariants(['USERNAME-CANARY','PASSWORD-CANARY'])};
 assert.equal(f.send(request).ready,true);const commit={...request,type:'credentialPrivacyCommit'};delete commit.redactions;assert.equal(f.send(commit).ready,true);
 f.w.document.body.innerHTML='<form><input autocomplete="username"><input type="password"><button>Login</button></form>';
 assert.equal(f.send(f.command('observe')).error.code,'secureDocumentRequired');
 assert.equal(f.send({...request,permitId:'c'.repeat(64)}).ready,false);assert.equal(f.send(f.command('observe')).error.code,'secureDocumentRequired');assert.equal(f.w.document.querySelector('[type=password]').value,'');
});

test('same recipient pre-input inspection retry retains target proof across decoration and refuses replacement or route drift',async t=>{
 for(const mode of ['decoration','replacement','route','challenge']){
  const f=fixture();t.after(f.close);const probe=f.frame({type:'credentialInspect',recipientId:'f'.repeat(64)});for(const key of ['attemptId','controlLease','username','password'])delete probe[key];assert.equal(f.send(probe).ready,true);
  f.w.document.body.append(f.w.document.createElement('aside'));
  if(mode==='replacement'){const input=f.w.document.querySelector('[autocomplete=username]');input.replaceWith(input.cloneNode(true));}
  if(mode==='route')f.w.document.querySelector('form').action='/changed';
  if(mode==='challenge')f.w.document.body.append(Object.assign(f.w.document.createElement('p'),{textContent:'Enter verification code'}));
  await new Promise(resolve=>setImmediate(resolve));const stale=f.acquire();assert.equal(stale.error.code,'staleGeneration');
  const current=f.send(probe);assert.equal(current.ready,mode==='decoration',mode);
  if(current.ready)assert.equal(f.send(f.command('executor.acquire',{identity:current.identity,controlLease:{id:'lease1',generation:1}})).validated,true);
  assert.equal(f.w.document.querySelector('[type=password]').value,'');
 }
});

test('fresh manual redactor qualification is separate from login and grants no input lease',t=>{
 const f=fixture('<main>USERNAME-CANARY PASSWORD-CANARY public report</main>',false);t.after(f.close);
 const seed=f.frame({type:'credentialManualPrivacyBind',permitId:'e'.repeat(64),redactions:f.w.MechanizeSecureInput.redactionVariants(['USERNAME-CANARY','PASSWORD-CANARY'])});for(const key of ['attemptId','controlLease','username','password'])delete seed[key];
 const prepared=f.send(seed);assert.equal(prepared.ready,true);assert.equal(prepared.privateInputRetired,true);assert.equal(f.send(f.command('observe')).error.code,'secureDocumentRequired');
 const commit={...seed,type:'credentialManualPrivacyCommit',identity:prepared.identity};delete commit.redactions;assert.equal(f.send(commit).ready,true);
 const observed=f.send(f.command('observe',{identity:prepared.identity}));assert.ok(!JSON.stringify(observed).includes('CANARY'));
 const mutation=f.send(f.command('element.press',{identity:prepared.identity,attemptId:'no-inherited-lease',locator:{strategy:'id',value:'absent'}}));assert.equal(mutation.error.code,'staleAuthority');
});
test('manual redactor refuses login/challenge documents and preexisting input authority',t=>{
 for(const mode of ['login','challenge','lease']){
  const f=fixture(mode==='login'?undefined:mode==='challenge'?'<p>Enter verification code</p>':'<main>Public report</main>',mode==='lease');t.after(f.close);if(mode==='lease')f.acquire();
  const seed=f.frame({type:'credentialManualPrivacyBind',permitId:'e'.repeat(64),redactions:['PRIVATE-CANARY']});for(const key of ['attemptId','controlLease','username','password'])delete seed[key];
  assert.equal(f.send(seed).ready,false,mode);assert.ok(!JSON.stringify(f.send(f.command('observe'))).includes('PRIVATE-CANARY'));
 }
});
test('negotiated inspection causes distinguish binding, form, submitter and retained input without page text',t=>{
 for(const mode of ['ready','binding','fields','submitter','challenge','retained']){
  const f=fixture();t.after(f.close);let probe=f.frame({type:'credentialInspect',recipientId:'f'.repeat(64),diagnostics:true});for(const k of ['attemptId','controlLease','username','password'])delete probe[k];
  if(mode==='binding')probe.channelEpoch='other';if(mode==='fields')f.w.document.body.innerHTML='<p>PRIVATE-CANARY</p>';if(mode==='submitter')f.w.document.querySelector('form').append(f.w.document.createElement('button'));if(mode==='challenge')f.w.document.body.innerHTML='<p>Enter verification code PRIVATE-CANARY</p>';if(mode==='retained'){f.acquire();assert.equal(f.send(f.frame()).status,'dispatched');}
  const result=f.send(probe);assert.equal(result.inspectionReason,({ready:'none',binding:'documentBindingUnavailable',fields:'noCredentialFields',submitter:'ambiguousSubmitter',challenge:'noCredentialFields',retained:'privateInputRetained'})[mode]);assert.equal(result.ready,mode==='ready');assert.ok(!JSON.stringify(result).includes('CANARY'));
 }
});
test('fixed inspector diagnostics identify value-free form predicates without changing admission',t=>{
 const cases={
  noCredentialFields:'<form><button>Login</button></form>',
  missingForm:'<input autocomplete="username" value="PRIVATE-CANARY">',
  ambiguousPasswordFields:'<form><input type="password"><input type="password"><button>Login</button></form>',
  hiddenChallengeControl:'<form><input autocomplete="username"><input type="hidden" name="otp" value="PRIVATE-CANARY"><button>Login</button></form>',
  visibleChallengeControl:'<form><input autocomplete="username"><input autocomplete="one-time-code"><button>Login</button></form>',
  unsafeFormTarget:'<form target="_blank"><input autocomplete="username"><button>Login</button></form>',
  ambiguousSubmitter:'<form><input autocomplete="username"><button>Login</button><button>Other</button></form>',
  unsafeSubmitter:'<form><input autocomplete="username"><button formaction="https://foreign.invalid/private">Login</button></form>'
 };
 for(const [reason,html] of Object.entries(cases)){const f=fixture(html);t.after(f.close);assert.equal(f.w.MechanizeSecureInput.inspectionReason(f.w.document,f.w.location.origin),reason);assert.equal(f.w.MechanizeSecureInput.inspect(f.w.document,f.w.location.origin,()=>true).ready,false);assert.ok(!reason.includes('CANARY'));}
});

test('failed privacy refresh retains exact committed evidence but never restores output before fresh commit',t=>{
 for(const mode of ['login','challenge']){
  const f=fixture('<h1>USERNAME-CANARY</h1><h2>Records</h2>',false);t.after(f.close);
  const request={type:'credentialPrivacyBind',requestId:'a'.repeat(64),identity,brokerEpoch:binding.brokerEpoch,channelEpoch:binding.channelEpoch,scopeHash:binding.scopeHash,deadlineUnixMs:Date.now()+5000,origin:f.w.location.origin,permitId:'b'.repeat(64),redactions:f.w.MechanizeSecureInput.redactionVariants(['USERNAME-CANARY','PASSWORD-CANARY'])};
  const commit=q=>{const c={...q,type:'credentialPrivacyCommit'};delete c.redactions;return c};
  assert.equal(f.send(request).ready,true);assert.equal(f.send(commit(request)).ready,true);
  f.w.document.body.innerHTML=mode==='login'?'<form><input autocomplete=username><input type=password><button>Login</button></form>':'<p>Enter verification code</p>';
  assert.equal(f.send(f.command('observe')).error.code,'secureDocumentRequired');
  const refresh={...request,permitId:'c'.repeat(64)};assert.equal(f.send(refresh).ready,false);assert.equal(f.send(f.command('observe')).error.code,'secureDocumentRequired');
  f.w.document.body.innerHTML='<h1>USERNAME-CANARY</h1><p>PASSWORD-CANARY</p><h2>Recovered records</h2>';
  assert.equal(f.send(f.command('observe')).error.code,'secureDocumentRequired');
  for(const invalid of [{channelEpoch:'foreign'},{identity:{...identity,documentId:'foreign'}},{redactions:['WRONG']}])assert.equal(f.send({...refresh,...invalid}).ready,false);
  assert.equal(f.send(refresh).ready,true);assert.equal(f.send(f.command('observe')).error.code,'secureDocumentRequired');assert.equal(f.send(commit(refresh)).ready,true);
  const out=f.send(f.command('observe'));assert.equal(out.error,undefined);assert.ok(!JSON.stringify(out).includes('CANARY'));
 }
});
test('fresh-document layout refusal does not leave a partial private binding that blocks later safe qualification',t=>{
 const f=fixture('<form><input type=password><button>Login</button></form>',false);t.after(f.close);
 const request={type:'credentialPrivacyBind',requestId:'a'.repeat(64),identity,brokerEpoch:binding.brokerEpoch,channelEpoch:binding.channelEpoch,scopeHash:binding.scopeHash,deadlineUnixMs:Date.now()+5000,origin:f.w.location.origin,permitId:'b'.repeat(64),redactions:f.w.MechanizeSecureInput.redactionVariants(['USERNAME-CANARY','PASSWORD-CANARY'])};
 assert.equal(f.send(request).ready,false);assert.equal(f.send(f.command('observe')).error.code,'secureDocumentRequired');
 f.w.document.body.innerHTML='<h1>USERNAME-CANARY</h1><h2>Safe records</h2>';assert.equal(f.send(request).ready,true);
 const commit={...request,type:'credentialPrivacyCommit'};delete commit.redactions;assert.equal(f.send(commit).ready,true);assert.ok(!JSON.stringify(f.send(f.command('observe'))).includes('CANARY'));
});
