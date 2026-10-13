const {test}=require('node:test'),assert=require('node:assert/strict'),fs=require('node:fs');
const base=require('node:path').resolve(__dirname,'..');
const {JSDOM}=require(base+'/node_modules/jsdom');
function fixture(html){const dom=new JSDOM(html,{url:'https://bank.example/login',runScripts:'outside-only'}),w=dom.window;w.TextEncoder=TextEncoder;Object.defineProperty(w.crypto,"subtle",{value:require("node:crypto").webcrypto.subtle});w.HTMLElement.prototype.getClientRects=function(){return [{width:100,height:20}]};for(const f of ['protocol.js','accessibility-provider.js'])w.eval(fs.readFileSync(base+'/'+f,'utf8'));w.eval(fs.readFileSync(base+'/dom.js','utf8'));return {w,doc:w.document,api:w.MechanizeDOM};}
test('metadata classification never reads values and rejects login and error',()=>{
 for(const html of ['<input type=password value=CANARY>','<input autocomplete=username value=CANARY>','<h1>nie możemy Cię zalogować</h1>','<h1>Login failed</h1>']){
 const f=fixture(html);for(const input of f.doc.querySelectorAll('input'))Object.defineProperty(input,'value',{get(){throw Error('value read')}});
 const c=f.api.credentialLayout(f.doc);assert.notEqual(c.state,'public');assert.ok(!JSON.stringify(c).includes('CANARY'));f.w.close();}
});
test('same-document login to dashboard fresh scope sanitizes retained hidden credentials; no scope means no bypass',()=>{
 const f=fixture('<input type=password value=PASSWORD-CANARY><input autocomplete=username value=USER-CANARY>');
 assert.throws(()=>f.api.snapshot(f.doc));
 f.doc.querySelectorAll('input').forEach(el=>el.hidden=true);f.doc.body.insertAdjacentHTML('beforeend','<h1>Dashboard</h1><button>History</button>');f.w.history.replaceState(null,'','/history');
 assert.equal(f.api.credentialLayout(f.doc).state,'public');assert.throws(()=>f.api.snapshot(f.doc));assert.throws(()=>f.api.withCredentialScope(f.doc,()=>false,()=>f.api.snapshot(f.doc)));
 const result=f.api.withCredentialScope(f.doc,()=>true,()=>f.api.snapshot(f.doc));const encoded=JSON.stringify(result);assert.ok(encoded.includes('History'));assert.ok(!encoded.includes('PASSWORD-CANARY'));assert.ok(!encoded.includes('USER-CANARY'));
 assert.throws(()=>f.api.snapshot(f.doc));f.w.close();
});
test('classification never outlives guard or dynamic return to login',()=>{
 const f=fixture('<h1>History</h1>');let current=true;
 assert.throws(()=>f.api.withCredentialScope(f.doc,()=>current,()=>{current=false;return f.api.snapshot(f.doc)}));
 assert.throws(()=>f.api.withCredentialScope(f.doc,()=>true,()=>{f.doc.body.insertAdjacentHTML('beforeend','<input type=password value=CANARY>');return f.api.snapshot(f.doc)}));f.w.close();
});

test('route evidence is URL-value-free and rechecks authority and URL after hashing',async()=>{
 const f=fixture('<h1>History</h1>');f.w.history.replaceState(null,'','/history?secret=QUERY-CANARY#FRAGMENT-CANARY');
 const proof=await f.api.credentialScopeEvidence(f.doc,()=>true);assert.equal(proof.public,true);assert.equal(proof.routeSHA256,require('node:crypto').createHash('sha256').update('https://bank.example/history').digest('hex'));assert.ok(!JSON.stringify(proof).includes('CANARY'));assert.ok(!JSON.stringify(proof).includes('/history'));
 let reads=0;assert.equal((await f.api.credentialScopeEvidence(f.doc,()=>++reads===1)).public,false);
 reads=0;const changed=await f.api.credentialScopeEvidence(f.doc,()=>{if(++reads===2)f.w.history.replaceState(null,'','/login');return true});assert.equal(changed.public,false);f.w.close();
});

test('public scope redacts non-login secret controls and descendant text without whole-page denial',()=>{
 const f=fixture('<h1>History</h1><input hidden type=password value=HIDDEN-CANARY><textarea aria-label="API key">KEY-CANARY</textarea><p id=parent>Public <span data-mechanize-secret>REFLECTED-CANARY</span> text</p>');
 assert.equal(f.api.credentialLayout(f.doc).state,'public');
 const output=f.api.withCredentialScope(f.doc,()=>true,()=>({snapshot:f.api.snapshot(f.doc),text:f.api.act(f.doc,'read',{strategy:'id',value:'parent'},{attribute:'text'}),value:f.api.act(f.doc,'read',{strategy:'css',value:'textarea'},{attribute:'value'})}));
 assert.ok(!JSON.stringify(output).includes('CANARY'));assert.equal(output.value.value,'[redacted]');assert.equal(output.text.value,'Public text');f.w.close();
});
async function contentFixture(){
 const f=fixture('<form><input type=password value=PASSWORD-CANARY><input autocomplete=username value=USERNAME-CANARY></form>');let receive;
 f.w.chrome={runtime:{id:'fixture',onMessage:{addListener(fn){receive=fn}}}};
 for(const file of ['secure-input.js','recorder.js'])f.w.eval(fs.readFileSync(base+'/'+file,'utf8'));
 f.w.eval(fs.readFileSync(base+'/content.js','utf8'));
 const identity={profileChannel:'profile',browserInstance:'browser',tabId:7,frameId:0,documentId:'doc',documentGeneration:1};
 const common={requestId:'a'.repeat(64),identity,brokerEpoch:'broker',channelEpoch:'channel',scopeHash:'b'.repeat(64),deadlineUnixMs:Date.now()+4000,origin:'https://bank.example'};
 const send=(message,sender={id:'fixture',url:'chrome-extension://fixture/worker.js'})=>new Promise(resolve=>receive(message,sender,resolve));
 return {...f,common,send};
}
test('actual content scope admits sanitized SPA observation while original private lease remains unavailable for reuse',async()=>{
 const f=await contentFixture();
 const initial=await f.send({...f.common,type:'credentialBind',controlLease:{id:'c'.repeat(32),generation:1}});assert.equal(initial.ready,false); // Missing safe submitter; private identity/lease still retained.
 f.doc.querySelectorAll('input').forEach(el=>el.hidden=true);f.doc.body.insertAdjacentHTML('beforeend','<h1>History</h1>');f.w.history.replaceState(null,'','/history');
 const proof=await f.send({...f.common,type:'credentialPublicScope',redactions:[]});assert.equal(proof.publicDocument.public,true);
 const command={requestId:'ordinary',action:'observe',identity:proof.publicDocument.identity,brokerEpoch:f.common.brokerEpoch,channelEpoch:f.common.channelEpoch,scopeHash:f.common.scopeHash,deadlineUnixMs:Date.now()+3000,args:{limit:100}};
 const observed=await f.send(command);assert.equal(observed.error,undefined);assert.ok(JSON.stringify(observed).includes('History'));assert.ok(!JSON.stringify(observed).includes('CANARY'));
 const acquire=await f.send({...command,action:'executor.acquire',controlLease:{id:'d'.repeat(32),generation:2}});assert.equal(acquire.error.code,'secureDocumentRequired');
 f.doc.querySelector('input').hidden=false;const stale=await f.send(command);assert.equal(stale.error.code,'secureDocumentRequired');f.w.close();
});
test('content scope rejects foreign binding and expired proof without changing private authority',async()=>{
 const f=await contentFixture();await f.send({...f.common,type:'credentialBind',controlLease:{id:'c'.repeat(32),generation:1}});
 f.doc.body.innerHTML='<h1>History</h1>';
 for(const change of [{brokerEpoch:'foreign'},{identity:{...f.common.identity,documentId:'foreign'}},{deadlineUnixMs:Date.now()-1}]){
  const proof=await f.send({...f.common,type:'credentialPublicScope',redactions:[],...change});assert.equal(proof.publicDocument,null);
 }
 f.w.close();
});

test('filled private source needs known-value redaction and cannot export reflected password in same-document dashboard',async()=>{
 const f=await contentFixture();f.doc.querySelector('form').setAttribute('method','post');f.doc.querySelector('form').insertAdjacentHTML('beforeend','<button>Login</button>');
 const lease={id:'c'.repeat(32),generation:1};const bound=await f.send({...f.common,type:'credentialBind',controlLease:lease});assert.equal(bound.ready,true);
 const inspected=await f.send({...f.common,type:'credentialInspect',controlLease:lease});assert.ok(inspected.identity.documentGeneration>0);
 const filled=await f.send({...f.common,type:'credentialDelivery',identity:inspected.identity,controlLease:lease,attemptId:'e'.repeat(64),username:'USER-REFLECTED-CANARY',password:'PASSWORD-REFLECTED-CANARY'});assert.equal(filled.status,'dispatched');
 f.doc.querySelectorAll('input').forEach(el=>el.hidden=true);f.doc.body.insertAdjacentHTML('beforeend','<h1>History</h1><h2>PASSWORD-REFLECTED-CANARY</h2>');
 const denied=await f.send({...f.common,type:'credentialPublicScope',redactions:[]});assert.equal(denied.publicDocument,null);
 const redactions=f.w.MechanizeSecureInput.redactionVariants(['USER-REFLECTED-CANARY','PASSWORD-REFLECTED-CANARY']);
 const proof=await f.send({...f.common,type:'credentialPublicScope',redactions});assert.equal(proof.publicDocument.public,true);
 const observed=await f.send({requestId:'observe',action:'observe',identity:proof.publicDocument.identity,brokerEpoch:f.common.brokerEpoch,channelEpoch:f.common.channelEpoch,scopeHash:f.common.scopeHash,deadlineUnixMs:Date.now()+3000,args:{limit:100}});
 assert.equal(observed.error,undefined);assert.ok(!JSON.stringify(observed).includes('CANARY'));assert.ok(JSON.stringify(observed).includes('History'));f.w.close();
});
test('existing scope transport validates public proof against fresh Chrome URL/doc metadata without retiring old source',async()=>{
 global.crypto=require('node:crypto').webcrypto;const {create}=require(base+'/protection-scopes.js');
 const i={profileChannel:'p',browserInstance:'b',tabId:7,frameId:0,documentId:'original',documentGeneration:3};let url='https://bank.example/history',doc='original',mode='ok',writes=0;
 const api={tabs:{query:async()=>[{id:7,url,status:'complete'}]},webNavigation:{getAllFrames:async()=>[{frameId:0,documentId:doc,url}]},storage:{local:{set:async()=>{writes++}}}};
 const q={type:'credentialScope',mode:'publicRead',requestId:'a'.repeat(64),preparationId:'0'.repeat(64),sourceIdentity:{...i,documentId:'',documentGeneration:0},sourceOrigin:'https://bank.example',loginRouteSHA256:'',brokerEpoch:'broker',channelEpoch:'channel',scopeHash:'b'.repeat(64),deadlineUnixMs:Date.now()+4000,targetTabId:7,targetOrigin:'https://bank.example'};
 const scopes=create(api,()=>i,async()=>{const proof={version:1,public:true,identity:i,routeSHA256:require('node:crypto').createHash('sha256').update(url).digest('hex')};if(mode==='doc')doc='replacement';if(mode==='url')url='https://bank.example/login';if(mode==='foreign')proof.identity={...i,documentId:'foreign'};if(mode==='unqualified')proof.extra=true;return proof;});
 const accepted=await scopes.respond(q,()=>{},()=>false);assert.equal(accepted.ready,true);assert.equal(accepted.targetIdentity,null);
 for(const bad of ['doc','url','foreign','unqualified']){mode=bad;doc='original';url='https://bank.example/history';assert.equal((await scopes.respond(q,()=>{},()=>false)).ready,false,bad);}
 assert.equal(writes,0);assert.equal(scopes.records().length,0);
});

test('large generic history has independent credential coverage and bounded snapshot output',()=>{
 const f=fixture('<h1>History</h1>'+'<div>History item</div>'.repeat(5000));
 const started=performance.now();assert.equal(f.api.credentialLayout(f.doc).state,'public');
 console.log(`5000-item metadata classification: ${(performance.now()-started).toFixed(1)} ms`);
 const snapshot=f.api.withCredentialScope(f.doc,()=>true,()=>f.api.snapshot(f.doc,{limit:10}));assert.ok(snapshot.nodes.length<=10);assert.equal(snapshot.truncated,true);
 f.w.close();
});

test('credential controls and login errors late in large light and open shadow trees remain protected',()=>{
 for(const html of ['<input type=password value=CANARY>','<input autocomplete=username value=CANARY>','<h1>Login failed</h1>'])for(const shadow of [false,true]){
  const f=fixture('<h1>History</h1>'+'<div>Row</div>'.repeat(5000)+'<section id=late></section>');
  const root=shadow?f.doc.querySelector('#late').attachShadow({mode:'open'}):f.doc.querySelector('#late');root.innerHTML=html;
  for(const input of root.querySelectorAll('input'))Object.defineProperty(input,'value',{get(){throw Error('value read')}});
  assert.equal(f.api.credentialLayout(f.doc).state,'login');f.w.close();
 }
});
test('exhausted metadata coverage or unavailable traversal never becomes public',()=>{
 const f=fixture('<div></div>'.repeat(20001));assert.deepEqual(JSON.parse(JSON.stringify(f.api.credentialLayout(f.doc))),{state:'unavailable',reason:'coverage'});f.w.close();
 const broken=fixture('<h1>History</h1>');broken.doc.createTreeWalker=()=>{throw Error('unavailable')};assert.equal(broken.api.credentialLayout(broken.doc).state,'unavailable');broken.w.close();
 const late=fixture('<div></div>'.repeat(20001)+'<section id=late></section>');late.doc.querySelector('#late').attachShadow({mode:'open'}).innerHTML='<input type=password value=CANARY>';assert.equal(late.api.credentialLayout(late.doc).state,'unavailable');late.w.close();
 const controls=fixture('<input hidden>'.repeat(2001));assert.equal(controls.api.credentialLayout(controls.doc).state,'unavailable');controls.w.close();
});

test('display-contents shadow host cannot hide a visible password',()=>{
 const f=fixture('<section id=host style="display:contents"></section>');const host=f.doc.querySelector('#host');host.getClientRects=()=>[];
 host.attachShadow({mode:'open'}).innerHTML='<input type=password value=CANARY>';assert.equal(f.api.credentialLayout(f.doc).state,'login');f.w.close();
});
