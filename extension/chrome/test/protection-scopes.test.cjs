const {test}=require('node:test');const assert=require('node:assert/strict');global.crypto=require('node:crypto').webcrypto;const {create,KEY}=require('../protection-scopes.js');
const source={profileChannel:'p',browserInstance:'b',tabId:7,frameId:0,documentId:'original',documentGeneration:1},origin='https://fixture.example.test';
function fixture(){const local={},state={tabs:[{id:7,status:'complete',url:origin+'/login?secret=CANARY'},{id:8,status:'complete',url:origin+'/dashboard'}],frames:{7:[{frameId:0,parentFrameId:-1,documentLifecycle:'active',frameType:'outermost_frame',documentId:'original',url:origin+'/login?secret=CANARY'}],8:[{frameId:0,parentFrameId:-1,documentLifecycle:'active',frameType:'outermost_frame',documentId:'other',url:origin+'/dashboard'}]},current:true};const api={storage:{local:{get:async key=>({[key]:local[key]}),set:async value=>Object.assign(local,structuredClone(value))}},tabs:{query:async()=>state.tabs},webNavigation:{getAllFrames:async({tabId})=>state.frames[tabId]}};const scopes=create(api),q={type:'credentialScope',requestId:'a'.repeat(64),mode:'capture',preparationId:'b'.repeat(64),sourceIdentity:source,sourceOrigin:origin,loginRouteSHA256:'',brokerEpoch:'broker',channelEpoch:'channel',scopeHash:'c'.repeat(64),deadlineUnixMs:Date.now()+4000,targetTabId:0,targetOrigin:'',controlLease:{id:'lease',generation:1}};const run=request=>scopes.respond(request,()=>{if(!state.current)throw 'scopeChanged'},()=>true);return {scopes,q,run,local,state,api};}
test('source capture persists exact private route without query and allows independent same-origin document',async()=>{const f=fixture(),r=await f.run(f.q);assert.equal(r.ready,true);assert.equal(r.loginRouteSHA256.length,64);assert.ok(!JSON.stringify(f.local).includes('CANARY'));assert.ok(!JSON.stringify(r).includes('/login'));const fresh=create(f.api);await fresh.load();assert.equal(fresh.protects(origin,source),true);assert.equal(fresh.protects(origin,{...source,tabId:8,documentId:'other'}),false);const q={...f.q,mode:'disjoint',loginRouteSHA256:r.loginRouteSHA256,targetTabId:8,targetOrigin:origin};delete q.controlLease;assert.equal((await f.run(q)).ready,true);q.targetTabId=7;assert.equal((await f.run(q)).reason,'scopeTargetProtected');});
test('legacy same-origin source must be independently absent; public inventory absence is insufficient',async()=>{const f=fixture(),q={...f.q,mode:'disjoint',targetTabId:8,targetOrigin:origin};delete q.controlLease;assert.equal((await f.run(q)).reason,'scopeSourcePresent');f.state.frames[7][0].documentId='replacement';assert.equal((await f.run(q)).ready,true);f.state.frames[7]=[];assert.equal((await f.run(q)).reason,'scopeInventoryUnavailable');f.state.tabs=f.state.tabs.filter(t=>t.id!==7);assert.equal((await f.run(q)).ready,true);});
test('absence and capture refuse stale authority, missing frames and tampered persistent source',async()=>{const f=fixture();await f.run(f.q);f.local[KEY].records[0].loginRoute=origin+'/other';await assert.rejects(create(f.api).load());const q={...f.q,mode:'absent'};delete q.controlLease;assert.equal((await f.run(q)).reason,'scopeSourcePresent');f.state.current=false;assert.equal((await f.run(q)).reason,'scopeChanged');});

test('unrelated approved HTTP target uses current metadata without becoming a credential source',async()=>{const f=fixture(),url='http://127.0.0.1:12345';f.state.tabs=[{id:8,status:'complete',url}];f.state.frames[8]=[{frameId:0,documentId:'public-http',url}];const q={...f.q,mode:'target',sourceIdentity:{...source,tabId:8,documentId:'public-http'},sourceOrigin:url,targetOrigin:url,targetTabId:8};delete q.controlLease;const result=await f.run(q);assert.equal(result.ready,true);assert.equal(result.targetIdentity.documentId,'public-http');assert.equal(f.local[KEY],undefined);});

test('source absence can retire stable committed replacement while source tab is loading',async()=>{
 const f=fixture();await f.run(f.q);f.local.retainedReceipt={dispatchState:'unknown',attemptId:'retained'};const receipt=JSON.stringify(f.local.retainedReceipt);
 f.state.tabs[0].status='loading';f.state.tabs[0].pendingUrl=origin+'/pending?CANARY';
 const q={...f.q,mode:'absent'};delete q.controlLease;
 assert.equal((await f.run(q)).reason,'scopeSourcePresent');
 f.state.frames[7][0].documentId='replacement';assert.equal((await f.run(q)).ready,true);
 const retired=await f.run({...q,mode:'retire'});assert.equal(retired.ready,true);assert.equal(f.local[KEY].records[0].retired,true);assert.equal(JSON.stringify(f.local.retainedReceipt),receipt);assert.ok(!JSON.stringify(retired).includes('CANARY'));
 assert.equal(f.scopes.protects(origin+'/login',source),true);assert.equal(f.scopes.protects(origin+'/public',source),true);
});
test('loading target capture and disjoint proof retain settled-document requirements',async()=>{
 const f=fixture(),captured=await f.run(f.q),disjoint={...f.q,mode:'disjoint',loginRouteSHA256:captured.loginRouteSHA256,targetTabId:8,targetOrigin:origin};delete disjoint.controlLease;
 f.state.tabs[1].status='loading';assert.equal((await f.run(disjoint)).reason,'scopeInventoryUnavailable');
 const target={...disjoint,mode:'target',sourceIdentity:{...source,tabId:8,documentId:'other'}};assert.equal((await f.run(target)).reason,'scopeInventoryUnavailable');
 f.state.tabs[0].status='loading';assert.equal((await f.run(f.q)).reason,'scopeInventoryUnavailable');
});
test('source absence requires complete active stable frame evidence, never pending URL alone',async()=>{
 for(const mode of ['missing','inactive','noLifecycle','duplicate','error','originalChild','changing','disappearing','discarded','incognito','authority']){
  const f=fixture(),q={...f.q,mode:'absent'};delete q.controlLease;f.state.tabs[0].status='loading';f.state.tabs[0].pendingUrl=origin+'/different';f.state.frames[7][0].documentId='replacement';
  if(mode==='missing')f.state.frames[7]=[];
  if(mode==='inactive')f.state.frames[7][0].documentLifecycle='cached';
  if(mode==='noLifecycle')delete f.state.frames[7][0].documentLifecycle;
  if(mode==='duplicate')f.state.frames[7].push({...f.state.frames[7][0]});
  if(mode==='error')f.state.frames[7][0].errorOccurred=true;
  if(['orphan','cycle','originalChild'].includes(mode))f.state.frames[7].push({frameId:1,parentFrameId:mode==='orphan'?9:mode==='cycle'?1:0,documentId:mode==='originalChild'?'original':'child',frameType:'sub_frame',documentLifecycle:'active'});
  if(mode==='discarded')f.state.tabs[0].discarded=true;if(mode==='incognito')f.state.tabs[0].incognito=true;
  if(mode==='authority')f.state.current=false;
  if(mode==='changing'||mode==='disappearing'){let reads=0;f.api.webNavigation.getAllFrames=async()=>{if(++reads===2){if(mode==='disappearing')return [];return [{...f.state.frames[7][0],documentId:'another'}];}return f.state.frames[7];};}
  const result=await f.run(q);assert.equal(result.ready,false,mode);assert.equal(f.local[KEY],undefined);assert.ok(!JSON.stringify(result).includes('/different'));
 }
});

test('absence permits unrelated subframe churn and cached documents but original cached identity remains present',async()=>{
 const f=fixture(),q={...f.q,mode:'absent'};delete q.controlLease;f.state.tabs[0].status='loading';f.state.frames[7][0].documentId='replacement';
 let reads=0;f.api.webNavigation.getAllFrames=async()=>[...f.state.frames[7],{frameId:1,parentFrameId:0,documentId:'ad-'+(++reads),documentLifecycle:'active',frameType:'sub_frame'},{frameId:2,parentFrameId:0,documentId:'unrelated-cached',documentLifecycle:'cached',frameType:'sub_frame'}];
 assert.equal((await f.run(q)).ready,true);assert.equal(reads,2);
 f.state.frames[7].push({frameId:0,parentFrameId:-1,documentId:'original',documentLifecycle:'cached',frameType:'outermost_frame'});assert.equal((await f.run(q)).reason,'scopeSourcePresent');
});
test('exact captured disjoint scope never requires the protected source to settle',async()=>{
 const f=fixture(),captured=await f.run(f.q);f.state.tabs[0].status='loading';f.state.tabs[0].pendingUrl=origin+'/pending';
 const q={...f.q,mode:'disjoint',loginRouteSHA256:captured.loginRouteSHA256,targetTabId:8,targetOrigin:origin};delete q.controlLease;
 const get=f.api.webNavigation.getAllFrames;f.api.webNavigation.getAllFrames=async d=>{assert.notEqual(d.tabId,source.tabId);return get(d);};
 assert.equal((await f.run(q)).ready,true);q.loginRouteSHA256='f'.repeat(64);assert.equal((await f.run(q)).reason,'scopeChanged');
});

test('retired login scope admits replacement dashboard but protects reauthentication and restored secret document',async()=>{
 const f=fixture();await f.run(f.q);
 const replacement={...source,documentId:'dashboard-document',documentGeneration:2};
 f.state.tabs[0].url=origin+'/dashboard';
 Object.assign(f.state.frames[7][0],{documentId:replacement.documentId,url:origin+'/dashboard'});
 const retire={...f.q,mode:'retire'};delete retire.controlLease;
 assert.equal((await f.run(retire)).ready,true);
 const reloaded=create(f.api);await reloaded.load();
 assert.equal(reloaded.protects(origin+'/dashboard',replacement),false);
 assert.equal(reloaded.protects(origin+'/history',replacement),false);
 // Query/hash changes must not unprotect a fresh login document.
 assert.equal(reloaded.protects(origin+'/login?next=dashboard#step2',replacement),true);
 // A route change alone does not prove that a filled document lost its secrets.
 assert.equal(reloaded.protects(origin+'/dashboard',source),true);
 const target={...retire,mode:'target',sourceIdentity:replacement,targetTabId:7,targetOrigin:origin};
 assert.equal((await f.run(target)).ready,true);
 Object.assign(f.state.frames[7][0],{documentId:source.documentId,url:origin+'/dashboard'});
 assert.equal((await f.run({...target,sourceIdentity:source})).reason,'scopeTargetProtected');
});

test('login scope follows private redirects and reopened routes without protecting unrelated public pages',async()=>{
 const f=fixture();await f.run(f.q);
 const otp={...source,documentId:'otp-document',documentGeneration:2};
 assert.equal(f.scopes.protects('https://identity.example.test/otp',otp),true);
 assert.equal(f.scopes.protects(origin+'/login',{...otp,tabId:8}),true);
 assert.equal(f.scopes.protects(origin+'/history',{...otp,tabId:8}),false);
 f.state.frames[7][0].documentId='replacement';
 const q={...f.q,mode:'retire'};delete q.controlLease;
 assert.equal((await f.run(q)).ready,true);
 assert.equal(f.scopes.protects(origin+'/login?next=public',{...otp,tabId:8}),true);
 assert.equal(f.scopes.protects(origin+'/history',{...otp,tabId:8}),false);
 assert.equal(f.scopes.protects(origin+'/history',{...source,tabId:8}),true);
 assert.equal(f.scopes.protects(origin+'/login',{...otp,tabId:8,browserInstance:'other-browser'}),false);
});
