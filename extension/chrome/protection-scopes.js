// Private source bindings. Route strings never leave extension-local storage;
// only their SHA-256 commitments cross the authenticated native channel.
globalThis.MechanizeProtectionScopes=(()=>{
 const KEY='mechanizeCredentialScopesV1',fields=['profileChannel','browserInstance','tabId','frameId','documentId','documentGeneration'];
 const same=(a,b)=>fields.every(k=>a?.[k]===b?.[k]);
 const identity=i=>i&&Object.keys(i).sort().join()===fields.slice().sort().join()&&typeof i.profileChannel==='string'&&typeof i.browserInstance==='string'&&Number.isSafeInteger(i.tabId)&&i.tabId>0&&i.frameId===0&&typeof i.documentId==='string'&&i.documentId.length>0&&Number.isSafeInteger(i.documentGeneration)&&i.documentGeneration>0;
 const webOrigin=s=>{try{const u=new URL(s);return u.origin===s&&['https:','http:'].includes(u.protocol)&&!u.username&&!u.password;}catch{return false;}};
 const origin=s=>{try{const u=new URL(s);return u.origin===s&&u.protocol==='https:'&&!u.username&&!u.password;}catch{return false;}};
 const route=s=>{const u=new URL(s);if(!origin(u.origin)||u.username||u.password)throw Error();return u.origin+u.pathname;};
 const publicRoute=s=>{const u=new URL(s);if(!webOrigin(u.origin)||u.username||u.password)throw Error();return u.origin+u.pathname;};
 const canonical=v=>JSON.stringify((function sorted(x){if(Array.isArray(x))return x.map(sorted);if(x&&typeof x==='object')return Object.fromEntries(Object.keys(x).sort().map(k=>[k,sorted(x[k])]));return x;})(v));
 const hash=async s=>Array.from(new Uint8Array(await crypto.subtle.digest('SHA-256',new TextEncoder().encode(s))),b=>b.toString(16).padStart(2,'0')).join('');
 function create(api,knownIdentity=()=>null,publicRead=null){
  let records=[];
  async function load(){const value=(await api.storage.local.get(KEY))[KEY];if(value===undefined)return; if(!value||Object.keys(value).sort().join()!=='records,version'||value.version!==1||!Array.isArray(value.records)||value.records.length>256)throw Error();const ids=new Set();for(const r of value.records){if(!r||Object.keys(r).sort().join()!=='identity,loginRoute,loginRouteSHA256,origin,preparationId,retired'||typeof r.retired!=='boolean'||!/^[a-f0-9]{64}$/.test(r.preparationId)||ids.has(r.preparationId)||!identity(r.identity)||!origin(r.origin)||route(r.loginRoute)!==r.loginRoute||new URL(r.loginRoute).origin!==r.origin||await hash(r.loginRoute)!==r.loginRouteSHA256)throw Error();ids.add(r.preparationId);}records=value.records;}
  function protects(value,i){
   let o;try{o=new URL(value).origin;}catch{return true;}
   return records.some(r=>{
    if(!i)return r.origin===o;
    if(r.identity.profileChannel!==i.profileChannel||r.identity.browserInstance!==i.browserInstance)return false;
    // A redirect does not end a private flow. The original document also
    // remains protected after retirement, even if its URL or tab changes.
    if(!r.retired&&r.identity.tabId===i.tabId||i.documentId===r.identity.documentId)return true;
    // Reopening a known login route in another tab can restore autofilled
    // credentials. Public routes on that same origin remain independent.
    return r.origin===o&&route(value)===r.loginRoute;
   });
  }
  function boundOrigin(o){return records.some(r=>r.origin===o);}
  function loginRoute(value,i){try{return records.some(r=>r.identity.tabId===i?.tabId&&r.loginRoute===route(value));}catch{return true;}}
  async function root(tabId,current){current();const tabs=await api.tabs.query({});current();if(!Array.isArray(tabs)||tabs.length>200||tabs.some(t=>!t||!Number.isSafeInteger(t.id)||t.id<0)||new Set(tabs.map(t=>t.id)).size!==tabs.length)throw 'scopeInventoryUnavailable';const tab=tabs.find(t=>t.id===tabId);if(!tab)return null;if(tab.incognito||tab.discarded||tab.pendingUrl||tab.status!=='complete')throw 'scopeInventoryUnavailable';const frames=await api.webNavigation.getAllFrames({tabId});current();if(!Array.isArray(frames)||frames.length>256)throw 'scopeInventoryUnavailable';const roots=frames.filter(f=>f.frameId===0);if(roots.length!==1||!roots[0].documentId||roots[0].errorOccurred||roots[0].frameType!==undefined&&roots[0].frameType!=='outermost_frame'||roots[0].documentLifecycle!==undefined&&roots[0].documentLifecycle!=='active')throw 'scopeInventoryUnavailable';try{for(const value of [tab.url,roots[0].url]){const u=new URL(value);if(u.username||u.password||!['https:','http:'].includes(u.protocol))throw Error();}}catch{throw 'scopeInventoryUnavailable';}return {tab,frame:roots[0]};}
  // Exposure retirement needs document absence, not successor load readiness.
  // A committed replacement may still download resources. Prove its active
  // root twice; pending URL/status are neither evidence nor a veto here.
  // Capture/target/disjoint continue using the settled-document root() above.
  async function sourceFrameSample(source,current){
   current();const tabs=await api.tabs.query({});current();
   if(!Array.isArray(tabs)||tabs.length>200||tabs.some(t=>!t||!Number.isSafeInteger(t.id)||t.id<0)||new Set(tabs.map(t=>t.id)).size!==tabs.length)throw 'scopeInventoryUnavailable';
   const tab=tabs.find(t=>t.id===source.tabId);if(!tab)return null;
   if(tab.incognito||tab.discarded)throw 'scopeInventoryUnavailable';
   const frames=await api.webNavigation.getAllFrames({tabId:source.tabId});current();
   if(!Array.isArray(frames)||!frames.length||frames.length>256)throw 'scopeInventoryUnavailable';
   // Presence wins even for cached/prerender documents. Other non-active
   // documents cannot expose the original and do not establish root readiness.
   for(const f of frames)if(f?.documentId===source.documentId)throw 'scopeSourcePresent';
   const active=frames.filter(f=>f?.documentLifecycle==='active');
   if(frames.some(f=>!f||typeof f.documentId!=='string'||!/^[A-Za-z0-9._:-]{1,128}$/.test(f.documentId)||!['active','cached','prerender','pending_deletion'].includes(f.documentLifecycle)))throw 'scopeInventoryUnavailable';
   const ids=new Set();for(const f of active){if(!Number.isSafeInteger(f.frameId)||f.frameId<0||f.errorOccurred===true||ids.has(f.frameId))throw 'scopeInventoryUnavailable';ids.add(f.frameId);}
   const roots=active.filter(f=>f.frameId===0);
   if(roots.length!==1||roots[0].frameType!=='outermost_frame'||roots[0].parentFrameId!==-1)throw 'scopeInventoryUnavailable';
   // Subframes may change harmlessly while resources load. Only the active
   // outermost document is pinned across samples; both inventories must omit
   // the original document in every lifecycle and retain complete API coverage.
   return roots[0].documentId;
  }
  async function proveSourceAbsent(source,current){
   const before=await sourceFrameSample(source,current),after=await sourceFrameSample(source,current);
   if(before!==after)throw 'scopeChanged';current();
  }
  async function respond(request,current,captureAllowed){
   const common=['type','requestId','mode','preparationId','sourceIdentity','sourceOrigin','loginRouteSHA256','brokerEpoch','channelEpoch','scopeHash','deadlineUnixMs','targetTabId','targetOrigin'];
   if(!request||Object.keys(request).sort().join()!==[...common,...(request.mode==='capture'?['controlLease']:[])].sort().join()||request.type!=='credentialScope'||!['capture','disjoint','absent','retire','target','publicRead'].includes(request.mode)||!/^[a-f0-9]{64}$/.test(request.requestId)||!/^[a-f0-9]{64}$/.test(request.preparationId)||!(request.mode==='publicRead'?request.sourceIdentity&&Object.keys(request.sourceIdentity).sort().join()===fields.slice().sort().join()&&typeof request.sourceIdentity.profileChannel==='string'&&typeof request.sourceIdentity.browserInstance==='string'&&Number.isSafeInteger(request.sourceIdentity.tabId)&&request.sourceIdentity.tabId>0&&request.sourceIdentity.frameId===0&&request.sourceIdentity.documentId===''&&request.sourceIdentity.documentGeneration===0:identity(request.sourceIdentity))||!(['target','publicRead'].includes(request.mode)?webOrigin(request.sourceOrigin):origin(request.sourceOrigin)))return null;
   const reply=(ready,reason,loginRouteSHA256='',targetIdentity=null)=>({type:'credentialScopeResult',requestId:request.requestId,brokerEpoch:request.brokerEpoch,channelEpoch:request.channelEpoch,scopeHash:request.scopeHash,ready,reason,loginRouteSHA256,targetIdentity});
   const check=()=>{current();if(!Number.isSafeInteger(request.deadlineUnixMs)||Date.now()>=request.deadlineUnixMs||request.deadlineUnixMs>Date.now()+5000)throw 'scopeChanged';};
   try{
    check();
    if(request.mode==='publicRead'){
     if(typeof publicRead!=='function'||request.targetTabId!==request.sourceIdentity.tabId||request.targetOrigin!==request.sourceOrigin)throw 'scopeTargetProtected';
     const before=await root(request.targetTabId,check);if(!before||new URL(before.tab.url).origin!==request.targetOrigin||new URL(before.frame.url).origin!==request.targetOrigin)throw 'scopeChanged';
     const proof=await publicRead(request,before,check);check();
     if(!proof||Object.keys(proof).sort().join()!=='identity,public,routeSHA256,version'||proof.version!==1||proof.public!==true||!identity(proof.identity)||fields.filter(k=>!['documentGeneration','documentId'].includes(k)).some(k=>proof.identity[k]!==request.sourceIdentity[k])||proof.identity.documentId!==before.frame.documentId||!/^([a-f0-9]{64})$/.test(proof.routeSHA256))throw 'scopeTargetProtected';
     const after=await root(request.targetTabId,check);if(!after||after.frame.documentId!==before.frame.documentId||publicRoute(after.frame.url)!==publicRoute(before.frame.url)||publicRoute(after.tab.url)!==publicRoute(after.frame.url)||await hash(publicRoute(after.frame.url))!==proof.routeSHA256)throw 'scopeChanged';check();
     return {...reply(true,'none'),publicDocument:proof};
    }
    if(request.mode==='target'){
     const target=await root(request.targetTabId,check);if(!target||target.frame.documentId!==request.sourceIdentity.documentId||new URL(target.frame.url).origin!==request.targetOrigin||new URL(target.tab.url).origin!==request.targetOrigin||protects(target.frame.url,request.sourceIdentity))throw 'scopeTargetProtected';
     const after=await root(request.targetTabId,check);if(!after||after.frame.documentId!==target.frame.documentId||new URL(after.frame.url).origin!==request.targetOrigin)throw 'scopeChanged';return reply(true,'none','',{...request.sourceIdentity});
    }
    if(request.mode==='absent'||request.mode==='retire'){await proveSourceAbsent(request.sourceIdentity,check);if(request.mode==='retire'){const next=records.map(r=>r.preparationId===request.preparationId&&same(r.identity,request.sourceIdentity)?{...r,retired:true}:r);await api.storage.local.set({[KEY]:{version:1,records:next}});check();records=next;}return reply(true,'none');}
    if(request.mode==='capture'){
     const source=await root(request.sourceIdentity.tabId,check);const absent=!source||source.frame.documentId!==request.sourceIdentity.documentId;
     if(absent||!captureAllowed(request)||new URL(source.frame.url).origin!==request.sourceOrigin||new URL(source.tab.url).origin!==request.sourceOrigin)throw 'scopeChanged';
     const loginRoute=route(source.frame.url),loginRouteSHA256=await hash(loginRoute),record={preparationId:request.preparationId,identity:{...request.sourceIdentity},origin:request.sourceOrigin,loginRoute,loginRouteSHA256,retired:false};check();
     const previous=records.find(r=>r.preparationId===record.preparationId);if(previous&&canonical(previous)!==canonical(record))throw 'scopeChanged';if(!previous){if(records.length>=256)throw 'scopeLimit';const next=[...records,record];await api.storage.local.set({[KEY]:{version:1,records:next}});check();const stored=(await api.storage.local.get(KEY))[KEY];if(canonical(stored)!==canonical({version:1,records:next}))throw 'scopeChanged';records=next;}
     const after=await root(request.sourceIdentity.tabId,check);if(!after||after.frame.documentId!==request.sourceIdentity.documentId||route(after.frame.url)!==loginRoute||!captureAllowed(request))throw 'scopeChanged';return reply(true,'none',loginRouteSHA256);
    }
    const record=records.find(r=>r.preparationId===request.preparationId);if(request.loginRouteSHA256){if(!record||!same(record.identity,request.sourceIdentity)||record.origin!==request.sourceOrigin||record.loginRouteSHA256!==request.loginRouteSHA256)throw 'scopeChanged';}else {const source=await root(request.sourceIdentity.tabId,check);if(source&&source.frame.documentId===request.sourceIdentity.documentId)throw 'scopeSourcePresent';}
    if(!Number.isSafeInteger(request.targetTabId)||request.targetTabId<=0||!origin(request.targetOrigin)||request.targetTabId===request.sourceIdentity.tabId)throw 'scopeTargetProtected';
    const target=await root(request.targetTabId,check);if(!target||new URL(target.frame.url).origin!==request.targetOrigin||new URL(target.tab.url).origin!==request.targetOrigin)throw 'scopeChanged';
    const observed=knownIdentity(request.targetTabId,target.frame.documentId);const i={profileChannel:request.sourceIdentity.profileChannel,browserInstance:request.sourceIdentity.browserInstance,tabId:request.targetTabId,frameId:0,documentId:target.frame.documentId,...(observed?{documentGeneration:observed.documentGeneration}:{})};if(protects(target.frame.url,i))throw 'scopeTargetProtected';const after=await root(request.targetTabId,check);if(!after||after.frame.documentId!==i.documentId||new URL(after.frame.url).origin!==request.targetOrigin)throw 'scopeChanged';return reply(true,'none',request.loginRouteSHA256,i);
   }catch(reason){return reply(false,['scopeChanged','scopeSourcePresent','scopeTargetProtected','scopeInventoryUnavailable','scopeLimit'].includes(reason)?reason:'scopeUnavailable');}
  }
  return {load,respond,protects,boundOrigin,loginRoute,hasSource:i=>records.some(r=>same(r.identity,i)),records:()=>records.map(r=>({preparationId:r.preparationId,identity:{...r.identity},origin:r.origin,loginRouteSHA256:r.loginRouteSHA256}))};
 }
 return {create,KEY};
})();
if(typeof module!=='undefined')module.exports=globalThis.MechanizeProtectionScopes;
