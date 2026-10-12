// Fixed authenticated browser metadata and tab visibility. No renderer code.
globalThis.MechanizeTabMetadata=(()=>{
 const closed=(v,keys)=>v&&typeof v==='object'&&!Array.isArray(v)&&Object.keys(v).sort().join()===keys.sort().join();
 const hex=v=>typeof v==='string'&&/^[a-f0-9]{64}$/.test(v);
 const safePath=(origin,path)=>{try{const u=new URL(origin+path),decoded=decodeURIComponent(path);if(/[\u0000-\u001f\u007f-\u009f\\]/u.test(decoded)||decoded.split('/').some(x=>x==='.'||x==='..'))return false;return typeof path==='string'&&path.length<=2048&&(path===''||path.startsWith('/')&&!path.startsWith('//')&&!/[?#\\\x00\r\n\t]/.test(path)&&u.origin===origin&&u.pathname===path&&!u.search&&!u.hash);}catch{return false;}};
 const base=(r,fence)=>r&&fence&&hex(r.requestId)&&['brokerEpoch','channelEpoch','scopeHash'].every(k=>r[k]===fence[k])&&Number.isSafeInteger(r.tabId)&&r.tabId>0&&r.tabId<=2147483647&&Number.isSafeInteger(r.deadlineUnixMs)&&r.deadlineUnixMs>Date.now()&&r.deadlineUnixMs<=Date.now()+10000;
 function exactOrigin(value,enrollment){try{const u=new URL(value);return u.origin===value&&!u.username&&!u.password&&['http:','https:'].includes(u.protocol)&&MechanizeProtocol.websiteAllowed(value,enrollment);}catch{return false;}}
 async function readTab(api,id,check,allowPending=false){
  check();let tab;try{tab=await api.tabs.get(id);}catch{throw 'tabUnavailable';}check();
  if(!tab||tab.id!==id||!Number.isSafeInteger(tab.windowId)||tab.windowId<0||tab.incognito===true||tab.discarded===true)throw 'unsafeTab';
  if(!allowPending&&(tab.status!=='complete'||tab.pendingUrl))throw 'pendingNavigation';
  if(typeof tab.url!=='string'||!tab.url||tab.url.length>16384)throw 'tabUnavailable';
  let url;try{url=new URL(tab.url);if(!['http:','https:'].includes(url.protocol)||url.username||url.password)throw Error();}catch{throw 'unsupportedLocation';}
  return {tab,url};
 }
 async function match(api,r,fence,enrollment,current){
  if(!closed(r,['type','requestId','tabId','expectedOrigin','expectedPath','brokerEpoch','channelEpoch','scopeHash','deadlineUnixMs'])||r.type!=='tabLocation'||!base(r,fence)||!exactOrigin(r.expectedOrigin,enrollment)||!safePath(r.expectedOrigin,r.expectedPath))return null;
  const reply=(available,matchesExpectedOrigin,pathChecked,matchesExpectedPath,reason)=>({type:'tabLocationResult',requestId:r.requestId,brokerEpoch:fence.brokerEpoch,channelEpoch:fence.channelEpoch,scopeHash:fence.scopeHash,available,matchesExpectedOrigin,pathChecked,matchesExpectedPath,reason});
  const check=()=>{if(!current()||Date.now()>=r.deadlineUnixMs)throw 'authorityChanged';};
  try{check();if(!await api.permissions.contains({origins:[r.expectedOrigin+'/*']}))throw 'permissionUnavailable';check();const a=await readTab(api,r.tabId,check),b=await readTab(api,r.tabId,check);if(a.tab.windowId!==b.tab.windowId||a.tab.url!==b.tab.url)throw 'authorityChanged';check();if(!await api.permissions.contains({origins:[r.expectedOrigin+'/*']}))throw 'permissionUnavailable';check();const same=b.url.origin===r.expectedOrigin,pathChecked=r.expectedPath!=='';return reply(true,same,pathChecked,same&&pathChecked&&b.url.pathname===r.expectedPath,'none');}
  catch(reason){return reply(false,false,false,false,['permissionUnavailable','tabUnavailable','pendingNavigation','unsafeTab','unsupportedLocation','authorityChanged'].includes(reason)?reason:'tabUnavailable');}
 }
 async function inventory(api,r,fence,enrollment,current){
  if(!closed(r,['type','requestId','expectedOrigin','brokerEpoch','channelEpoch','scopeHash','deadlineUnixMs'])||r.type!=='tabInventory'||!hex(r.requestId)||!Number.isSafeInteger(r.deadlineUnixMs)||['brokerEpoch','channelEpoch','scopeHash'].some(k=>typeof r[k]!=='string'||!r[k]||r[k].length>256))return null;
  const reply=(tabIds,complete,reason)=>({type:'tabInventoryResult',requestId:r.requestId,brokerEpoch:r.brokerEpoch,channelEpoch:r.channelEpoch,scopeHash:r.scopeHash,tabIds,complete,reason});
  const check=()=>{if(!fence||!current()||['brokerEpoch','channelEpoch','scopeHash'].some(k=>r[k]!==fence[k])||Date.now()>=r.deadlineUnixMs||r.deadlineUnixMs>Date.now()+10000)throw 'authorityChanged';};
  // Every metadata await shares the request's deadline, including saved config.
  // A late Chrome reply has no state to commit and cannot produce a second result.
  const wait=async work=>{check();let timer;try{return await Promise.race([Promise.resolve().then(work),new Promise((_,reject)=>{timer=setTimeout(()=>reject('authorityChanged'),Math.max(1,r.deadlineUnixMs-Date.now()));})]);}finally{clearTimeout(timer);check();}};
  try{
   enrollment=await wait(typeof enrollment==='function'?enrollment:()=>enrollment);
   if(!exactOrigin(r.expectedOrigin,enrollment))throw 'permissionUnavailable';
   if(!await wait(()=>api.permissions.contains({origins:[r.expectedOrigin+'/*']})))throw 'permissionUnavailable';
   const rows=await wait(()=>api.tabs.query({url:r.expectedOrigin+'/*'}));
   if(!Array.isArray(rows))throw 'inventoryUnavailable';
   const ids=[],seen=new Set(),limited=rows.length>200;
   for(const tab of rows.slice(0,200)){
    if(!tab||!Number.isSafeInteger(tab.id)||tab.id<=0||tab.id>2147483647||seen.has(tab.id))throw 'inventoryUnavailable';seen.add(tab.id);
    if(tab.incognito===true)continue;
    // Committed URL metadata remains useful while a tab loads or is discarded.
    // No pending URL or renderer state is consulted and no input is authorized.
    if(tab.incognito!==false||typeof tab.url!=='string'||tab.url.length>16384)throw 'inventoryUnavailable';
    let url;try{url=new URL(tab.url);}catch{throw 'inventoryUnavailable';}
    if(url.origin!==r.expectedOrigin||url.username||url.password)continue;
    ids.push(tab.id);
   }
   if(!await wait(()=>api.permissions.contains({origins:[r.expectedOrigin+'/*']})))throw 'permissionUnavailable';
   check();ids.sort((a,b)=>a-b);return reply(ids,!limited,limited?'inventoryLimit':'none');
  }catch(reason){return reply([],false,['permissionUnavailable','inventoryUnavailable','authorityChanged'].includes(reason)?reason:'inventoryUnavailable');}
 }
 async function activate(api,r,fence,enrollment,current){
  const keys=['type','requestId','attemptId','origin','brokerEpoch','channelEpoch','scopeHash','deadlineUnixMs','tabId',...(r?.controlBadge===true?['controlBadge']:[])];
  if(!closed(r,keys)||r.type!=='browser.activateTab'||!base(r,fence)||!hex(r.attemptId)||!exactOrigin(r.origin,enrollment))return null;
  const reply=(dispatchState,tabId=0,errorCode='none')=>({type:'browser.activateTabResult',requestId:r.requestId,attemptId:r.attemptId,brokerEpoch:fence.brokerEpoch,channelEpoch:fence.channelEpoch,scopeHash:fence.scopeHash,dispatchState,tabId,errorCode});
  const check=()=>{if(!current()||Date.now()>=r.deadlineUnixMs)throw 'authorityChanged';};
  const originCheck=x=>{if(x.url.origin!==r.origin)throw 'originDenied';if(x.tab.pendingUrl){let u;try{u=new URL(x.tab.pendingUrl);}catch{throw 'originDenied';}if(u.origin!==r.origin||u.username||u.password)throw 'originDenied';}};
  const errors=['authorityChanged','permissionUnavailable','windowUnavailable','receiptCapacity','unknownEffect','lifecycleInhibited','activationUnavailable','receiptUnavailable','attemptConflict','originDenied','tabUnavailable'];
  const ik='browserIntent:'+r.attemptId,rk='browserReceipt:'+r.attemptId;let intended=false,crossed=false,receiptStored=false,confirmedReceipt=null;
  try{
   check();const canonical=JSON.stringify(['mechanize-browser-activate-tab-v1',enrollment.profileChannel,enrollment.browserInstance,r.attemptId,r.origin,r.tabId,r.brokerEpoch,r.channelEpoch,r.scopeHash]);const fingerprint=[...new Uint8Array(await crypto.subtle.digest('SHA-256',new TextEncoder().encode(canonical)))].map(x=>x.toString(16).padStart(2,'0')).join('');
   const saved=await api.storage.session.get(null);check();
   if(saved[ik]){if(saved[ik].action!=='browser.activateTab'||saved[ik].fingerprint!==fingerprint)return reply('notDispatched',0,'attemptConflict');const old=saved[rk];if(!old)return reply('unknown',0,'receiptUnavailable');const shaped=reply(old.dispatchState,old.tabId,old.errorCode);if(!closed(old,Object.keys(shaped))||!hex(old.requestId)||['type','attemptId','brokerEpoch','channelEpoch','scopeHash'].some(k=>old[k]!==shaped[k])||!['dispatched','notDispatched','unknown'].includes(old.dispatchState)||old.dispatchState==='dispatched'&&(old.tabId!==r.tabId||old.errorCode!=='none')||old.dispatchState!=='dispatched'&&(old.tabId!==0||!errors.includes(old.errorCode)))return reply('unknown',0,'receiptUnavailable');return shaped;}
   if(Object.keys(saved).some(k=>k.startsWith('browserIntent:')&&(!saved[k.replace('browserIntent:','browserReceipt:')]||saved[k.replace('browserIntent:','browserReceipt:')].dispatchState==='unknown'||saved[k.replace('browserIntent:','browserReceipt:')].error?.dispatchState==='unknown')))throw 'unknownEffect';
   if(Object.keys(saved).filter(k=>k.startsWith('browserIntent:')).length>=512)throw 'receiptCapacity';if(saved.mechanizeLifecycleInhibited)throw 'lifecycleInhibited';
   if(!await api.permissions.contains({origins:[r.origin+'/*']}))throw 'permissionUnavailable';check();const before=await readTab(api,r.tabId,check,true);originCheck(before);
   const w=await api.windows.get(before.tab.windowId);check();if(!w||w.id!==before.tab.windowId||w.type!=='normal'||w.incognito===true)throw 'windowUnavailable';
   await api.storage.session.set({[ik]:{action:'browser.activateTab',fingerprintVersion:1,fingerprint,brokerEpoch:fence.brokerEpoch,channelEpoch:fence.channelEpoch,scopeHash:fence.scopeHash}});intended=true;
   check();const fresh=await readTab(api,r.tabId,check,true);originCheck(fresh);if(fresh.tab.windowId!==w.id)throw 'authorityChanged';if(!await api.permissions.contains({origins:[r.origin+'/*']}))throw 'permissionUnavailable';check();
   crossed=true;await api.tabs.update(r.tabId,{active:true});check();const active=await readTab(api,r.tabId,check,true);originCheck(active);if(active.tab.windowId!==w.id)throw 'activationUnavailable';
   await api.windows.update(w.id,{focused:true,...(w.state==='minimized'?{state:'normal'}:{})});check();
   // Chrome may acknowledge the request before OS focus readback settles.
   // These updates execute once; only exact-target metadata is polled, under
   // the original authority and deadline. No new deadline or action retry.
   for(;;){
    const after=await readTab(api,r.tabId,check,true),window=await api.windows.get(w.id);check();originCheck(after);
    if(after.tab.windowId!==w.id||window?.id!==w.id||window.type!=='normal'||window.incognito===true)throw 'activationUnavailable';
    if(!await api.permissions.contains({origins:[r.origin+'/*']}))throw 'permissionUnavailable';check();
    if(after.tab.active===true&&window.focused===true&&window.state!=='minimized')break;
    const remaining=r.deadlineUnixMs-Date.now();if(remaining<=1)throw 'activationUnavailable';
    await new Promise(resolve=>setTimeout(resolve,Math.min(25,remaining)));
   }
   const result=reply('dispatched',r.tabId);await api.storage.session.set({[rk]:result});receiptStored=true;const stored=(await api.storage.session.get(rk))[rk];if(!closed(stored,Object.keys(result))||Object.keys(result).some(k=>stored[k]!==result[k]))throw 'receiptUnavailable';confirmedReceipt=result;check();
   if(r.controlBadge===true&&globalThis.MechanizeControlBadgeMetadata&&r.deadlineUnixMs-Date.now()>300){const controlBadgeWindow=await MechanizeControlBadgeMetadata.window(api,r.tabId,Math.min(r.deadlineUnixMs,Date.now()+250),current);check();if(controlBadgeWindow)return {...result,controlBadgeWindow};}return result;
  }catch(reason){
   // A committed/read-back terminal receipt cannot be rewritten by a late
   // deadline, port check or optional badge read. This reports past evidence;
   // it never authorizes input after the command deadline.
   if(confirmedReceipt)return confirmedReceipt;
   const result=reply(crossed?'unknown':'notDispatched',0,errors.includes(reason)?reason:'activationUnavailable');
   if(intended&&!receiptStored)try{const prior=(await api.storage.session.get(rk))[rk];if(prior===undefined)await api.storage.session.set({[rk]:result});}catch{return reply('unknown',0,'receiptUnavailable');}
   return result;
  }
 }
 async function activationStatus(api,r,fence,enrollment,current){
  const keys=['type','requestId','attemptId','brokerEpoch','channelEpoch','scopeHash','deadlineUnixMs','originalBrokerEpoch','originalChannelEpoch','originalScopeHash','origin','tabId','fingerprintSHA256'];
  if(!closed(r,keys)||r.type!=='browser.activationStatus'||!base(r,fence)||!hex(r.attemptId)||!hex(r.fingerprintSHA256)||!hex(r.originalScopeHash)||!exactOrigin(r.origin,enrollment))return null;
  const reply=quiescent=>({type:'browser.activationStatusResult',requestId:r.requestId,attemptId:r.attemptId,brokerEpoch:r.brokerEpoch,channelEpoch:r.channelEpoch,scopeHash:r.scopeHash,quiescent});
  const check=()=>{if(!current()||Date.now()>=r.deadlineUnixMs)throw Error();};
  try{
   check();const canonical=JSON.stringify(['mechanize-browser-activate-tab-v1',enrollment.profileChannel,enrollment.browserInstance,r.attemptId,r.origin,r.tabId,r.originalBrokerEpoch,r.originalChannelEpoch,r.originalScopeHash]);
   const fingerprint=[...new Uint8Array(await crypto.subtle.digest('SHA-256',new TextEncoder().encode(canonical)))].map(x=>x.toString(16).padStart(2,'0')).join('');
   if(fingerprint!==r.fingerprintSHA256)throw Error();
   const saved=await api.storage.session.get(['browserIntent:'+r.attemptId,'browserReceipt:'+r.attemptId]);check();
   const intent=saved['browserIntent:'+r.attemptId],receipt=saved['browserReceipt:'+r.attemptId];
   if(!closed(intent,['action','fingerprintVersion','fingerprint','brokerEpoch','channelEpoch','scopeHash'])||intent.action!=='browser.activateTab'||intent.fingerprintVersion!==1||intent.fingerprint!==fingerprint||intent.brokerEpoch!==r.originalBrokerEpoch||intent.channelEpoch!==r.originalChannelEpoch||intent.scopeHash!==r.originalScopeHash)throw Error();
   if(!closed(receipt,['type','requestId','attemptId','brokerEpoch','channelEpoch','scopeHash','dispatchState','tabId','errorCode'])||receipt.type!=='browser.activateTabResult'||!hex(receipt.requestId)||receipt.attemptId!==r.attemptId||receipt.brokerEpoch!==intent.brokerEpoch||receipt.channelEpoch!==intent.channelEpoch||receipt.scopeHash!==intent.scopeHash||!['dispatched','notDispatched','unknown'].includes(receipt.dispatchState))throw Error();
   const codes=['authorityChanged','permissionUnavailable','windowUnavailable','receiptCapacity','unknownEffect','lifecycleInhibited','activationUnavailable','receiptUnavailable','attemptConflict','originDenied','tabUnavailable'];
   if(receipt.dispatchState==='dispatched'?(receipt.tabId!==r.tabId||receipt.errorCode!=='none'):(receipt.tabId!==0||!codes.includes(receipt.errorCode)))throw Error();
   check();return reply(true);
  }catch{return reply(false);}
 }
 return {match,inventory,activate,activationStatus,safePath};
})();
