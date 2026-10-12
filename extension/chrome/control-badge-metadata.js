// Native-port presentation metadata only. No page script, title, URL or input.
globalThis.MechanizeControlBadgeMetadata=(()=>{
 const closed=(v,keys)=>v&&typeof v==='object'&&!Array.isArray(v)&&Object.keys(v).sort().join()===keys.sort().join();
 async function window(api,tabId,deadline,current,identity){
  const check=()=>{if(!current()||Date.now()>=deadline)throw Error();};
  const read=async()=>{
   check();const tab=await api.tabs.get(tabId);check();
   if(tab?.id!==tabId||tab.incognito===true||!Number.isSafeInteger(tab.windowId)||tab.windowId<0)throw Error();
   if(identity){const roots=await api.webNavigation.getAllFrames({tabId});check();if(!Array.isArray(roots)||roots.length>256||!roots.some(f=>f.frameId===0&&f.documentId===identity.documentId&&!f.errorOccurred))throw Error();}
   const w=await api.windows.get(tab.windowId);check();
   if(w?.id!==tab.windowId||w.type!=='normal'||w.state==='minimized'||w.incognito===true||![w.left,w.top,w.width,w.height].every(n=>Number.isFinite(n)&&Math.abs(n)<=100000)||w.width<120||w.height<48)throw Error();
   return {windowId:w.id,x:w.left,y:w.top,width:w.width,height:w.height};
  };
  let timer;
  try{return await Promise.race([(async()=>{const a=await read(),b=await read();check();if(Object.keys(a).some(k=>a[k]!==b[k]))throw Error();return {x:a.x,y:a.y,width:a.width,height:a.height};})(),new Promise(resolve=>{timer=setTimeout(()=>resolve(null),Math.max(1,Math.min(250,deadline-Date.now())));})]);}catch{return null;}finally{clearTimeout(timer);}
 }
 async function respond(api,r,fence,enrollment,current){
  if(!closed(r,['type','requestId','identity','brokerEpoch','channelEpoch','scopeHash','deadlineUnixMs'])||r.type!=='controlBadgeMetadata'||typeof r.requestId!=='string'||!/^[a-f0-9]{64}$/.test(r.requestId)||!fence||['brokerEpoch','channelEpoch','scopeHash'].some(k=>r[k]!==fence[k])||!Number.isSafeInteger(r.deadlineUnixMs)||r.deadlineUnixMs<=Date.now()||r.deadlineUnixMs>Date.now()+1500)return null;
  const i=r.identity;if(!closed(i,['profileChannel','browserInstance','tabId','frameId','documentId','documentGeneration'])||i.profileChannel!==enrollment.profileChannel||i.browserInstance!==enrollment.browserInstance||!Number.isSafeInteger(i.tabId)||i.tabId<=0||i.frameId!==0||typeof i.documentId!=='string'||!i.documentId||i.documentId.length>256||!Number.isSafeInteger(i.documentGeneration)||i.documentGeneration<1)return null;
  const result=await window(api,i.tabId,r.deadlineUnixMs,current,i);
  if(!current())return null;
  return {type:'controlBadgeMetadataResult',requestId:r.requestId,brokerEpoch:fence.brokerEpoch,channelEpoch:fence.channelEpoch,scopeHash:fence.scopeHash,window:result};
 }
 return {respond,window};
})();
