// Fixed browser-owned metadata only. No document injection, title, DOM or input.
globalThis.MechanizeFocusedLocation=(()=>{
 const reasons=new Set(['none','noFocusedWindow','ambiguousFocusedTab','permissionUnavailable','tabUnavailable','pendingNavigation','unsafeTab','unsupportedLocation','authorityChanged']);
 async function respond(api,request,fence,enrollment,current){
  const keys=['type','requestId','brokerEpoch','channelEpoch','scopeHash','deadlineUnixMs','expectedOrigin'];
  if(!request||Object.keys(request).sort().join()!==keys.sort().join()||request.type!=='focusedLocation'||typeof request.requestId!=='string'||!/^[a-f0-9]{64}$/.test(request.requestId)||!Number.isSafeInteger(request.deadlineUnixMs)||request.deadlineUnixMs<=Date.now()||request.deadlineUnixMs>Date.now()+5000||!fence||['brokerEpoch','channelEpoch','scopeHash'].some(key=>request[key]!==fence[key]))return null;
  let expected;try{expected=new URL(request.expectedOrigin);if(expected.origin!==request.expectedOrigin||expected.username||expected.password||!['https:','http:'].includes(expected.protocol)||!MechanizeProtocol.websiteAllowed(expected.origin,enrollment))return null;}catch{return null;}
  const reply=(available,matchesExpectedOrigin,reason,tabId=0,windowFocused=false)=>({type:'focusedLocationResult',requestId:request.requestId,brokerEpoch:fence.brokerEpoch,channelEpoch:fence.channelEpoch,scopeHash:fence.scopeHash,available,windowFocused,matchesExpectedOrigin,reason,tabId});
  const check=()=>{if(!current()||Date.now()>=request.deadlineUnixMs)throw 'authorityChanged';};
  const read=async()=>{
   check();const windows=await api.windows.getAll({populate:false,windowTypes:['normal']});check();
   if(!Array.isArray(windows)||windows.length>64)throw 'tabUnavailable';
   const focused=windows.filter(window=>window?.focused===true);if(focused.length>1)throw 'ambiguousFocusedTab';
   const window=focused.length?focused[0]:await api.windows.getLastFocused({populate:false,windowTypes:['normal']});check();
   if(!window)throw 'noFocusedWindow';
   const windowFocused=window.focused===true,evidence=windowFocused?'extensionFocusedTab':'extensionLastActiveTab';if(!Number.isSafeInteger(window.id)||window.id<0||window.incognito===true)throw 'unsafeTab';
   const tabs=await api.tabs.query({windowId:window.id,active:true});check();
   if(!Array.isArray(tabs)||tabs.length!==1)throw tabs?.length>1?'ambiguousFocusedTab':'tabUnavailable';
   const tab=tabs[0];if(!tab||!Number.isSafeInteger(tab.id)||tab.id<=0||tab.windowId!==window.id||tab.active!==true||tab.incognito===true||tab.discarded===true)throw 'unsafeTab';
   if(tab.pendingUrl!==undefined&&tab.pendingUrl!=='')throw 'pendingNavigation';
   if(tab.status!=='complete')throw 'pendingNavigation';
   if(typeof tab.url!=='string'||!tab.url||tab.url.length>16384)throw 'tabUnavailable';
   let url;try{url=new URL(tab.url);}catch{throw 'unsupportedLocation';}
   if(!['https:','http:'].includes(url.protocol)||url.username||url.password)throw 'unsupportedLocation';
   return {windowId:window.id,tabId:tab.id,origin:url.origin,windowFocused,evidence};
  };
  try{
   check();if(!await api.permissions.contains({origins:[expected.origin+'/*']}))throw 'permissionUnavailable';check();
   const before=await read(),after=await read();check();if(!await api.permissions.contains({origins:[expected.origin+'/*']}))throw 'permissionUnavailable';check();if(before.windowId!==after.windowId||before.tabId!==after.tabId||before.origin!==after.origin||before.windowFocused!==after.windowFocused||before.evidence!==after.evidence)throw 'authorityChanged';
   const matches=before.origin===expected.origin;return reply(true,matches,'none',matches?before.tabId:0,before.windowFocused);
  }catch(reason){return reply(false,false,reasons.has(reason)?reason:'tabUnavailable');}
 }
 return {respond};
})();
if(typeof module!=='undefined')module.exports=globalThis.MechanizeFocusedLocation;
