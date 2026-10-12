// Own-extension maintenance only. This journal contains no page or input data.
globalThis.MechanizeExtensionMaintenance=(()=>{
 const KEY='mechanizeExtensionMaintenanceV1',MAX_RECORDS=512,MAX_BYTES=262144;
 const closed=(v,keys)=>v&&typeof v==='object'&&!Array.isArray(v)&&Object.keys(v).sort().join()===keys.slice().sort().join();
 const hex=v=>typeof v==='string'&&/^[a-f0-9]{64}$/.test(v);
 const opaque=v=>typeof v==='string'&&/^[A-Za-z0-9._:-]{1,128}$/.test(v);
 const version=v=>typeof v==='string'&&/^\d+(?:\.\d+){0,3}$/.test(v)&&v.split('.').every(n=>Number(n)<=65535);
 const canonical=v=>Array.isArray(v)?'['+v.map(canonical).join(',')+']':v&&typeof v==='object'?'{'+Object.keys(v).sort().map(k=>JSON.stringify(k)+':'+canonical(v[k])).join(',')+'}':JSON.stringify(v);
 const recordKeys=['attemptId','expectedVersion','profileChannel','browserInstance','brokerEpoch','channelEpoch','scopeHash','bootId','dispatchState'];
 function create(api,hooks){
  const bootId=Array.from(crypto.getRandomValues(new Uint8Array(32)),n=>n.toString(16).padStart(2,'0')).join('');
  let owner=null;
  const validRecord=r=>closed(r,recordKeys)&&hex(r.attemptId)&&version(r.expectedVersion)&&hex(r.scopeHash)&&hex(r.bootId)&&r.dispatchState==='unknown'&&['profileChannel','browserInstance','brokerEpoch','channelEpoch'].every(k=>opaque(r[k]));
  async function handle(r,fence,current){
   const status=r?.type==='extension.reloadStatus';
   if(!['extension.reload','extension.reloadStatus'].includes(r?.type)||!closed(r,['type','requestId','attemptId','expectedVersion','brokerEpoch','channelEpoch','scopeHash','deadlineUnixMs'])||!hex(r.requestId)||!hex(r.attemptId)||!version(r.expectedVersion)||!hex(r.scopeHash)||!opaque(r.brokerEpoch)||!opaque(r.channelEpoch)||!Number.isSafeInteger(r.deadlineUnixMs))return null;
   const prefix=()=>({type:status?'extension.reloadStatusResult':'extension.reloadResult',requestId:r.requestId,attemptId:r.attemptId,brokerEpoch:r.brokerEpoch,channelEpoch:r.channelEpoch,scopeHash:r.scopeHash});
   const result=(dispatchState,reason,record)=>status?{...prefix(),available:Boolean(record),observedVersion:record?api.runtime.getManifest().version:'',bootChanged:Boolean(record&&record.bootId!==bootId),matchesExpectedVersion:Boolean(record&&record.expectedVersion===api.runtime.getManifest().version),dispatchState,reason}:{...prefix(),dispatchState,reason};
   const check=()=>{if(!fence||!current()||['brokerEpoch','channelEpoch','scopeHash'].some(k=>r[k]!==fence[k])||Date.now()>=r.deadlineUnixMs||r.deadlineUnixMs>Date.now()+10000)throw 'authorityChanged';};
   const wait=async fn=>{check();let timer;try{return await Promise.race([Promise.resolve().then(fn),new Promise((_,reject)=>{timer=setTimeout(()=>reject('authorityChanged'),Math.max(1,r.deadlineUnixMs-Date.now()));})]);}finally{clearTimeout(timer);check();}};
   let reserved=false,writeStarted=false,persisted=false;
   try{
    check();
    if(!status&&owner&&owner!==r.attemptId)return result('notDispatched','busy');
    if(!status&&!owner){if(hooks.busy())return result('notDispatched','busy');owner=r.attemptId;reserved=true;hooks.hold(true);}
    const enrollment=await wait(()=>hooks.config());
    if(!opaque(enrollment?.profileChannel)||!opaque(enrollment?.browserInstance))throw 'authorityChanged';
    await wait(()=>api.storage.local.setAccessLevel({accessLevel:'TRUSTED_CONTEXTS'}));
    const value=(await wait(()=>api.storage.local.get(KEY)))[KEY];
    const journal=value===undefined?{version:1,records:{}}:value;
    if(!closed(journal,['version','records'])||journal.version!==1||!journal.records||typeof journal.records!=='object'||Array.isArray(journal.records)||Object.keys(journal.records).length>MAX_RECORDS||new TextEncoder().encode(JSON.stringify(journal)).length>MAX_BYTES||Object.entries(journal.records).some(([id,row])=>!validRecord(row)||id!==row.attemptId))throw 'receiptUnavailable';
    const old=journal.records[r.attemptId];
    if(old){
     if(old.expectedVersion!==r.expectedVersion||old.profileChannel!==enrollment.profileChannel||old.browserInstance!==enrollment.browserInstance||old.scopeHash!==r.scopeHash)throw 'attemptConflict';
     // A retained intent is never executed again, even if its write ACK or the
     // reload call was lost. New-boot observation does not prove causality.
     return result('unknown',status?(old.expectedVersion!==api.runtime.getManifest().version?'versionMismatch':old.bootId===bootId?'reloadUnconfirmed':'none'):'reloadRequested',old);
    }
    if(status)return result('unknown','notFound');
    if(!reserved)return result('unknown','receiptUnavailable');
    if(Object.keys(journal.records).length>=MAX_RECORDS)throw 'receiptCapacity';
    const record={attemptId:r.attemptId,expectedVersion:r.expectedVersion,profileChannel:enrollment.profileChannel,browserInstance:enrollment.browserInstance,brokerEpoch:r.brokerEpoch,channelEpoch:r.channelEpoch,scopeHash:r.scopeHash,bootId,dispatchState:'unknown'};
    const next={version:1,records:{...journal.records,[r.attemptId]:record}};
    if(new TextEncoder().encode(JSON.stringify(next)).length>MAX_BYTES)throw 'receiptCapacity';
    check();writeStarted=true;await wait(()=>api.storage.local.set({[KEY]:next}));
    const saved=(await wait(()=>api.storage.local.get(KEY)))[KEY];
    if(canonical(saved)!==canonical(next))throw 'receiptUnavailable';persisted=true;
    check();api.runtime.reload();return result('unknown','reloadRequested');
   }catch(reason){return result(writeStarted?'unknown':'notDispatched',['authorityChanged','receiptUnavailable','receiptCapacity','attemptConflict'].includes(reason)?reason:'receiptUnavailable');}
   finally{
    // No pending write can race a later journal read-modify-write. Once the
    // write starts, this boot stays inhibited until reload, even on lost ACK.
    if(reserved&&!writeStarted&&!persisted){owner=null;hooks.hold(false);}
   }
  }
  return {handle};
 }
 return {create,KEY};
})();
