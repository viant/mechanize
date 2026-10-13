// In-memory Chrome APIs; executes the production worker and journal, no browser.
const fs=require('node:fs'),vm=require('node:vm'),path=require('node:path');
(async()=>{
 const input=JSON.parse(fs.readFileSync(0,'utf8'));
 const responses=[], local={enrollment:{profileChannel:'p1',browserInstance:'b1',origins:['https://fixture.test'],trustScope:'desktop'}},session={};
 const first=input.commands[0],old={brokerEpoch:'old-broker',channelEpoch:'old-channel',scopeHash:first.scopeHash,mutationFingerprintVersion:2,leaseRequired:true,trustScope:first.trustScope,scopeQualified:true,profileQualified:first.profileQualified}; local.lastGrant=old;
 const fence=x=>({brokerEpoch:x.brokerEpoch,channelEpoch:x.channelEpoch,scopeHash:x.scopeHash}); const history=[]; for(let i=0;i<64;i++) history.push({nonce:(i+1).toString(16).padStart(64,'0'),oldFence:{...fence(old),brokerEpoch:'history-'+i,channelEpoch:'history-'+i},newFence:i===63?fence(old):{...fence(old),brokerEpoch:'history-'+(i+1),channelEpoch:'history-'+(i+1)},executors:[]}); const tail=history.at(-1);local.mechanizeReconnect={version:1,phase:'adopted',nonce:tail.nonce,oldFence:tail.oldFence,newFence:tail.newFence,history};
 const original=JSON.stringify(local.mechanizeReconnect);
 const event={addListener(){}};
 const storage=values=>({async setAccessLevel(options){if(options?.accessLevel!=='TRUSTED_CONTEXTS')throw Error('unexpected storage access level');},async get(key){return key===null?{...values}:Object.hasOwn(values,key)?{[key]:values[key]}:{}},async set(value){Object.assign(values,value);if(!input.success)for(const key of Object.keys(value))if(key.startsWith('mechanizeReconnectAudit:'))values[key]={version:1,journalJSON:'{}'};}});
 const chrome={permissions:{contains:async()=>true},storage:{local:storage(local),session:storage(session)},runtime:{id:'fixture',getManifest:()=>({version:'fixture'}),getURL:value=>'chrome-extension://fixture/'+value,onMessage:event,sendMessage:async()=>{},connectNative:()=>({onMessage:event,onDisconnect:event,postMessage:value=>responses.push(JSON.parse(JSON.stringify(value)))})},tabs:{query:async()=>[],onRemoved:event},webNavigation:{getAllFrames:async()=>[],onCommitted:event}};
 async function boot(command){
 const start=responses.length;
 const context=vm.createContext({chrome,TextEncoder,URL,Date,setTimeout,clearTimeout,crypto:require('node:crypto').webcrypto});
 const root=path.resolve(__dirname,'../../../extension/chrome');
 require('./load_worker.cjs')(context,root,'globalThis.fixtureReceive=receive;');
 for(let i=0;i<100&&!responses.slice(start).some(r=>r.type==='hello');i++)await new Promise(resolve=>setTimeout(resolve,5));
 if(!responses.slice(start).some(r=>r.type==='hello'))throw Error('startup-unavailable');
 await context.fixtureReceive(command);return responses.slice(start);
 }
 let frames;for(const command of input.commands){frames=await boot(command);if(input.success&&!frames.some(r=>r.type==='executorPrepared'))throw Error('qualification:'+frames.filter(r=>r.type==='attention').map(r=>r.error?.code+':'+r.reconnectPhase+':'+r.reconnectReason).join(','));}
 const keys=Object.keys(local).filter(k=>k.startsWith('mechanizeReconnectAudit:'));
 if(input.success){if(keys.length!==input.commands.length||!keys.some(key=>local[key].journalJSON===original)||local.mechanizeReconnect.history.length!==1)throw Error('archive-summary:'+keys.length+':'+local.mechanizeReconnect.history.length);}
 else if(!frames.some(r=>r.type==='attention'&&r.reconnectJournal))throw Error();
 process.stdout.write(JSON.stringify({frames:frames.filter(r=>['attention','executorPrepared','documents'].includes(r.type)),preserved:input.success,historyCount:local.mechanizeReconnect.history.length}));
})().catch(error=>{process.stderr.write('worker journal fixture failed '+error.message+'\n');process.exitCode=1;});
