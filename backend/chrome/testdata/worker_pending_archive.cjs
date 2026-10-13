// Production worker, disposable in-memory Chrome storage. No user browser/data.
const fs=require('node:fs'),vm=require('node:vm'),path=require('node:path'),crypto=require('node:crypto');
(async()=>{
 const input=JSON.parse(fs.readFileSync(0,'utf8')),command=input.command,scope=command.scopeHash;
 const fence=(id)=>({brokerEpoch:id,channelEpoch:id,scopeHash:scope}),old={...fence('original'),mutationFingerprintVersion:2,leaseRequired:true,trustScope:'desktop',scopeQualified:true,profileQualified:false};
 const history=Array.from({length:36},(_,i)=>({nonce:(i+100).toString(16).padStart(64,'0'),oldFence:fence('history-'+i),newFence:i===35?fence('original'):fence('history-'+(i+1)),executors:i===0?[]:Array.from({length:24},(_,n)=>({identity:{profileChannel:'p1',browserInstance:'b1',tabId:n+20,frameId:0,documentId:'original-'+n,documentGeneration:1},receiptRevision:3,receiptCount:3}))}));
 const predecessor={version:1,phase:'pending',nonce:'c'.repeat(64),oldFence:history[0].oldFence,newFence:fence('abandoned-original'),history:[]};
 const journal={version:2,phase:'pending',nonce:'d'.repeat(64),oldFence:fence('original'),newFence:fence('abandoned-second'),history,recovery:{kind:'emptySetupDocuments',originalPending:predecessor}};
 const original=JSON.stringify(journal),local={lastGrant:old,mechanizeReconnect:journal,enrollment:{profileChannel:'p1',browserInstance:'b1',origins:['https://fixture.test']}},session={};
 const events={addListener(){}};let context,interrupted=false,interrupt=true;const messages=[];
 const storage=values=>({async setAccessLevel(options){if(options?.accessLevel!=='TRUSTED_CONTEXTS')throw Error('unexpected storage access level');},async get(key){return key===null?{...values}:Object.hasOwn(values,key)?{[key]:values[key]}:{}},async set(value){Object.assign(values,value);if(interrupt&&value.mechanizeReconnect?.phase==='pending'&&value.mechanizeReconnect.recovery?.originalPendingRef){interrupted=true;context.fixtureDisconnect();}}});
 const chrome={permissions:{contains:async()=>true},storage:{local:storage(local),session:storage(session)},runtime:{id:'fixture',getManifest:()=>({version:'fixture'}),getURL:value=>'chrome-extension://fixture/'+value,onMessage:events,sendMessage:async()=>{},connectNative:()=>({onMessage:events,onDisconnect:events,disconnect(){},postMessage:value=>messages.push(JSON.parse(JSON.stringify(value)))})},tabs:{query:async()=>[],onRemoved:events},webNavigation:{getAllFrames:async()=>[],onCommitted:events}};
 const root=path.resolve(__dirname,'../../../extension/chrome');
 async function boot(c){
  messages.length=0;context=vm.createContext({chrome,TextEncoder,URL,Date,setTimeout,clearTimeout,crypto:crypto.webcrypto});
 require('./load_worker.cjs')(context,root,'globalThis.fixtureReceive=receive;globalThis.fixtureDisconnect=closeNativeConnection;');
  for(let i=0;i<100&&!messages.some(m=>m.type==='hello');i++)await new Promise(r=>setTimeout(r,5));await context.fixtureReceive(c);
 }
 await boot(command);if(!interrupted||messages.some(m=>m.type==='executorPrepared'))throw Error('interruption not retained');
 const pending=JSON.parse(JSON.stringify(local.mechanizeReconnect)),ref=pending.recovery.originalPendingRef,key='mechanizeReconnectPendingArchive:'+ref.digest;
 if(local[key]?.pendingJSON!==original||crypto.createHash('sha256').update(original).digest('hex')!==ref.digest)throw Error('original bytes changed');
 const archive=JSON.stringify(local[key]);interrupt=false;
 await boot({...command,brokerEpoch:command.brokerEpoch+'-restart',channelEpoch:command.channelEpoch+'-restart',executorChallenge:'restart-proof'});
 if(!messages.some(m=>m.type==='executorPrepared')||JSON.stringify(local[key])!==archive)throw Error('restart did not preserve/qualify');
 process.stdout.write(JSON.stringify({pending,originalBytes:Buffer.byteLength(original),preserved:true,restarted:true}));
})().catch(e=>{process.stderr.write('pending archive fixture failed: '+e.message+'\n');process.exitCode=1;});
