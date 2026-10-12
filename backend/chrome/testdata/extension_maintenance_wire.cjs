const fs=require('node:fs'),vm=require('node:vm'),path=require('node:path');
(async()=>{
 const input=JSON.parse(fs.readFileSync(0,'utf8')),q=input.request;
 const context=vm.createContext({crypto:require('node:crypto').webcrypto,Uint8Array,TextEncoder,Date,setTimeout,clearTimeout});
 vm.runInContext(fs.readFileSync(path.resolve(__dirname,'../../../extension/chrome/extension-maintenance.js'),'utf8'),context);
 let saved=input.saved||{},reloads=0;
 const api={runtime:{getManifest:()=>({version:q.expectedVersion}),reload(){reloads++;}},storage:{local:{async setAccessLevel(o){if(o.accessLevel!=='TRUSTED_CONTEXTS')throw Error();},async get(){return structuredClone(saved)},async set(v){Object.assign(saved,structuredClone(v));}}}};
 const module=context.MechanizeExtensionMaintenance.create(api,{config:()=>({profileChannel:input.profile,browserInstance:input.browser}),busy:()=>false,hold:()=>{}});
 const fence={brokerEpoch:q.brokerEpoch,channelEpoch:q.channelEpoch,scopeHash:q.scopeHash};
 const reply=await module.handle(q,fence,()=>true);
 process.stdout.write(JSON.stringify({reply,saved,reloads}));
})().catch(()=>{process.stderr.write('maintenance fixture failed');process.exitCode=1});
