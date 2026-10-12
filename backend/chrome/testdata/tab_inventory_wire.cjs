const fs=require('node:fs'),vm=require('node:vm'),path=require('node:path');
(async()=>{
 const q=JSON.parse(fs.readFileSync(0,'utf8'));
 const root=path.resolve(__dirname,'../../../extension/chrome');
 vm.runInThisContext(fs.readFileSync(path.join(root,'protocol.js'),'utf8'));
 vm.runInThisContext(fs.readFileSync(path.join(root,'tab-metadata.js'),'utf8'));
 let queries=0,permissions=0;
 const api={permissions:{async contains(p){permissions++;if(JSON.stringify(p)!==JSON.stringify({origins:[q.expectedOrigin+'/*']}))throw Error('unexpectedpermission');return true;}},tabs:{async query(filter){queries++;if(JSON.stringify(filter)!==JSON.stringify({url:q.expectedOrigin+'/*'}))throw Error('unexpectedquery');return [{id:9,incognito:false,url:q.expectedOrigin+'/public',title:'PRIVATE_CANARY',status:'loading',get pendingUrl(){throw Error('pendingURLread');}},{id:7,incognito:false,url:q.expectedOrigin+'/public',title:'PRIVATE_CANARY',discarded:true}];}}};
 const fence={brokerEpoch:q.brokerEpoch,channelEpoch:q.channelEpoch,scopeHash:q.scopeHash};
 const answer=await MechanizeTabMetadata.inventory(api,q,fence,{profileChannel:'metadata-channel',browserInstance:'browser',origins:[q.expectedOrigin]},()=>true);
 if(!answer?.complete||queries!==1||permissions!==2||JSON.stringify(answer).includes('PRIVATE_CANARY'))throw Error('productionmetadatafailed');
 process.stdout.write(JSON.stringify(answer));
})().catch(()=>{process.stderr.write('metadata fixture failed');process.exitCode=1;});
