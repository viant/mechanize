// In-memory Chrome APIs; executes the production worker and journal, no browser.
const fs=require('node:fs'),vm=require('node:vm'),path=require('node:path');
(async()=>{
 const input=JSON.parse(fs.readFileSync(0,'utf8'));
 const responses=[], local={enrollment:{profileChannel:'p1',browserInstance:'b1',origins:['https://fixture.test']}},session={};
 const event={addListener(){}};
 const storage=values=>({async get(key){return key===null?{...values}:Object.hasOwn(values,key)?{[key]:values[key]}:{}},async set(value){Object.assign(values,value)}});
 const chrome={permissions:{contains:async()=>true},storage:{local:storage(local),session:storage(session)},runtime:{id:'fixture',getManifest:()=>({version:'fixture'}),getURL:value=>'chrome-extension://fixture/'+value,onMessage:event,sendMessage:async()=>{},connectNative:()=>({onMessage:event,onDisconnect:event,postMessage:value=>responses.push(JSON.parse(JSON.stringify(value)))})},tabs:{query:async()=>[],onRemoved:event},webNavigation:{getAllFrames:async()=>[],onCommitted:event}};
 const context=vm.createContext({chrome,TextEncoder,URL,Date,setTimeout,clearTimeout,crypto:require('node:crypto').webcrypto});
 const root=path.resolve(__dirname,'../../../extension/chrome');
 for(const file of ['protocol.js','protection-scopes.js','focused-location.js','tab-metadata.js','control-badge-metadata.js','connection-lifecycle.js','browser.js','cdp-transport.js','browser-input.js','secure-input.js','retirement.js','setup-metadata.js','controller.js','fingerprint.js','playwright-target.js','playwright-relay.js','playwright-worker.js'])vm.runInContext(fs.readFileSync(path.join(root,file),'utf8'),context);
 const worker=fs.readFileSync(path.join(root,'worker.js'),'utf8').replace(/import "\.\/(protocol|tab-metadata|control-badge-metadata|protection-scopes|focused-location|connection-lifecycle|browser|retirement|setup-metadata|controller|fingerprint|secure-input|browser-input|cdp-transport|playwright-target|playwright-relay|playwright-worker)\.js";/g,'');
 vm.runInContext(worker+'\nglobalThis.fixtureReceive=receive;',context);
 await new Promise(resolve=>setImmediate(resolve));
 await context.fixtureReceive({type:'enrolled',...input.grant});
 for(const command of input.commands)await context.fixtureReceive(command);
 process.stdout.write(JSON.stringify(responses.filter(r=>r.requestId)));
})().catch(()=>{process.stderr.write('worker journal fixture failed\n');process.exitCode=1;});
