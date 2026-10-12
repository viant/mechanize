const {test}=require('node:test');
const assert=require('node:assert/strict');
const vm=require('node:vm');
const fs=require('node:fs');
function fixture(origin='http://localhost:3000') {
 const events={}, sent=[], outward=[],state={nativeReady:true,disconnectOutward:[],autoAcknowledge:true};
 const event=k=>({addListener:f=>events[k]=f});
 const chrome={runtime:{id:'id',getURL:p=>'chrome-extension://id/'+p,onMessage:event('local'),onConnectExternal:event('external')},webNavigation:{onCommitted:event('navigate'),getFrame:async()=>({url:origin+'/shell',documentId:'d1'})},tabs:{onRemoved:event('removed')}};
 const timers=new Map();let next=0;
 const ctx=vm.createContext({URL,Date:class extends Date{static now(){return state.now??Date.now();}},TextEncoder,TextDecoder,atob,btoa,crypto:require('node:crypto').webcrypto,setTimeout:(f,delay)=>{timers.set(++next,{f,delay});return next},clearTimeout:id=>timers.delete(id)});
 vm.runInContext(fs.readFileSync(require('node:path').join(__dirname,'../controller.js'),'utf8'),ctx);
 const bridge=ctx.MechanizeController.install(chrome,{binding:()=>state.nativeReady?(state.binding||{brokerEpoch:'b',channelEpoch:'c',scopeHash:'h'}):null,send:m=>sent.push(m)});
 const p={name:'mechanize-controller-v1',sender:{url:origin+'/shell',origin,frameId:0,tab:{id:7},documentId:'d1'},postMessage:m=>{outward.push(m);if(m.type==='setupRefused'&&state.autoAcknowledge)events.message({type:'setupRefusedAck'});},disconnect:()=>{p.disconnected=true;state.disconnectOutward=outward.slice();},onMessage:event('message'),onDisconnect:event('disconnect')};
 const binding={brokerEpoch:'b',channelEpoch:'c',scopeHash:'h'};
 bridge.receive({type:'controllerPolicy',enabled:true,origins:['http://localhost:3000','https://steward.agently.viantinc.com'],...binding});
 const approve=async()=>{bridge.receive({type:'controllerApproval',sessionId:sent[0].sessionId,...binding});await new Promise(resolve=>setImmediate(resolve));sent.length=0;};
 return {events,sent,outward,p,bridge,approve,binding,state,timers};
}
const request=()=>({type:'request',requestId:'r1',operation:'connection.status',deadlineUnixMs:Date.now()+5000});
test('standard initialization metadata and empty list params negotiate without entering native requests',async()=>{
 const f=fixture();f.events.external(f.p);await f.approve();
 await f.events.message({...request(),operation:'initialize',params:{protocolVersion:'2025-03-26',capabilities:{},clientInfo:{name:'fixture-client',version:'1.0'}}});
 assert.equal(f.p.disconnected,undefined);assert.equal(f.sent.length,1);assert.equal(f.sent[0].operation,'initialize');assert.equal(Object.hasOwn(f.sent[0],'params'),false);
 f.bridge.receive({type:'controllerResult',requestId:f.sent[0].requestId,result:{protocolVersion:'2025-03-26',capabilities:{tools:{}},serverInfo:{name:'mechanize',version:'1.0'}}});
 assert.equal(f.outward.at(-1).result.serverInfo.name,'mechanize');
 await f.events.message({...request(),requestId:'r2',operation:'tools/list',params:{}});
 assert.equal(f.sent[1].operation,'tools/list');assert.equal(Object.hasOwn(f.sent[1],'params'),false);
});
test('negotiation metadata cannot add native authority fields or loosen other request schemas',async()=>{
 const initialize={protocolVersion:'2025-03-26',capabilities:{},clientInfo:{name:'fixture-client',version:'1.0'}};
 for(const [operation,params] of [['initialize',null],['initialize',{}],['initialize',{...initialize,sessionId:'foreign'}],['initialize',{...initialize,capabilities:[]}],['initialize',{...initialize,clientInfo:{name:'fixture-client'}}],['initialize',{...initialize,clientInfo:{name:'x'.repeat(65536),version:'1'}}],['tools/list',{cursor:'unsupported'}],['connection.status',{}]]){
  const f=fixture();f.events.external(f.p);await f.approve();await f.events.message({...request(),operation,params});
  assert.equal(f.p.disconnected,true);assert.equal(f.sent.filter(x=>x.type==='controllerRequest').length,0);
 }
});
test('exact origins independent of website permission',()=>{
 for(const origin of ['https://fixture.example.test','http://localhost:3001','https://steward.viantinc.com','https://evil.steward.agently.viantinc.com']) {const f=fixture(origin);f.events.external(f.p);assert.equal(f.p.disconnected,true);}
});
test('approval bound to a live document; native responses are projected',async()=>{
 const f=fixture();f.events.external(f.p);
 await f.approve();
 await f.events.message(request());assert.equal(f.sent.length,1);assert.equal(f.sent[0].documentId,'d1');
 f.bridge.receive({type:'controllerResult',requestId:f.sent[0].requestId,ready:true,secret:'never-forward'});
 assert.equal(f.outward.at(-1).error,'unavailable');assert.equal(JSON.stringify(f.outward).includes('never-forward'),false);
 f.events.navigate({tabId:7,frameId:0});assert.equal(f.p.disconnected,true);
 await f.events.message({...request(),requestId:'r2'});assert.equal(f.sent.filter(x=>x.type==='controllerRequest').length,1);
});
test('unapproved pages cannot call and reconnect requires approval',async()=>{
 const f=fixture();f.events.external(f.p);await f.events.message(request());assert.equal(f.sent.filter(x=>x.type==='controllerRequest').length,0);assert.equal(f.p.disconnected,true);
});
test('native disconnection revokes sessions',()=>{const f=fixture();f.events.external(f.p);f.bridge.reset();assert.equal(f.p.disconnected,true)});
test('successful reply correlates once; duplicate requests revoke',async()=>{
 const f=fixture('https://steward.agently.viantinc.com');f.events.external(f.p);
 await f.approve();
 await f.events.message(request());
 f.bridge.receive({type:'controllerResult',requestId:f.sent[0].requestId,ready:true});assert.equal(f.outward.at(-1).ready,true);assert.equal(f.outward.at(-1).requestId,'r1');
 const count=f.outward.length;f.bridge.receive({type:'controllerResult',requestId:f.sent[0].requestId,ready:true});assert.equal(f.outward.length,count);
 await f.events.message(request());assert.equal(f.p.disconnected,true);assert.equal(f.sent.filter(x=>x.type==='controllerRequest').length,1);
});
test('subframes and sender origin mismatch are denied',()=>{
 for(const changes of [{frameId:1},{origin:'https://fixture.example.test'},{documentId:''}]){const f=fixture();Object.assign(f.p.sender,changes);f.events.external(f.p);assert.equal(f.p.disconnected,true)}
});
test('only native policy configures origins; reconfiguration revokes',async()=>{
 const f=fixture('https://shell.fixture.test');
 f.bridge.receive({type:'controllerPolicy',enabled:true,origins:['https://shell.fixture.test'],...f.binding});
 f.events.external(f.p);await f.approve();await f.events.message(request());assert.equal(f.sent[0].type,'controllerRequest');
 f.bridge.receive({type:'controllerPolicy',enabled:false,origins:['https://shell.fixture.test'],...f.binding});assert.equal(f.p.disconnected,true);
 assert.equal(f.events.local,undefined);
});
test('catalog is closed and cannot carry extra secret output',async()=>{
 const f=fixture();f.events.external(f.p);await f.approve();await f.events.message({...request(),operation:'tools.list'});
 f.bridge.receive({type:'controllerResult',requestId:f.sent[0].requestId,tools:['connection.status','tools.list','browser.inventory.summary']});assert.equal(f.outward.at(-1).tools.length,3);
});
test('stale channel policy cannot authorize a new origin',()=>{
 const f=fixture('https://shell.fixture.test');
 f.bridge.receive({type:'controllerPolicy',enabled:true,origins:['https://shell.fixture.test'],...f.binding,channelEpoch:'stale'});
 f.events.external(f.p);assert.equal(f.p.disconnected,true);
});
test('deadline and raw-argument requests revoke without native dispatch',async()=>{
 for(const change of [{deadlineUnixMs:Date.now()-1},{deadlineUnixMs:Date.now()+60000},{arguments:{code:'arbitrary'}},{operation:'vault.read'}]){
  const f=fixture();f.events.external(f.p);await f.approve();await f.events.message({...request(),...change});assert.equal(f.p.disconnected,true);assert.equal(f.sent.filter(x=>x.type==='controllerRequest').length,0);
 }
});
test('standard MCP tools/call requires canonical catalog and projects only text structured results',async()=>{
 const f=fixture();f.events.external(f.p);await f.approve();
 await f.events.message({...request(),operation:'tools/list'});
 f.bridge.receive({type:'controllerResult',requestId:f.sent[0].requestId,result:{tools:[{name:'mechanize_session_open',inputSchema:{type:'object',properties:{name:{type:'string'}}}}]}});
 await f.events.message({...request(),requestId:'r2',operation:'tools/call',params:{name:'mechanize_session_open',arguments:{name:'fixture'}}});
 assert.equal(f.sent[1].params.name,'mechanize_session_open');assert.equal(f.sent[1].sessionId,f.sent[0].sessionId);
 f.bridge.receive({type:'controllerResult',requestId:f.sent[1].requestId,result:{content:[{type:'text',text:'{"sessionId":"owned"}'}],structuredContent:{sessionId:'owned'}}});assert.equal(f.outward.at(-1).result.structuredContent.sessionId,'owned');
 await f.events.message({...request(),requestId:'r3',operation:'tools/call',params:{name:'mechanize_session_open',arguments:{}}});
 f.bridge.receive({type:'controllerResult',requestId:f.sent[2].requestId,result:{content:[{type:'resource',uri:'secret://value'}],structuredContent:{}}});assert.equal(f.outward.at(-1).error,'unavailable');assert.equal(JSON.stringify(f.outward).includes('secret://'),false);
});
test('canonical skill discovery and retrieval survive MCP catalog projection',async()=>{
 const f=fixture();f.events.external(f.p);await f.approve();
 await f.events.message({...request(),operation:'tools/list'});
 const tools=['mechanize_capabilities','skill_list','skill_get'].map(name=>({name,inputSchema:{type:'object'}}));
 f.bridge.receive({type:'controllerResult',requestId:f.sent[0].requestId,result:{tools}});
 assert.deepEqual(Array.from(f.outward.at(-1).result.tools,t=>t.name),tools.map(t=>t.name));
 await f.events.message({...request(),requestId:'r2',operation:'tools/call',params:{name:'skill_list',arguments:{}}});
 assert.equal(f.sent[1].params.name,'skill_list');
 await f.events.message({...request(),requestId:'r3',operation:'tools/call',params:{name:'skill_get',arguments:{uri:'skill://fixture'}}});
 assert.equal(f.sent[2].params.name,'skill_get');
});
test('catalog projection rejects other unprefixed tool names',async()=>{
 for(const name of ['skill_delete','tool_read','system_exec']){
  const f=fixture();f.events.external(f.p);await f.approve();
  await f.events.message({...request(),operation:'tools/list'});
  f.bridge.receive({type:'controllerResult',requestId:f.sent[0].requestId,result:{tools:[{name,inputSchema:{type:'object'}}]}});
  assert.equal(f.outward.at(-1).error,'unavailable');
  await f.events.message({...request(),requestId:'r2',operation:'tools/call',params:{name,arguments:{}}});
  assert.equal(f.p.disconnected,true);assert.equal(f.sent.filter(m=>m.type==='controllerRequest').length,1);
 }
});
test('missing optional Chrome sender fields refuse with only presence flags before disconnect',()=>{
 for(const field of ['origin','frameId','tab','documentId']){
  const f=fixture();delete f.p.sender[field];f.events.external(f.p);
  assert.equal(f.p.disconnected,true);assert.equal(f.sent.length,0);
  const diagnostic=f.state.disconnectOutward.at(-1);assert.equal(diagnostic.type,'setupRefused');assert.equal(diagnostic.stage,'senderQualification');assert.equal(diagnostic.code,'senderMetadataUnavailable');
  assert.deepEqual(Object.keys(diagnostic).sort(),['code','senderPresence','stage','type']);assert.deepEqual(Object.keys(diagnostic.senderPresence).sort(),['documentId','frameId','origin','tabId']);
  assert.equal(diagnostic.senderPresence[field==='tab'?'tabId':field],false);assert.ok(Object.values(diagnostic.senderPresence).every(v=>typeof v==='boolean'));
  assert.ok(!JSON.stringify(diagnostic).includes('http://localhost'));assert.ok(!JSON.stringify(diagnostic).includes('d1'));
 }
});
test('sender refusal reasons remain closed without echoing invalid identity values',()=>{
 for(const [change,code] of [[{origin:'https://PRIVATE-CANARY.test'},'senderOriginMismatch'],[{frameId:1},'senderFrameDenied'],[{tab:{id:-1}},'senderTabInvalid'],[{documentId:'PRIVATE-CANARY'.repeat(20)},'senderDocumentInvalid'],[{url:'PRIVATE-CANARY'},'senderURLInvalid']]){
  const f=fixture();Object.assign(f.p.sender,change);f.events.external(f.p);
  assert.equal(f.state.disconnectOutward.at(-1).code,code);assert.equal(f.sent.length,0);assert.ok(!JSON.stringify(f.outward).includes('PRIVATE-CANARY'));
 }
 const f=fixture();f.p.sender=undefined;f.events.external(f.p);assert.equal(f.state.disconnectOutward.at(-1).code,'senderURLInvalid');
});
test('missing native channel has a distinct closed setup refusal and retains no session',()=>{
 const f=fixture();f.state.nativeReady=false;f.events.external(f.p);
 assert.equal(f.p.disconnected,true);assert.equal(f.sent.length,0);
 const diagnostic=f.state.disconnectOutward.at(-1);assert.equal(diagnostic.type,'setupRefused');assert.equal(diagnostic.stage,'nativeQualification');assert.equal(diagnostic.code,'nativeChannelUnavailable');
 assert.deepEqual(Object.values(diagnostic.senderPresence),[true,true,true,true]);
});
test('queued refusal arrives before close and only exact acknowledgement closes early',async()=>{
 const f=fixture();f.state.autoAcknowledge=false;delete f.p.sender.documentId;
 const queued=[];f.p.postMessage=message=>queued.push(()=>{if(!f.p.disconnected)f.outward.push(message);});
 f.events.external(f.p);assert.equal(f.p.disconnected,undefined);assert.equal(f.outward.length,0);assert.equal(f.sent.length,0);
 assert.equal(f.timers.size,1);assert.equal([...f.timers.values()][0].delay,1000);
 queued.forEach(deliver=>deliver());assert.equal(f.outward.at(-1).code,'senderMetadataUnavailable');
 await f.events.message({...request(),operation:'initialize'});assert.equal(f.sent.length,0);assert.equal(f.p.disconnected,undefined);
 await f.events.message({type:'setupRefusedAck',sessionId:'foreign'});assert.equal(f.p.disconnected,undefined);
 await f.events.message({type:'setupRefusedAck'});assert.equal(f.p.disconnected,true);assert.equal(f.timers.size,0);
});
test('unacknowledged and client-closed refusals have bounded notification-only lifetimes',()=>{
 for(const clientClosed of [false,true]){
  const f=fixture();f.state.nativeReady=false;f.state.autoAcknowledge=false;f.events.external(f.p);
  assert.equal(f.outward.at(-1).code,'nativeChannelUnavailable');assert.equal(f.p.disconnected,undefined);assert.equal(f.sent.length,0);assert.equal(f.timers.size,1);
  if(clientClosed){f.events.disconnect();assert.equal(f.timers.size,0);}
  else {[...f.timers.values()][0].f();assert.equal(f.p.disconnected,true);assert.equal(f.timers.size,0);}
 }
});
test('policy synchronization failures remain distinct from an excluded origin',()=>{
 for(const mode of ['unavailable','disabled','invalid','excluded']){
  const f=fixture();f.bridge.reset();
  if(mode==='disabled')f.bridge.receive({type:'controllerPolicy',enabled:false,origins:[],...f.binding});
  if(mode==='invalid')f.bridge.receive({type:'controllerPolicy',enabled:true,origins:['not-an-origin'],...f.binding});
  if(mode==='excluded')f.bridge.receive({type:'controllerPolicy',enabled:true,origins:['https://another.fixture.test'],...f.binding});
  if(mode==='unavailable')f.bridge.receive({type:'controllerPolicy',enabled:true,origins:['http://localhost:3000'],...f.binding,channelEpoch:'stale'});
  f.events.external(f.p);assert.equal(f.sent.length,0);const diagnostic=f.state.disconnectOutward.at(-1);
  assert.equal(diagnostic.code,{unavailable:'controllerPolicyUnavailable',disabled:'controllerPolicyDisabled',invalid:'controllerPolicyInvalid',excluded:'controllerOriginDenied'}[mode]);assert.equal(diagnostic.stage,mode==='excluded'?'senderQualification':'policyQualification');
 }
});

test('identical authenticated policy synchronization preserves pending and approved document sessions',async()=>{
 for(const approved of [false,true]){
  const f=fixture();f.events.external(f.p);if(approved)await f.approve();
  const timers=f.timers.size;
  f.bridge.receive({type:'controllerPolicy',enabled:true,origins:['https://steward.agently.viantinc.com','http://localhost:3000'],...f.binding});
  assert.equal(f.p.disconnected,undefined);assert.equal(f.timers.size,timers);
  if(!approved)await f.approve();
  await f.events.message(request());assert.equal(f.sent.filter(m=>m.type==='controllerRequest').length,1);
  f.bridge.receive({type:'controllerPolicy',enabled:true,origins:['http://localhost:3000'],...f.binding});assert.equal(f.p.disconnected,true);
 }
});

test('localhost port policies qualify actual sender and preserve exact document origin',async()=>{
 for(const pattern of ['localhost:*','http://localhost:*','https://localhost:*'])for(const origin of ['http://localhost','https://localhost','http://localhost:49173','https://localhost:65535']){
  const f=fixture(origin);f.bridge.receive({type:'controllerPolicy',enabled:true,origins:[pattern],...f.binding});f.events.external(f.p);
  const allowed=pattern==='localhost:*'||pattern.split('://')[0]+':'===new URL(origin).protocol;
  assert.equal(f.sent.some(m=>m.type==='controllerOpen'),allowed,pattern+' '+origin);
  if(!allowed)continue;
  assert.equal(f.sent[0].origin,origin);await f.approve();await f.events.message(request());assert.equal(f.sent[0].origin,origin);
  f.bridge.receive({type:'controllerPolicy',enabled:true,origins:['https://fixture.test'],...f.binding});assert.equal(f.p.disconnected,true);
 }
});
test('localhost wildcard excludes forged sender metadata and nonexact host policy',()=>{
 for(const origin of ['http://127.0.0.1:3000','http://localhost.evil:3000','https://evil.localhost:3000','http://localhost.:3000','http://localhost:0']){
  const f=fixture(origin);f.bridge.receive({type:'controllerPolicy',enabled:true,origins:['localhost:*'],...f.binding});f.events.external(f.p);assert.equal(f.p.disconnected,true);assert.equal(f.sent.length,0);
 }
 for(const pattern of ['*','*.localhost:*','localhost:*/path','http://localhost:*/','https://user@localhost:*','https://localhost:*?x=1','https://localhost:*#x','https://localhost.evil:*','http://127.0.0.1:*']){
  const f=fixture();f.bridge.receive({type:'controllerPolicy',enabled:true,origins:[pattern],...f.binding});f.events.external(f.p);assert.equal(f.p.disconnected,true);assert.equal(f.sent.length,0);
 }
 for(const mode of ['origin','url','frame']){
  const f=fixture('http://localhost:49173');f.bridge.receive({type:'controllerPolicy',enabled:true,origins:['localhost:*'],...f.binding});
  if(mode==='origin')f.p.sender.origin='http://localhost:3000';if(mode==='url')f.p.sender.url='http://user:private@localhost:49173/app';if(mode==='frame')f.p.sender.frameId=1;
  f.events.external(f.p);assert.equal(f.p.disconnected,true);assert.equal(f.sent.length,0);
 }
});

test('document controller cannot follow a changed native fence before policy resynchronizes',async()=>{
 const f=fixture();f.events.external(f.p);await f.approve();
 // The injected native adapter models a same-port epoch replacement. The
 // original document session must not borrow that replacement authority.
 f.state.binding={...f.binding,channelEpoch:'replacement'};
 await f.events.message(request());
 assert.equal(f.p.disconnected,true);
 assert.equal(f.sent.some(m=>m.type==='controllerRequest'),false);
});


function imageFixturePNG(){
 const zlib=require('node:zlib');const crc=b=>{let c=0xffffffff;for(const v of b){c^=v;for(let n=0;n<8;n++)c=c&1?(c>>>1)^0xedb88320:c>>>1;}return (c^0xffffffff)>>>0;};
 const chunk=(type,data)=>{const name=Buffer.from(type),out=Buffer.alloc(12+data.length);out.writeUInt32BE(data.length);name.copy(out,4);data.copy(out,8);out.writeUInt32BE(crc(Buffer.concat([name,data])),8+data.length);return out;};
 const width=320,height=320,rows=Buffer.alloc(height*(1+width*4));let x=17;
 for(let y=0;y<height;y++)for(let col=0;col<width*4;col++){x=(Math.imul(x,1664525)+1013904223)>>>0;rows[y*(1+width*4)+1+col]=col%4===3?255:x>>>24;}
 const header=Buffer.alloc(13);header.writeUInt32BE(width);header.writeUInt32BE(height,4);header[8]=8;header[9]=6;
 return Buffer.concat([Buffer.from([137,80,78,71,13,10,26,10]),chunk('IHDR',header),chunk('IDAT',zlib.deflateSync(rows)),chunk('IEND',Buffer.alloc(0))]);
}
async function imageCall(){const f=fixture();f.events.external(f.p);await f.approve();await f.events.message({...request(),operation:'tools/list'});f.bridge.receive({type:'controllerResult',requestId:f.sent[0].requestId,result:{tools:[{name:'mechanize_capture',inputSchema:{type:'object'}}]}});await f.events.message({...request(),requestId:'image-call',operation:'tools/call',params:{name:'mechanize_capture',arguments:{}}});return f;}
function imageChunks(f,result){const bytes=Buffer.from(JSON.stringify(result)),size=96*1024,r=f.sent.at(-1),hash=require('node:crypto').createHash('sha256').update(bytes).digest('hex');return Array.from({length:Math.ceil(bytes.length/size)},(_,sequence)=>({type:'controllerResultChunk',requestId:r.requestId,sessionId:r.sessionId,...f.binding,deadlineUnixMs:r.deadlineUnixMs,sequence,count:Math.ceil(bytes.length/size),totalBytes:bytes.length,sha256:hash,data:bytes.subarray(sequence*size,(sequence+1)*size).toString('base64')}));}
const imageResult=()=>({content:[{type:'text',text:'before'},{type:'image',mimeType:'image/png',data:imageFixturePNG().toString('base64'),annotations:{audience:['assistant'],priority:0.5}},{type:'text',text:'after'}],structuredContent:{width:320,_meta:{business:'preserved'}},isError:false});
async function imageTerminal(f){for(let n=0;n<200;n++){const result=f.outward.find(v=>v.type==='result'&&v.requestId==='image-call');if(result)return result;await new Promise(resolve=>setTimeout(resolve,5));}throw Error('terminal result missing');}

test('chunked real PNG preserves canonical content ordering MIME annotations and structured business metadata once',async()=>{
 const f=await imageCall(),result=imageResult(),chunks=imageChunks(f,result);assert.ok(chunks.length>2);assert.ok(Buffer.from(result.content[1].data,'base64').length>192*1024);
 for(const c of chunks){assert.ok(Buffer.byteLength(JSON.stringify(c))<192*1024);assert.equal(f.bridge.receive(c),true);}
 const terminal=await imageTerminal(f);assert.equal(terminal.error,undefined);assert.equal(JSON.stringify(terminal.result),JSON.stringify(result));
 f.bridge.receive(chunks[0]);f.bridge.receive(chunks.at(-1));assert.equal(f.outward.filter(v=>v.requestId==='image-call').length,1);assert.equal(f.sent.filter(v=>v.operation==='tools/call').length,1);
});

test('image chunk transfer rejects malformed ordering identity digest sizes and host metadata without redispatch',async()=>{
 for(const mode of ['outOfOrder','duplicate','digest','session','fence','deadline','count','length','base64','extra','hostMeta','blockMeta','foreignMime','foreignDocument','bindingChanged']){
  const f=await imageCall(),result=imageResult();if(mode==='hostMeta')result._meta={secret:'HOST-CANARY'};if(mode==='blockMeta')result.content[1]._meta={secret:'HOST-CANARY'};if(mode==='foreignMime')result.content[1].mimeType='text/html';
  const chunks=imageChunks(f,result);if(mode==='outOfOrder')chunks.reverse();if(mode==='digest')for(const c of chunks)c.sha256='0'.repeat(64);if(mode==='session')chunks[0].sessionId='foreign';if(mode==='fence')chunks[0].channelEpoch='foreign';if(mode==='deadline')chunks[0].deadlineUnixMs++;if(mode==='count')chunks[0].count++;if(mode==='length')chunks[0].totalBytes++;if(mode==='base64')chunks[0].data='!!!!';if(mode==='extra')chunks[0].secret='HOST-CANARY';if(mode==='bindingChanged')f.state.binding={...f.binding,channelEpoch:'changed'};
  if(mode==='foreignDocument')f.events.navigate({tabId:7,frameId:0});
  for(let i=0;i<chunks.length;i++){f.bridge.receive(chunks[i]);if(mode==='duplicate'&&i===0)f.bridge.receive(chunks[i]);}
  if(mode==='foreignDocument'){await new Promise(resolve=>setImmediate(resolve));assert.equal(f.p.disconnected,true);assert.equal(f.outward.filter(v=>v.requestId==='image-call').length,0);}
  else{const result=await imageTerminal(f);assert.equal(result.error,'resultTransferInvalid',mode);assert.equal(result.dispatchState,'unknown');assert.equal(f.outward.filter(v=>v.requestId==='image-call').length,1);assert.ok(!JSON.stringify(result).includes('HOST-CANARY'));}
  assert.equal(f.sent.filter(v=>v.operation==='tools/call').length,1);
 }
});

test('image transfer original deadline produces one unknown terminal and late chunks cannot revive it',async()=>{
 const f=await imageCall(),chunks=imageChunks(f,imageResult());f.bridge.receive(chunks[0]);
 const timer=[...f.timers.values()].find(v=>v.delay<10000);assert.ok(timer);timer.f();
 const result=await imageTerminal(f);assert.equal(result.error,'resultTransferTimeout');assert.equal(result.dispatchState,'unknown');
 for(const c of chunks)f.bridge.receive(c);await new Promise(resolve=>setImmediate(resolve));assert.equal(f.outward.filter(v=>v.requestId==='image-call').length,1);assert.equal(f.sent.filter(v=>v.operation==='tools/call').length,1);
});


test('late unchunked reply cannot erase the original terminal deadline',async()=>{
 const f=await imageCall(),r=f.sent.at(-1);f.state.now=r.deadlineUnixMs+1;
 f.bridge.receive({type:'controllerResult',requestId:r.requestId,result:{content:[{type:'text',text:'too late'}]}});
 const result=await imageTerminal(f);assert.equal(result.error,'resultTransferTimeout');assert.equal(result.dispatchState,'unknown');
 for(const timer of [...f.timers.values()])if(timer.delay<10000)timer.f();assert.equal(f.outward.filter(v=>v.requestId==='image-call').length,1);
});

test('concurrent result assembly reserves a bounded aggregate and timeout releases capacity',async()=>{
 const f=await imageCall();
 const first=id=>{const r=f.sent.at(-1);return {type:'controllerResultChunk',requestId:r.requestId,sessionId:r.sessionId,...f.binding,deadlineUnixMs:r.deadlineUnixMs,sequence:0,count:128,totalBytes:12*1024*1024,sha256:'a'.repeat(64),data:Buffer.alloc(96*1024).toString('base64')};};
 f.bridge.receive(first());
 for(const id of ['second','third']){await f.events.message({...request(),requestId:id,operation:'tools/call',params:{name:'mechanize_capture',arguments:{}}});f.bridge.receive(first());}
 const rejected=f.outward.find(v=>v.requestId==='third');assert.equal(rejected.error,'resultTransferTooLarge');assert.equal(rejected.dispatchState,'unknown');
 for(const timer of [...f.timers.values()])if(timer.delay<10000)timer.f();
 await f.events.message({...request(),requestId:'fourth',operation:'tools/call',params:{name:'mechanize_capture',arguments:{}}});f.bridge.receive(first());assert.equal(f.outward.some(v=>v.requestId==='fourth'),false);
 assert.equal(f.sent.filter(v=>v.operation==='tools/call').length,4);
});
test('canonical catalog allows sixty-four explicit tools within unchanged byte budget',async()=>{
 for(const [count,description,accepted] of [[64,'',true],[65,'',false],[34,'x'.repeat(6000),false]]){
  const f=fixture();f.events.external(f.p);await f.approve();await f.events.message({...request(),operation:'tools/list'});
  const tools=Array.from({length:count},(_,i)=>({name:`mechanize_fixture_${String.fromCharCode(97+Math.floor(i/26),97+i%26)}`,description,inputSchema:{type:'object'}}));
  f.bridge.receive({type:'controllerResult',requestId:f.sent[0].requestId,result:{tools}});
  assert.equal(Array.isArray(f.outward.at(-1).result?.tools),accepted);
 }
});
