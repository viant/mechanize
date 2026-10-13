const {test}=require('node:test');
const assert=require('node:assert/strict');
const fs=require('node:fs');
const path=require('node:path');
const base=path.resolve(__dirname,'..');
const {JSDOM}=require(base+'/node_modules/jsdom');

function content(html){
 const dom=new JSDOM(html,{url:'https://fixture.example/history',runScripts:'outside-only'}),w=dom.window;
 w.TextEncoder=TextEncoder;
 Object.defineProperty(w.crypto,'subtle',{value:require('node:crypto').webcrypto.subtle});
 w.HTMLElement.prototype.getClientRects=function(){return [{width:100,height:20}]};
 let receive;
 w.chrome={runtime:{id:'fixture',onMessage:{addListener(fn){receive=fn}}}};
 for(const file of ['protocol.js','accessibility-provider.js','dom.js','secure-input.js','recorder.js','content.js'])w.eval(fs.readFileSync(path.join(base,file),'utf8'));
 const request={type:'credentialPublicScope',requestId:'a'.repeat(64),identity:{profileChannel:'profile',browserInstance:'browser',tabId:7,frameId:0,documentId:'document',documentGeneration:0},brokerEpoch:'broker',channelEpoch:'channel',scopeHash:'b'.repeat(64),deadlineUnixMs:Date.now()+4000,origin:'https://fixture.example',redactions:[]};
 return {w,request,send:message=>new Promise(resolve=>receive(message,{id:'fixture',url:'chrome-extension://fixture/worker.js'},resolve))};
}

test('public read reports private fields separately from incomplete observation coverage',async()=>{
 for(const [html,reason]of [
  ['<input type=password value=PRIVATE-CANARY>','scopeTargetProtected'],
  ['<h1>Login failed</h1>','scopeTargetProtected'],
  ['<div></div>'.repeat(21000),'scopeInventoryUnavailable'],
 ]){
  const f=content(html);
  const result=await f.send(f.request);
  assert.equal(result.publicDocument,null);
  assert.equal(result.reason,reason);
  assert.ok(!JSON.stringify(result).includes('PRIVATE-CANARY'));
  f.w.close();
 }
});

test('stale binding is a refreshable identity failure, not credential evidence',async()=>{
 const f=content('<h1>History</h1>');
 const rejected=await f.send({...f.request,deadlineUnixMs:Date.now()-1});
 assert.equal(rejected.publicDocument,null);
 assert.equal(rejected.reason,'scopeChanged');
 const accepted=await f.send(f.request);
 assert.equal(accepted.publicDocument.public,true);
 assert.equal(accepted.reason,undefined);
 f.w.close();
});

test('scope transport does not infer credentials from a missing or malformed proof',async()=>{
 global.crypto=require('node:crypto').webcrypto;
 const {create}=require(path.join(base,'protection-scopes.js'));
 const url='https://fixture.example/history';
 const api={tabs:{query:async()=>[{id:7,url,status:'complete'}]},webNavigation:{getAllFrames:async()=>[{frameId:0,documentId:'document',url}]},storage:{local:{}}};
 const request={type:'credentialScope',mode:'publicRead',requestId:'a'.repeat(64),preparationId:'0'.repeat(64),sourceIdentity:{profileChannel:'profile',browserInstance:'browser',tabId:7,frameId:0,documentId:'',documentGeneration:0},sourceOrigin:'https://fixture.example',loginRouteSHA256:'',brokerEpoch:'broker',channelEpoch:'channel',scopeHash:'b'.repeat(64),deadlineUnixMs:Date.now()+4000,targetTabId:7,targetOrigin:'https://fixture.example'};
 for(const [reader,reason]of [
  [async()=>null,'scopeChanged'],
  [async()=>({public:true}),'scopeChanged'],
  [async()=>{throw 'scopeInventoryUnavailable'},'scopeInventoryUnavailable'],
  [async()=>{throw 'scopeTargetProtected'},'scopeTargetProtected'],
  [null,'scopeUnavailable'],
 ]){
  const result=await create(api,()=>null,reader).respond(request,()=>{},()=>false);
  assert.equal(result.ready,false);
  assert.equal(result.reason,reason);
  assert.equal(result.publicDocument,undefined);
 }
});
