const {test}=require('node:test');
const assert=require('node:assert/strict');
require('../cdp-transport.js');
const {create}=require('../playwright-relay.js');
function fixture(){
 const calls=[],identity={profileChannel:'fixture',browserInstance:'isolated',tabId:7,frameId:0,documentId:'root',documentGeneration:1};let allowed=true;
 const api={debugger:{attach:async target=>calls.push({attach:target}),sendCommand:async(target,method,params)=>{calls.push({target,method,params});return{};}},webNavigation:{getAllFrames:async()=>[{frameId:0,documentId:'root',url:'https://fixture.test'}]}};
 return {calls,identity,api,relay:create(api,()=>allowed),deny:()=>{allowed=false;}};
}
test('focus emulation belongs only to the exactly admitted root tab and is not physical input',async()=>{
 const f=fixture(),session=await f.relay.open({identity:f.identity,origin:'https://fixture.test',command:{action:'read'}},Date.now()+1000);
 assert.deepEqual(f.calls,[{attach:{tabId:7}},{target:{tabId:7},method:'Emulation.setFocusEmulationEnabled',params:{enabled:true}}]);
 await assert.rejects(session.send('Emulation.setFocusEmulationEnabled',{enabled:false},Date.now()+500),e=>e.code==='playwrightCDPDenied');
 await assert.rejects(session.send('Emulation.setFocusEmulationEnabled',{enabled:true,tabId:8},Date.now()+500),e=>e.code==='playwrightCDPDenied');
 f.deny();await assert.rejects(session.send('Emulation.setFocusEmulationEnabled',{enabled:true},Date.now()+500),e=>e.code==='playwrightAuthorityChanged');
 assert.equal(f.calls.length,2);session.close();
});
test('foreign document or denied authority never receives focus emulation',async()=>{
 for(const mode of ['document','authority']){
  const f=fixture();if(mode==='document')f.identity.documentId='foreign';else f.deny();
  await assert.rejects(f.relay.open({identity:f.identity,origin:'https://fixture.test',command:{action:'read'}},Date.now()+1000));assert.deepEqual(f.calls,[]);
 }
});

test('selector engine proof accepts only the pinned package count wrapper and successful scalar count',()=>{
 const guard=require('../playwright-target.js');
 const params={functionDeclaration:'(utilityScript, ...args) => utilityScript.evaluate(...args)',returnByValue:true,awaitPromise:true,arguments:[{objectId:'utility'},{value:true},{value:true},{value:guard.querySource},{value:2},{value:{h:0}},{value:{o:[{k:'functionText',v:'({ elements }) => elements.length'}]}},{objectId:'injected'}]};
 const result={result:{type:'number',value:1}};assert.equal(guard.queryObject(params,result),'injected');
 for(const mode of ['expression','wrapper','handle','returnByValue','promise','error','negative','nonscalar','function']){
  const p=structuredClone(params),r=structuredClone(result);
  if(mode==='expression')p.arguments[3].value+=' ';
  if(mode==='wrapper')p.functionDeclaration='function(){return 1}';
  if(mode==='handle')p.arguments[7]={value:'injected'};
  if(mode==='returnByValue')p.returnByValue=false;
  if(mode==='promise')p.awaitPromise=false;
  if(mode==='error')r.exceptionDetails={};
  if(mode==='negative')r.result.value=-1;
  if(mode==='nonscalar')r.result.type='object';
  if(mode==='function')p.arguments[6].value.o[0].v='() => 1';
  assert.equal(guard.queryObject(p,r),undefined,mode);
 }
});
