const {test}=require('node:test');
const assert=require('node:assert/strict');
const fs=require('node:fs');
const path=require('node:path');
const {pathToFileURL}=require('node:url');
async function transportClass(){const source=fs.readFileSync(path.join(__dirname,'../controller-transport.js'),'utf8');return (await import('data:text/javascript;base64,'+Buffer.from(source).toString('base64'))).MechanizeExtensionTransport;}
function fakeRuntime(){
 const state={messages:[],connections:0};let incoming,disconnected;
 const runtime={connect(id,options){state.connections++;assert.equal(options.name,'mechanize-controller-v1');const port={onMessage:{addListener:f=>{incoming=f;setImmediate(()=>f({type:'approved',conversationId:'conversation1'}));}},onDisconnect:{addListener:f=>disconnected=f},disconnect:()=>disconnected?.(),postMessage:m=>{
  state.messages.push(m);let result;
  if(m.operation==='initialize')result={protocolVersion:'2025-11-25',capabilities:{tools:{}},serverInfo:{name:'mechanize',version:'fixture'}};
  if(m.operation==='tools/list')result={tools:[{name:'mechanize_session_open',description:'Canonical fixture',inputSchema:{type:'object',properties:{name:{type:'string'}}}}]};
  if(m.operation==='tools/call'&&!state.hold)result={content:[{type:'text',text:'{"sessionId":"owned"}'}],structuredContent:{sessionId:'owned'}};
  if(result)setImmediate(()=>incoming({type:'result',requestId:m.requestId,result}));
 }};return port;}};
 return {runtime,state,disconnect:()=>disconnected()};
}
test('browser transport negotiates actual host version and maps standard MCP envelopes',async()=>{
 const Transport=await transportClass(),f=fakeRuntime(),transport=new Transport({extensionId:'a'.repeat(32),runtime:f.runtime});
 const outputs=[];transport.onmessage=m=>outputs.push(m);await transport.start();
 await transport.send({jsonrpc:'2.0',id:1,method:'initialize',params:{protocolVersion:'2025-06-18'}});
 assert.equal(outputs[0].result.protocolVersion,'2025-11-25');assert.equal(f.state.messages[0].operation,'initialize');assert.equal(f.state.messages[1].operation,'tools/list');
 await transport.send({jsonrpc:'2.0',id:2,method:'tools/call',params:{name:'mechanize_session_open',arguments:{}}});assert.equal(outputs[1].result.structuredContent.sessionId,'owned');
 f.state.hold=true;const pending=transport.send({jsonrpc:'2.0',id:3,method:'tools/call',params:{name:'mechanize_session_open',arguments:{}}});await new Promise(resolve=>setImmediate(resolve));f.disconnect();await pending;
 assert.equal(outputs.at(-1).error.code,-32000);assert.equal(f.state.connections,1);assert.equal(f.state.messages.filter(m=>m.operation==='tools/call').length,2);
});
test('official MCP SDK Client uses the browser extension transport',{skip:!process.env.MECHANIZE_MCP_SDK_PATH},async()=>{
 const {Client}=await import(pathToFileURL(path.join(process.env.MECHANIZE_MCP_SDK_PATH,'dist/esm/client/index.js')).href);
 const Transport=await transportClass(),f=fakeRuntime(),transport=new Transport({extensionId:'a'.repeat(32),runtime:f.runtime});
 const client=new Client({name:'generic-web-fixture',version:'1'});
 await client.connect(transport);
 const tools=await client.listTools();assert.equal(tools.tools[0].name,'mechanize_session_open');
 const results=await Promise.all([client.callTool({name:'mechanize_session_open',arguments:{name:'SDK fixture'}}),client.callTool({name:'mechanize_session_open',arguments:{name:'parallel SDK fixture'}})]);for(const result of results)assert.equal(result.structuredContent.sessionId,'owned');
 await client.close();assert.equal(f.state.connections,1);
});
test('SDK cancellation closes queued work without reconnecting or replaying',async()=>{
 const Transport=await transportClass(),f=fakeRuntime(),transport=new Transport({extensionId:'a'.repeat(32),runtime:f.runtime});
 const out=[];transport.onmessage=m=>out.push(m);await transport.start();await transport.send({jsonrpc:'2.0',id:1,method:'initialize',params:{}});
 f.state.hold=true;
 const one=transport.send({jsonrpc:'2.0',id:2,method:'tools/call',params:{name:'mechanize_session_open',arguments:{}}});
 const two=transport.send({jsonrpc:'2.0',id:3,method:'tools/call',params:{name:'mechanize_session_open',arguments:{}}});
 await new Promise(resolve=>setImmediate(resolve));await transport.send({jsonrpc:'2.0',method:'notifications/cancelled',params:{requestId:2}});await Promise.all([one,two]);
 assert.equal(f.state.messages.filter(m=>m.operation==='tools/call').length,1);assert.equal(f.state.connections,1);assert.equal(out.filter(m=>m.error).length,2);
});
