// Synthetic end-to-end check of the built container; creates no real login data.
import {mkdtemp,writeFile,rm} from 'node:fs/promises';
import {tmpdir} from 'node:os';
import {join,resolve} from 'node:path';
import {randomBytes} from 'node:crypto';
import {execFileSync} from 'node:child_process';
import {createServer} from 'node:http';
import assert from 'node:assert/strict';

const dir = await mkdtemp(join(tmpdir(), 'mechanize-browser-smoke-'));
const name = `mechanize-browser-smoke-${randomBytes(5).toString('hex')}`;
const livePages = new Set();
const fixture = createServer((req,res) => {
  if(req.url==='/live'){
    res.writeHead(200,{'Content-Type':'text/event-stream'});res.write(': connected\n\n');
    livePages.add(res);req.on('close',()=>livePages.delete(res));return;
  }
  res.setHeader('Content-Type','text/html');
  res.end('<input id="query"><div id="profile"></div><script>window.live=new EventSource("/live");document.querySelector("#profile").textContent=localStorage.getItem("seed")||"empty";</script>');
});
await new Promise(resolve => fixture.listen(0,'0.0.0.0',resolve));
const origin = `http://host.docker.internal:${fixture.address().port}`;
let started = false;
const withProfile = !process.argv.includes('--without-profile');
const docker = (...args) => execFileSync('docker',args,{encoding:'utf8',stdio:['ignore','pipe','pipe']}).trim();
try {
  await writeFile(join(dir,'state.json'),JSON.stringify({cookies:[],origins:[{origin,localStorage:[{name:'seed',value:'deployment-fixture'}]}]}),{mode:0o600});
  await writeFile(join(dir,'config.json'),JSON.stringify({listen:'0.0.0.0:8080',worker:'/app/browser/container-worker.mjs',
    allowedOrigins:[origin],allowMutation:true}),{mode:0o600});
  docker('run','-d','--name',name,'--user',`${process.getuid()}:${process.getgid()}`,'--shm-size','1gb','-p','127.0.0.1::8080',
    '-v',`${resolve(dir)}:/run/browser-secrets:ro`,'-e','MECHANIZE_IDLE_MS=5000',
    ...(withProfile?['-e','MECHANIZE_STORAGE_STATE=/run/browser-secrets/state.json']:[]),
    'mechanize-browser-mcp:local','-config','/run/browser-secrets/config.json');
  started = true;
  const port = docker('port',name,'8080/tcp').split(':').at(-1);
  const url = `http://127.0.0.1:${port}/mcp`;
  let serial = 0;
  async function rpc(method,params,session,subject='fixture-user') {
    const response = await fetch(url,{method:'POST',headers:{'Content-Type':'application/json',Accept:'application/json, text/event-stream','MCP-Protocol-Version':'2025-11-25',...(session?{'Mcp-Session-Id':session}:{})},body:JSON.stringify({jsonrpc:'2.0',id:++serial,method,params})});
    const text = await response.text();
    assert.equal(response.ok,true,`HTTP ${response.status}: ${text}`);
    const json = JSON.parse(text.startsWith('event:')||text.startsWith('data:')?text.split('\n').find(line=>line.startsWith('data:')).slice(5):text);
    assert.equal(json.error,undefined,JSON.stringify(json.error));
    return {body:json.result,session:response.headers.get('mcp-session-id')};
  }
  for(let i=0;i<60;i++){
    try {await fetch(url);break;}catch{await new Promise(resolve=>setTimeout(resolve,250));}
  }
  const initialize = () => rpc('initialize',{protocolVersion:'2025-11-25',capabilities:{},clientInfo:{name:'fixture',version:'1'}});
  const a = (await initialize()).session, b = (await initialize()).session;
  assert.ok(a);assert.ok(b);assert.notEqual(a,b);
  const run = async(session,source,subject) => {
    const {body}=await rpc('tools/call',{name:'mechanize_script_run',arguments:{source}},session,subject);
    return {error:body.isError,value:JSON.parse(body.content[0].text)};
  };
  const tab = `web.tab(origin: ${JSON.stringify(origin)})`;
  async function pageCount(expected){
    const end=Date.now()+3000;
    while(livePages.size!==expected&&Date.now()<end)await new Promise(resolve=>setTimeout(resolve,50));
    assert.equal(livePages.size,expected,'live browser page connections');
  }
  let reply=await run(a,`${tab}.openOrigin(); let profile = ${tab}.getById("profile").read("text"); ${tab}.getById("query").fill("session-a")`);
  const cold = reply.value;
  assert.ok(!reply.error,JSON.stringify(reply));assert.equal(reply.value.values.profile,withProfile?'deployment-fixture':'empty');
  const dom=(await rpc('tools/call',{name:'mechanize_browser_dom',arguments:{}},a)).body;
  assert.ok(!dom.isError);assert.ok(JSON.parse(dom.content[0].text).html.includes('id="query"'));
  const screenshot=(await rpc('tools/call',{name:'mechanize_browser_screenshot',arguments:{}},a)).body;
  assert.equal(screenshot.content[0].type,'image');assert.equal(screenshot.content[0].mimeType,'image/png');
  const full=Buffer.from(screenshot.content[0].data,'base64');
  assert.equal(full.subarray(1,4).toString(),'PNG');
  const scaled=(await rpc('tools/call',{name:'mechanize_browser_screenshot',arguments:{scale:0.5}},a)).body;
  const half=Buffer.from(scaled.content[0].data,'base64');
  assert.equal(half.readUInt32BE(16),Math.round(full.readUInt32BE(16)/2));
  assert.equal(half.readUInt32BE(20),Math.round(full.readUInt32BE(20)/2));
  const invalid=(await rpc('tools/call',{name:'mechanize_browser_screenshot',arguments:{scale:0}},a)).body;
  assert.equal(invalid.isError,true);
  reply=await run(a,`let value = ${tab}.getById("query").read("value")`);
  const warm = reply.value;
  assert.equal(reply.value.values.value,'session-a');
  reply=await run(b,`${tab}.openOrigin(); let value = ${tab}.getById("query").read("value")`);
  assert.equal(reply.value.values.value,'');
  await pageCount(2);
  reply=await run(a,`let value = ${tab}.getById("query").read("value")`);
  assert.equal(reply.value.values.value,'session-a');
  await new Promise(resolve=>setTimeout(resolve,5300));
  await pageCount(0);
  const c=(await initialize()).session;
  reply=await run(c,`${tab}.openOrigin(); let missing = ${tab}.getById("missing").read("text", timeout: 100ms)`);
  assert.equal(reply.error,true);assert.equal(reply.value.code,'deadline');assert.equal(reply.value.outcome,'notDispatched');
  await rpc('tools/call',{name:'mechanize_session_close',arguments:{}},c);
  await pageCount(0);
  console.log(JSON.stringify({cold:{compileMs:cold.compileMs||0,browserMs:cold.browserMs||0,elapsedMs:cold.elapsedMs||0},warm:{compileMs:warm.compileMs||0,browserMs:warm.browserMs||0,elapsedMs:warm.elapsedMs||0}}));
  reply=await run(a,`${tab}.openOrigin(); let value = ${tab}.getById("query").read("value")`);
  assert.equal(reply.value.values.value,'');
  reply=await run(a,`${tab}.getById("query").fill("temporary"); ${tab}.getById("query").fill(""); expect(${tab}.getById("query")).toHaveValue(""); let cleared = ${tab}.getById("query").read("value")`);
  assert.ok(!reply.error,JSON.stringify(reply));assert.equal(reply.value.values.cleared,'');
  await pageCount(1);
  const closed=await fetch(url,{method:'DELETE',headers:{'Mcp-Session-Id':a,'MCP-Protocol-Version':'2025-11-25'}});
  assert.ok(closed.ok,`termination HTTP ${closed.status}`);
  await pageCount(0);
  const d=(await initialize()).session;
  await run(d,`${tab}.openOrigin()`);
  await pageCount(1);
  const pending=run(d,`let missing = ${tab}.getById("missing").read("text", timeout: 20s)`);
  await new Promise(resolve=>setTimeout(resolve,200));
  const deleted=await fetch(url,{method:'DELETE',headers:{'Mcp-Session-Id':d,'MCP-Protocol-Version':'2025-11-25'}});
  assert.ok(deleted.ok);await pageCount(0);
  assert.equal((await pending).error,true,'active operation must fail on termination');
  const e=(await initialize()).session;
  await run(e,`${tab}.openOrigin()`);await pageCount(1);
  const controller=new AbortController();
  const aborted=fetch(url,{method:'POST',signal:controller.signal,headers:{'Content-Type':'application/json',Accept:'application/json, text/event-stream','Mcp-Session-Id':e,'MCP-Protocol-Version':'2025-11-25'},body:JSON.stringify({jsonrpc:'2.0',id:++serial,method:'tools/call',params:{name:'mechanize_script_run',arguments:{source:`let missing = ${tab}.getById("missing").read("text", timeout: 20s)`}}})});
  const abortCheck=assert.rejects(aborted,error=>error.name==='AbortError');
  await new Promise(resolve=>setTimeout(resolve,200));controller.abort();
  await abortCheck;await pageCount(0);
  console.log(`PASS: active termination and client-disconnect cleanup; deployment profile=${withProfile}`);
  console.log('PASS: MCP DSL execution, deployment state, tab reuse, context isolation, idle recreation and transport termination');
} finally {
  if(started){try{docker('rm','-f',name);}catch{}}
  for(const response of livePages)response.end();
  fixture.close();
  await rm(dir,{recursive:true,force:true});
}
