// Synthetic end-to-end qualification of the built inspection-only MCP service.
import {mkdtemp,writeFile,rm} from 'node:fs/promises';
import {tmpdir} from 'node:os';
import {join,resolve} from 'node:path';
import {randomBytes} from 'node:crypto';
import {execFileSync,spawnSync} from 'node:child_process';
import {createServer,request as httpRequest} from 'node:http';
import {connect} from 'node:net';
import assert from 'node:assert/strict';
import {browserOAuthFixture} from './browser-oauth-fixture.mjs';

const directory=await mkdtemp(join(tmpdir(),'mechanize-inspection-'));
const name=`mechanize-inspection-${randomBytes(5).toString('hex')}`;
const oauth=await browserOAuthFixture(directory);
const host=process.env.MECHANIZE_FIXTURE_HOST||'host.docker.internal';
const image=process.env.MECHANIZE_IMAGE||'mechanize-browser-mcp:local';
const docker=(...args)=>execFileSync('docker',args,{encoding:'utf8',stdio:['ignore','pipe','pipe']}).trim();
let storeOrigin,siteHits=0,deniedHits=0,started=false,serial=0;
const proxiedPaths=new Set();
const streamClients=new Set();
const denied=createServer((req,res)=>{deniedHits++;res.end('unexpected');});
const store=createServer((req,res)=>{
  if(req.socket.remoteAddress==='127.0.0.1')proxiedPaths.add(new URL(req.url,'http://fixture').pathname);
  if(req.url==='/live'){res.writeHead(200,{'Content-Type':'text/event-stream'});res.write(': connected\n\n');streamClients.add(res);res.on('close',()=>streamClients.delete(res));return;}
  if(req.url.startsWith('/collect')){res.writeHead(204);res.end();return;}
  if(req.url==='/redirect-frame'){res.writeHead(302,{Location:'/frame'});res.end();return;}
  res.setHeader('Content-Type','text/html');
  res.end('<h1 id="frame-title">Store setup</h1><p>'+(req.headers.cookie?.includes('redirect_seed=expected')?'cookie-received':'no-cookie')+'</p><img src="/collect?pixel=42&amount=%5BAmount%5D&currency=%5BCurrency%5D&order=PRIVATE_ORDER&token=PRIVATE_TOKEN"><script>window.live=new EventSource("/live");fetch("/collect",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({pixel:42,amount:19.95,currency:"USD",order:"PRIVATE_ORDER",secret:"PRIVATE_BODY"})})</script>');
});
const site=createServer((req,res)=>{
  if(req.socket.remoteAddress==='127.0.0.1')proxiedPaths.add(new URL(req.url,'http://fixture').pathname);
  siteHits++;
  if(req.url==='/redirect-ok'){res.writeHead(302,{Location:storeOrigin+'/redirect-frame','Set-Cookie':'redirect_seed=expected; Path=/'});res.end();return;}
  if(req.url==='/redirect-safe'){res.writeHead(302,{Location:'/redirect'});res.end();return;}
  if(req.url==='/redirect'){res.writeHead(302,{Location:forbidden});res.end();return;}
  res.setHeader('Content-Type','text/html');
  res.end(req.url==='/empty'?'<h1>Empty page</h1>':`<p>MAIN_ONLY</p><input id="query"><iframe id="store-frame" name="store" src="${storeOrigin}/redirect-frame"></iframe>`);
});
for(const server of [denied,store,site])await new Promise(resolve=>server.listen(0,'0.0.0.0',resolve));
const origin=`http://${host}:${site.address().port}`;
storeOrigin=`http://${host}:${store.address().port}`;
const forbidden=`http://${host}:${denied.address().port}`;
const proxyRequests=[];
const fixtureOrigins=new Set([origin,storeOrigin,forbidden]);
const proxy=createServer((req,res)=>{
  let target;
  try {target=new URL(req.url);}catch{res.writeHead(400);res.end();return;}
  if(!fixtureOrigins.has(target.origin)){res.writeHead(403);res.end();return;}
  proxyRequests.push(target.pathname);
  // Resolve only the test fixture's own listeners; never operate as a general proxy.
  const upstream=httpRequest({hostname:'127.0.0.1',port:target.port,path:target.pathname+target.search,method:req.method,
    headers:{...req.headers,host:target.host}},reply=>{res.writeHead(reply.statusCode,reply.headers);reply.pipe(res);});
  upstream.on('error',()=>{res.writeHead(502);res.end();});
  res.on('close',()=>upstream.destroy());
  req.on('aborted',()=>upstream.destroy());
  req.pipe(upstream);
});
const tunnels=new Set();
proxy.on('connect',(req,client,head)=>{
  let target;
  try{target=new URL('http://'+req.url);}catch{client.end('HTTP/1.1 400 Bad Request\r\n\r\n');return;}
  if(!fixtureOrigins.has(target.origin)){client.end('HTTP/1.1 403 Forbidden\r\n\r\n');return;}
  const upstream=connect(Number(target.port),'127.0.0.1',()=>{
    client.write('HTTP/1.1 200 Connection Established\r\n\r\n');
    if(head.length)upstream.write(head);
    client.pipe(upstream);upstream.pipe(client);
  });
  tunnels.add(client);tunnels.add(upstream);
  client.on('error',()=>upstream.destroy());upstream.on('error',()=>client.destroy());
  client.on('close',()=>{upstream.destroy();tunnels.delete(client);});
  upstream.on('close',()=>{client.destroy();tunnels.delete(upstream);});
});
await new Promise(resolve=>proxy.listen(0,'0.0.0.0',resolve));
try {
  await writeFile(join(directory,'config.json'),JSON.stringify({listen:'0.0.0.0:8080',worker:'/app/browser/container-worker.mjs',
    allowAllWeb:false,allowedOrigins:[origin,storeOrigin],inspectionOnly:true,...oauth.config,
    networkRules:[{origin:storeOrigin,path:'/collect',parameters:{pixel:'value',amount:'value',currency:'value',order:'presence'}},
      {origin,path:'/redirect-ok',parameters:{}}]}),{mode:0o600});
  docker('run','-d','--name',name,'--user',`${process.getuid()}:${process.getgid()}`,'--shm-size','1gb','-p','127.0.0.1::8080',
    '-v',`${resolve(directory)}:/run/browser-secrets:ro`,'-e',`MECHANIZE_PROXY_SERVER=http://${host}:${proxy.address().port}`,
    image,'-config','/run/browser-secrets/config.json');
  started=true;
  let published;
  for(let i=0;i<100;i++) {
    try{published=docker('port',name,'8080/tcp');if(published)break;}catch{}
    const state=JSON.parse(docker('inspect','--format','{{json .State}}',name));
    assert.notEqual(state.Status,'exited',`browser service exited with code ${state.ExitCode}`);
    await new Promise(resolve=>setTimeout(resolve,100));
  }
  assert.ok(published,'browser service port was not published');
  const port=published.split(':').at(-1);
  const url=`http://127.0.0.1:${port}/mcp`;
  for(let i=0;i<80;i++){try{await fetch(url);break;}catch{await new Promise(resolve=>setTimeout(resolve,100));}}
  assert.equal((await fetch(url)).status,401,'anonymous access must be denied');
  const headers=(owner,session)=>({'Content-Type':'application/json',Accept:'application/json, text/event-stream',
    'MCP-Protocol-Version':'2025-11-25',...oauth.authorization(owner),...(session?{'Mcp-Session-Id':session}:{})});
  async function rpc(method,params,session,owner='user-a/chat-a') {
    const response=await fetch(url,{method:'POST',headers:headers(owner,session),body:JSON.stringify({jsonrpc:'2.0',id:++serial,method,params})});
    assert.ok(response.ok,`MCP HTTP ${response.status}`);
    const text=await response.text();
    const decoded=JSON.parse(text.startsWith('event:')||text.startsWith('data:')?text.split('\n').find(line=>line.startsWith('data:')).slice(5):text);
    assert.equal(decoded.error,undefined,JSON.stringify(decoded.error));
    return {body:decoded.result,session:response.headers.get('mcp-session-id')};
  }
  const initialize=async owner=>(await rpc('initialize',{protocolVersion:'2025-11-25',capabilities:{},clientInfo:{name:'inspection-fixture',version:'1'}},undefined,owner)).session;
  const a=await initialize('user-a/chat-a'),b=await initialize('user-b/chat-b');
  assert.ok(a&&b);assert.notEqual(a,b);
  const call=async(session,name,args={},owner)=>(await rpc('tools/call',{name,arguments:args},session,owner)).body;
  const value=result=>{assert.ok(!result.isError,JSON.stringify(result));return JSON.parse(result.content[0].text);};
  const run=async(session,source,owner)=>call(session,'mechanize_script_run',{source},owner);
  const tab=`web.tab(origin: ${JSON.stringify(origin)})`;
  const tools=(await rpc('tools/list',{},a)).body.tools.map(tool=>tool.name);
  assert.ok(tools.includes('mechanize_browser_network')&&tools.includes('mechanize_browser_frames'));
  const capabilities=value(await call(a,'mechanize_capabilities'));
  assert.equal(capabilities.inspectionOnly,true);assert.equal(capabilities.capabilities['web:frameScope'],true);
  const rejected=await run(a,`${tab}.openOrigin(); ${tab}.getById("query").fill("blocked")`);
  assert.equal(rejected.isError,true);assert.equal(JSON.parse(rejected.content[0].text).outcome,'notDispatched');
  assert.equal(siteHits,0,'entire input plan must be rejected before navigation');
  value(await run(a,`${tab}.openOrigin(timeout: 15s)`));
  let frames;
  const deadline=Date.now()+5000;
  do {frames=value(await call(a,'mechanize_browser_frames'));if(frames.frames.some(frame=>frame.id==='store-frame'))break;await new Promise(resolve=>setTimeout(resolve,50));}while(Date.now()<deadline);
  assert.ok(frames.frames.some(frame=>frame.id==='store-frame'&&frame.name==='store'&&frame.origin===storeOrigin));
  const read=value(await run(a,`let title = ${tab}.frame(id: "store-frame").getById("frame-title").read("text")`));
  assert.equal(read.values.title,'Store setup');
  const dom=value(await call(a,'mechanize_browser_dom',{frame:{name:'store'}}));
  assert.equal(dom.origin,storeOrigin);assert.ok(dom.html.includes('frame-title'));assert.ok(!dom.html.includes('MAIN_ONLY'));
  let network;
  do {network=value(await call(a,'mechanize_browser_network'));if(network.requests.some(request=>request.method==='POST'&&request.status===204))break;await new Promise(resolve=>setTimeout(resolve,50));}while(Date.now()<deadline);
  assert.ok(network.requests.some(request=>request.parameters.amount.values.includes('[Amount]')));
  assert.ok(network.requests.some(request=>request.parameters.amount.values.includes('19.95')));
  assert.ok(network.requests.every(request=>request.parameters.order.present));
  assert.doesNotMatch(JSON.stringify(network),/PRIVATE_|Authorization|cookie|secret|token/);
  const streamDeadline=Date.now()+3000;
  while(!streamClients.size&&Date.now()<streamDeadline)await new Promise(resolve=>setTimeout(resolve,50));
  assert.ok(streamClients.size>0,'inspection must preserve long-lived page connections');
  const d=await initialize('user-a/chat-a');
  value(await run(d,`${tab}.openOrigin(); ${tab}.navigate(${JSON.stringify(origin+'/redirect-ok')})`));
  const redirected=value(await call(d,'mechanize_browser_dom'));
  assert.equal(redirected.origin,storeOrigin);assert.equal(redirected.url,storeOrigin+'/frame');
  assert.ok(redirected.text.includes('cookie-received'),'allowed redirects must preserve cookie state');
  assert.ok(value(await call(d,'mechanize_browser_network')).requests.some(request=>request.path==='/redirect-ok'&&request.status===302&&request.redirectHandled),
    'network evidence must preserve the actual server redirect status');
  assert.ok(proxiedPaths.has('/redirect-ok'),'navigation inspection must use the configured proxy');
  assert.ok(proxiedPaths.has('/collect'),'browser subresources must use the configured proxy');
  assert.equal(value(await call(d,'mechanize_session_close')).status,'closed');
  const blocked=await run(a,`${tab}.navigate(${JSON.stringify(forbidden)}, timeout: 5s)`);
  assert.equal(blocked.isError,true);assert.equal(deniedHits,0,'unapproved origin contacted');
  const redirect=await run(a,`${tab}.navigate(${JSON.stringify(origin+'/redirect')}, timeout: 5s)`);
  assert.equal(redirect.isError,true);assert.equal(deniedHits,0,'unapproved redirect contacted');
  // A blocked navigation can leave Chromium on its error document. Use a fresh context.
  const c=await initialize('user-a/chat-a');
  value(await run(c,`${tab}.openOrigin()`));
  const chain=await run(c,`${tab}.navigate(${JSON.stringify(origin+'/redirect-safe')}, timeout: 5s)`);
  assert.equal(chain.isError,true);assert.equal(deniedHits,0,'unapproved chained redirect contacted');
  assert.equal(value(await call(c,'mechanize_session_close')).status,'closed');
  for(const method of ['GET','DELETE'])assert.equal((await fetch(url,{method,headers:headers('user-b/chat-b',a)})).status,403);
  assert.equal((await fetch(url,{method:'POST',headers:headers('user-b/chat-b',a),body:JSON.stringify({jsonrpc:'2.0',id:++serial,method:'tools/list',params:{}})})).status,403);
  value(await run(b,`${tab}.openOrigin(); ${tab}.navigate(${JSON.stringify(origin+'/empty')})`,'user-b/chat-b'));
  assert.equal(value(await call(b,'mechanize_browser_network',{},'user-b/chat-b')).requests.length,0);
  assert.equal(value(await call(a,'mechanize_session_close')).status,'closed');
  assert.equal(value(await call(b,'mechanize_session_close',{},'user-b/chat-b')).status,'closed');
  const closeDeadline=Date.now()+3000;
  while(streamClients.size&&Date.now()<closeDeadline)await new Promise(resolve=>setTimeout(resolve,50));
  assert.equal(streamClients.size,0,'session cleanup must close long-lived page connections');
  console.log(JSON.stringify({status:'passed',checks:['OAuth access-token authentication','verified identity session binding','input rejection before navigation',
    'cross-origin frame discovery','canonical frame DSL read','frame DOM read','sanitized GET and POST request fields','response status',
    'allowed frame and cross-origin redirect chains preserve URL/cookies','real redirect response status is preserved','unapproved origin and redirect blocked before contact',
    'configured proxy covers navigation inspection and subresources','long-lived stream support and cleanup','cross-owner POST/GET/DELETE rejection','request evidence isolation','explicit session cleanup'],
    networkRequests:network.requests.length,productionEgressQualified:false}));
} catch(error) {
  if(started){const logs=spawnSync('docker',['logs','--tail','20',name],{encoding:'utf8'});console.error(logs.stdout,logs.stderr);}
  throw error;
} finally {
  if(started){try{docker('rm','-f',name);}catch{}}
  for(const socket of tunnels)socket.destroy();
  for(const server of [site,store,denied,proxy]){server.closeAllConnections();await new Promise(resolve=>server.close(resolve));}
  await rm(directory,{recursive:true,force:true});
}
