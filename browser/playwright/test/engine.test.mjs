import {test} from 'node:test';
import assert from 'node:assert/strict';
import {createServer} from 'node:http';
import {access} from 'node:fs/promises';
import vm from 'node:vm';
import {readFile} from 'node:fs/promises';
import {spawn} from 'node:child_process';
import {createInterface} from 'node:readline';
import {chromium} from 'playwright-core';
import {PlaywrightEngine} from '../engine.mjs';
import {pageEvents} from '../relay.mjs';
import fingerprint from '../../../extension/chrome/fingerprint.js';
import relayPolicy from '../../../extension/chrome/playwright-relay.js';

const executable=process.env.MECHANIZE_FIXTURE_CHROMIUM||'/tmp/agently-mcp-apps-audit-browsers/chromium_headless_shell-1223/chrome-headless-shell-mac-arm64/chrome-headless-shell';
const html=`<!doctype html><html><body><section id="login"><input type="password" id="password" data-mechanize-secret><button id="sign-in">Sign in</button></section><main id="app" hidden><p id="ready">Loading</p><label>Record filter<input id="filter" aria-label="Record filter"></label><section id="results"></section><button id="review">Review selected</button><p id="review-result"></p></main><script>
const rows=[['group-blue','Record A'],['group-blue','Record B'],['group-green','Record C']];let selected=[];
document.querySelector('#sign-in').onclick=()=>{document.querySelector('#login').remove();document.querySelector('#app').hidden=false;setTimeout(()=>{document.querySelector('#ready').textContent='SPA ready';render();},80)};
function render(){const target=document.querySelector('#results');target.innerHTML='';for(const [property,label] of rows.filter(r=>r[0].includes(document.querySelector('#filter').value))){const box=document.createElement('section');box.innerHTML='<button>Expand current row</button><div role="region" aria-label="Expanded record" hidden>'+label+' '+property+' <button>Select current row</button></div>';box.querySelector('button').onclick=()=>{box.querySelector('div').hidden=!box.querySelector('div').hidden};box.querySelector('div button').onclick=()=>{selected.push(label);box.querySelector('div button').disabled=true};target.append(box)}}
document.querySelector('#filter').oninput=render;document.querySelector('#review').onclick=()=>{document.querySelector('#review-result').textContent='Review: '+selected.join(', ')+'; total 2 items';};
</script></body></html>`;

async function fixture(){
  await access(executable);
  const server=createServer((_,res)=>{res.setHeader('content-type','text/html');res.end(html);});
  await new Promise(resolve=>server.listen(0,'127.0.0.1',resolve));
  const origin=`http://127.0.0.1:${server.address().port}`;
  const browser=await chromium.launch({executablePath:executable,headless:true});
  const context=await browser.newContext();const page=await context.newPage();await page.goto(origin);
  const identity={profileChannel:'fixture',browserInstance:'isolated',tabId:1,frameId:0,documentId:'fixture-document',documentGeneration:1};
  const receipt=[],intent=[],methods=[];let live=true,privateQuarantined=true,loseInputReply=false,loseMoveReply=false,inputCount=0,maxParamsBytes=0;
  const scope=vm.createContext({TextEncoder,btoa:input=>Buffer.from(input,'binary').toString('base64')});
  vm.runInContext(await readFile(new URL('../../../extension/chrome/secure-input.js',import.meta.url),'utf8'),scope);
  const redactions=scope.MechanizeSecureInput.redactionVariants(['fixture-private-value']);
  const host={
    admit:async command=>({identity,origin,brokerEpoch:'broker1',channelEpoch:'channel1',scopeHash:'a'.repeat(64),controlLease:{id:'lease1',generation:1},fingerprintSHA256:command.fingerprintSHA256,committed:true,privateQuarantined,protectedOrigin:true,privacyState:'redacted-dom',domReadQualified:!privateQuarantined,privacyRevision:'privacy-revision-1'}),
    current:async()=>live&&!privateQuarantined,
    async openRelay(_authority,boundCommand){
      const cdp=await context.newCDPSession(page),listeners=new Set();
      for(const method of pageEvents)cdp.on(method,params=>{for(const listener of listeners)listener({method,params});});
      return {origin,current:async()=>live,onMethod:method=>methods.push('virtual:'+method),onEvent(listener){listeners.add(listener);return()=>listeners.delete(listener);},
        async send(method,params){
          methods.push(method);maxParamsBytes=Math.max(maxParamsBytes,Buffer.byteLength(JSON.stringify(params||{})));
          if(!relayPolicy.methods.has(method)||!relayPolicy.inputAllowed(boundCommand,method,params)||maxParamsBytes>508*1024){
            if(method.startsWith('Input.'))methods.push(JSON.stringify({deniedInput:method,keys:Object.keys(params),type:params.type,button:params.button,buttons:params.buttons,modifiers:params.modifiers,code:params.code,key:params.key,virtualKey:params.windowsVirtualKeyCode}));
            throw Object.assign(Error('Denied CDP'),{dispatchState:'notDispatched'});
          }
          if(method==='Input.insertText'||method==='Input.dispatchMouseEvent'&&params.type==='mousePressed')inputCount++;
          const result=await cdp.send(method,params);
          if(loseInputReply&&method==='Input.insertText'){loseInputReply=false;throw Object.assign(Error('Lost input acknowledgement'),{dispatchState:'unknown'});}
          if(loseMoveReply&&method==='Input.dispatchMouseEvent'&&params.type==='mouseMoved'){loseMoveReply=false;throw Object.assign(Error('Preparation acknowledgement lost'),{dispatchState:'notDispatched'});}
          return result;
        },
        close:()=>cdp.detach().catch(()=>{}),
      };
    },
    commitIntent:async logical=>{intent.push(logical);return true;},persistReceipt:async value=>{receipt.push(value);return true;},redact:async value=>scope.MechanizeSecureInput.redact(value,redactions),
  };
  const engine=new PlaywrightEngine(host);
  let counter=0;
  async function command(action,id,args){
    const c={requestId:'request-'+(++counter),action,identity,brokerEpoch:'broker1',channelEpoch:'channel1',scopeHash:'a'.repeat(64),deadlineUnixMs:Date.now()+3000,locator:id.startsWith('expand-')||id.startsWith('select-')?{strategy:'role',value:'button',name:id.startsWith('expand-')?'Expand current row':'Select current row',exact:true,index:id.endsWith('A')?0:1,order:'document'}:{strategy:'id',value:id,exact:true},...(args?{args}:{})};
    if(action!=='read'){Object.assign(c,{attemptId:'attempt-'+counter,controlLease:{id:'lease1',generation:1},fingerprintVersion:2});c.fingerprintSHA256=(await fingerprint.mutationV2(c)).sha256;}
    return c;
  }
  const close=async()=>{await browser.close();await new Promise(resolve=>server.close(resolve));};
  const privateLogin=async()=>{
    await page.locator('#password').fill('fixture-private-value');await page.locator('#sign-in').click();
    await page.locator('#ready').getByText('SPA ready',{exact:true}).waitFor();
    assert.equal(await page.locator('input[type="password"]').count(),0);privateQuarantined=false;
  };
  return {engine,command,page,origin,identity,receipt,intent,methods,host,privateLogin,loseNextInputReply:()=>{loseInputReply=true},loseNextMoveReply:()=>{loseMoveReply=true},inputCount:()=>inputCount,maxParamsBytes:()=>maxParamsBytes,stop:()=>{live=false},close};
}
test('actual Playwright scoped CDP follows login, SPA readiness, filter, repeated expansion and review',{timeout:45000},async()=>{
  const f=await fixture();try{
    const timings=[];
    // Secrets are supplied to the isolated test browser, never the engine/MCP.
    await f.privateLogin();
    for(const [action,id,args] of [
      ['read','ready',{attribute:'text'}],['element.fill','filter',{value:'group-blue'}],
      ['element.press','expand-A'],['element.press','select-A'],['element.press','expand-B'],['element.press','select-B'],
      ['element.press','expand-A'],['element.press','expand-A'],['element.press','review'],['read','review-result',{attribute:'text'}],
    ]){
      if(id==='ready')await f.page.locator('#ready').getByText('SPA ready',{exact:true}).waitFor();
      const began=performance.now();const result=await f.engine.execute(await f.command(action,id,args));
      timings.push({action,target:id,elapsedMs:Math.round(performance.now()-began)});
      assert.equal(result.errorCode,undefined,`${action} ${id}: ${JSON.stringify(result)}; maxParamsBytes=${f.maxParamsBytes()}; CDP methods ${f.methods.join(',')}`);
      if(id==='ready')assert.equal(result.value,'SPA ready');
      if(id==='review-result')assert.equal(result.value,'Review: Record A, Record B; total 2 items');
      assert.equal(JSON.stringify(result).includes('fixture-private-value'),false);
    }
    assert.ok(f.methods.includes('Input.insertText'));assert.ok(f.methods.includes('Input.dispatchMouseEvent'));
    assert.equal(f.intent.length,8);assert.equal(f.receipt.length,8);
    await f.page.locator('#review-result').evaluate(el=>{el.textContent+=' fixture-private-value';});
    const redacted=await f.engine.execute(await f.command('read','review-result',{attribute:'text'}));assert.equal(redacted.value,'[redacted]');
    console.log(JSON.stringify({fixture:'login→SPA→filter→expand→repeat→review',actualPlaywright:true,mutations:f.receipt.length,reviewMatched:true,credentialCanaryRedacted:redacted.value==='[redacted]',maxCDPParamsBytes:f.maxParamsBytes(),timings}));
  }finally{await f.close();}
});
test('pre-input pointer preparation failure does not become an unknown business effect',{timeout:30000},async()=>{
  const f=await fixture();try{
    await f.privateLogin();f.loseNextMoveReply();
    const result=await f.engine.execute(await f.command('element.press','expand-A'));
    assert.equal(result.dispatchState,'notDispatched');assert.equal(result.effectState,'none');assert.equal(f.inputCount(),0);
    assert.equal(f.receipt.at(-1).dispatchState,'notDispatched');
  }finally{await f.close();}
});
test('empty text fill uses one admitted Delete key sequence and unsupported direct-DOM types are denied',{timeout:30000},async()=>{
  const f=await fixture();try{
    await f.privateLogin();await f.page.locator('#filter').fill('group-blue');
    const emptied=await f.engine.execute(await f.command('element.fill','filter',{value:''}));assert.equal(emptied.dispatchState,'dispatched');assert.equal(await f.page.locator('#filter').inputValue(),'');
    await f.page.locator('#app').evaluate(el=>{const date=document.createElement('input');date.type='date';date.id='date-control';el.append(date);});
    const intents=f.intent.length,inputs=f.inputCount();
    const denied=await f.engine.execute(await f.command('element.fill','date-control',{value:'2030-01-01'}));assert.equal(denied.dispatchState,'notDispatched');assert.equal(f.intent.length,intents);assert.equal(f.inputCount(),inputs);
  }finally{await f.close();}
});
test('lost reply after physical input remains unknown and never redispatches the attempt',{timeout:30000},async()=>{
  const f=await fixture();try{
    await f.privateLogin();f.loseNextInputReply();
    const command=await f.command('element.fill','filter',{value:'group-blue'});
    const first=await f.engine.execute(command);
    assert.equal(first.dispatchState,'unknown');assert.equal(first.effectState,'unknown');
    assert.equal(await f.page.locator('#filter').inputValue(),'group-blue');
    const count=f.inputCount(),methods=f.methods.length;
    const repeated=await f.engine.execute(command);
    assert.equal(repeated.dispatchState,'unknown');assert.equal(f.inputCount(),count);assert.equal(f.methods.length,methods);assert.equal(count,1);
    assert.equal(f.receipt.at(-1).dispatchState,'unknown');
  }finally{await f.close();}
});
test('private sidecar IPC drives actual Playwright and finishes receipt before closing relay',{timeout:30000},async()=>{
  const f=await fixture();let child;
  try{
    await f.privateLogin();
    const env={...process.env};delete env.OPENAI_API_KEY;delete env.OPENAI_SDK_KEY;
    child=spawn(process.execPath,[new URL('../sidecar.mjs',import.meta.url).pathname],{env,stdio:['pipe','pipe','pipe']});
    const lines=createInterface({input:child.stdout});const relays=new Map(),order=[],results=new Map();let relaySequence=0,authority,boundCommand,maxSidecarFrameBytes=0,maxNativeFrameBytes=0;
    const write=message=>child.stdin.write(JSON.stringify(message)+'\n');
    lines.on('line',async line=>{
      let m;try{m=JSON.parse(line);}catch{return;}
      maxSidecarFrameBytes=Math.max(maxSidecarFrameBytes,Buffer.byteLength(line));
      if(m.type==='result'){results.get(m.id)?.(m.result);return;}
      if(m.type!=='callback')return;
      try{
        let result;const p=m.params;
        switch(m.method){
          case 'admit':boundCommand=p.command;result=authority=await f.host.admit(p.command);break;
          case 'current':result=await f.host.current();break;
          case 'relay.open':{
            const relayId='relay-'+(++relaySequence),adapter=await f.host.openRelay(authority,boundCommand);
            adapter.onEvent(e=>write({type:'relayEvent',relayId,method:e.method,params:e.params}));relays.set(relayId,adapter);result={relayId};break;
          }
          case 'relay.send':{
            const outer={type:'playwright.send',requestId:m.id,relayId:p.relayId,identity:boundCommand.identity,brokerEpoch:boundCommand.brokerEpoch,channelEpoch:boundCommand.channelEpoch,scopeHash:boundCommand.scopeHash,controlLease:boundCommand.controlLease,method:p.method,params:p.params,deadlineUnixMs:p.deadlineUnixMs};
            maxNativeFrameBytes=Math.max(maxNativeFrameBytes,Buffer.byteLength(JSON.stringify(outer)));
            result=await relays.get(p.relayId).send(p.method,p.params,p.deadlineUnixMs);break;
          }
          case 'relay.redact':result=await f.host.redact(p.value);break;
          case 'intent.confirm':order.push('intent');result=await f.host.commitIntent(p);break;
          case 'receipt.persist':order.push('receipt');result=await f.host.persistReceipt(p);break;
          case 'relay.close':order.push('close');await relays.get(p.relayId).close();relays.delete(p.relayId);result=true;break;
          default:throw Error('Unsupported callback');
        }
        write({type:'callbackResult',id:m.id,result});
      }catch(error){write({type:'callbackResult',id:m.id,errorCode:'playwrightHostDenied',dispatchState:error.dispatchState||'notDispatched'});}
    });
    async function execute(command){
      const id='execution-'+command.requestId;
      return new Promise((resolve,reject)=>{
        const timer=setTimeout(()=>reject(Error('Sidecar fixture deadline')),5000);
        results.set(id,result=>{clearTimeout(timer);results.delete(id);resolve(result);});write({type:'execute',id,command});
      });
    }
    const filled=await execute(await f.command('element.fill','filter',{value:'group-blue'}));
    assert.equal(filled.dispatchState,'dispatched');assert.deepEqual(order,['intent','receipt','close']);
    assert.equal(await f.page.locator('#filter').inputValue(),'group-blue');
    const read=await execute(await f.command('read','ready',{attribute:'text'}));assert.equal(read.value,'SPA ready');
    assert.equal(relays.size,0);assert.ok(maxSidecarFrameBytes<512*1024);assert.ok(maxNativeFrameBytes<512*1024);
    console.log(JSON.stringify({fixture:'private-sidecar-IPC',actualPlaywright:true,receiptBeforeClose:true,maxSidecarFrameBytes,maxNativeFrameBytes}));
  }finally{child?.kill();await f.close();}
});
test('credential targets and revoked authority fail before input; completed attempts never replay',{timeout:30000},async()=>{
  const f=await fixture();try{
    const denied=await f.engine.execute(await f.command('element.fill','password',{value:'do-not-echo'}));
    assert.equal(denied.dispatchState,'notDispatched');assert.equal(denied.errorCode,'playwrightAuthorityDenied');assert.equal(JSON.stringify(denied).includes('do-not-echo'),false);
    await f.privateLogin();
    const command=await f.command('element.press','expand-A');
    const first=await f.engine.execute(command);assert.equal(first.dispatchState,'dispatched');
    const before=f.methods.length;const second=await f.engine.execute(command);assert.equal(second.dispatchState,'dispatched');assert.equal(f.methods.length,before);
    f.stop();const revoked=await f.engine.execute(await f.command('element.fill','filter',{value:'group-blue'}));assert.equal(revoked.dispatchState,'notDispatched');
  }finally{await f.close();}
});
test('oversized read never truncates a credential variant before the owned redactor',{timeout:30000},async()=>{
  const f=await fixture();try{
    await f.privateLogin();await f.page.locator('#review-result').evaluate(el=>{el.textContent='x'.repeat(32760)+' fixture-private-value';});
    const result=await f.engine.execute(await f.command('read','review-result',{attribute:'text'}));
    assert.equal(result.errorCode,'playwrightReadTooLarge');assert.equal(result.value,undefined);assert.equal(result.dispatchState,'notDispatched');
    assert.equal(JSON.stringify(result).includes('fixture-private'),false);
  }finally{await f.close();}
});

test('missing target waits within original deadline before intent while ambiguous targets deny without input',{timeout:30000},async()=>{
 const f=await fixture();try{
  await f.privateLogin();
  await f.page.evaluate(()=>{window.fixtureDelayedClicks=0;const decoration=document.createElement('aside');document.body.append(decoration);let n=0;window.fixtureDelayTimer=setInterval(()=>{decoration.textContent=String(++n)},20);setTimeout(()=>{const button=document.createElement('button');button.id='delayed-target';button.innerHTML='<span style="display:block">Delayed</span><span>action</span>';button.onclick=()=>window.fixtureDelayedClicks++;document.body.append(button);},500);});
  const command=await f.command('element.press','delayed-target');const result=await f.engine.execute(command);
  assert.equal(result.dispatchState,'dispatched');assert.equal(f.intent.length,1);assert.equal(f.inputCount(),1);assert.equal(await f.page.evaluate(()=>window.fixtureDelayedClicks),1);
  await f.page.evaluate(()=>{clearInterval(window.fixtureDelayTimer);document.body.insertAdjacentHTML('beforeend','<button id="ambiguous">One</button><button id="ambiguous">Two</button>');});
  const ambiguous=await f.engine.execute(await f.command('element.press','ambiguous'));assert.equal(ambiguous.errorCode,'playwrightTargetDenied');assert.equal(f.intent.length,1);assert.equal(f.inputCount(),1);
  const missing=await f.command('element.press','never-present');missing.deadlineUnixMs=Date.now()+250;missing.fingerprintSHA256=(await fingerprint.mutationV2(missing)).sha256;
  const started=Date.now(),expired=await f.engine.execute(missing);assert.equal(expired.dispatchState,'notDispatched');assert.equal(f.intent.length,1);assert.equal(f.inputCount(),1);assert.ok(Date.now()-started<1500);
 }finally{await f.close();}
});
