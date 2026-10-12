import {test} from 'node:test';
import assert from 'node:assert/strict';
import {readFile,writeFile,mkdtemp,rm,mkdir} from 'node:fs/promises';
import {tmpdir} from 'node:os';
import path from 'node:path';
import {chromium} from 'playwright-core';

// A real extension running in a disposable Chrome profile. It contains the
// production inventory proof but never runs connectNative or reads user state.
const source=await readFile(new URL('../../../extension/chrome/worker.js',import.meta.url),'utf8');
const dependencies=source.split('\n').filter(line=>line.startsWith('const channelShape =')||line.startsWith('function inactiveExecutorFrame(')).join('\n');
const inventory=dependencies+'\n'+source.slice(source.indexOf('function reconnectFrameState('),source.indexOf('\nfunction reconnectJournalValid(',source.indexOf('async function emptyReconnectInventory(')));
const actualManifest=JSON.parse(await readFile(new URL('../../../extension/chrome/manifest.json',import.meta.url),'utf8'));

test('real Chrome recovery inventory with production permissions and explicit tabs metadata',{timeout:60000},async()=>{
 const results=[];
 for(const tabsPermission of [false,true]){
  const directory=await mkdtemp(path.join(tmpdir(),'mechanize-recovery-chrome-'));
  const extension=path.join(directory,'extension');await mkdir(extension);
  const manifest={manifest_version:3,name:'Mechanize isolated recovery fixture',version:'1.0.0',permissions:[...actualManifest.permissions,...(tabsPermission?['tabs']:[])],optional_host_permissions:actualManifest.optional_host_permissions,background:{service_worker:'worker.js'},options_page:'options.html'};
  await writeFile(path.join(extension,'manifest.json'),JSON.stringify(manifest));
  await writeFile(path.join(extension,'options.html'),'<!doctype html><title>Isolated recovery fixture</title>');
  await writeFile(path.join(extension,'worker.js'),`let reconnectInventoryReason='none';const reconnectRefuse=code=>({code});const reconnectInventoryRefuse=code=>{reconnectInventoryReason=code;return {code:'inventoryChanged'};};${inventory}\nglobalThis.runFixture=async()=>{const tabs=await chrome.tabs.query({});const shape=tabs.map(t=>({urlPresent:typeof t.url==='string',pendingURLPresent:typeof t.pendingUrl==='string',pendingEqualsURL:typeof t.pendingUrl==='string'&&t.pendingUrl===t.url,ownOptions:typeof t.url==='string'&&t.url===chrome.runtime.getURL('options.html'),manager:typeof t.url==='string'&&t.url.startsWith('chrome://extensions/')}));try{await emptyReconnectInventory();return {ready:true,reason:'none',shape};}catch{return {ready:false,reason:reconnectInventoryReason,shape};}};`);
  let context;
  try{
   context=await chromium.launchPersistentContext(path.join(directory,'profile'),{executablePath:'/Applications/Google Chrome.app/Contents/MacOS/Google Chrome',headless:true,ignoreDefaultArgs:['--disable-extensions'],args:['--enable-unsafe-extension-debugging']});
   // Branded Chrome ignores command-line load-extension; this supported
   // test-only extension loader is enabled solely in the disposable profile.
   const browserCDP=await context.browser().newBrowserCDPSession();
   await browserCDP.send('Extensions.loadUnpacked',{path:extension});
   const worker=context.serviceWorkers()[0]||await context.waitForEvent('serviceworker',{timeout:15000});
   const extensionID=new URL(worker.url()).hostname;
   const options=await context.newPage();await options.goto(`chrome-extension://${extensionID}/options.html`);
   for(const page of context.pages())if(page!==options)await page.close();
   const ownOnly=await worker.evaluate(()=>runFixture());
   const management=await context.newPage();await management.goto('chrome://extensions/');
   const ownAndManager=await worker.evaluate(()=>runFixture());
   const missingURLFrames=await worker.evaluate(async()=>{const tabs=await chrome.tabs.query({});const result=[];for(const t of tabs)if(typeof t.url!=='string'){try{const frames=await chrome.webNavigation.getAllFrames({tabId:t.id}),root=frames?.find(f=>f.frameId===0);result.push({frameCount:frames?.length??0,rootPresent:!!root,rootURLPresent:typeof root?.url==='string',rootIsExtensions:root?.url==='chrome://extensions/',rootDocumentPresent:typeof root?.documentId==='string'&&root.documentId.length>0,rootActive:root?.documentLifecycle==='active',rootOutermost:root?.frameType==='outermost_frame',rootParent:root?.parentFrameId===-1,rootFailed:root?.errorOccurred===true,tabComplete:t.status==='complete'});}catch{result.push({frameUnavailable:true});}}return result;});
   console.log(JSON.stringify({fixture:'special-tab-frame-metadata',tabsPermission,missingURLFrames}));
   if(!tabsPermission){const proof=await worker.evaluate(async()=>{const tab=(await chrome.tabs.query({})).find(t=>typeof t.url!=='string');const rows=await reconnectInternalTabCensus(tab);return {count:rows.length,allIdentified:rows.every(r=>typeof r.documentId==='string'&&r.documentId.length>0),nonExecutable:rows.every(r=>r.executable===false&&r.origin===null),noURL:rows.every(r=>!Object.hasOwn(r,'url'))};});assert.ok(proof.count>0);assert.equal(proof.allIdentified,true);assert.equal(proof.nonExecutable,true);assert.equal(proof.noURL,true);}

   {
    const censusTab=await context.newPage();await censusTab.goto('chrome://newtab/');
    const lifecycleShape=await worker.evaluate(async()=>{
     const result=[];
     for(let n=0;n<10;n++){
      const rows=[];for(const tab of await chrome.tabs.query({}))for(const f of await chrome.webNavigation.getAllFrames({tabId:tab.id})||[])rows.push({zero:f.frameId===0,parentRoot:f.parentFrameId===0,parentAbsent:f.parentFrameId===-1,life:['active','cached','prerender','pending_deletion'].includes(f.documentLifecycle)?f.documentLifecycle:'missingOrInvalid',type:['outermost_frame','sub_frame','fenced_frame'].includes(f.frameType)?f.frameType:'missingOrInvalid',identified:typeof f.documentId==='string'});
      for(const row of rows)if(!result.some(r=>JSON.stringify(r)===JSON.stringify(row)))result.push(row);
      await new Promise(r=>setTimeout(r,100));
     }return result;
    });console.log(JSON.stringify({fixture:'disposable-lifecycle-shapes',tabsPermission,lifecycleShape}));
    await censusTab.close();
   }
   if(tabsPermission){
    const newtab=await context.newPage();await newtab.goto('chrome://newtab/');
    const builtin=await worker.evaluate(async()=>{
     const tabs=await chrome.tabs.query({}),tab=tabs.find(t=>t.url==='chrome://newtab/');
     if(!tab)return {present:false};
     const read=chrome.webNavigation.getAllFrames.bind(chrome.webNavigation);
     let frames=[];const until=Date.now()+5000;
     do{frames=await read({tabId:tab.id});if(frames.some(f=>f.frameId!==0&&f.url.startsWith('chrome-untrusted://new-tab-page/')))break;await new Promise(resolve=>setTimeout(resolve,50));}while(Date.now()<until);
     const children=frames.filter(f=>f.frameId!==0);
     if(!children.length)return {present:true,children:0};
     chrome.webNavigation.getAllFrames=async query=>(await read(query)).map(f=>query.tabId===tab.id&&f.frameId!==0?{...f,errorOccurred:true}:f);
     let shortcutDenied=false,fullReady=false,identitiesRetained=false,shortcutReason="none",fullReason="none";
     try{await emptyReconnectInventory();}catch{shortcutReason=reconnectInventoryReason;shortcutDenied=reconnectInventoryReason==='nonSetupTab';}
     try{const proof=JSON.parse(await emptyReconnectInventory([tab]));fullReady=true;identitiesRetained=children.every(f=>proof[0].frames.some(p=>p.documentId===f.documentId&&p.frameId===f.frameId&&p.parentFrameId===f.parentFrameId));}catch{fullReason=reconnectInventoryReason;}
     chrome.webNavigation.getAllFrames=read;
     return {present:true,children:children.length,shortcutDenied,fullReady,identitiesRetained,shortcutReason,fullReason,childShape:children.map(f=>{let u;try{u=new URL(f.url);}catch{return {valid:false}}return {protocol:u.protocol,host:u.hostname,path:u.pathname,queryKeys:[...u.searchParams.keys()],length:f.url.length};})};
    });
    assert.equal(builtin.present,true);assert.ok(builtin.children>0,'real built-in child metadata unavailable');assert.equal(builtin.shortcutDenied,true,JSON.stringify(builtin));assert.equal(builtin.fullReady,true);assert.equal(builtin.identitiesRetained,true);
    await newtab.close();
   }
   await management.close();
   const afterClosingManager=await worker.evaluate(()=>runFixture());
   results.push({tabsPermission,ownOnly,ownAndManager,afterClosingManager});
   assert.equal(ownOnly.shape.length,1);assert.equal(ownAndManager.shape.length,2);
   assert.equal(ownOnly.ready,true);assert.equal(ownOnly.shape[0].ownOptions,true);
   assert.equal(afterClosingManager.ready,true);assert.equal(afterClosingManager.shape.length,1);
   if(tabsPermission){assert.equal(ownAndManager.ready,true);assert.equal(ownAndManager.shape.filter(t=>t.manager).length,1);}
   else{assert.equal(ownAndManager.ready,false);assert.equal(ownAndManager.reason,'nonSetupTab');assert.equal(ownAndManager.shape.filter(t=>!t.urlPresent).length,1);assert.ok(ownAndManager.shape.every(t=>!t.pendingURLPresent));}
  }finally{await context?.close();await rm(directory,{recursive:true,force:true});}
 }
 console.log(JSON.stringify({fixture:'real-isolated-Chrome-extension-metadata',results}));
});
