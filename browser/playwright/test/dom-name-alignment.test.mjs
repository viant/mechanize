import {test} from 'node:test';
import assert from 'node:assert/strict';
import {chromium} from 'playwright-core';
import {readFile,mkdtemp,rm} from 'node:fs/promises';
import {tmpdir} from 'node:os';
import {join} from 'node:path';

test('DOM observation names resolve unchanged through public Playwright role locators',{timeout:30000},async()=>{
 const directory=await mkdtemp(join(tmpdir(),'mechanize-name-parity-'));let context;
 try {
  context=await chromium.launchPersistentContext(join(directory,'profile'),{executablePath:'/Applications/Google Chrome.app/Contents/MacOS/Google Chrome',headless:true});
  const page=await context.newPage();
  await page.route("https://fixture.test/**",route=>route.fulfill({contentType:"text/html",body:"<!doctype html>"}));await page.goto("https://fixture.test/");
  await page.setContent('<a id="items" href="#items"><div>Upcoming items</div><div>1&nbsp;234 units</div></a><button id="inline"><span>Re</span><span>open</span></button><button id="blocks"><span style="display:inline-block">Save</span><span style="display:inline-block">changes</span></button><button id="decoration"><span>Public</span><span aria-hidden="true">decoration</span></button><span id="caption" hidden>Reference caption</span><button id="reference" aria-labelledby="caption">ignored</button><button id="break">Line<br>break</button><div id="shadow" role="button"></div><input id="placeholder" placeholder="Search public items"><textarea id="placeholdernote" placeholder="Public note"></textarea>');
  await page.evaluate(()=>{document.querySelector('#shadow').attachShadow({mode:'open'}).innerHTML='<div>Shadow</div><span>action</span>';document.querySelector('#items').addEventListener('click',()=>{document.body.dataset.itemClicked='yes';});});
  for(const file of ['protocol.js','accessibility-provider.js','dom.js'])await page.addScriptTag({content:await readFile(new URL('../../../extension/chrome/'+file,import.meta.url),'utf8')});
  const observed=await page.evaluate(()=>MechanizeDOM.snapshot(document).nodes.filter(node=>node.id));
  for(const [id,expected] of [['items','Upcoming items 1 234 units'],['inline','Reopen'],['blocks','Save changes'],['decoration','Public'],['reference','Reference caption'],['break','Line break'],['shadow','Shadow action'],['placeholder','Search public items'],['placeholdernote','Public note']]){
   const node=observed.find(node=>node.id===id);assert.ok(node,id);assert.equal(node.name,expected,id);
   const locator=page.getByRole(node.role,{name:node.name,exact:true});assert.equal(await locator.count(),1,id);
   assert.equal(await locator.getAttribute('id'),id);
   assert.equal(await page.evaluate(({role,name})=>MechanizeDOM.resolve(document,{strategy:'role',value:role,name,exact:true}).id,node),id);
  }
  await page.evaluate(()=>{const decoration=document.createElement('span');decoration.setAttribute('aria-hidden','true');document.body.append(decoration);globalThis.churn=setInterval(()=>decoration.textContent=String(Date.now()),20);setTimeout(()=>{const button=document.createElement('button');button.id='delayed';button.innerHTML='<div>Continue</div><div>review</div>';button.onclick=()=>document.body.dataset.delayedClicked='yes';document.body.append(button);},200);});
  await page.getByRole('button',{name:'Continue review',exact:true}).click({timeout:3000});
  assert.equal(await page.evaluate(()=>document.body.dataset.delayedClicked),'yes');
  await page.evaluate(()=>clearInterval(globalThis.churn));
  const target=observed.find(node=>node.id==='items');await page.getByRole(target.role,{name:target.name,exact:true}).click({timeout:3000});
  assert.equal(await page.evaluate(()=>document.body.dataset.itemClicked),'yes');
 } finally {await context?.close();await rm(directory,{recursive:true,force:true});}
});
