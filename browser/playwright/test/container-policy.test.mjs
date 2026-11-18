import {test} from 'node:test';
import assert from 'node:assert/strict';
import {assertAllowed,selectFrame,restrictNavigation} from '../container-policy.mjs';
import {executeStep} from '../container-executor.mjs';

const policy={allowAllWeb:false,allowedOrigins:['https://site.example','https://store.example'],inspectionOnly:true};
function fixture() {
  const frame={name:()=> 'store',url:()=> 'https://store.example/catalogue',
    frameElement:async()=>({getAttribute:async()=> 'store-frame',dispose:async()=>{}})};
  const page={url:()=> 'https://site.example/',mainFrame:()=> page,frames:()=>[page,frame],setDefaultTimeout:()=>{}};
  return {page,frame};
}

test('matches one frame by name or DOM id and rejects missing/ambiguous frames',async()=>{
  const {page,frame}=fixture();
  assert.equal(await selectFrame(page,{name:'store'},policy),frame);
  assert.equal(await selectFrame(page,{id:'store-frame'},policy),frame);
  await assert.rejects(selectFrame(page,{name:'missing'},policy),/Exactly one/);
  page.frames=()=>[page,frame,frame];
  await assert.rejects(selectFrame(page,{name:'store'},policy),/Exactly one/);
});

test('rejects blocked frames and unapproved navigation before dispatch',async()=>{
  const {page,frame}=fixture();frame.url=()=> 'https://unapproved.example';
  await assert.rejects(selectFrame(page,{name:'store'},policy),/denied/);
  let handler,continued=0,blocked=0;
  await restrictNavigation({route:async(pattern,fn)=>{handler=fn;}},policy);
  for(const url of ['https://unapproved.example','file:///private/test','https://site.example@unapproved.example']) {
    await handler({request:()=>({isNavigationRequest:()=>true,url:()=>url}),abort:async()=>{blocked++;},continue:async()=>{continued++;}});
  }
  assert.equal(blocked,3);assert.equal(continued,0);
  assert.throws(()=>assertAllowed('https://user:secret@site.example',policy));
});

test('inspection mode rejects clicks, fill and keyboard before touching a page',async()=>{
  const {page}=fixture();
  for(const action of ['element.press','element.fill','element.pressKey','element.check','element.select']) {
    await assert.rejects(executeStep(page,{action,target:{surface:{kind:'web',origin:'https://site.example'},scope:{}},timeoutMs:100},policy),
      error=>error.outcome==='notDispatched');
  }
});

test('navigation responses are inspected without following redirects first',async()=>{
  let handler,blocked=0,fulfilled=0,disposed=0;
  await restrictNavigation({route:async(pattern,fn)=>{handler=fn;}},policy);
  for(const location of ['https://unapproved.example',undefined]) {
    await handler({request:()=>({isNavigationRequest:()=>true,url:()=> 'https://site.example/start'}),
      fetch:async options=>{assert.equal(options.maxRedirects,0);return {headers:()=>({location}),status:()=>location?302:200,dispose:async()=>{disposed++;}};},
      abort:async()=>{blocked++;},fulfill:async()=>{fulfilled++;}});
  }
  assert.equal(blocked,1);assert.equal(fulfilled,1);assert.equal(disposed,2);
});

test('reads the selected frame and refuses evidence after a frame changes origin',async()=>{
  const {page,frame}=fixture();
  const target={waitFor:async()=>{},count:async()=>1,textContent:async()=> 'expected'};
  frame.getByText=()=> target;
  const step={action:'element.read',timeoutMs:100,target:{surface:{kind:'web',origin:'https://site.example'},
    scope:{frame:{name:{kind:'string',string:'store'}}},locator:{strategy:'text',value:{kind:'string',string:'value'}},cardinality:'one'},
    arguments:{attribute:{kind:'string',string:'text'}}};
  assert.equal(await executeStep(page,step,policy),'expected');
  target.textContent=async()=>{frame.url=()=> 'https://unapproved.example';return 'PRIVATE';};
  await assert.rejects(executeStep(page,step,policy),/Browser step failed/);
});
