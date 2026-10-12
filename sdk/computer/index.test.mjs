import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createComputer } from './index.mjs';
function fixture(status='succeeded') {
 const calls=[];
 const callTool=async(name,args)=>{
  calls.push({name,args});
  let result;
  if(name==='mechanize_session_open')result={sessionId:'session'};
  else if(name==='mechanize_browser_tabs')result={complete:true,tabs:[{handle:'tab'}]};
  else if(name==='mechanize_observe')result={epoch:'epoch',nodes:[{role:'button',name:'Send',enabled:true}]};
  else if(name==='mechanize_script_run')result={operationId:'operation',runId:'run',executionStatus:'queued'};
  else if(name==='mechanize_operation_status')result={operationId:'operation',executionStatus:status};
  else result={};
  return {structuredContent:result};
 };
 return {calls,callTool};
}
test('selected tab uses exact typed MCP locator and invalidates numeric indices after input',async()=>{
 const f=fixture(),computer=await createComputer({...f,grantId:'grant',purpose:'public fixture'});
 const tab=await computer.getTab({origin:'https://fixture.test',tabId:'tab'});
 await tab.getAXState();await tab.click(0,{businessKey:{case:'public fixture'}});
 const call=f.calls.find(c=>c.name==='mechanize_script_run'),plan=JSON.parse(call.args.source);
 assert.equal(plan.steps[0].action,'element.press');assert.equal(plan.steps[0].target.locator.exact,true);
 assert.equal(plan.steps[0].timeoutMs,3000);
 assert.deepEqual(f.calls.find(c=>c.name==='mechanize_operation_status').args,{sessionId:'session',operationId:'operation'});
 await assert.rejects(tab.click(0,{businessKey:{case:'second'}}),/Fresh state/);
 await computer.close();await assert.rejects(tab.getAXState(),/closed/);
});
test('unknown action is not replayed and error retains only owned operation handles',async()=>{
 const f=fixture('failed'),computer=await createComputer(f),tab=await computer.getTab({origin:'https://fixture.test',tabId:'tab'});
 await assert.rejects(tab.getByRole('button',{name:'Send'}).click({businessKey:{case:'fixture'}}),error=>error.operationId==='operation'&&error.runId==='run');
 assert.equal(f.calls.filter(c=>c.name==='mechanize_script_run').length,1);
});
test('requires explicit effect key and rejects stale/unowned tab before dispatch',async()=>{
 const f=fixture(),computer=await createComputer(f);
 await assert.rejects(computer.getTab({origin:'https://fixture.test',tabId:'other'}),/unavailable/);
 const tab=await computer.getTab({origin:'https://fixture.test',tabId:'tab'});
 await assert.rejects(tab.getByRole('button',{name:'Send'}).click(),/businessKey/);
 assert.equal(f.calls.filter(c=>c.name==='mechanize_script_run').length,0);
});
test('coordinate clicks use only a fresh original-pixel permit and cannot reuse it',async()=>{
 const f=fixture(),original=f.callTool;
 f.callTool=async(name,args)=>name==='mechanize_capture_window_frame'?{structuredContent:{captureRef:'permit',metadata:{widthPixels:100,heightPixels:80}}}:original(name,args);
 const computer=await createComputer(f),app=await computer.getApp({bundleId:'fixture.app',processId:1,processStartToken:'birth',windowId:2});
 await assert.rejects(app.click([1,2],{businessKey:{case:'fixture'}}),/Fresh screenshot/);
 await app.getClickScreenshot();await app.click([10,20],{businessKey:{case:'fixture'}});
 const step=JSON.parse(f.calls.find(c=>c.name==='mechanize_script_run').args.source).steps[0];
 assert.equal(step.command,'target.clickWindowFrame(captureRef:"permit",x:10,y:20)');
 await assert.rejects(app.click([10,20],{businessKey:{case:'repeat'}}),/Fresh screenshot/);
});
test('timing telemetry contains no arguments, results, or private error content',async()=>{
 const events=[];
 const computer=await createComputer({onTiming:event=>events.push(event),callTool:async(name)=>{
  if(name==='mechanize_session_open')return {structuredContent:{sessionId:'PRIVATE_SESSION_CANARY'}};
  return {isError:true,content:[{type:'text',text:'PRIVATE_ERROR_CANARY'}]};
 }});
 await assert.rejects(computer.listTabs({origin:'https://private-canary.test'}),/refused/);
 assert.deepEqual(events.map(e=>e.outcome),['returned','failed']);
 assert.ok(events.every(e=>Object.keys(e).sort().join()==='elapsedMs,outcome,tool'&&e.elapsedMs>=0));
 assert.ok(!JSON.stringify(events).includes('CANARY')&&!JSON.stringify(events).includes('private-canary'));
});
