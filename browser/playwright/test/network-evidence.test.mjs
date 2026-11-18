import {test} from 'node:test';
import assert from 'node:assert/strict';
import {EventEmitter} from 'node:events';
import {NetworkEvidence,navigationResponses} from '../network-evidence.mjs';

const rules = [{origin:'https://metrics.example',path:'/collect',parameters:{pixel:'value',amount:'value',currency:'value',order:'presence'}}];
function request(url, body, contentType) {
  return {url:()=>url,postData:()=>body,headers:()=>({'content-type':contentType,cookie:'PRIVATE_COOKIE'}),
    frame:()=>({url:()=> 'https://shop.example/checkout?secret=PRIVATE_FRAME'}),method:()=>body?'POST':'GET',resourceType:()=> 'fetch'};
}

test('captures only configured fields, presence instead of order IDs, and response status', () => {
  const evidence=new NetworkEvidence(rules),context=new EventEmitter();evidence.attach(context);
  const req=request('https://metrics.example/collect?pixel=42&amount=19.95&currency=USD&order=PRIVATE_ORDER&token=PRIVATE_TOKEN');
  context.emit('request',req);
  context.emit('response',{request:()=>req,status:()=>204});
  const snapshot=evidence.snapshot(),record=snapshot.requests[0];
  assert.equal(record.status,204);assert.ok(record.elapsedMs>=0);
  assert.deepEqual(record.parameters.amount.values,['19.95']);
  assert.deepEqual(record.parameters.order,{present:true,nonempty:true});
  assert.equal(record.frameOrigin,'https://shop.example');
  assert.doesNotMatch(JSON.stringify(snapshot),/PRIVATE_|token|cookie|checkout|startedAt/);
  snapshot.requests[0].parameters.amount.values[0]='changed';
  assert.deepEqual(evidence.snapshot().requests[0].parameters.amount.values,['19.95']);
});

test('captures supported bounded POST fields without returning request bodies', () => {
  for(const [body,type] of [['amount=24.50&order=PRIVATE_ORDER&secret=PRIVATE_SECRET','application/x-www-form-urlencoded'],
    [JSON.stringify({amount:24.5,order:'PRIVATE_ORDER',secret:'PRIVATE_SECRET'}),'application/json']]) {
    const evidence=new NetworkEvidence(rules);
    evidence.capture(request('https://metrics.example/collect',body,type));
    const snapshot=evidence.snapshot();
    assert.equal(snapshot.requests.length,1);
    assert.equal(snapshot.requests[0].parameters.order.present,true);
    assert.doesNotMatch(JSON.stringify(snapshot),/PRIVATE_|body|secret/);
  }
});

test('unconfigured endpoints are ignored and a new session has no previous evidence', () => {
  const evidence=new NetworkEvidence(rules);
  evidence.capture(request('https://other.example/collect?amount=PRIVATE'));
  evidence.capture(request('https://metrics.example/private?amount=PRIVATE'));
  assert.equal(evidence.snapshot().requests.length,0);
  assert.equal(new NetworkEvidence().snapshot().captureConfigured,false);
});

test('reports the real server status when navigation safely handles a redirect',()=>{
  const evidence=new NetworkEvidence(rules),context=new EventEmitter();evidence.attach(context);
  const req=request('https://metrics.example/collect');context.emit('request',req);
  navigationResponses.set(req,{status:302,redirectHandled:true});
  context.emit('response',{request:()=>req,status:()=>200});
  const record=evidence.snapshot().requests[0];
  assert.equal(record.status,302);assert.equal(record.redirectHandled,true);
});

test('caps request count and value length and records failure without raw error text', () => {
  const evidence=new NetworkEvidence(rules),context=new EventEmitter();evidence.attach(context);
  const req=request('https://metrics.example/collect?amount='+ 'a'.repeat(200));
  context.emit('request',req);context.emit('requestfailed',req);
  for(let i=0;i<105;i++)evidence.capture(request('https://metrics.example/collect'));
  const snapshot=evidence.snapshot();
  assert.equal(snapshot.requests.length,100);assert.equal(snapshot.dropped,6);
  assert.equal(snapshot.truncated,true);
  assert.equal(snapshot.requests[0].parameters.amount.values[0].length,128);
  assert.equal(snapshot.requests[0].parameters.amount.truncated,true);
  assert.equal(snapshot.requests[0].failed,true);
});

test('rejects invalid capture policies and bounds malformed payload errors', () => {
  for(const rule of [{...rules[0],origin:'https://metrics.example/private'}, {...rules[0],path:'/collect?token=x'},
    {...rules[0],parameters:{order:'raw'}}]) assert.throws(()=>new NetworkEvidence([rule]));
  const evidence=new NetworkEvidence(rules);
  evidence.capture(request('https://metrics.example/collect','PRIVATE_MALFORMED','application/json'));
  assert.equal(evidence.snapshot().requests[0].payloadStatus,'malformed');
  assert.equal(evidence.snapshot().requests[0].parameters.amount.unknown,true);
  assert.doesNotMatch(JSON.stringify(evidence.snapshot()),/PRIVATE/);
});

test('bounds UTF-8 payload and snapshot sizes below the worker result limit',()=>{
  const parameters=Object.fromEntries(Array.from({length:20},(_,i)=>['v'+i,'value']));
  const evidence=new NetworkEvidence([{origin:'https://metrics.example',path:'/collect',parameters}]);
  const query=new URLSearchParams();
  for(const key of Object.keys(parameters))for(let i=0;i<5;i++)query.append(key,'🌲'.repeat(80));
  for(let i=0;i<100;i++)evidence.capture(request('https://metrics.example/collect?'+query));
  const snapshot=evidence.snapshot();
  assert.equal(snapshot.truncated,true);assert.ok(snapshot.dropped>0);
  assert.ok(Buffer.byteLength(JSON.stringify(snapshot),'utf8')<600*1024);
  const payload=new NetworkEvidence(rules);
  payload.capture(request('https://metrics.example/collect',JSON.stringify({amount:'🌲'.repeat(5000)}),'application/json'));
  assert.equal(payload.snapshot().requests[0].payloadStatus,'too-large');
  assert.equal(payload.snapshot().requests[0].parameters.amount.unknown,true);
});
