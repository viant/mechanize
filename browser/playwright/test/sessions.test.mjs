import {test} from 'node:test';
import assert from 'node:assert/strict';
import {EventEmitter} from 'node:events';
import {BrowserSessions} from '../sessions.mjs';

function fixture() {
  let launches = 0;
  const contexts = [], timers = [];
  const browser = new EventEmitter();
  browser.newContext = async options => {
    const context = new EventEmitter();
    Object.assign(context, {options, closed: false, newPage: async () => ({context}), close: async () => {context.closed = true; context.emit('closed');}});
    contexts.push(context);
    return context;
  };
  browser.close = async () => browser.emit('disconnected');
  const sessions = new BrowserSessions({launch: async () => {launches++; return browser;},
    storageState: {cookies: [], origins: []}, setTimer: fn => {timers.push(fn); return fn;}, clearTimer: () => {}});
  return {sessions, contexts, timers, launches: () => launches};
}

test('default idle timeout is exactly five minutes', () => {
  const sessions=new BrowserSessions({launch:async()=>{}});
  assert.equal(sessions.idleMs,5*60*1000);
});

test('transport sessions reuse tabs and isolate contexts and deployment state', async () => {
  const f = fixture();
  f.sessions.register('a'); f.sessions.register('b');
  const a = await f.sessions.use('a', page => page);
  assert.equal(await f.sessions.use('a', page => page), a);
  const b = await f.sessions.use('b', page => page);
  assert.notEqual(a, b);
  assert.notEqual(f.contexts[0].options.storageState, f.contexts[1].options.storageState);
  assert.equal(f.launches(), 1);
  await f.sessions.terminate('a');
  assert.equal(f.contexts[0].closed, true);
  assert.equal(f.contexts[1].closed, false);
  await assert.rejects(f.sessions.use('a', () => {}), /terminated/);
  await f.sessions.close();
});

test('stale timers cannot close reused tabs; idle expiry gives a fresh tab', async () => {
  const f = fixture(); f.sessions.register('a');
  const first = await f.sessions.use('a', page => page);
  await f.sessions.use('a', () => {});
  f.timers[0]();
  assert.equal(f.contexts[0].closed, false);
  f.timers[1]();
  await Promise.resolve();
  assert.equal(f.contexts[0].closed, true);
  assert.notEqual(await f.sessions.use('a', page => page), first);
  await f.sessions.close();
});

test('termination interrupts active browser work without waiting for its lane', async () => {
  const f = fixture(); f.sessions.register('a');
  let started;
  const ready = new Promise(resolve => {started = resolve;});
  const active = f.sessions.use('a', (page, context) => new Promise(resolve => {
    context.once('closed', resolve); started();
  }));
  await ready;
  await assert.rejects(f.sessions.use('a', () => {}), /already active/);
  await f.sessions.terminate('a');
  await active;
  assert.equal(f.contexts[0].closed, true);
  assert.equal(f.timers.length, 0);
  await f.sessions.close();
});

test('failed idle cleanup refuses resource reuse', async () => {
  const f = fixture(); f.sessions.register('a');
  await f.sessions.use('a', () => {});
  f.contexts[0].close = async () => {throw Error('close failed');};
  f.timers[0]();
  await assert.rejects(f.sessions.use('a', () => {}), /close failed/);
  assert.equal(f.contexts.length, 1);
});

test('termination waits for in-flight context creation and closes the late context', async () => {
  const f = fixture(); f.sessions.register('a');
  const browser = await f.sessions.browserFor();
  const original = browser.newContext;
  let release, entered;
  const ready = new Promise(resolve => {entered = resolve;});
  browser.newContext = async options => {entered(); await new Promise(resolve => {release = resolve;}); return original(options);};
  const operation = f.sessions.use('a', () => assert.fail('terminated operation dispatched'));
  const rejected = assert.rejects(operation, /terminated/);
  await ready;
  let closed = false;
  const closing = f.sessions.terminate('a').then(() => {closed = true;});
  await Promise.resolve(); assert.equal(closed, false);
  release(); await closing; await rejected;
  assert.equal(f.contexts.length, 1); assert.equal(f.contexts[0].closed, true);
  await f.sessions.close();
});

test('failed newPage releases its context before another request', async () => {
  const f = fixture(); f.sessions.register('a');
  const browser = await f.sessions.browserFor(), original = browser.newContext;
  browser.newContext = async options => {const c=await original(options); c.newPage=async()=>{throw Error('page failed');}; return c;};
  await assert.rejects(f.sessions.use('a', () => {}), /page failed/);
  assert.equal(f.contexts[0].closed,true);
  browser.newContext = original;
  await f.sessions.use('a', page => assert.ok(page));
  await f.sessions.close();
});
