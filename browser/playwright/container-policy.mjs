import {navigationResponses} from './network-evidence.mjs';
import {randomUUID} from 'node:crypto';

const frameRefs = new WeakMap();
export function frameReference(frame) {
  if (!frameRefs.has(frame)) frameRefs.set(frame, randomUUID());
  return frameRefs.get(frame);
}

export function assertAllowed(url, policy = {allowAllWeb: true}) {
  const parsed = new URL(url);
  if (!['http:', 'https:'].includes(parsed.protocol) || parsed.username || parsed.password ||
      (!policy.allowAllWeb && !policy.allowedOrigins?.includes(parsed.origin))) throw Error('Browser origin denied');
  return parsed;
}

// Frame IDs are DOM iframe IDs, not internal browser handles.
export async function selectFrame(page, scope, policy) {
  await finishNavigation(page);
  assertAllowed(page.url(), policy);
  if (!scope || !Object.keys(scope).length) return page;
  if (Object.keys(scope).some(key => !['id', 'name', 'ref'].includes(key))) throw Error('Unsupported frame selector');
  const matches = [];
  for (const frame of page.frames()) {
    if (frame === page.mainFrame()) continue;
    if (scope.ref !== undefined && frameRefs.get(frame) !== scope.ref) continue;
    if (scope.name !== undefined && frame.name() !== scope.name) continue;
    if (scope.id !== undefined) {
      const element = await frame.frameElement();
      try { if (await element.getAttribute('id') !== scope.id) continue; }
      finally { await element.dispose(); }
    }
    matches.push(frame);
  }
  if (matches.length !== 1) throw Error('Exactly one frame required');
  await finishNavigation(matches[0]);
  assertAllowed(matches[0].url(), policy);
  return matches[0];
}

export const inspectionActions = ['browser.openOrigin', 'browser.navigate', 'browser.activate', 'element.read', 'expect'];

const redirects = new WeakMap();

export async function finishNavigation(target) {
  const frame = target.mainFrame ? target.mainFrame() : target;
  let state = redirects.get(frame);
  while (state) {
    await state.promise;
    if (redirects.get(frame) === state) { redirects.delete(frame); return; }
    state = redirects.get(frame);
  }
}

function followRedirect(frame, destination) {
  const previous = redirects.get(frame);
  const hops = previous && !previous.settled ? previous.hops + 1 : 1;
  if (hops > 10) throw Error('Redirect limit exceeded');
  const committed = frame.page().waitForEvent('framenavigated', {predicate: changed => changed === frame, timeout:30000});
  const state = {hops, settled:false};
  state.promise = (async () => {
    await committed;
    await frame.waitForLoadState('domcontentloaded', {timeout:30000});
    await frame.goto(destination, {waitUntil:'domcontentloaded', timeout:30000});
    const next = redirects.get(frame);
    if (next && next !== state) await next.promise;
  })();
  // Keep a rejected transition available to the next observation, without an unhandled rejection.
  state.promise.then(() => {state.settled=true;}, () => {state.settled=true;});
  redirects.set(frame,state);
}

export async function restrictNavigation(context, policy) {
  await context.route('**/*', async route => {
    if (route.request().isNavigationRequest()) {
      let response;
      try {
        const url = assertAllowed(route.request().url(), policy);
        // continue() follows server redirects without invoking this handler again.
        response = await route.fetch({maxRedirects:0, timeout:30000});
        const observed = {status:response.status()};
        navigationResponses.set(route.request(),observed);
        const location = response.headers().location;
        if (response.status() >= 300 && response.status() < 400 && location) {
          const destination = assertAllowed(new URL(location,url).href,policy).href;
          followRedirect(route.request().frame(),destination);
          observed.redirectHandled = true;
          // A normal redirect response bypasses future route hooks. Commit an inert
          // document, then navigate explicitly so every hop is checked exactly once.
          await route.fulfill({status:200,contentType:'text/html',body:''});
        } else { await route.fulfill({response}); }
      } catch { await route.abort('blockedbyclient').catch(()=>{}); }
      finally { if (response) await response.dispose().catch(()=>{}); }
      return;
    }
    await route.continue();
  });
}
