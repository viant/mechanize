import {createInterface} from 'node:readline';
import {readFile} from 'node:fs/promises';
import {chromium} from 'playwright-core';
import {BrowserSessions} from './sessions.mjs';
import {executeStep} from './container-executor.mjs';
import {assertAllowed, selectFrame, restrictNavigation} from './container-policy.mjs';
import {NetworkEvidence} from './network-evidence.mjs';

// Deployment-only path, never a tool argument. No profile content goes to logs.
const profile = process.env.MECHANIZE_STORAGE_STATE;
const storageState = profile ? JSON.parse(await readFile(profile, 'utf8')) : undefined;
const policy = JSON.parse(process.env.MECHANIZE_BROWSER_POLICY || '{"allowAllWeb":true}');
new NetworkEvidence(policy.networkRules);
const evidence = new WeakMap();
const sessions = new BrowserSessions({storageState, inspectionOnly: policy.inspectionOnly,
  idleMs: Number(process.env.MECHANIZE_IDLE_MS || 300000),
  maxSessions: Number(process.env.MECHANIZE_MAX_SESSIONS || 32),
  launch: () => chromium.launch({headless: true, executablePath: process.env.CHROMIUM_PATH || undefined,
    ...(process.env.MECHANIZE_PROXY_SERVER ? {proxy: {server: process.env.MECHANIZE_PROXY_SERVER, bypass: '<-loopback>'}} : {})}),
  prepareContext: async context => {
    if (policy.inspectionOnly) await restrictNavigation(context, policy);
    const collector = new NetworkEvidence(policy.networkRules);
    collector.attach(context);
    evidence.set(context, collector);
  },
});
const lines = createInterface({input: process.stdin, crlfDelay: Infinity});
const active = new Set();
const emit = value => {
  let wire = JSON.stringify(value);
  if (Buffer.byteLength(wire) > 1048576) wire = JSON.stringify({id:value.id,error:{code:'resultTooLarge',message:'Browser result exceeds 1 MiB',outcome:'unknown'}});
  process.stdout.write(wire + '\n');
};
async function dispatch(message) {
  switch (message.method) {
    case 'register': sessions.register(message.session); return {};
    case 'terminate': await sessions.terminate(message.session); return {};
    case 'execute': return sessions.use(message.session, page => executeStep(page, message.step, policy));
    case 'dom': return sessions.use(message.session, async page => {
      const scope = Object.fromEntries(Object.entries(message.step?.target?.scope?.frame ?? {}).map(([key,value])=>[key,value.string]));
      const target = await selectFrame(page, scope, policy);
      const html=await target.content(),text=await target.locator('body').innerText({timeout:5000}),title=await target.title();
      const url=assertAllowed(target.url(),policy);
      assertAllowed(page.url(),policy);
      return {origin:url.origin,url:url.href,title,html:html.slice(0,300000),text:text.slice(0,64000),truncated:html.length>300000||text.length>64000};
    });
    case 'frames': return sessions.use(message.session, async page => {
      const origin=assertAllowed(page.url(),policy).origin,frames=[];
      let omitted=0;
      for(const frame of page.frames()) {
        if(frame===page.mainFrame())continue;
        try {assertAllowed(frame.url(),policy);} catch {omitted++;continue;}
        const element=await frame.frameElement();
        let id;
        try {id=await element.getAttribute('id');} finally {await element.dispose();}
        frames.push({id:id||undefined,name:frame.name()||undefined,origin:new URL(frame.url()).origin});
      }
      assertAllowed(page.url(),policy);
      return {origin,frames:frames.slice(0,100),truncated:frames.length>100,omitted};
    });
    case 'network': return sessions.use(message.session, page => ({origin:assertAllowed(page.url(),policy).origin,
      ...evidence.get(page.context()).snapshot()}));
    case 'screenshot': return sessions.use(message.session, async page => {
      assertAllowed(page.url(),policy);
      const scale=message.scale??1;
      if(!Number.isFinite(scale)||scale<=0||scale>1)throw Error('Invalid screenshot scale');
      let data;
      if(scale===1)data=(await page.screenshot({type:'png',timeout:5000})).toString('base64');
      else {
        const session=await page.context().newCDPSession(page);
        try {
          const {cssVisualViewport:view}=await session.send('Page.getLayoutMetrics');
          ({data}=await session.send('Page.captureScreenshot',{format:'png',captureBeyondViewport:false,clip:{x:view.pageX,y:view.pageY,width:view.clientWidth,height:view.clientHeight,scale}}));
        } finally {await session.detach();}
      }
      assertAllowed(page.url(),policy);
      return {origin:new URL(page.url()).origin,url:page.url(),mimeType:'image/png',data};
    });
    default: throw Error('Unsupported worker operation');
  }
}
lines.on('line', line => {
  if (Buffer.byteLength(line) > 1048576) {lines.close(); return;}
  let message;
  try {message = JSON.parse(line);} catch {lines.close(); return;}
  if (typeof message.id !== 'string' || active.has(message.id)) {lines.close(); return;}
  active.add(message.id);
  dispatch(message).then(result => emit({id: message.id, result}), error => {
    // Browser errors may include page values or URLs. Return a closed envelope.
    const code = ['deadline','browserStepFailed'].includes(error.code) ? error.code : 'browserOperationFailed';
    emit({id: message.id, error: {code,
      message: 'Browser operation failed', outcome: error.outcome ?? 'notDispatched'}});
  }).finally(() => active.delete(message.id));
});
let stopping;
function stop() {
  if (!stopping) stopping = sessions.close().catch(() => {process.exitCode = 1;});
  return stopping;
}
lines.on('close', stop);
process.on('SIGTERM', () => {lines.close(); void stop();});
process.on('SIGINT', () => {lines.close(); void stop();});
