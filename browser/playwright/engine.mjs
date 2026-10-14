import {chromium,errors as playwrightErrors} from 'playwright-core';
import fingerprint from './fingerprint.cjs';
import targetGuard from './target.cjs';
import {createScopedRelay,bounded} from './relay.mjs';

const sameIdentity=(a,b)=>a&&b&&['profileChannel','browserInstance','tabId','frameId','documentId','documentGeneration'].every(k=>a[k]===b[k]);
const closed=(value,required,optional=[])=>value&&typeof value==='object'&&!Array.isArray(value)&&required.every(k=>Object.hasOwn(value,k))&&Object.keys(value).every(k=>required.includes(k)||optional.includes(k));
const denied=code=>Object.assign(Error('Local Playwright operation unavailable'),{code});
const mutations=new Set(['element.fill','element.press']);
function validate(command){
  if(!closed(command,['requestId','action','identity','brokerEpoch','channelEpoch','scopeHash','deadlineUnixMs','locator'],['args','attemptId','controlLease','fingerprintVersion','fingerprintSHA256'])||!['read',...mutations].includes(command.action)||command.identity?.frameId!==0||!Number.isSafeInteger(command.deadlineUnixMs)||command.deadlineUnixMs<=Date.now()||command.deadlineUnixMs>Date.now()+30000||Buffer.byteLength(JSON.stringify(command))>256*1024)throw denied('playwrightCommandDenied');
  const l=command.locator;
  if(!closed(l,['strategy','value','exact'],['name','index','order'])||!['id','testId','role','label'].includes(l.strategy)||l.exact!==true||typeof l.value!=='string'||!l.value.length||l.value.length>1024||l.name!==undefined&&(l.strategy!=='role'||typeof l.name!=='string'||l.name.length>1024)||l.index!==undefined&&(!Number.isSafeInteger(l.index)||l.index<0||l.index>999||l.order!=='document')||l.index===undefined&&l.order!==undefined)throw denied('playwrightLocatorDenied');
  if(command.action==='read'&&(!closed(command.args,['attribute'])||!['text','name'].includes(command.args.attribute)))throw denied('playwrightReadDenied');
  if(mutations.has(command.action)&&(command.fingerprintVersion!==2||!/^([a-f0-9]{64})$/.test(command.fingerprintSHA256||'')))throw denied('playwrightBindingRequired');
}
function locatorFor(page,l){
  let locator;
  if(l.strategy==='role')locator=page.getByRole(l.value,{exact:true,...(l.name!==undefined?{name:l.name}:{})});
  else if(l.strategy==='label')locator=page.getByLabel(l.value,{exact:true});
  else if(l.strategy==='testId')locator=page.getByTestId(l.value);
  // JSON string quoting prevents selector/code injection; no caller CSS allowed.
  else locator=page.locator(`[id=${JSON.stringify(l.value)}]`);
  return l.index===undefined?locator:locator.nth(l.index);
}
export class PlaywrightEngine {
  #host;#attempts=new Map();#busy=false;
  constructor(host){
    // These are native-host callbacks, never JSON supplied by an MCP caller.
    for(const name of ['admit','current','openRelay','commitIntent','persistReceipt','redact'])if(typeof host?.[name]!=='function')throw denied('playwrightHostRequired');
    this.#host=host;
  }
  async execute(input){
    let command,authority,relay,browser,dispatched=false,recorded=false,ownsBusy=false;
    let result={dispatchState:'notDispatched',effectState:'none',errorCode:'playwrightUnavailable'};
    try{
      command=structuredClone(input);validate(command);
      if(this.#busy)throw denied('playwrightBusy');
      // Own the execution lane before fingerprint hashing yields. A refused
      // concurrent call must never acquire authority or release this owner.
      this.#busy=true;ownsBusy=true;
      if(mutations.has(command.action)){
        const fp=await fingerprint.mutationV2(command);
        if(fp.sha256!==command.fingerprintSHA256)throw denied('playwrightFingerprintMismatch');
        const prior=this.#attempts.get(command.attemptId);
        if(prior){if(prior.hash!==fp.sha256)throw denied('playwrightAttemptConflict');return structuredClone(prior.result??{dispatchState:'unknown',effectState:'unknown',errorCode:'playwrightUncertain'});}
        if(this.#attempts.size>=256)throw denied('playwrightAttemptCapacity');
      }
      authority=await bounded(this.#host.admit(command),command.deadlineUnixMs);
      if(!authority||authority.privateQuarantined!==false||!sameIdentity(authority.identity,command.identity)||!['brokerEpoch','channelEpoch','scopeHash'].every(k=>authority[k]===command[k])||!await this.#host.current(authority,command))throw denied('playwrightAuthorityDenied');
      if(authority.protectedOrigin===true&&(authority.privacyState!=='redacted-dom'||authority.domReadQualified!==true||!authority.privacyRevision))throw denied('playwrightPrivateDOMDenied');
      if(mutations.has(command.action)&&(!authority.committed||authority.fingerprintSHA256!==command.fingerprintSHA256||authority.controlLease?.id!==command.controlLease?.id||authority.controlLease?.generation!==command.controlLease?.generation))throw denied('playwrightBindingRequired');
      const origin=new URL(authority.origin);
      if(origin.origin!==authority.origin||origin.username||origin.password||!['https:','http:'].includes(origin.protocol))throw denied('playwrightOriginDenied');
      const local=await this.#host.openRelay(authority,command);
      const current=async()=>authority.privateQuarantined===false&&await this.#host.current(authority,command)&&await local.current();
      // The scoped relay checks current immediately before each route. The
      // native send callback independently rechecks authority at its boundary.
      const adapter={origin:authority.origin,current,onMethod:local.onMethod,onEvent:listener=>local.onEvent(listener),close:()=>local.close?.(),send:(method,params,deadline)=>local.send(method,params,deadline)};
      relay=await createScopedRelay(adapter,{deadlineUnixMs:command.deadlineUnixMs,onDispatch:()=>{dispatched=true;}});
      browser=await chromium.connectOverCDP(relay.transport,{isLocal:true,noDefaults:true,timeout:Math.max(1,command.deadlineUnixMs-Date.now())});
      const pages=browser.contexts().flatMap(c=>c.pages());
      if(pages.length!==1||new URL(pages[0].url()).origin!==authority.origin)throw denied('playwrightDocumentChanged');
      pages[0].setDefaultTimeout(Math.max(1,command.deadlineUnixMs-Date.now()));
      const target=locatorFor(pages[0],command.locator);
      const remaining=()=>Math.max(1,command.deadlineUnixMs-Date.now());
      // Wait only before intent/input, and only when no target exists yet.
      // Ambiguity remains a refusal; dispatch is never inside a retry loop.
      let count=await target.count();
      if(count===0){await target.waitFor({state:'attached',timeout:remaining()});count=await target.count();}
      if(count!==1)throw denied('playwrightTargetDenied');
      const element=await target.elementHandle();
      if(!element||!await element.evaluate(targetGuard.publicTarget,command.action)||!await this.#host.current(authority,command))throw denied('playwrightTargetDenied');
      if(mutations.has(command.action)){
        const logical={attemptId:command.attemptId,identity:{...command.identity},brokerEpoch:command.brokerEpoch,channelEpoch:command.channelEpoch,scopeHash:command.scopeHash,controlLease:{...command.controlLease},fingerprintSHA256:command.fingerprintSHA256};
        if(await this.#host.commitIntent(logical)!==true)throw denied('playwrightIntentRequired');
        this.#attempts.set(command.attemptId,{hash:command.fingerprintSHA256});recorded=true;
        if(!await this.#host.current(authority,command))throw denied('playwrightAuthorityChanged');
        relay.beginMutation();
        // One call, no engine-level retry. A lost CDP reply closes the relay.
        if(command.action==='element.fill')await element.fill(command.args.value,{timeout:remaining()});
        // The receipt describes this one input, not navigation/business readiness.
        // Observe the destination separately under freshly qualified authority.
        else await element.click({timeout:remaining(),noWaitAfter:true});
        result={dispatchState:'dispatched',effectState:'unverified',inputSemantics:'Local Playwright over scoped extension CDP'};
      }else{
        if(command.args.attribute==='name')throw denied('playwrightReadDenied');
        const text=await element.textContent();
        if(!await this.#host.current(authority,command))throw denied('playwrightAuthorityChanged');
        // Never cut a credential variant before the extension-owned redactor.
        if(String(text??'').length>32768)throw denied('playwrightReadTooLarge');
        const value=await this.#host.redact(String(text??''),authority);
        if(typeof value!=='string'||value.length>32768)throw denied('playwrightRedactionDenied');
        result={dispatchState:'notDispatched',effectState:'none',value};
      }
    }catch(error){
      result={dispatchState:dispatched?'unknown':'notDispatched',effectState:dispatched?'unknown':'none',errorCode:relay?.failure()?.code??(error?.code?.startsWith('playwright')?error.code:error instanceof playwrightErrors.TimeoutError?'playwrightDeadline':'playwrightUnavailable')};
    }finally{
      if(recorded){
        const unavailable=()=>({dispatchState:dispatched?'unknown':'notDispatched',effectState:dispatched?'unknown':'none',errorCode:'playwrightReceiptUncertain'});
        try{if(await this.#host.persistReceipt({attemptId:command.attemptId,fingerprintSHA256:command.fingerprintSHA256,...result})!==true)result=unavailable();}
        catch{result=unavailable();}
        this.#attempts.get(command.attemptId).result=structuredClone(result);
      }
      // Disconnect only the private relay; never browser.close() a user browser.
      await relay?.close().catch(()=>{});if(ownsBusy)this.#busy=false;
    }
    return {requestId:command?.requestId,...result};
  }
}
