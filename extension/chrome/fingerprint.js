// Unwired v2 foundation. This module does not replace existing v1 renderer
// receipt/idempotency behavior, authorize dispatch or retain logical arguments.
globalThis.MechanizeFingerprint = (() => {
  const opaque = value => typeof value === "string" && /^[A-Za-z0-9._:-]{1,128}$/.test(value);
  const hash = value => typeof value === "string" && /^[0-9a-f]{64}$/.test(value);
  const positive = value => Number.isSafeInteger(value) && value > 0;
  function fail() { throw new Error("Invalid qualified logical mutation envelope"); }
  function object(value, required, optional = []) {
    if (!value || typeof value !== "object" || Array.isArray(value) || required.some(key => !Object.hasOwn(value,key)) || Object.keys(value).some(key => !required.includes(key) && !optional.includes(key))) fail();
  }
  function scalarString(value, maximum, empty = false) {
    if (typeof value !== "string" || (!empty && !value.length) || value.length > maximum) return false;
    for (let i=0;i<value.length;i++) {
      const unit=value.charCodeAt(i);
      if (unit>=0xD800 && unit<=0xDBFF) { const next=value.charCodeAt(++i); if (!(next>=0xDC00 && next<=0xDFFF)) return false; }
      else if (unit>=0xDC00 && unit<=0xDFFF) return false;
    }
    return true;
  }
  function canonical(value) {
    if (value && typeof value === "object") return "{"+Object.keys(value).sort().map(key => canonical(key)+":"+canonical(value[key])).join(",")+"}";
    return JSON.stringify(value).replace(/\u2028/g,"\\u2028").replace(/\u2029/g,"\\u2029");
  }
  function canonicalEnvelope(command) {
    object(command,["action","identity","brokerEpoch","channelEpoch","scopeHash","attemptId","locator","controlLease"],["args","requestId","deadlineUnixMs","fingerprintVersion","fingerprintSHA256"]);
    if (!["element.press","element.fill"].includes(command.action)) fail();
    const i=command.identity; object(i,["profileChannel","browserInstance","tabId","frameId","documentId","documentGeneration"]);
    if (![i.profileChannel,i.browserInstance,i.documentId,command.brokerEpoch,command.channelEpoch,command.attemptId].every(opaque) || !hash(command.scopeHash) || !positive(i.tabId) || i.tabId>2147483647 || i.frameId!==0 || !positive(i.documentGeneration)) fail();
    const lease=command.controlLease; object(lease,["id","generation"]); if (!opaque(lease.id) || !positive(lease.generation)) fail();
    const l=command.locator; object(l,["strategy","value","exact"],["name"]);
    if (!["id","testId","role","label"].includes(l.strategy) || l.exact!==true || !scalarString(l.value,1024)) fail();
    let name=null;
    if (l.name!==undefined && l.name!==null) { if (l.strategy!=="role" || !scalarString(l.name,1024)) fail(); name=l.name; }
    let args={};
    if (command.action==="element.press") { if (command.args!==undefined && command.args!==null) object(command.args,[]); }
    else { object(command.args,["value"]); if (!scalarString(command.args.value,16384,true)) fail(); args={value:command.args.value}; }
    return canonical({version:2,action:command.action,identity:{profileChannel:i.profileChannel,browserInstance:i.browserInstance,tabId:i.tabId,frameId:i.frameId,documentId:i.documentId,documentGeneration:i.documentGeneration},brokerEpoch:command.brokerEpoch,channelEpoch:command.channelEpoch,scopeHash:command.scopeHash,controlLease:{id:lease.id,generation:lease.generation},attemptId:command.attemptId,locator:{strategy:l.strategy,value:l.value,name,exact:true},args});
  }
  async function mutationV2(command) {
    const encoded=new TextEncoder().encode(canonicalEnvelope(command));
    const digest=await crypto.subtle.digest("SHA-256",encoded);
    return {version:2,sha256:[...new Uint8Array(digest)].map(byte=>byte.toString(16).padStart(2,"0")).join("")};
  }
  return Object.freeze({mutationV2});
})();
if (typeof module !== "undefined") module.exports = globalThis.MechanizeFingerprint;
