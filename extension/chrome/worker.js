// Correlation IDs support rolling upgrades from 128-bit to 256-bit tokens.
// Credential delivery attempt IDs remain strictly 256-bit.
const privateWireID = value => typeof value === "string" && /^[a-f0-9]{32}(?:[a-f0-9]{32})?$/.test(value);
import "./protocol.js";
import "./connection-lifecycle.js";
import "./focused-location.js";
import "./tab-metadata.js";
import "./extension-maintenance.js";
import "./control-badge-metadata.js";
import "./protection-scopes.js";
import "./browser.js";
import "./fingerprint.js";
import "./retirement.js";
import "./setup-metadata.js";
import "./controller.js";
import "./secure-input.js";
import "./cdp-transport.js";
import "./browser-input.js";
import "./playwright-target.js";
import "./playwright-relay.js";
import "./playwright-worker.js";
const retirementJournal = MechanizeRetirement.create(chrome.storage.local);
let port = null, grant = null, mutationBusy = false, lifecycleGuardId = null, maintenanceBusy=false;
const requests = new Set();
const browserInput = MechanizeBrowserInput.create(chrome);
const activeBrowserInputs = new Map();
const documents = new Map();
const documentControlLeases = new Map();
const inactiveLeaseDocuments = new Set();
const documentOrigins = new Map();
const protectedOrigins = new Set();
const legacyProtectedOrigins=new Set(),disjointDocuments=new Map();
const publicReadScopes=new Map();
const protectionScopes=MechanizeProtectionScopes.create(chrome,(tabId,documentId)=>documents.get(`${tabId}:${documentId}`),qualifyPublicReadRenderer);
let privatePending = false, privateSilencedPort = null, privateAdmission = null, privateFlow = null;
const privateAttempts = new Set();
const privateRecipients = new Map();
let privateRedactions=[],privatePrivacy=null,manualPrivacyFlow=null;
const privacyDocument = i => Boolean(privatePrivacy?.active&&privatePrivacy.port===port&&i&&i.tabId===privatePrivacy.identity.tabId&&i.documentId===privatePrivacy.identity.documentId&&i.frameId===0);
const privacySanitize = value => privateRedactions.length?MechanizeSecureInput.redact(value,privateRedactions):value;
const isProtectedURL=(value,i)=>{try{const origin=new URL(value).origin;const disjoint=i&&disjointDocuments.get(`${i.tabId}:${i.documentId}`);return protectionScopes.protects(value,i)||(legacyProtectedOrigins.has(origin)&&!(disjoint?.port===port&&disjoint.origin===origin));}catch{return true;}};
// Read proofs are separate from the ordinary executor and input lease maps.
const publicReadActions=new Set(['observe','read','resolve','executor.validate']);
async function qualifyPublicReadRenderer(request,sample,current){
 const i={...request.sourceIdentity,documentId:sample.frame.documentId,documentGeneration:0};
 current();const enrollment=await config();current();
 if(i.profileChannel!==enrollment.profileChannel||i.browserInstance!==enrollment.browserInstance||!allowedOrigin(sample.frame.url,enrollment)||!allowedOrigin(sample.tab.url,enrollment))throw 'scopeChanged';
 await chrome.scripting.executeScript({target:{tabId:i.tabId,documentIds:[i.documentId]},world:'ISOLATED',files:['protocol.js','fingerprint.js','accessibility-provider.js','dom.js','recorder.js','secure-input.js','content.js']});current();
 const result=await privateRenderer({type:'credentialPublicScope',requestId:request.requestId,identity:i,brokerEpoch:request.brokerEpoch,channelEpoch:request.channelEpoch,scopeHash:request.scopeHash,deadlineUnixMs:request.deadlineUnixMs,origin:request.targetOrigin,redactions:[...privateRedactions]});current();
 if(!result||!['publicDocument,requestId','publicDocument,reason,requestId'].includes(Object.keys(result).sort().join())||result.requestId!==request.requestId)throw 'scopeChanged';
 if(result.publicDocument===null)throw ['scopeTargetProtected','scopeInventoryUnavailable','scopeChanged'].includes(result.reason)?result.reason:'scopeUnavailable';
 if(Object.hasOwn(result,'reason'))throw 'scopeChanged';
 return result.publicDocument;
}
async function receiveScopedPublicRead(command){
 const ownPort=port,scope=publicReadScopes.get(`${command.identity?.tabId}:${command.identity?.documentId}`);
 const deny=()=>{if(ownPort&&ownPort===port)ownPort.postMessage({requestId:command.requestId,identity:command.identity,error:MechanizeProtocol.error('secureDocumentRequired','Fresh exact public document read proof required')});};
 try{
  MechanizeProtocol.validate(command);
  if(command.publicRead!==true||!publicReadActions.has(command.action)||command.type&&command.type!=='command'||command.controlLease||command.attemptId||command.fingerprintVersion||command.fingerprintSHA256)throw Error();
  const current=()=>{
   if(!scope||port!==ownPort||scope.port!==ownPort||scope.fence!==setupFence||!setupFence||privatePending||mutationBusy||activeBrowserInputs.size||lifecycleGuardId||reconnectBusy||Date.now()>=scope.deadline||Date.now()>=command.deadlineUnixMs||['brokerEpoch','channelEpoch','scopeHash'].some(k=>command[k]!==setupFence[k])||['profileChannel','browserInstance','tabId','frameId','documentId','documentGeneration'].some(k=>command.identity[k]!==scope.proof.identity[k]))throw Error();
  };
  current();if(requests.has(command.requestId)||requests.size>=4096)throw Error();requests.add(command.requestId);
  const enrollment=await config();current();
  const sample=async()=>{const tab=await chrome.tabs.get(command.identity.tabId);current();const frames=await chrome.webNavigation.getAllFrames({tabId:tab.id});current();const roots=frames?.filter(f=>f.frameId===0&&!f.errorOccurred&&f.documentId===command.identity.documentId&&(!f.documentLifecycle||f.documentLifecycle==='active'));if(!tab||tab.pendingUrl||tab.status!=='complete'||tab.discarded||tab.incognito||!allowedOrigin(tab.url,enrollment)||roots?.length!==1||!allowedOrigin(roots[0].url,enrollment))throw Error();const u=new URL(roots[0].url),top=new URL(tab.url);if(u.origin!==scope.origin||u.origin+u.pathname!==top.origin+top.pathname)throw Error();const digest=await crypto.subtle.digest('SHA-256',new TextEncoder().encode(u.origin+u.pathname));current();if(Array.from(new Uint8Array(digest),v=>v.toString(16).padStart(2,'0')).join('')!==scope.proof.routeSHA256)throw Error();};
  await sample();
  const {publicRead:omittedPublicRead,...rendererCommand}=command;
  const result=await privateRenderer(rendererCommand);current();await sample();current();
  if(!result||result.requestId!==command.requestId||result.error||!result.identity||['profileChannel','browserInstance','tabId','frameId','documentId'].some(k=>result.identity[k]!==scope.proof.identity[k])||!Number.isSafeInteger(result.identity.documentGeneration)||result.identity.documentGeneration!==scope.proof.identity.documentGeneration)throw Error();
  const safe=privacySanitize(result);if(new TextEncoder().encode(JSON.stringify(safe)).length>MechanizeProtocol.MAX_BYTES)throw Error();current();ownPort.postMessage(safe);
 }catch{deny();}
}
function ordinaryDisjoint(i){
 if(!i||i.frameId!==0||!documents.has(`${i.tabId}:${i.documentId}`))return false;
 const origin=documentOrigins.get(`${i.tabId}:${i.documentId}`);if(!origin||isProtectedURL(origin,i))return false;
 const held=[privateAdmission,privateFlow,privatePrivacy,manualPrivacyFlow].filter(Boolean);if(!held.length)return !privateSilencedPort;
 return held.every(x=>x.identity?.tabId!==i.tabId&&x.sourceIdentity?.tabId!==i.tabId);
}
const ordinaryPrivateBlocked=i=>privatePending||((privateAdmission||privateFlow||port===privateSilencedPort)&&!ordinaryDisjoint(i));
const documentFingerprintVersions = new Map();
const unknownAttempts = new Map();
const sameInputTarget=(a,b)=>a&&b&&['profileChannel','browserInstance','tabId','frameId'].every(k=>a[k]===b[k]);
function unknownTargetRecord(attempt,source){
 const i=source?.identity,l=source?.controlLease,fingerprint=source?.fingerprintSHA256||source?.fingerprint,version=source?.fingerprintVersion??source?.receipt?.fingerprintVersion;
 if(source?.attemptId!==undefined&&source.attemptId!==attempt||version!==2||!i||!l||!['profileChannel','browserInstance','documentId'].every(k=>typeof i[k]==='string'&&i[k].length>0&&i[k].length<=512)||!Number.isSafeInteger(i.tabId)||i.tabId<1||i.frameId!==0||!Number.isSafeInteger(i.documentGeneration)||i.documentGeneration<1||typeof l.id!=='string'||!l.id||l.id.length>512||!Number.isSafeInteger(l.generation)||l.generation<1||!['brokerEpoch','channelEpoch','scopeHash'].every(k=>typeof source[k]==='string'&&source[k].length>0&&source[k].length<=512)||typeof fingerprint!=='string'||!/^([a-f0-9]{64})$/.test(fingerprint))return null;
 return Object.freeze({attemptId:attempt,identity:Object.freeze(Object.fromEntries(['profileChannel','browserInstance','tabId','frameId','documentId','documentGeneration'].map(k=>[k,i[k]]))),controlLease:Object.freeze({id:l.id,generation:l.generation}),brokerEpoch:source.brokerEpoch,channelEpoch:source.channelEpoch,scopeHash:source.scopeHash,fingerprintSHA256:fingerprint});
}
function retainUnknown(attempt,source){
 const record=unknownTargetRecord(attempt,source);
 if(!unknownAttempts.has(attempt)){unknownAttempts.set(attempt,record);return;}
 const previous=unknownAttempts.get(attempt);
 // A later error without metadata cannot overwrite an existing exact tuple.
 // Conflicting metadata remains unbound and conservative.
 if(source&&(!record||previous&&JSON.stringify(previous)!==JSON.stringify(record)))unknownAttempts.set(attempt,null);
}
// UNKNOWN journal records remain immutable. These connection-local proofs only
// distinguish dead executor hazards from unresolved business outcomes.
const retiredUnknownTargets = new Map();
function rearmRetiredUnknownTargets(){for(const [attempt,proof] of retiredUnknownTargets)retainUnknown(attempt,proof.record);retiredUnknownTargets.clear();}
function currentRetiredUnknown(attempt){const proof=retiredUnknownTargets.get(attempt);return proof&&proof.port===port&&setupFence&&['brokerEpoch','channelEpoch','scopeHash'].every(k=>proof.fence[k]===setupFence[k])?proof:null;}

// Classification is volatile and bound to this exact signed native connection.
// The original attempt and terminal journal are never deleted or rewritten.
const visibilityUnknown = new Map();
const domUnknownBlocked = (own='',target=null) => [...unknownAttempts].some(([id,record])=>{
 if(id===own)return false;
 const v=visibilityUnknown.get(id);
 if(v&&v.action==='browser.activateTab'&&v.attemptId===id&&v.port===port&&setupFence&&['brokerEpoch','channelEpoch','scopeHash'].every(k=>v[k]===setupFence[k]))return false;
 return !target||!record||!setupFence||['brokerEpoch','channelEpoch','scopeHash'].some(k=>record[k]!==setupFence[k])||sameInputTarget(record.identity,target);
});
let setupFence = null, setupActiveCommands = 0;
// Native-only Playwright hooks share the existing browser mutation authority.
const playwrightWorker = MechanizePlaywrightWorker.create(chrome, {
  port: () => port,
  retiredUnknown(record){const proof=currentRetiredUnknown(record.attemptId);return Boolean(proof&&reconnectCanonical(proof.record)===reconnectCanonical(record));},
  acquire(held) {
    if(visibilityUnknown.has(held.command.attemptId))throw Error();
    if (maintenanceBusy || !port || port !== held.originalPort || !grant || !qualifiedNativePorts.has(port) || mutationBusy || setupActiveCommands || domUnknownBlocked('',held.identity) || lifecycleGuardId || ordinaryPrivateBlocked(held.identity) || port === startupFailurePort) throw Error();
    const initial=documents.get(`${held.identity.tabId}:${held.identity.documentId}`);
    if(!initial||!['profileChannel','browserInstance','tabId','frameId','documentId'].every(k=>initial[k]===held.identity[k])||!Number.isSafeInteger(initial.documentGeneration)||initial.documentGeneration<held.identity.documentGeneration)throw Error();
    if(requests.has(held.command.requestId)||requests.size>=4096)throw Error();
    requests.add(held.command.requestId);
    held.originalGrant = grant;
    held.lease = documentControlLeases.get(`${held.identity.tabId}:${held.identity.documentId}`);
    mutationBusy = true;
  },
  release(held) {
    mutationBusy = false;
    if(held.inputCrossed&&held.observedIdentity&&port===held.originalPort&&grant===held.originalGrant){
      const key=`${held.identity.tabId}:${held.identity.documentId}`;
      const prior=documents.get(key);
      if(prior&&prior.documentGeneration<=held.observedIdentity.documentGeneration){
        documents.set(key,{...held.observedIdentity});
        const ownPort=port,ownGrant=grant;
        void config().then(inventory).then(snapshot=>{if(port===ownPort&&grant===ownGrant)send({type:'documents',...snapshot});}).catch(()=>{});
      }
    }
  },
  receiptCurrent(held) {
    // This grants no document access or input. Only the original authenticated
    // execution may finish its receipt after its own navigation invalidates DOM.
    const c=held.command;
    return Boolean(port===held.originalPort&&grant===held.originalGrant&&grant?.leaseRequired&&qualifiedNativePorts.has(port)&&port!==startupFailurePort&&!maintenanceBusy&&!lifecycleGuardId&&!privatePending&&Date.now()<c.deadlineUnixMs&&['brokerEpoch','channelEpoch','scopeHash'].every(k=>c[k]===grant[k]));
  },
  async current(held) {
    const c=held.command,i=c.identity,key=`${i.tabId}:${i.documentId}`;
    // Only this already-admitted semantic relay tolerates a newer DOM revision.
    // Input still requires the relay's pinned element and immediate target guard.
    const exact=(a,b)=>a&&b&&['profileChannel','browserInstance','tabId','frameId','documentId'].every(k=>a[k]===b[k])&&Number.isSafeInteger(a.documentGeneration)&&a.documentGeneration>=b.documentGeneration;
    const permitted=()=>!held.closed && port===held.originalPort && grant===held.originalGrant && grant.leaseRequired===true && qualifiedNativePorts.has(port) &&
      !ordinaryPrivateBlocked(i) && port!==startupFailurePort && !lifecycleGuardId &&
      !domUnknownBlocked(c.attemptId,c.identity) && c.deadlineUnixMs>Date.now() &&
      ['brokerEpoch','channelEpoch','scopeHash'].every(k=>c[k]===grant[k]) && exact(documents.get(key),i) && documentOrigins.get(key)===held.origin &&
      documentControlLeases.get(key)===held.lease && (!held.mutation || grant.leaseRequired===true && grant.mutationFingerprintVersion===2 && documentFingerprintVersions.get(key)===2 && held.lease?.id===c.controlLease?.id && held.lease?.generation===c.controlLease?.generation) &&
      (!privatePrivacy || ordinaryDisjoint(i) || privatePrivacy.committed && privacyDocument(i)) && (!isProtectedURL(held.origin,i) || privatePrivacy?.committed && privacyDocument(i));
    if(!permitted())return false;
    const enrollment=await config();
    if(i.profileChannel!==enrollment.profileChannel||i.browserInstance!==enrollment.browserInstance||!allowedOrigin(held.origin,enrollment))return false;
    const tab=await chrome.tabs.get(i.tabId);if(suspendDiscardedTab(tab))return false;
    const frames=await chrome.webNavigation.getAllFrames({tabId:i.tabId});
    const frame=frames?.find(f=>f.frameId===0&&f.documentId===i.documentId&&!f.errorOccurred&&f.frameType!=='fenced_frame');
    if(frame)noteInactiveFrame(i.tabId,frame,frames);
    if(!permitted()||nonExecutableTreeFrame(frame,frames)||inactiveLeaseDocuments.has(key)||new URL(tab.url).origin!==held.origin||new URL(frame.url).origin!==held.origin)return false;
    const proof=await chrome.tabs.sendMessage(i.tabId,{requestId:c.requestId,action:'executor.validate',identity:i,brokerEpoch:c.brokerEpoch,channelEpoch:c.channelEpoch,scopeHash:c.scopeHash,deadlineUnixMs:c.deadlineUnixMs},{documentId:i.documentId});
    const observed=proof?.identity;
    if(!permitted()||!proof||Object.keys(proof).sort().join()!=='identity,requestId,validated'||proof.requestId!==c.requestId||proof.validated!==true||!observed||Object.keys(observed).sort().join()!=='browserInstance,documentGeneration,documentId,frameId,profileChannel,tabId'||!['profileChannel','browserInstance','tabId','frameId','documentId'].every(k=>observed[k]===i[k])||!Number.isSafeInteger(observed.documentGeneration)||observed.documentGeneration<i.documentGeneration)return false;
    // Concurrent read-only event checks may return in a different order;
    // retain a monotonic maximum without rejecting a same-document older sample.
    if(!held.observedIdentity||held.observedIdentity.documentGeneration<observed.documentGeneration)held.observedIdentity={...observed};
    if(documents.get(key).documentGeneration<observed.documentGeneration){
      documents.set(key,{...observed});
      const ownPort=port,ownGrant=grant;
      void config().then(inventory).then(snapshot=>{if(port===ownPort&&grant===ownGrant)send({type:'documents',...snapshot});}).catch(()=>{});
    }
    return true;
  },
  unknown(attempt,unknown,record) { if(unknown)retainUnknown(attempt,record?{...record,fingerprintVersion:2}:undefined);else unknownAttempts.delete(attempt); },
  redact: privacySanitize
});
const setupState = () => {
  if (privatePending || privateAdmission) throw Error();
  return {activeCommands: setupActiveCommands, unknownAttempts: unknownAttempts.size,
    mutationBusy, lifecycleInhibited: Boolean(lifecycleGuardId), nativeConnected: Boolean(port), executorQualified: Boolean(grant)};
};
let reconnectDiagnosticPhase = "idle", reconnectDiagnosticReason = "none", reconnectInventoryReason="none", reconnectJournalDiagnostic=null,reconnectRecoveryDiagnostic=null,reconnectMissingReceiptSources=null,reconnectMissingDocuments=[];
// Safe authenticated status projection: exactly the vocabulary exposed by the
// extension's local setup metadata, with no storage, identity, or error text.
const reconnectPhases = new Set(["idle", "scope", "barriers", "journal", "inventory", "inspect", "prepare", "adopt", "commit"]);
const reconnectReasons = new Set(["none", "portChanged", "deadline", "busy", "unknownReceipts", "privateProtection", "lifecycle", "scopeChanged", "journalChanged", "inventoryChanged", "storageFailure", "rendererUnavailable", "executorRefused", "injectionUnavailable", "restrictedBrowserPage", "packagedExecutorUnavailable", "documentChanged", "websitePermissionMissing", "extensionContextInvalidated", "restrictedFrame", "injectionArgumentsRejected", "executorEvaluationFailed"]);
const reconnectAttention = value => value?.type === 'attention' && value.error?.code === 'storedFenceMismatch' &&
  reconnectPhases.has(reconnectDiagnosticPhase) && reconnectReasons.has(reconnectDiagnosticReason) ?
  {...value,...(reconnectRecoveryDiagnostic?{reconnectRecovery:{...reconnectRecoveryDiagnostic}}:{}),reconnectPhase:reconnectDiagnosticPhase,reconnectReason:reconnectDiagnosticReason,...(reconnectDiagnosticReason==='inventoryChanged'&&MechanizeSetupMetadata.INVENTORY_REASONS.includes(reconnectInventoryReason)?{reconnectInventoryReason}:{}),...(reconnectDiagnosticReason==='journalChanged'&&reconnectJournalDiagnostic?{reconnectJournal:{...reconnectJournalDiagnostic}}:{})} : value;
MechanizeSetupMetadata.installLocal(setupState, () => ({phase: reconnectDiagnosticPhase, reason: reconnectDiagnosticReason,inventoryReason:reconnectInventoryReason,
  privatePending: Boolean(privatePending || privateAdmission || privateFlow || privatePrivacy || privateAttempts.size || privateRedactions.length || protectedOrigins.size),
  missingReceiptSources: reconnectMissingReceiptSources,
  lifecyclePending: Boolean(lifecycleGuardId)}));
const controllers = MechanizeController.install(chrome, {
  binding: () => port && setupFence && !lifecycleGuardId && port !== startupFailurePort ? {...setupFence} : null,
  send:sendController
});
function sendController(value) {
  const restricted=privatePending||privateAdmission||privateFlow||port===privateSilencedPort;
  if(!restricted){send(value);return;}
  const args=value?.params?.arguments;
  if(!port||!grant||value?.type!=="controllerRequest"||value.operation!=="tools/call"||
     !["mechanize_credential_apply","mechanize_credential_submit","mechanize_credential_status","mechanize_session_close"].includes(value.params?.name)||
     !args||Object.keys(args).sort().join()!==(value.params.name==="mechanize_session_close"?"sessionId":"preparationId,sessionId")||typeof args.sessionId!=="string"||!/^[A-Za-z0-9._:-]{1,128}$/.test(args.sessionId)||value.params.name!=="mechanize_session_close"&&(typeof args.preparationId!=="string"||!/^[a-f0-9]{64}$/.test(args.preparationId)))return;
  port.postMessage(value);
}
// Lifecycle suspension revokes eligibility, never receipts or old lease evidence.
// A retained lease can only leave this barrier through its existing exact
// retirement/quiescence response, or the independently proved reconnect handoff.
function inactiveExecutorFrame(frame){return frame?.documentLifecycle!==undefined&&frame.documentLifecycle!=='active';}
function nonExecutableFrame(frame){return !frame||inactiveExecutorFrame(frame)||frame.errorOccurred===true||frame.frameType!==undefined&&frame.frameType!==(frame.frameId===0?'outermost_frame':'sub_frame');}
function nonExecutableTreeFrame(frame,frames){
 if(!Array.isArray(frames))return true;
 const byFrame=new Map(frames.map(f=>[f.frameId,f]));if(byFrame.size!==frames.length)return true;
 const seen=new Set();let current=frame;
 while(current){
  if(nonExecutableFrame(current)||seen.has(current.frameId))return true;seen.add(current.frameId);
  if(current.frameId===0)return current.parentFrameId!==undefined&&current.parentFrameId!==-1;
  // Older compatible metadata may omit parent IDs. It cannot bridge a known
  // independent page root; modern metadata always follows the exact forest.
  if(current.parentFrameId===undefined)return frames.some(f=>f.frameId>0&&f.frameType==='outermost_frame');
  if(current.parentFrameId<0)return true;current=byFrame.get(current.parentFrameId);
 }
 return true;
}
function noteInactiveFrame(tabId,frame,frames){
 if(!(inactiveExecutorFrame(frame)||frames&&nonExecutableTreeFrame(frame,frames))||!frame?.documentId)return;
 const key=`${tabId}:${frame.documentId}`;
 if(documentControlLeases.has(key))inactiveLeaseDocuments.add(key);
 playwrightWorker.invalidate(held=>held.identity.tabId===tabId&&held.identity.documentId===frame.documentId);
}
function suspendDiscardedTab(tab) {
  if(tab?.discarded!==undefined&&typeof tab.discarded!=='boolean')throw MechanizeProtocol.error('documentDenied','Valid discarded-tab metadata required');
  if(tab?.discarded!==true)return false;
  for(const [key,identity] of documents)if(identity.tabId===tab.id&&documentControlLeases.has(key))inactiveLeaseDocuments.add(key);
  playwrightWorker.invalidate(held=>held.identity.tabId===tab.id);
  return true;
}
const MAX_INVENTORY_DOCUMENTS = 200;
async function inventory(enrollment, qualification) {
  const read=operation=>qualification?qualificationRead(qualification,operation):operation();
  if (privatePending) return {documents: [], truncated: true};
  const result = [], credentialCandidates=[];
  for (const tab of await read(()=>chrome.tabs.query({}))) {
    if(suspendDiscardedTab(tab))continue;
    if (!allowedOrigin(tab.url, enrollment)) continue;
    if(isProtectedURL(tab.url,{profileChannel:enrollment.profileChannel,browserInstance:enrollment.browserInstance,tabId:tab.id,frameId:0})&&!(privatePrivacy?.active&&privatePrivacy.identity.tabId===tab.id)) {
      // Private routing metadata only. Never read the protected tab's title or DOM.
      const url=new URL(tab.url);
      if(url.protocol!=='https:'||url.username||url.password)continue;
      const privateFrames=await read(()=>chrome.webNavigation.getAllFrames({tabId:tab.id}))||[];
      const roots=privateFrames.filter(f=>{noteInactiveFrame(tab.id,f,privateFrames);return f.frameId===0&&!nonExecutableTreeFrame(f,privateFrames);});
      for(const frame of roots) {
        const root=new URL(frame.url);
        if(!frame.documentId||root.origin!==url.origin||root.username||root.password)continue;
        credentialCandidates.push({profileChannel:enrollment.profileChannel,browserInstance:enrollment.browserInstance,tabId:tab.id,frameId:0,documentId:frame.documentId,documentGeneration:documents.get(`${tab.id}:${frame.documentId}`)?.documentGeneration||1,origin:url.origin});
        if(credentialCandidates.length>MAX_INVENTORY_DOCUMENTS)return {documents:[],truncated:true};
      }
      continue;
    }
    const frames=await read(()=>chrome.webNavigation.getAllFrames({tabId:tab.id}))||[];
    for (const frame of frames) {
      // Chrome error documents can retain an https URL while their privileged
      // error page cannot host an executor. Fenced frames likewise prohibit
      // extension injection. Neither is an eligible automation document.
      // Unknown receipts and private-origin quarantine remain separate gates.
      noteInactiveFrame(tab.id,frame,frames);
      if (nonExecutableTreeFrame(frame,frames)) continue;
      if (!allowedOrigin(frame.url, enrollment) || isProtectedURL(frame.url,{profileChannel:enrollment.profileChannel,browserInstance:enrollment.browserInstance,tabId:tab.id,frameId:frame.frameId,documentId:frame.documentId})&&!privacyDocument({tabId:tab.id,frameId:frame.frameId,documentId:frame.documentId}) || !frame.documentId) continue;
      result.push({profileChannel: enrollment.profileChannel, browserInstance: enrollment.browserInstance, tabId: tab.id, frameId: frame.frameId, documentId: frame.documentId, documentGeneration: documents.get(`${tab.id}:${frame.documentId}`)?.documentGeneration || 1, mutationFingerprintVersion: documentFingerprintVersions.get(`${tab.id}:${frame.documentId}`) || 1, origin: new URL(frame.url).origin, title: privacySanitize(tab.title || "").slice(0, 256), titleTruncated: privacySanitize(tab.title || "").length > 256});
      if (result.length > MAX_INVENTORY_DOCUMENTS) return {documents: result, truncated: true};
    }
  }
  return {documents: result, truncated: false,...(credentialCandidates.length?{credentialCandidates}:{})};
}
const allowedOrigin = MechanizeProtocol.websiteAllowed;
async function config() {
  const {enrollment} = await chrome.storage.local.get("enrollment");
  if (!enrollment?.profileChannel || !enrollment?.browserInstance || !MechanizeProtocol.websiteScopeValid(enrollment)) throw MechanizeProtocol.error("notEnrolled", "Enroll this browser profile in extension options");
  return enrollment;
}
function send(value) {
  if (!port || privatePending || (privateAdmission || port === privateSilencedPort)&&!(value?.type==="documents"&&protectionScopes.records().length) || port === startupFailurePort) return;
  value=privacySanitize(value);
  if (new TextEncoder().encode(JSON.stringify(value)).length > MechanizeProtocol.MAX_BYTES) value = {requestId: value.requestId, error: MechanizeProtocol.error("frameTooLarge", "Result exceeds 256 KiB; request a smaller snapshot")};
  port.postMessage(value);
}
function validBoundIdentity(value,expected){return value&&reconnectRecordKeys(value)==='browserInstance,documentGeneration,documentId,frameId,profileChannel,tabId'&&['profileChannel','browserInstance','tabId','frameId','documentId'].every(k=>value[k]===expected[k])&&Number.isSafeInteger(value.documentGeneration)&&value.documentGeneration>=1&&value.documentGeneration>=expected.documentGeneration;}
// Trust presentation metadata is copied only from the already-qualified
// worker grant (or its validated enrollment candidate), never command fields.
// Keep the legacy no-metadata shape when negotiating an older enrollment.
function executorTrustMetadata(qualified) {
  const keys=['trustScope','scopeQualified','profileQualified'];
  if(!keys.some(key=>Object.hasOwn(qualified,key)))return {};
  if(qualified.scopeQualified!==true || !['desktop','profile'].includes(qualified.trustScope) || qualified.profileQualified!==(qualified.trustScope==='profile'))throw MechanizeProtocol.error('executorBindingFailed','Qualified executor trust metadata required');
  return {trustScope:qualified.trustScope,scopeQualified:true,profileQualified:qualified.profileQualified};
}
async function attach(command, enrollment) {
  const privateAcquire=command.action==='executor.acquire'&&privateAdmission?.port===port&&privateAdmission.deadline>Date.now()&&['profileChannel','browserInstance','tabId','frameId','documentId','documentGeneration'].every(k=>command.identity?.[k]===privateAdmission.identity[k]);
  const tab = await chrome.tabs.get(command.identity.tabId);
  if(suspendDiscardedTab(tab))throw MechanizeProtocol.error('documentDenied','Discarded document cannot receive executor authority');
  if (isProtectedURL(tab.url,command.identity)&&!privacyDocument(command.identity)&&!privateAcquire) throw MechanizeProtocol.error("secureDocumentRequired", "Protected origin requires private control");
  if (!allowedOrigin(tab.url, enrollment)) throw MechanizeProtocol.error("originDenied", "Top-level tab origin is not enrolled");
  const frames = await chrome.webNavigation.getAllFrames({tabId: tab.id});
  const frame = frames.find(f => f.frameId === command.identity.frameId && f.documentId === command.identity.documentId);
  if(frame)noteInactiveFrame(tab.id,frame,frames);
  if(nonExecutableTreeFrame(frame,frames))throw MechanizeProtocol.error("documentDenied","Inactive or non-executable document cannot receive executor authority");
  if(inactiveLeaseDocuments.has(`${tab.id}:${command.identity.documentId}`)&&(MechanizeProtocol.mutations.has(command.action)||command.action==='executor.acquire'))throw MechanizeProtocol.error("staleAuthority","Suspended document lease requires exact retirement before new input");
  if (frame && isProtectedURL(frame.url,command.identity)&&!privacyDocument(command.identity)&&!privateAcquire) throw MechanizeProtocol.error("secureDocumentRequired", "Protected origin requires private control");
  if (!frame || !allowedOrigin(frame.url, enrollment)) throw MechanizeProtocol.error("documentDenied", "Frame document/origin unavailable or not enrolled");
  const key = `${tab.id}:${frame.documentId}`;
  if (!documents.has(key)) {
    await chrome.scripting.executeScript({target: {tabId: tab.id, documentIds: [frame.documentId]}, world: "ISOLATED", files: ["protocol.js", "fingerprint.js", "accessibility-provider.js", "dom.js", "recorder.js", "secure-input.js", "content.js"]});
    const bound = await chrome.tabs.sendMessage(tab.id, {type: "bind", binding: {identity: command.identity, brokerEpoch: grant.brokerEpoch, channelEpoch: grant.channelEpoch, scopeHash: grant.scopeHash, leaseRequired: grant.leaseRequired === true, mutationFingerprintVersion: grant.mutationFingerprintVersion || 1,...executorTrustMetadata(grant)}}, {documentId: frame.documentId});
    if (bound?.error || !validBoundIdentity(bound?.identity,command.identity) || (grant.mutationFingerprintVersion === 2 && bound.mutationFingerprintVersion !== 2)) throw MechanizeProtocol.error("executorBindingFailed", "Exact negotiated document executor required");
    documents.set(key, bound.identity);
    documentOrigins.set(key,new URL(frame.url).origin);
    documentFingerprintVersions.set(key, bound.mutationFingerprintVersion || 1);
    // New tabs initially publish inventory with no negotiated executor version.
    // Publish the successful binding before its read reply so the broker can
    // subsequently admit v2 control without waiting for another browser event.
    const qualified=await inventory(enrollment);
    if(qualified.truncated)throw MechanizeProtocol.error('inventoryIncomplete','Complete bound document inventory required');
    send({type:'documents',...qualified});
  }
  return frame;
}
function validateRetirementCommand(command) {
  const keys = ["requestId", "action", "identity", "brokerEpoch", "channelEpoch", "scopeHash", "deadlineUnixMs", "args"];
  const id = command.identity;
  if (!command || Object.keys(command).some(k => !keys.includes(k)) || keys.some(k => !Object.hasOwn(command, k)) ||
      typeof command.requestId !== "string" || !/^[A-Za-z0-9._:-]{1,128}$/.test(command.requestId) ||
      !Number.isSafeInteger(command.deadlineUnixMs) || command.deadlineUnixMs <= Date.now() ||
      new TextEncoder().encode(JSON.stringify(command)).length > MechanizeProtocol.MAX_BYTES ||
      !id || Object.keys(id).sort().join(",") !== "browserInstance,documentGeneration,documentId,frameId,profileChannel,tabId" ||
      id.tabId !== 0 || id.frameId !== 0 || id.documentId !== "" || id.documentGeneration !== 0)
    throw MechanizeProtocol.error("lifecycleDenied", "Closed channel journal command required");
}
async function privateRenderer(command) {
  let timer;
  try {
    return await Promise.race([
      chrome.tabs.sendMessage(command.identity.tabId,command,{documentId:command.identity.documentId}),
      new Promise((_,reject)=>{timer=setTimeout(()=>reject(Error()),Math.max(0,command.deadlineUnixMs-Date.now()));})
    ]);
  } finally {clearTimeout(timer);}
}
async function receiveCredentialInspect(command) {
  const originalPort=port,originalGrant=grant;
  if (!originalPort || privatePending || originalPort===privateSilencedPort && !privateFlow?.awaitingFill) return;
  privatePending=true;
  let ready=false,stage="unavailable",resultIdentity,requestId,inspectionReason="requestInvalid";
  const diagnostics=command.diagnostics===true;
  const pinned=Object.hasOwn(command,"recipientId");
  try {
    const fresh=Object.hasOwn(command,"controlLease");
    const keys=["type","requestId","identity","brokerEpoch","channelEpoch","scopeHash","deadlineUnixMs","origin",...(fresh?["controlLease"]:[]),...(pinned?["recipientId"]:[]),...(diagnostics?["diagnostics"]:[])],i=command.identity;
    if (Object.keys(command).sort().join()!==keys.sort().join() || !privateWireID(command.requestId) ||
        !i || Object.keys(i).sort().join()!=="browserInstance,documentGeneration,documentId,frameId,profileChannel,tabId" || i.frameId!==0 ||
        !originalGrant?.leaseRequired || mutationBusy || setupActiveCommands || unknownAttempts.size || lifecycleGuardId ||
        !Number.isSafeInteger(command.deadlineUnixMs) || command.deadlineUnixMs<=Date.now() || command.deadlineUnixMs>Date.now()+10000 ||
        typeof command.origin!=="string" || !command.origin.startsWith("https://") || new URL(command.origin).origin!==command.origin ||
        protectedOrigins.has(command.origin) && !privateFlow?.awaitingFill && (privateFlow||privatePrivacy) || ["brokerEpoch","channelEpoch","scopeHash"].some(k=>command[k]!==originalGrant[k])) throw Error();
    if(pinned&&(typeof command.recipientId!=='string'||!/^[a-f0-9]{64}$/.test(command.recipientId)))throw Error();
    requestId=command.requestId;resultIdentity={...i};inspectionReason="workerAuthorityUnavailable";
    const enrollment=await config(),key=`${i.tabId}:${i.documentId}`;
    if(i.profileChannel!==enrollment.profileChannel || i.browserInstance!==enrollment.browserInstance) throw Error();
    if (fresh) {
      const held=documentControlLeases.get(key),lease=command.controlLease;
      if(!lease || Object.keys(lease).sort().join()!=="generation,id" || !held || held.id!==lease.id || held.generation!==lease.generation || (pinned ? privateRecipients.get(key)!==command.recipientId||documents.get(key).documentGeneration<i.documentGeneration : documents.get(key).documentGeneration!==i.documentGeneration)) throw Error();
    }
    inspectionReason="documentUnavailable";const tab=await chrome.tabs.get(i.tabId),frames=await chrome.webNavigation.getAllFrames({tabId:i.tabId});
    const frame=frames?.find(f=>f.frameId===0 && f.documentId===i.documentId);
    if(suspendDiscardedTab(tab)||!frame || new URL(tab.url).origin!==command.origin || new URL(frame.url).origin!==command.origin || !allowedOrigin(command.origin,enrollment)) throw Error();
    if(port!==originalPort || grant!==originalGrant || command.deadlineUnixMs<=Date.now()) throw Error();
    if(!documents.has(key)) {
      inspectionReason="rendererBindingUnavailable";
      if(fresh||!protectedOrigins.has(command.origin)||frame.errorOccurred||frame.frameType==='fenced_frame'||new URL(tab.url).username||new URL(tab.url).password)throw Error();
      await chrome.scripting.executeScript({target:{tabId:i.tabId,documentIds:[i.documentId]},world:'ISOLATED',files:['protocol.js','fingerprint.js','accessibility-provider.js','dom.js','recorder.js','secure-input.js','content.js']});
      if(port!==originalPort||grant!==originalGrant||command.deadlineUnixMs<=Date.now())throw Error();
      const bound=await chrome.tabs.sendMessage(i.tabId,{type:'bind',binding:{identity:i,brokerEpoch:command.brokerEpoch,channelEpoch:command.channelEpoch,scopeHash:command.scopeHash,leaseRequired:true,mutationFingerprintVersion:2,...executorTrustMetadata(originalGrant)}},{documentId:i.documentId});
      if(bound?.error||!bound?.identity||bound.mutationFingerprintVersion!==2||['profileChannel','browserInstance','tabId','frameId','documentId'].some(k=>bound.identity[k]!==i[k])||(!Number.isSafeInteger(bound.identity.documentGeneration)||bound.identity.documentGeneration<i.documentGeneration))throw Error();
      documents.set(key,{...bound.identity});documentOrigins.set(key,command.origin);documentFingerprintVersions.set(key,2);
    }
    inspectionReason="documentChanged";const currentFrames=await chrome.webNavigation.getAllFrames({tabId:i.tabId});
    if(port!==originalPort||grant!==originalGrant||command.deadlineUnixMs<=Date.now()||!currentFrames?.some(f=>f.frameId===0&&f.documentId===i.documentId&&new URL(f.url).origin===command.origin))throw Error();
    inspectionReason="rendererReplyUnavailable";
    // Existing content executors keep their closed v2/v3 request shape across
    // extension reloads. Diagnostics are a fixed, read-only ISOLATED helper.
    const rendererCommand={...command};delete rendererCommand.diagnostics;
    const result=await privateRenderer(rendererCommand);
    inspectionReason="rendererProtocolUnavailable";
    if(port!==originalPort || grant!==originalGrant || command.deadlineUnixMs<=Date.now() ||
       !result || Object.keys(result).sort().join()!==["identity","privateCredentialProtocolVersion","ready","stage",...(pinned?["recipientId"]:[])].sort().join() || result.privateCredentialProtocolVersion!==(pinned?3:2)||pinned&&result.recipientId!==command.recipientId || typeof result.ready!=="boolean" ||
       !result.identity || Object.keys(result.identity).sort().join()!=="browserInstance,documentGeneration,documentId,frameId,profileChannel,tabId" ||
       ["profileChannel","browserInstance","tabId","frameId","documentId"].some(k=>result.identity[k]!==i[k]) ||
       !Number.isSafeInteger(result.identity.documentGeneration) || result.identity.documentGeneration<i.documentGeneration || fresh && !pinned && result.identity.documentGeneration!==i.documentGeneration) throw Error();
    inspectionReason=result.ready?'none':result.stage==='challenge'?'challenge':'readinessUnavailable';
    if(diagnostics&&!result.ready&&result.stage!=='challenge'){
      inspectionReason='rendererProtocolUnavailable';
      const sample=await chrome.scripting.executeScript({target:{tabId:i.tabId,documentIds:[i.documentId]},world:'ISOLATED',func:origin=>globalThis.MechanizeSecureInput?.inspectionReason?.(document,origin)||'rendererProtocolUnavailable',args:[command.origin]});
      if(port!==originalPort||grant!==originalGrant||command.deadlineUnixMs<=Date.now())throw Error();
      if(!Array.isArray(sample)||sample.length!==1||typeof sample[0]?.result!=='string'||!MechanizeSecureInput.isInspectionReason(sample[0].result))throw Error();
      inspectionReason=sample[0].result==='none'?'documentBindingOrProtectionUnavailable':sample[0].result;
    }
    resultIdentity={...result.identity};ready=result.ready;stage=["username","password","pair","challenge","unavailable"].includes(result.stage)?result.stage:"unavailable";
    if(ready) { if(pinned&&!privateRecipients.has(key)&&privateRecipients.size>=512)throw Error(); documents.set(key,resultIdentity); if(pinned)privateRecipients.set(key,command.recipientId); privateAdmission={port:originalPort,identity:resultIdentity,deadline:command.deadlineUnixMs}; }
  } catch {ready=false;}
  finally {
    if(port===originalPort && requestId && resultIdentity) try {originalPort.postMessage({type:"credentialInspectResult",requestId,identity:resultIdentity,ready,stage,privateCredentialProtocolVersion:pinned?3:2,...(pinned?{recipientId:command.recipientId}:{}),...(diagnostics?{inspectionReason}:{})});}catch{}
    privatePending=false;
  }
}
// Separate private transport. Never pass this object through public validation,
// browser journals, fingerprints, recording, receipts, or generic error handling.
async function receiveCredential(command) {
  const originalPort = port, originalGrant = grant;
  if (!originalPort || privatePending || originalPort === privateSilencedPort && !privateFlow?.awaitingFill) return;
  privatePending = true;
  let status = "notDispatched", forwarded = false;
  let resultIdentity, requestId, attemptId;
  try {
    const keys = ["type","requestId","attemptId","identity","brokerEpoch","channelEpoch","scopeHash","controlLease","deadlineUnixMs","origin","username","password"];
    const pinned=Object.hasOwn(command,'recipientId');
    if(pinned){if(typeof command.recipientId!=='string'||!/^[a-f0-9]{64}$/.test(command.recipientId))throw Error();keys.push('recipientId');}

    const i = command.identity, lease = command.controlLease;
    if (Object.keys(command).sort().join() !== keys.sort().join() ||
        !privateWireID(command.requestId) || typeof command.attemptId !== "string" || !/^[a-f0-9]{64}$/.test(command.attemptId) ||
        !i || Object.keys(i).sort().join() !== "browserInstance,documentGeneration,documentId,frameId,profileChannel,tabId" ||
        ![i.profileChannel,i.browserInstance,i.documentId].every(v => typeof v === "string" && /^[A-Za-z0-9._:-]{1,128}$/.test(v)) ||
        !Number.isSafeInteger(i.tabId) || i.tabId < 0 || i.frameId !== 0 || !Number.isSafeInteger(i.documentGeneration) || i.documentGeneration < 1 ||
        !lease || Object.keys(lease).sort().join() !== "generation,id" || typeof lease.id !== "string" || !/^[A-Za-z0-9._:-]{1,128}$/.test(lease.id) || !Number.isSafeInteger(lease.generation) || lease.generation < 1 ||
        typeof command.username !== "string" || typeof command.password !== "string" || !command.username || !command.password ||
        new TextEncoder().encode(command.username).length > 1024 || new TextEncoder().encode(command.password).length > 4096 ||
        typeof command.origin !== "string" || new URL(command.origin).origin !== command.origin || !command.origin.startsWith("https://") ||
        !Number.isSafeInteger(command.deadlineUnixMs) || command.deadlineUnixMs <= Date.now() || command.deadlineUnixMs > Date.now()+10000) throw Error();
    requestId = command.requestId; attemptId = command.attemptId; resultIdentity = {...i};
    const key = `${i.tabId}:${i.documentId}`, existing = documents.get(key), held = documentControlLeases.get(key);
    if (!originalGrant?.leaseRequired || !existing || !held || held.id !== lease.id || held.generation !== lease.generation ||
        ["profileChannel","browserInstance","tabId","frameId","documentId"].some(k => existing[k] !== i[k]) ||
        (pinned ? privateRecipients.get(key)!==command.recipientId||existing.documentGeneration<i.documentGeneration : existing.documentGeneration!==i.documentGeneration) ||
        ["brokerEpoch","channelEpoch","scopeHash"].some(k => command[k] !== originalGrant[k]) ||
        mutationBusy || setupActiveCommands || unknownAttempts.size || lifecycleGuardId || privateAttempts.has(attemptId) || privateAttempts.size >= 256) throw Error();
    privateAttempts.add(attemptId);
    const enrollment = await config();
    if (i.profileChannel !== enrollment.profileChannel || i.browserInstance !== enrollment.browserInstance || !allowedOrigin(command.origin,enrollment)) throw Error();
    const tab = await chrome.tabs.get(i.tabId), frames = await chrome.webNavigation.getAllFrames({tabId:i.tabId});
    const frame = frames?.find(f => f.frameId === 0 && f.documentId === i.documentId);
    if (!frame || new URL(tab.url).origin !== command.origin || new URL(frame.url).origin !== command.origin ||
        new URL(tab.url).username || new URL(tab.url).password || new URL(frame.url).username || new URL(frame.url).password) throw Error();
    protectedOrigins.add(command.origin);
    if(!protectionScopes.hasSource(i))legacyProtectedOrigins.add(command.origin);
    await chrome.storage.local.set({mechanizeLegacyProtectedOriginsV1:[...legacyProtectedOrigins]});
    if (protectedOrigins.size > 256) throw Error();
    await chrome.storage.local.set({mechanizeProtectedOrigins: [...protectedOrigins]});
    await chrome.storage.session.set({mechanizeProtectedOrigins: [...protectedOrigins]});
    const current = () => port === originalPort && grant === originalGrant && command.deadlineUnixMs > Date.now() && documentControlLeases.get(key) === held && documents.get(key) === existing;
    if (!current()) throw Error();
    const variants=Array.from(new Set([...privateRedactions,...MechanizeSecureInput.redactionVariants([command.username,command.password])]));if(!MechanizeSecureInput.validRedactions(variants))throw Error();privateRedactions=variants;
    privateSilencedPort = originalPort;
    forwarded = true;
    const response = await privateRenderer(command);
    if (!current()) throw Error();
    status = response && Object.keys(response).join() === "status" && ["dispatched","notDispatched","unknown"].includes(response.status) ? response.status : "unknown";
    if(status==="dispatched")privateFlow={port:originalPort,identity:{...i},lease:{...lease},origin:command.origin,fillAttempt:attemptId,submitted:null,awaitingFill:false};
  } catch { status = forwarded ? "unknown" : "notDispatched"; }
  finally {
    // Drop transport copies without serializing, hashing or retaining them.
    command.username = ""; command.password = "";
    if (port === originalPort && requestId && attemptId && resultIdentity) {
      try { originalPort.postMessage({type:"credentialDeliveryResult",requestId,attemptId,identity:resultIdentity,status}); } catch {}
    }
    privatePending = false;
  }
}
function privateFlowCommand(command,kind,originalPort,originalGrant) {
  const f=privateFlow,i=command.identity;
  const extra=["credentialSubmit","credentialRetire"].includes(kind)?["fillAttemptId"]:["nextLease"];
  if(!f||f.retireAttempt&&kind!=="credentialRetire"||f.port!==originalPort||port!==originalPort||grant!==originalGrant||!originalGrant?.leaseRequired||
     Object.keys(command).sort().join()!==["type","requestId","attemptId","identity","brokerEpoch","channelEpoch","scopeHash","controlLease","deadlineUnixMs","origin",...extra].sort().join()||
     !privateWireID(command.requestId)||typeof command.attemptId!=="string"||!/^[a-f0-9]{64}$/.test(command.attemptId)||
     !i||Object.keys(i).sort().join()!=="browserInstance,documentGeneration,documentId,frameId,profileChannel,tabId"||
     ["profileChannel","browserInstance","tabId","frameId","documentId","documentGeneration"].some(k=>i[k]!==f.identity[k])||
     !command.controlLease||Object.keys(command.controlLease).sort().join()!=="generation,id"||command.controlLease.id!==f.lease.id||command.controlLease.generation!==f.lease.generation||
     ["brokerEpoch","channelEpoch","scopeHash"].some(k=>command[k]!==originalGrant[k])||command.origin!==f.origin||
     !Number.isSafeInteger(command.deadlineUnixMs)||command.deadlineUnixMs<=Date.now()||command.deadlineUnixMs>Date.now()+10000||mutationBusy||setupActiveCommands||unknownAttempts.size||lifecycleGuardId)throw Error();
  return f;
}
async function receiveCredentialSubmit(command) {
 const originalPort=port,originalGrant=grant;if(!originalPort||privatePending)return;privatePending=true;
 let status="notDispatched",forwarded=false,accepted=false;
 try {
  const f=privateFlowCommand(command,"credentialSubmit",originalPort,originalGrant);
  if(f.awaitingFill||f.submitted||command.fillAttemptId!==f.fillAttempt||privateAttempts.has(command.attemptId)||privateAttempts.size>=256)throw Error();
  privateAttempts.add(command.attemptId);f.submitted=command.attemptId;accepted=true;
  const frames=await chrome.webNavigation.getAllFrames({tabId:f.identity.tabId}),frame=frames?.find(x=>x.frameId===0&&x.documentId===f.identity.documentId);
  if(!frame||new URL(frame.url).origin!==f.origin)throw Error();
  privateFlowCommand(command,"credentialSubmit",originalPort,originalGrant);forwarded=true;
  const result=await privateRenderer(command);
  if(port!==originalPort||grant!==originalGrant||privateFlow!==f||command.deadlineUnixMs<=Date.now())throw Error();
  status=result&&Object.keys(result).sort().join()==="controlLease,retiredAuthorityQuiesced,status"&&typeof result.retiredAuthorityQuiesced==="boolean"&&result.controlLease&&Object.keys(result.controlLease).sort().join()==="generation,id"&&result.controlLease.id===f.lease.id&&result.controlLease.generation===f.lease.generation&&["dispatched","notDispatched","unknown"].includes(result.status)&& (result.status!=="dispatched"||result.retiredAuthorityQuiesced)?result.status:"unknown";
  f.submitConfirmed=status==="dispatched";
 }catch{status=forwarded?"unknown":"notDispatched";}
 finally {if(accepted&&privateFlow?.port===originalPort)privateFlow.submitStatus=status;if(accepted&&port===originalPort)try{originalPort.postMessage({type:"credentialSubmitResult",requestId:command.requestId,attemptId:command.attemptId,identity:command.identity,status,retiredAuthorityQuiesced:status==="dispatched",controlLease:command.controlLease});}catch{}privatePending=false;}
}
// Close only the exact filled document after a confirmed no-submit outcome.
// This never reads the DOM or releases the origin quarantine, and is one-shot
// even if the browser removes the tab but the acknowledgement is lost.
async function receiveCredentialRetire(command) {
 const originalPort=port,originalGrant=grant;if(!originalPort||privatePending)return;privatePending=true;
 let status="notDispatched",accepted=false,started=false;
 try {
  const f=privateFlowCommand(command,"credentialRetire",originalPort,originalGrant);
  if(f.awaitingFill||f.retireAttempt||f.submitConfirmed||f.submitted&&f.submitStatus!=="notDispatched"||command.fillAttemptId!==f.fillAttempt||privateAttempts.has(command.attemptId)||privateAttempts.size>=256)throw Error();
  privateAttempts.add(command.attemptId);f.retireAttempt=command.attemptId;accepted=true;
  const frames=await chrome.webNavigation.getAllFrames({tabId:f.identity.tabId});
  if(!frames?.some(x=>x.frameId===0&&x.documentId===f.identity.documentId&&new URL(x.url).origin===f.origin))throw Error();
  privateFlowCommand(command,"credentialRetire",originalPort,originalGrant);
  started=true;await chrome.tabs.remove(f.identity.tabId);
  const tabs=await chrome.tabs.query({});
  if(!Array.isArray(tabs)||tabs.some(x=>x.id===f.identity.tabId)||port!==originalPort||grant!==originalGrant||privateFlow!==f||command.deadlineUnixMs<=Date.now())throw Error();
  f.retired=true;status="dispatched";
 }catch{status=started?"unknown":"notDispatched";}
 finally{if(accepted&&port===originalPort)try{originalPort.postMessage({type:"credentialRetireResult",requestId:command.requestId,attemptId:command.attemptId,identity:command.identity,status});}catch{}privatePending=false;}
}
async function receiveCredentialAdvance(command) {
 const originalPort=port,originalGrant=grant;if(!originalPort||privatePending)return;privatePending=true;
 let identity=command.identity,ready=false,stage="unavailable",accepted=false;
 try {
  const f=privateFlowCommand(command,"credentialAdvance",originalPort,originalGrant),lease=command.nextLease;
  if(!f.submitConfirmed||f.submitted!==command.attemptId||f.advanceAttempted||!lease||Object.keys(lease).sort().join()!=="generation,id"||typeof lease.id!=="string"||!/^[A-Za-z0-9._:-]{1,128}$/.test(lease.id)||!Number.isSafeInteger(lease.generation)||lease.generation<=f.lease.generation)throw Error();
  accepted=true;
  const enrollment=await config();let tab,frame;
  const settleUntil=Math.min(command.deadlineUnixMs-50,Date.now()+1000);
  while(settleUntil>Date.now()) {
    privateFlowCommand(command,"credentialAdvance",originalPort,originalGrant);
    tab=await chrome.tabs.get(f.identity.tabId);const frames=await chrome.webNavigation.getAllFrames({tabId:f.identity.tabId});frame=frames?.find(x=>x.frameId===0);
    if(frame&&frame.documentId!==f.identity.documentId)break;
    await new Promise(resolve=>setTimeout(resolve,25));
  }
  if(!frame||!frame.documentId||new URL(frame.url).origin!==f.origin||new URL(tab.url).origin!==f.origin||!allowedOrigin(f.origin,enrollment)||new URL(frame.url).username||new URL(frame.url).password)throw Error();
  if(frame.documentId===f.identity.documentId) {
    const probe={type:'credentialPostSubmit',requestId:command.requestId,attemptId:command.attemptId,identity:f.identity,brokerEpoch:command.brokerEpoch,channelEpoch:command.channelEpoch,scopeHash:command.scopeHash,controlLease:f.lease,deadlineUnixMs:Math.min(command.deadlineUnixMs-250,Date.now()+1000),origin:f.origin};
    let result,probeLost=false;
    try {result=await privateRenderer(probe);} catch {probeLost=true;}
    const after=await chrome.webNavigation.getAllFrames({tabId:f.identity.tabId});
    privateFlowCommand(command,'credentialAdvance',originalPort,originalGrant);
    const afterRoot=after?.find(x=>x.frameId===0),afterTab=await chrome.tabs.get(f.identity.tabId);
    // Navigation can replace the renderer while the read-only status probe is
    // outstanding. Preserve the original flow and retry metadata qualification,
    // without adopting the new document or repeating any credential input.
    if(afterRoot?.documentId&&afterRoot.documentId!==f.identity.documentId&&
       !afterRoot.errorOccurred&&afterRoot.frameType!=='fenced_frame'&&
       new URL(afterRoot.url).origin===f.origin&&new URL(afterTab.url).origin===f.origin&&
       !new URL(afterRoot.url).username&&!new URL(afterRoot.url).password&&
       !new URL(afterTab.url).username&&!new URL(afterTab.url).password) {
      privateFlowCommand(command,'credentialAdvance',originalPort,originalGrant);
      stage='pending';return;
    }
    if(probeLost){
      // A bounded read timeout never grants DOM access or repeats login input.
      // Keep quarantine and permit another status read only after fresh exact
      // same-origin tab/frame metadata; drift continues to fail closed.
      if(afterRoot?.documentId===f.identity.documentId&&!afterRoot.errorOccurred&&afterRoot.frameType!=='fenced_frame'&&
         new URL(afterRoot.url).origin===f.origin&&new URL(afterTab.url).origin===f.origin&&
         !new URL(afterRoot.url).username&&!new URL(afterRoot.url).password&&
         !new URL(afterTab.url).username&&!new URL(afterTab.url).password){stage='pending';return;}
      throw Error();
    }
    if(!after?.some(x=>x.frameId===0&&x.documentId===f.identity.documentId&&new URL(x.url).origin===f.origin)||!result||Object.keys(result).sort().join()!=='identity,privateCredentialProtocolVersion,ready,stage'||result.privateCredentialProtocolVersion!==2||result.ready!==false||!['pending','rejected','challenge','unavailable'].includes(result.stage)||!result.identity||Object.keys(result.identity).sort().join()!=='browserInstance,documentGeneration,documentId,frameId,profileChannel,tabId'||['profileChannel','browserInstance','tabId','frameId','documentId'].some(k=>result.identity[k]!==f.identity[k])||!Number.isSafeInteger(result.identity.documentGeneration)||result.identity.documentGeneration<f.identity.documentGeneration)throw Error();
    identity={...result.identity};stage=result.stage;f.sameDocumentPrivacy=stage==='unavailable';return;
  }
  f.advanceAttempted=true;
  identity={...f.identity,documentId:frame.documentId,documentGeneration:1};
  await chrome.scripting.executeScript({target:{tabId:identity.tabId,documentIds:[identity.documentId]},world:"ISOLATED",files:["protocol.js","fingerprint.js","accessibility-provider.js","dom.js","recorder.js","secure-input.js","content.js"]});
  privateFlowCommand(command,"credentialAdvance",originalPort,originalGrant);
  const next={type:"credentialBind",requestId:command.requestId,identity,brokerEpoch:command.brokerEpoch,channelEpoch:command.channelEpoch,scopeHash:command.scopeHash,controlLease:lease,deadlineUnixMs:command.deadlineUnixMs,origin:f.origin};
  const result=await privateRenderer(next),after=await chrome.webNavigation.getAllFrames({tabId:identity.tabId});
  if(port!==originalPort||grant!==originalGrant||command.deadlineUnixMs<=Date.now()||!after?.some(x=>x.frameId===0&&x.documentId===identity.documentId&&new URL(x.url).origin===f.origin)||
     !result||Object.keys(result).sort().join()!=="identity,ready,stage"||typeof result.ready!=="boolean"||!result.identity||Object.keys(result.identity).sort().join()!=="browserInstance,documentGeneration,documentId,frameId,profileChannel,tabId"||
     ["profileChannel","browserInstance","tabId","frameId","documentId"].some(k=>identity[k]!==result.identity[k])||!Number.isSafeInteger(result.identity.documentGeneration)||result.identity.documentGeneration<1||!["username","password","pair","challenge","unavailable"].includes(result.stage))throw Error();
  identity={...result.identity};stage=result.stage;ready=result.ready&&["username","password","pair"].includes(stage);
  if(!ready&&stage==="challenge")f.advanceAttempted=false;
  if(ready){const key=`${identity.tabId}:${identity.documentId}`;documents.delete(`${f.identity.tabId}:${f.identity.documentId}`);documentControlLeases.delete(`${f.identity.tabId}:${f.identity.documentId}`);documents.set(key,identity);documentControlLeases.set(key,{...lease});privateFlow={port:originalPort,identity,lease:{...lease},origin:f.origin,awaitingFill:true};}
 }catch{ready=false;}
 finally{if(accepted&&port===originalPort)try{originalPort.postMessage({type:"credentialAdvanceResult",requestId:command.requestId,attemptId:command.attemptId,identity,ready,stage});}catch{}privatePending=false;}
}
// This lane proves old-tab absence, or negotiated original-document absence,
// then independently qualifies the exact replacement manual document.
// It never closes/navigates tabs, delivers credentials, or inherits a lease.
const manualPrivacyReasons=new Set(['invalidRequest','authorityChanged','expired','busy','unknownEffects','lifecycleInhibited','sourceTabPresent','inventoryUnavailable','candidateUnavailable','candidateAmbiguous','candidateChanged','documentNotReady','redactionUnavailable']);
const manualPrivacyFailure=reason=>Object.assign(Error('Private manual document unavailable'),{manualReason:manualPrivacyReasons.has(reason)?reason:'authorityChanged'});
const manualIdentity=value=>value&&Object.keys(value).sort().join()==='browserInstance,documentGeneration,documentId,frameId,profileChannel,tabId'&&[value.profileChannel,value.browserInstance,value.documentId].every(channelShape)&&Number.isSafeInteger(value.tabId)&&value.tabId>0&&value.frameId===0&&Number.isSafeInteger(value.documentGeneration)&&value.documentGeneration>0;
const manualSameSource=(a,b)=>a&&b&&['profileChannel','browserInstance','tabId','frameId','documentId','documentGeneration'].every(key=>a[key]===b[key]);
// Document mode is explicitly negotiated. Legacy callers still require the
// entire original tab to be absent. No URL or generation proves replacement.
async function manualSourceProof(source,current,documentMode=false){
 current();let tabs;try{tabs=await chrome.tabs.query({});}catch{throw manualPrivacyFailure('inventoryUnavailable');}current();
 if(!Array.isArray(tabs)||tabs.length>200||tabs.some(tab=>!tab||!Number.isSafeInteger(tab.id)||tab.id<0)||new Set(tabs.map(tab=>tab.id)).size!==tabs.length)throw manualPrivacyFailure('inventoryUnavailable');
 const tab=tabs.find(tab=>tab.id===source.tabId);if(!tab)return {absent:true,successor:null};
 if(!documentMode)return {absent:false,successor:null};
 if(tab.incognito||tab.discarded||tab.pendingUrl||tab.status!=='complete')throw manualPrivacyFailure('inventoryUnavailable');
 let frames;try{frames=await chrome.webNavigation.getAllFrames({tabId:source.tabId});}catch{throw manualPrivacyFailure('inventoryUnavailable');}current();
 if(!Array.isArray(frames)||!frames.length||frames.length>256)throw manualPrivacyFailure('inventoryUnavailable');
 const roots=frames.filter(f=>f.frameId===0),root=roots[0];
 if(roots.length!==1||root.errorOccurred||root.frameType!=='outermost_frame'||root.documentLifecycle!=='active'||!channelShape(root.documentId))throw manualPrivacyFailure('inventoryUnavailable');
 if(frames.some(frame=>frame.documentId===source.documentId))return {absent:false,successor:null};
 return {absent:true,successor:root.documentId};
}
async function manualPrivacyCandidate(source,origin,current,expected,documentMode=false,successor=null){
 const proof=await manualSourceProof(source,current,documentMode);if(!proof.absent)throw manualPrivacyFailure('sourceTabPresent');
 if(proof.successor!==successor)throw manualPrivacyFailure('candidateChanged');
 // A URL-filtered query requires the existing exact host grant. Internal tabs
 // need no URL metadata and cannot make the absence proof incomplete.
 let allowed,tabs;try{allowed=await chrome.permissions.contains({origins:[origin+'/*']});if(allowed)tabs=await chrome.tabs.query({url:origin+'/*'});}catch{throw manualPrivacyFailure('inventoryUnavailable');}current();
 if(allowed!==true||!Array.isArray(tabs)||tabs.length>200||tabs.some(tab=>!tab||!Number.isSafeInteger(tab.id)||tab.id<=0)||new Set(tabs.map(tab=>tab.id)).size!==tabs.length)throw manualPrivacyFailure('inventoryUnavailable');
 if(successor)tabs=tabs.filter(tab=>tab.id===source.tabId);
 if(tabs.length!==1)throw manualPrivacyFailure(tabs.length?'candidateAmbiguous':'candidateUnavailable');
 const tab=tabs[0];let url,frames;
 try{url=new URL(tab.url);frames=await chrome.webNavigation.getAllFrames({tabId:tab.id});}catch{throw manualPrivacyFailure('candidateUnavailable');}current();
 if(tab.incognito||tab.discarded||tab.pendingUrl||url.origin!==origin||url.username||url.password||!Array.isArray(frames)||frames.length>256)throw manualPrivacyFailure('candidateChanged');
 const roots=frames.filter(frame=>frame.frameId===0),frame=roots[0];
 if(roots.length!==1||!frame||frame.errorOccurred||frame.frameType!==undefined&&frame.frameType!=='outermost_frame'||frame.documentLifecycle!==undefined&&frame.documentLifecycle!=='active'||typeof frame.documentId!=='string'||!channelShape(frame.documentId))throw manualPrivacyFailure('candidateChanged');
 let root;try{root=new URL(frame.url);}catch{throw manualPrivacyFailure('candidateChanged');}
 if(root.origin!==origin||root.username||root.password||tab.id===source.tabId&&(!documentMode||frame.documentId!==successor)||frame.documentId===source.documentId||expected&&(tab.id!==expected.tabId||frame.documentId!==expected.documentId))throw manualPrivacyFailure('candidateChanged');
 const after=await manualSourceProof(source,current,documentMode);if(!after.absent||after.successor!==successor)throw manualPrivacyFailure('candidateChanged');
 return {profileChannel:source.profileChannel,browserInstance:source.browserInstance,tabId:tab.id,frameId:0,documentId:frame.documentId,documentGeneration:expected?.documentGeneration||1};
}
async function receiveCredentialManualPrivacy(command){
 const originalPort=port,originalGrant=grant;if(!originalPort||privatePending)return;
 privatePending=true;
 const absence=command.type==='credentialTabAbsent',commit=command.type==='credentialManualPrivacyCommit',documentMode=command.sourceDocumentAbsence===true;
 let accepted=false,absent=false,inventoryComplete=false,identity=null,ready=false,redactionReady=false,privateInputRetired=false,reason;
 let held=manualPrivacyFlow;
 const current=()=>{
  if(port!==originalPort||grant!==originalGrant||!grant?.leaseRequired||!qualifiedNativePorts.has(port))throw manualPrivacyFailure('authorityChanged');
  if(Date.now()>=command.deadlineUnixMs)throw manualPrivacyFailure('expired');
  if(mutationBusy||setupActiveCommands||privateAdmission||privateFlow||activeBrowserInputs.size)throw manualPrivacyFailure('busy');
  if(unknownAttempts.size)throw manualPrivacyFailure('unknownEffects');
  if(lifecycleGuardId)throw manualPrivacyFailure('lifecycleInhibited');
  if(privatePrivacy&&!(privatePrivacy.origin===command.origin&&(privatePrivacy.identity.tabId===command.sourceIdentity.tabId||privatePrivacy.manual&&manualSameSource(privatePrivacy.sourceIdentity,command.sourceIdentity))))throw manualPrivacyFailure('busy');
  if([...documentControlLeases.keys()].some(key=>documentMode||!key.startsWith(command.sourceIdentity.tabId+':')))throw manualPrivacyFailure('busy');
 };
 try{
  const keys=['type','requestId','proofId','sourceIdentity','brokerEpoch','channelEpoch','scopeHash','deadlineUnixMs','origin',...(documentMode?['sourceDocumentAbsence']:[]),...(absence?[]:commit?['identity','permitId']:['username','password'])];
  if(new TextEncoder().encode(JSON.stringify(command)).length>MechanizeProtocol.MAX_BYTES||Object.keys(command).sort().join()!==keys.sort().join()||!privateWireID(command.requestId)||!privateWireID(command.proofId)||!manualIdentity(command.sourceIdentity)||
     !Number.isSafeInteger(command.deadlineUnixMs)||command.deadlineUnixMs<=Date.now()||command.deadlineUnixMs>Date.now()+10000||typeof command.origin!=='string'||!command.origin.startsWith('https://')||new URL(command.origin).origin!==command.origin||
     ['brokerEpoch','channelEpoch','scopeHash'].some(key=>command[key]!==originalGrant?.[key]))throw manualPrivacyFailure('invalidRequest');
  accepted=true;current();const enrollment=await config();
  if(command.sourceIdentity.profileChannel!==enrollment.profileChannel||command.sourceIdentity.browserInstance!==enrollment.browserInstance||!allowedOrigin(command.origin,enrollment)||!protectedOrigins.has(command.origin))throw manualPrivacyFailure('authorityChanged');
  if(absence){
   const first=await manualSourceProof(command.sourceIdentity,current,documentMode);absent=first.absent;inventoryComplete=true;
   if(!absent)throw manualPrivacyFailure('sourceTabPresent');
   const second=await manualSourceProof(command.sourceIdentity,current,documentMode);absent=second.absent;
   if(!absent||first.successor!==second.successor)throw manualPrivacyFailure('candidateChanged');
   held={port:originalPort,grant:originalGrant,proofId:command.proofId,sourceIdentity:{...command.sourceIdentity},origin:command.origin,deadline:command.deadlineUnixMs,documentMode,successor:first.successor,identity:null,phase:'absent'};manualPrivacyFlow=held;privateSilencedPort=originalPort;return;
  }
  if(!held||held.documentMode!==documentMode||held.port!==originalPort||held.grant!==originalGrant||held.proofId!==command.proofId||held.origin!==command.origin||Date.now()>=held.deadline||command.deadlineUnixMs>held.deadline||!manualSameSource(held.sourceIdentity,command.sourceIdentity)||commit&&held.phase!=='ready'||!commit&&held.phase!=='absent')throw manualPrivacyFailure('authorityChanged');
  if(commit&&(!manualIdentity(command.identity)||!manualSameSource(command.identity,held.identity)||command.permitId!==command.proofId))throw manualPrivacyFailure('invalidRequest');
  identity=await manualPrivacyCandidate(command.sourceIdentity,command.origin,current,commit?held.identity:undefined,documentMode,held.successor);
  if(!commit){
   if(typeof command.username!=='string'||typeof command.password!=='string'||!command.username||!command.password||command.username.length+command.password.length>65536)throw manualPrivacyFailure('redactionUnavailable');
   const variants=MechanizeSecureInput.redactionVariants([command.username,command.password]);if(!MechanizeSecureInput.validRedactions(variants))throw manualPrivacyFailure('redactionUnavailable');
   // Redactor material stays private and volatile. No session/local journal,
   // model-facing reply, ordinary renderer command, or input adapter receives it.
   const combinedVariants=Array.from(new Set([...privateRedactions,...variants]));if(!MechanizeSecureInput.validRedactions(combinedVariants))throw Error();privateRedactions=combinedVariants;privateSilencedPort=originalPort;held.identity={...identity};held.phase='binding';
   await chrome.scripting.executeScript({target:{tabId:identity.tabId,documentIds:[identity.documentId]},world:'ISOLATED',files:['protocol.js','fingerprint.js','accessibility-provider.js','dom.js','recorder.js','secure-input.js','content.js']});current();
  }
  const renderer={type:commit?'credentialManualPrivacyCommit':'credentialManualPrivacyBind',requestId:command.requestId,identity,brokerEpoch:command.brokerEpoch,channelEpoch:command.channelEpoch,scopeHash:command.scopeHash,deadlineUnixMs:command.deadlineUnixMs,origin:command.origin,permitId:command.proofId,...(commit?{}:{redactions:privateRedactions})};
  const result=await privateRenderer(renderer);current();await manualPrivacyCandidate(command.sourceIdentity,command.origin,current,identity,documentMode,held.successor);
  if(!result||Object.keys(result).sort().join()!=='identity,permitId,privateInputRetired,ready,redactionReady'||!manualIdentity(result.identity)||['profileChannel','browserInstance','tabId','frameId','documentId'].some(key=>result.identity[key]!==identity[key])||result.identity.documentGeneration<identity.documentGeneration||result.permitId!==command.proofId||typeof result.ready!=='boolean'||typeof result.redactionReady!=='boolean'||typeof result.privateInputRetired!=='boolean')throw manualPrivacyFailure('redactionUnavailable');
  identity={...result.identity};redactionReady=result.redactionReady;privateInputRetired=result.privateInputRetired;
  if(!redactionReady||!privateInputRetired)throw manualPrivacyFailure('redactionUnavailable');
  if(!result.ready)throw manualPrivacyFailure('documentNotReady');
  ready=true;held.identity=identity;held.phase=commit?'committed':'ready';
  if(commit){
   privatePrivacy={manual:true,port:originalPort,sourceIdentity:{...held.sourceIdentity},identity,origin:held.origin,proofId:held.proofId,permitId:held.proofId,active:true,committed:true};
   for(const [key,old] of documents)if(old.tabId===held.sourceIdentity.tabId){documents.delete(key);documentControlLeases.delete(key);documentFingerprintVersions.delete(key);documentOrigins.delete(key);}
   const key=`${identity.tabId}:${identity.documentId}`;documents.set(key,identity);documentOrigins.set(key,held.origin);documentFingerprintVersions.set(key,2);privateSilencedPort=null;
  }
 }catch(error){reason=manualPrivacyReasons.has(error?.manualReason)?error.manualReason:'authorityChanged';ready=false;}
 finally{
  if(Object.hasOwn(command,'username'))command.username='';if(Object.hasOwn(command,'password'))command.password='';
  if(accepted&&port===originalPort)try{originalPort.postMessage(absence?{type:'credentialTabAbsentResult',requestId:command.requestId,proofId:command.proofId,sourceIdentity:command.sourceIdentity,absent,inventoryComplete,...(reason?{reason}:{})}:{type:'credentialManualPrivacyResult',requestId:command.requestId,proofId:command.proofId,identity,ready,redactionReady,privateInputRetired,...(reason?{reason}:{})});}catch{}
  privatePending=false;
 }
}
// Retire only the capability descended from this exact original source. An
// old worker omitted sourceIdentity; its confirmed submit/lease pair is the
// only accepted correlation with the authenticated broker's retained receipt.
function privacyForSourceRetirement(command, held) {
 const proof=command.retirementProof;
 if(proof!==undefined){
  if(!['absent','retire'].includes(command.mode)||!proof||Object.keys(proof).join()!=='candidates'||!Array.isArray(proof.candidates)||!proof.candidates.length||proof.candidates.length>512||new TextEncoder().encode(JSON.stringify(command)).length>MechanizeProtocol.MAX_BYTES)throw 'scopeChanged';
  const seen=new Set();for(const row of proof.candidates){if(!row||Object.keys(row).sort().join()!=='controlLease,submitAttemptId'||typeof row.submitAttemptId!=='string'||!/^[a-f0-9]{64}$/.test(row.submitAttemptId)||!row.controlLease||Object.keys(row.controlLease).sort().join()!=='generation,id'||!channelShape(row.controlLease.id)||!Number.isSafeInteger(row.controlLease.generation)||row.controlLease.generation<1)throw 'scopeChanged';const key=JSON.stringify([row.submitAttemptId,row.controlLease.id,row.controlLease.generation]);if(seen.has(key))throw 'scopeChanged';seen.add(key);}
 }
 if(!['absent','retire'].includes(command.mode)||!held)return null;
 const source=command.sourceIdentity,same=i=>i&&source&&['profileChannel','browserInstance','tabId','frameId','documentId'].every(k=>i[k]===source[k]);
 const pair=proof&&held.submitConfirmed===true&&proof.candidates.filter(row=>row.submitAttemptId===held.sourceSubmit&&row.controlLease.id===held.sourceLease?.id&&row.controlLease.generation===held.sourceLease?.generation).length===1;
 // A retained old-port capability is never rebound. Only an independently
 // authenticated current-fence cleanup with its exact confirmed pair may
 // dispose of it after the existing source-absence proof.
 if(held.port!==port&&!pair)throw 'scopeChanged';
 let matches=same(held.sourceIdentity)||same(held.identity);
 if(!held.sourceIdentity&&!matches){
  if(!pair||!manualIdentity(source)||['profileChannel','browserInstance','tabId','frameId'].some(k=>source[k]!==held.identity[k])||command.sourceOrigin!==held.origin)throw 'scopeChanged';
  matches=true;
 }
 if(!matches){if(proof!==undefined)throw 'scopeChanged';return null;}
 if(command.sourceOrigin!==held.origin)throw 'scopeChanged';
 if(proof!==undefined&&!pair)throw 'scopeChanged';
 if(!held.committed||documentControlLeases.has(`${held.identity.tabId}:${held.identity.documentId}`))throw 'scopeChanged';
 return held;
}
async function receiveCredentialPrivacy(command) {
 const originalPort=port,originalGrant=grant;if(!originalPort||privatePending)return;privatePending=true;
 let identity=command.identity,ready=false,redactionReady=false,retiredAuthorityQuiesced=false,accepted=false,documentChanged=false,heldState=null;
 try {
  const qualification=command.type==="credentialPrivacy",commit=command.type==="credentialPrivacyCommit",f=qualification?(privatePrivacy||privateFlow):privatePrivacy;
  const lease=f?.sourceLease||f?.lease,sourceSubmit=f?.sourceSubmit||f?.submitted;
  if(!f||f.port!==originalPort||!f.submitConfirmed||sourceSubmit!==command.attemptId||
     Object.keys(command).sort().join()!==["type","requestId","attemptId","identity","brokerEpoch","channelEpoch","scopeHash","controlLease","deadlineUnixMs","origin","permitId"].sort().join()||
     !privateWireID(command.requestId)||!privateWireID(command.permitId)||typeof command.attemptId!=="string"||!/^[a-f0-9]{64}$/.test(command.attemptId)||
     !identity||Object.keys(identity).sort().join()!=="browserInstance,documentGeneration,documentId,frameId,profileChannel,tabId"||!Number.isSafeInteger(identity.documentGeneration)||identity.documentGeneration<1||
     ["profileChannel","browserInstance","tabId","frameId","documentId"].some(k=>identity[k]!==f.identity[k])||
     !command.controlLease||Object.keys(command.controlLease).sort().join()!=="generation,id"||command.controlLease.id!==lease.id||command.controlLease.generation!==lease.generation||
     ["brokerEpoch","channelEpoch","scopeHash"].some(k=>command[k]!==originalGrant[k])||command.origin!==f.origin||
     !Number.isSafeInteger(command.deadlineUnixMs)||command.deadlineUnixMs<=Date.now()||command.deadlineUnixMs>Date.now()+10000||mutationBusy||setupActiveCommands||unknownAttempts.size||lifecycleGuardId||
     !MechanizeSecureInput.validRedactions(privateRedactions)||!qualification&&command.permitId!==f.permitId||commit&&f.committed||!qualification&&!commit&&!f.committed)throw Error();
  accepted=true;heldState=f;
  // An already committed redactor is independent same-document evidence.
  // Initial login promotion still requires the private post-submit proof.
  const sameDocumentPrivacy=f===privatePrivacy&&f.committed===true||f.sameDocumentPrivacy===true;
  let frame,tab;
  while(command.deadlineUnixMs>Date.now()) {
   if(port!==originalPort||grant!==originalGrant)throw Error();
   tab=await chrome.tabs.get(identity.tabId);const frames=await chrome.webNavigation.getAllFrames({tabId:identity.tabId});frame=frames?.find(x=>x.frameId===0);
   if(frame&&(!qualification||frame.documentId!==identity.documentId||sameDocumentPrivacy))break;
   await new Promise(resolve=>setTimeout(resolve,25));
  }
  if(!frame||new URL(frame.url).origin!==f.origin||new URL(tab.url).origin!==f.origin||new URL(frame.url).username||new URL(frame.url).password||qualification&&frame.documentId===identity.documentId&&!sameDocumentPrivacy)throw Error();
  if(!qualification&&!commit&&frame.documentId!==identity.documentId){identity={...identity,documentId:frame.documentId,documentGeneration:1};documentChanged=true;retiredAuthorityQuiesced=true;redactionReady=true;privatePrivacy.active=false;privateSilencedPort=originalPort;return;}
  if(!qualification&&frame.documentId!==identity.documentId)throw Error();
  if(qualification){
   privateSilencedPort=originalPort;
   identity={...identity,documentId:frame.documentId,documentGeneration:1};
   await chrome.scripting.executeScript({target:{tabId:identity.tabId,documentIds:[identity.documentId]},world:"ISOLATED",files:["protocol.js","fingerprint.js","accessibility-provider.js","dom.js","recorder.js","secure-input.js","content.js"]});
  }
  const renderer={type:qualification?"credentialPrivacyBind":commit?"credentialPrivacyCommit":"credentialPrivacyInspect",requestId:command.requestId,identity,brokerEpoch:command.brokerEpoch,channelEpoch:command.channelEpoch,scopeHash:command.scopeHash,deadlineUnixMs:command.deadlineUnixMs,origin:f.origin,permitId:command.permitId};
  if(qualification)renderer.redactions=privateRedactions;
  const settleDeadline=Math.min(command.deadlineUnixMs-250,Date.now()+1000);
  let result,after;
  do {
  result=await privateRenderer(renderer);after=await chrome.webNavigation.getAllFrames({tabId:identity.tabId});
  if(port!==originalPort||grant!==originalGrant||command.deadlineUnixMs<=Date.now()||!after?.some(x=>x.frameId===0&&x.documentId===identity.documentId&&new URL(x.url).origin===f.origin)||
     !result||Object.keys(result).sort().join()!=="identity,permitId,privateInputRetired,ready,redactionReady"||result.permitId!==command.permitId||
     typeof result.ready!=="boolean"||typeof result.redactionReady!=="boolean"||typeof result.privateInputRetired!=="boolean"||!result.identity||Object.keys(result.identity).sort().join()!=="browserInstance,documentGeneration,documentId,frameId,profileChannel,tabId"||
     ["profileChannel","browserInstance","tabId","frameId","documentId"].some(k=>identity[k]!==result.identity[k])||!Number.isSafeInteger(result.identity.documentGeneration)||result.identity.documentGeneration<identity.documentGeneration)throw Error();
  // Only retry a validated read-only qualification with intact retirement and
  // redaction. Never retry credential input, missing proof, or a changed frame.
  if(!qualification||result.ready||!result.redactionReady||!result.privateInputRetired||Date.now()+50>=settleDeadline)break;
  await new Promise(resolve=>setTimeout(resolve,50));
  } while(Date.now()<settleDeadline);
  identity={...result.identity};redactionReady=result.redactionReady;retiredAuthorityQuiesced=result.privateInputRetired;ready=result.ready&&redactionReady&&retiredAuthorityQuiesced;
  if(ready){
   if(qualification)privatePrivacy={port:originalPort,identity,...(f.sourceIdentity?{sourceIdentity:{...f.sourceIdentity}}:f===privateFlow?{sourceIdentity:{...f.identity}}:{}),sameDocumentPrivacy:true,origin:f.origin,sourceLease:{...lease},sourceSubmit,submitConfirmed:true,permitId:command.permitId,active:false,committed:false};
   if(commit){privatePrivacy.active=true;privatePrivacy.committed=true;privatePrivacy.identity=identity;privatePrivacy.publicRoute=new URL(frame.url).origin+new URL(frame.url).pathname;privateAdmission=null;privateFlow=null;privateSilencedPort=null;
     const key=`${identity.tabId}:${identity.documentId}`;documents.set(key,identity);documentOrigins.set(key,f.origin);documentFingerprintVersions.set(key,2);}
  }else{if(privatePrivacy)privatePrivacy.active=false;privateSilencedPort=originalPort;}
 }catch{ready=false;if(accepted&&port===originalPort&&grant===originalGrant&&(privatePrivacy===heldState||privateFlow===heldState)){if(privatePrivacy)privatePrivacy.active=false;privateSilencedPort=originalPort;}}
 finally {if(accepted&&port===originalPort)try{originalPort.postMessage({type:"credentialPrivacyResult",requestId:command.requestId,attemptId:command.attemptId,identity,ready,retiredAuthorityQuiesced,redactionReady,permitId:command.permitId,...(documentChanged?{documentChanged:true}:{})});}catch{}privatePending=false;}
}
// A broker reconnect is an executor handoff, never a storage reset or replay.
// The durable pending record is retained on every uncertain/partial outcome.
const reconnectKey = "mechanizeReconnect";
let reconnectBusy = false;
let qualificationFlight=null, queuedQualification=null;
function qualificationCurrent(owner){
 if(port!==owner.port||qualificationFlight!==owner)throw reconnectRefuse('portChanged');
 if(owner.expired||Date.now()>=owner.deadline){owner.expired=true;throw reconnectRefuse('deadline');}
}
function qualificationDeadline(owner){
 owner.expired=true;
 if(port!==owner.port||qualificationFlight!==owner)return;
 // A stalled Chrome API is not quiescence. Keep its owner/lane until it drains;
 // report the deadline without permitting a competing bind or input replay.
 reconnectDiagnosticReason='deadline';connectionAttention='storedFenceMismatch';
 try{owner.port.postMessage(reconnectAttention({type:'attention',error:reconnectFail()}));}catch{}
 chrome.runtime.sendMessage({type:'nativeConnectionStatus',connected:true,qualified:false,attentionCode:connectionAttention}).catch(()=>{});
}
async function qualificationRead(owner,operation){
 qualificationCurrent(owner);
 // The flight timer reports a finite deadline. Chrome operations cannot be
 // cancelled: retain their original owner until settlement, especially writes
 // that may still commit after the deadline. Recovery must not race that work.
 try{return await operation();}finally{qualificationCurrent(owner);}
}

const reconnectPorts = new WeakSet(), qualifiedNativePorts = new WeakSet(), reconnectRecoveryChecks = new WeakMap(), reconnectPendingRecords=new WeakMap();
const fenceKeys = ["brokerEpoch","channelEpoch","scopeHash"];
const reconnectFence = value => Object.fromEntries(fenceKeys.map(key=>[key,value[key]]));
const sameReconnectFence = (a,b) => a && b && fenceKeys.every(key=>a[key]===b[key]);
const reconnectFail = () => MechanizeProtocol.error("storedFenceMismatch","Stored channel fence requires independent quiescence and receipt recovery");
const reconnectRefuse = reason => {reconnectDiagnosticReason=reason;if(reason==='journalChanged'&&reconnectJournalDiagnostic?.reason==='none')reconnectJournalDiagnostic.reason='recordChanged';return reconnectFail();};
function captureReconnectJournal(journal,lastGrant){
  const matches=fence=>fence&&lastGrant&&['brokerEpoch','channelEpoch','scopeHash'].every(k=>typeof fence[k]==='string'&&fence[k]!==''&&fence[k]===lastGrant[k]);
  const old=matches(journal?.oldFence),next=matches(journal?.newFence);
  reconnectJournalDiagnostic={reason:'none',version:journal===undefined?0:Number.isSafeInteger(journal?.version)&&journal.version>=1&&journal.version<=MAX_RECONNECT_VERSION?journal.version:-1,
    historyCount:Array.isArray(journal?.history)&&journal.history.length<=64?journal.history.length:journal===undefined?0:-1,
    state:journal===undefined?'absent':['pending','adopted'].includes(journal?.phase)?journal.phase:'unrecognized',
    grantRelation:journal===undefined?'none':!lastGrant?'unavailable':old&&next?'both':old?'old':next?'new':'neither'};
}
function reconnectJournalRefuse(reason){
  const closed=['recoveryDepthLimit','historyLimit','lineageInvalid','recordChanged','bindingSnapshotUnavailable'].includes(reason)?reason:'recordChanged';
  if(reconnectJournalDiagnostic)reconnectJournalDiagnostic.reason=closed;
  const error=reconnectRefuse('journalChanged');Object.defineProperty(error,'journalReason',{value:closed});return error;
}
const reconnectInventoryRefuse = reason => {reconnectInventoryReason=MechanizeSetupMetadata.INVENTORY_REASONS.includes(reason)?reason:"none";return reconnectRefuse("inventoryChanged");};
// Chrome errors may contain private URLs. Classify locally and export only one
// closed code; never retain or transmit the original error or message.
function injectionFailureReason(error) {
  const message=typeof error?.message==="string"?error.message:"";
  if(/extension context invalidated/i.test(message))return "extensionContextInvalidated";
  if(/fenced frame|sandboxed|error page/i.test(message))return "restrictedFrame";
  if(/Error at parameter|Error at property|Unexpected property|Invalid value for argument/i.test(message))return "injectionArgumentsRejected";
  if(/ReferenceError|TypeError|SyntaxError|is not a function|Cannot read properties/i.test(message))return "executorEvaluationFailed";
  if(/extensions gallery cannot be scripted|chrome web store|chromewebstore/i.test(message))return "restrictedBrowserPage";
  if(/Could not load file|Could not load javascript/i.test(message))return "packagedExecutorUnavailable";
  if(/No document with id|No frame with id|Frame with ID.*removed|No tab with id/i.test(message))return "documentChanged";
  if(/Cannot access contents of|host permission|Missing host permission/i.test(message))return "websitePermissionMissing";
  return "injectionUnavailable";
}
async function reconnectStorage(operation, qualification) {
  try{return await (qualification?qualificationRead(qualification,operation):operation());}catch(error){if(error?.code==='storedFenceMismatch')throw error;throw reconnectRefuse("storageFailure");}
}
const channelShape = value => typeof value === "string" && /^[A-Za-z0-9._:-]{1,128}$/.test(value);
const reconnectRecordKeys = value => value && typeof value === "object" && !Array.isArray(value) && Object.keys(value).sort().join();
const reconnectFenceValid = v => reconnectRecordKeys(v)==="brokerEpoch,channelEpoch,scopeHash" && fenceKeys.every(k=>channelShape(v[k])) && /^[a-f0-9]{64}$/.test(v.scopeHash);
// Chrome storage dictionaries may reorder keys. Canonicalize only JSON data,
// preserving all keys, scalar types, and array order under fixed resource bounds.
function reconnectCanonical(value) {
  if(value===undefined)return "undefined";
  let nodes=0;
  const normalize=(item,depth)=>{
    if(++nodes>32768 || depth>16)throw reconnectJournalRefuse("historyLimit");
    if(item===null || typeof item==="string" || typeof item==="boolean")return item;
    if(typeof item==="number" && Number.isFinite(item))return item;
    if(Array.isArray(item))return item.map(child=>normalize(child,depth+1));
    if(item && typeof item==="object")return Object.fromEntries(Object.keys(item).sort().map(key=>[key,normalize(item[key],depth+1)]));
    throw reconnectRefuse("journalChanged");
  };
  const result=JSON.stringify(normalize(value,0));
  if(new TextEncoder().encode(result).length>MechanizeProtocol.MAX_BYTES)throw reconnectJournalRefuse("historyLimit");
  return result;
}
// Each recovery embeds its predecessor unchanged. Six versions fit inside the
// canonical depth-16 budget even with a retained receipt history; the writer
// refuses another nesting level before persisting an unreadable record.
const MAX_RECONNECT_VERSION=6;
const reconnectVersionValid=value=>Number.isSafeInteger(value)&&value>=1&&value<=MAX_RECONNECT_VERSION;
// Active handoffs have a fixed format. Legacy versions remain readable audit
// evidence; their recursive recovery depth is never an active lifetime counter.
const activeReconnectJournal=value=>value?.format==='activeHandoff';
const reconnectAuditPrefix='mechanizeReconnectAudit:';
const verifiedReconnectAudits=new Map();
function reconnectAuditReferenceValid(ref,scope){
 return reconnectRecordKeys(ref)==='bytes,digest,format,newFence,nonce,oldFence,phase,version'&&
  /^[a-f0-9]{64}$/.test(ref.digest)&&/^[a-f0-9]{64}$/.test(ref.nonce)&&Number.isSafeInteger(ref.bytes)&&ref.bytes>0&&ref.bytes<=MechanizeProtocol.MAX_BYTES&&
  ['pending','adopted'].includes(ref.phase)&&['legacy','activeHandoff'].includes(ref.format)&&reconnectVersionValid(ref.version)&&(ref.format!=='activeHandoff'||ref.version===1)&&
  reconnectFenceValid(ref.oldFence)&&reconnectFenceValid(ref.newFence)&&ref.oldFence.scopeHash===scope&&ref.newFence.scopeHash===scope&&!sameReconnectFence(ref.oldFence,ref.newFence);
}
function reconnectAuditMatches(ref,value){return value&&ref.version===value.version&&ref.phase===value.phase&&ref.format===(value.format||'legacy')&&ref.nonce===value.nonce&&sameReconnectFence(ref.oldFence,value.oldFence)&&sameReconnectFence(ref.newFence,value.newFence);}
function activeReconnectShape(record){
 if(!activeReconnectJournal(record)||record.version!==1||record.recovery!==undefined||record.archive!==undefined||!Array.isArray(record.history)||record.history.length!==(record.phase==='pending'?0:1)||!Array.isArray(record.recoveryFences)||record.recoveryFences.length<1||record.recoveryFences.length>MAX_INVENTORY_DOCUMENTS+2)return false;
 const seen=new Set();for(const fence of record.recoveryFences){if(!reconnectFenceValid(fence)||fence.scopeHash!==record.oldFence?.scopeHash)return false;const key=JSON.stringify(fence);if(seen.has(key))return false;seen.add(key);}
 return record.recoveryFences.some(fence=>sameReconnectFence(fence,record.newFence))&&
  (record.audit===undefined||reconnectAuditReferenceValid(record.audit,record.oldFence?.scopeHash));
}
async function loadReconnectAudit(record,qualification){
 if(record?.audit===undefined)return;
 const ref=record.audit;if(!activeReconnectShape(record))throw reconnectJournalRefuse('lineageInvalid');
 const stored=(await reconnectStorage(()=>chrome.storage.local.get(reconnectAuditPrefix+ref.digest),qualification))[reconnectAuditPrefix+ref.digest];
 if(reconnectRecordKeys(stored)!=='journalJSON,version'||stored.version!==1||typeof stored.journalJSON!=='string'||new TextEncoder().encode(stored.journalJSON).length!==ref.bytes||await reconnectPendingDigest(stored.journalJSON)!==ref.digest)throw reconnectJournalRefuse('lineageInvalid');
 let prior;try{prior=JSON.parse(stored.journalJSON);if(JSON.stringify(prior)!==stored.journalJSON)throw Error();}catch{throw reconnectJournalRefuse('lineageInvalid');}
 reconnectCanonical(prior);if(!reconnectAuditMatches(ref,prior))throw reconnectJournalRefuse('lineageInvalid');
 if(qualification)qualificationCurrent(qualification);
 verifiedReconnectAudits.set(ref.digest,freezeReconnectJSON(prior));
}
function reconnectAuditConsistent(record){
 if(!activeReconnectShape(record))return false;
 if(record.audit===undefined)return true;
 const prior=verifiedReconnectAudits.get(record.audit.digest);
 if(!reconnectAuditMatches(record.audit,prior)||record.nonce===prior.nonce)return false;
 return sameReconnectFence(record.oldFence,prior.phase==='pending'?prior.oldFence:prior.newFence)&&
  (prior.phase!=='pending'||!record.history.some(entry=>entry.nonce===prior.nonce));
}
async function archiveReconnectAudit(journal,previous,barriers,qualification){
 if(journal===undefined)return undefined;
 await verifyReconnectArchives(journal,qualification);
 if(!(journal.phase==='pending'?pendingReconnectValid(journal,previous):reconnectJournalValid(journal,previous)))throw reconnectJournalRefuse('lineageInvalid');
 await barriers();const before=reconnectCanonical(journal),journalJSON=JSON.stringify(journal),bytes=new TextEncoder().encode(journalJSON).length;
 if(bytes>MechanizeProtocol.MAX_BYTES)throw reconnectJournalRefuse('historyLimit');
 const digest=await reconnectPendingDigest(journalJSON),key=reconnectAuditPrefix+digest;
 const existing=(await reconnectStorage(()=>chrome.storage.local.get(key),qualification))[key];
 if(existing!==undefined&&(reconnectRecordKeys(existing)!=='journalJSON,version'||existing.version!==1||existing.journalJSON!==journalJSON))throw reconnectJournalRefuse('lineageInvalid');
 if(reconnectCanonical((await reconnectStorage(()=>chrome.storage.local.get(reconnectKey),qualification))[reconnectKey])!==before)throw reconnectJournalRefuse('recordChanged');
 if(existing===undefined)await reconnectStorage(()=>chrome.storage.local.set({[key]:{version:1,journalJSON}}),qualification);
 const saved=(await reconnectStorage(()=>chrome.storage.local.get(key),qualification))[key];
 if(reconnectRecordKeys(saved)!=='journalJSON,version'||saved.version!==1||saved.journalJSON!==journalJSON||await reconnectPendingDigest(saved.journalJSON)!==digest)throw reconnectJournalRefuse('lineageInvalid');
 await barriers();if(reconnectCanonical((await reconnectStorage(()=>chrome.storage.local.get(reconnectKey),qualification))[reconnectKey])!==before)throw reconnectJournalRefuse('recordChanged');
 verifiedReconnectAudits.set(digest,freezeReconnectJSON(JSON.parse(journalJSON)));
 return{digest,bytes,format:journal.format||'legacy',version:journal.version,phase:journal.phase,nonce:journal.nonce,oldFence:reconnectFence(journal.oldFence),newFence:reconnectFence(journal.newFence)};
}
// Archives retain complete adopted records, including original recovery trees.
// Only the active window is compacted; archive values are content-addressed and
// never overwritten or deleted. Verification work and bytes are explicitly bounded.
const reconnectArchivePrefix="mechanizeReconnectArchive:";
const MAX_RECONNECT_ARCHIVES=1024,MAX_RECONNECT_ARCHIVE_BYTES=8*1024*1024;
function reconnectArchiveReferenceValid(value,history){
  if(reconnectRecordKeys(value)!=="digest,endFence,nonce,segments"||typeof value.digest!=="string"||!/^[a-f0-9]{64}$/.test(value.digest)||
     !Number.isSafeInteger(value.segments)||value.segments<1||value.segments>MAX_RECONNECT_ARCHIVES||!reconnectFenceValid(value.endFence)||
     typeof value.nonce!=="string"||!/^[a-f0-9]{64}$/.test(value.nonce)||!Array.isArray(history)||!history.length)return false;
  return history[0]?.nonce===value.nonce&&sameReconnectFence(history[0]?.newFence,value.endFence);
}
function reconnectWithoutArchive(value){const result={...value};delete result.archive;return result;}
function reconnectLogicalHistory(record){
 const windows=[],seen=new Set();let cursor=record,remaining=record?.archive?.segments||0;
 while(cursor?.archive){
  const ref=cursor.archive,stored=verifiedHistoryArchives.get(ref.digest);
  if(!reconnectArchiveReferenceValid(ref,cursor.history)||ref.segments!==remaining||seen.has(ref.digest)||!stored||stored.journal.nonce!==ref.nonce||!sameReconnectFence(stored.journal.newFence,ref.endFence)||reconnectCanonical(stored.journal.history.at(-1))!==reconnectCanonical(cursor.history[0]))throw reconnectJournalRefuse('lineageInvalid');
  seen.add(ref.digest);windows.push(cursor.history.slice(1));cursor=stored.journal;remaining--;
 }
 if(remaining!==0||!Array.isArray(cursor?.history))throw reconnectJournalRefuse('lineageInvalid');
 const history=[...cursor.history];for(const window of windows.reverse())history.push(...window);return history;
}
const reconnectHistoryPrefix=(history,prefix)=>history.length>=prefix.length&&prefix.every((entry,index)=>reconnectCanonical(entry)===reconnectCanonical(history[index]));

function reconnectArchiveCanonical(value){
  if(reconnectRecordKeys(value)!=='journal,version'||value.version!==1)throw reconnectJournalRefuse('lineageInvalid');
  // The envelope must not reduce the existing record's depth/node budget.
  const result='{"journal":'+reconnectCanonical(value.journal)+',"version":1}';
  if(new TextEncoder().encode(result).length>MechanizeProtocol.MAX_BYTES)throw reconnectJournalRefuse('lineageInvalid');
  return result;
}
async function reconnectArchiveDigest(value){
  const bytes=new TextEncoder().encode(reconnectArchiveCanonical(value));
  return Array.from(new Uint8Array(await crypto.subtle.digest('SHA-256',bytes)),b=>b.toString(16).padStart(2,'0')).join('');
}
const reconnectPendingArchivePrefix="mechanizeReconnectPendingArchive:";
const verifiedPendingArchives=new Map(),verifiedHistoryArchives=new Map();
function reconnectPendingReferenceValid(ref){
 return reconnectRecordKeys(ref)==='bytes,digest,newFence,nonce,oldFence,version'&&/^[a-f0-9]{64}$/.test(ref.digest)&&/^[a-f0-9]{64}$/.test(ref.nonce)&&Number.isSafeInteger(ref.bytes)&&ref.bytes>0&&ref.bytes<=MechanizeProtocol.MAX_BYTES&&reconnectVersionValid(ref.version)&&ref.version<MAX_RECONNECT_VERSION&&reconnectFenceValid(ref.oldFence)&&reconnectFenceValid(ref.newFence)&&ref.oldFence.scopeHash===ref.newFence.scopeHash&&!sameReconnectFence(ref.oldFence,ref.newFence);
}
function reconnectPendingReferenceMatches(ref,value){return reconnectPendingReferenceValid(ref)&&value?.phase==='pending'&&value.version===ref.version&&value.nonce===ref.nonce&&sameReconnectFence(value.oldFence,ref.oldFence)&&sameReconnectFence(value.newFence,ref.newFence);}
function reconnectRecoveryShape(recovery){return ['kind,originalPending','kind,originalPendingRef'].includes(reconnectRecordKeys(recovery))&&['emptySetupDocuments','verifiedCurrentDocuments'].includes(recovery.kind);}
function reconnectOriginalPending(recovery){
 if(recovery===undefined)return undefined;
 if(!reconnectRecoveryShape(recovery))throw reconnectJournalRefuse('lineageInvalid');
 if(Object.hasOwn(recovery,'originalPending'))return recovery.originalPending;
 const value=verifiedPendingArchives.get(recovery.originalPendingRef?.digest);
 if(!reconnectPendingReferenceMatches(recovery.originalPendingRef,value))throw reconnectJournalRefuse('lineageInvalid');return value;
}
async function reconnectPendingDigest(text){return Array.from(new Uint8Array(await crypto.subtle.digest('SHA-256',new TextEncoder().encode(text))),b=>b.toString(16).padStart(2,'0')).join('');}
function freezeReconnectJSON(value){if(value&&typeof value==='object'){for(const child of Object.values(value))freezeReconnectJSON(child);Object.freeze(value);}return value;}
async function loadReconnectPendingArchives(record,budget,depth=0,qualification){
 if(!record?.recovery)return;
 if(depth>=MAX_RECONNECT_VERSION||!reconnectRecoveryShape(record.recovery))throw reconnectJournalRefuse('lineageInvalid');
 const recovery=record.recovery;let original=recovery.originalPending;
 if(Object.hasOwn(recovery,'originalPendingRef')){
  const ref=recovery.originalPendingRef;if(!reconnectPendingReferenceValid(ref))throw reconnectJournalRefuse('lineageInvalid');
  const key=reconnectPendingArchivePrefix+ref.digest,stored=(await reconnectStorage(()=>chrome.storage.local.get(key),qualification))[key];
  if(reconnectRecordKeys(stored)!=='pendingJSON,version'||stored.version!==1||typeof stored.pendingJSON!=='string'||new TextEncoder().encode(stored.pendingJSON).length!==ref.bytes||await reconnectPendingDigest(stored.pendingJSON)!==ref.digest)throw reconnectJournalRefuse('lineageInvalid');
  if(!budget.pending.has(ref.digest)){budget.pending.add(ref.digest);budget.bytes+=ref.bytes;if(budget.bytes>MAX_RECONNECT_ARCHIVE_BYTES||budget.pending.size>MAX_RECONNECT_ARCHIVES)throw reconnectJournalRefuse('historyLimit');}
  try{original=JSON.parse(stored.pendingJSON);if(JSON.stringify(original)!==stored.pendingJSON)throw Error();}catch{throw reconnectJournalRefuse('lineageInvalid');}
  if(!reconnectPendingReferenceMatches(ref,original)||original.version!==record.version-1)throw reconnectJournalRefuse('lineageInvalid');
  reconnectCanonical(original);if(qualification)qualificationCurrent(qualification);verifiedPendingArchives.set(ref.digest,freezeReconnectJSON(original));
 }
 if(!original||original.version!==record.version-1)throw reconnectJournalRefuse('lineageInvalid');
 await loadReconnectPendingArchives(original,budget,depth+1,qualification);
}
async function verifyReconnectArchives(record,qualification){
 const legacySignature=!activeReconnectJournal(record)&&qualification?reconnectCanonical(record):undefined;
 if(legacySignature!==undefined&&qualification.legacyProofSignature===legacySignature)return;
 verifiedPendingArchives.clear();verifiedHistoryArchives.clear();verifiedReconnectAudits.clear();
 try{const result=await verifyReconnectArchiveGraph(record,qualification);if(legacySignature!==undefined)qualification.legacyProofSignature=legacySignature;return result;}
 catch(error){verifiedPendingArchives.clear();verifiedHistoryArchives.clear();verifiedReconnectAudits.clear();throw error;}
}
async function verifyReconnectArchiveGraph(record,qualification){
 reconnectCanonical(record);if(record===undefined)return;
 if(activeReconnectJournal(record)){
  await loadReconnectAudit(record,qualification);
  if(!reconnectAuditConsistent(record))throw reconnectJournalRefuse('lineageInvalid');
  return;
 }
 const budget={bytes:0,pending:new Set()},queue=[record],roots=[],visited=new Set(),checkedArchives=new Map();
 // Load the bounded graph before pure validation: different recovery generations
 // may reference different history windows, but all immutable bytes remain.
 while(queue.length){
  const root=queue.shift(),signature=reconnectCanonical(root);if(visited.has(signature))continue;visited.add(signature);roots.push(root);
  await loadReconnectAudit(root,qualification);
  await loadReconnectPendingArchives(root,budget,0,qualification);
  for(let original=reconnectOriginalPending(root.recovery);original;original=reconnectOriginalPending(original.recovery))queue.push(original);
  let cursor=root,remaining=root?.archive?.segments||0;const seen=new Set();
  while(cursor?.archive){
   const ref=cursor.archive;if(!reconnectArchiveReferenceValid(ref,cursor.history)||ref.segments!==remaining||seen.has(ref.digest))throw reconnectJournalRefuse('lineageInvalid');seen.add(ref.digest);
   let stored=verifiedHistoryArchives.get(ref.digest);
   if(!stored){
    stored=(await reconnectStorage(()=>chrome.storage.local.get(reconnectArchivePrefix+ref.digest),qualification))[reconnectArchivePrefix+ref.digest];
    if(reconnectRecordKeys(stored)!=='journal,version'||stored.version!==1||!Array.isArray(stored.journal?.history)||stored.journal.history.length<1||stored.journal.history.length>64)throw reconnectJournalRefuse('lineageInvalid');
    const bytes=new TextEncoder().encode(reconnectArchiveCanonical(stored)).length;budget.bytes+=bytes;
    if(budget.bytes>MAX_RECONNECT_ARCHIVE_BYTES||verifiedHistoryArchives.size>=MAX_RECONNECT_ARCHIVES||await reconnectArchiveDigest(stored)!==ref.digest)throw reconnectJournalRefuse('lineageInvalid');
    stored=freezeReconnectJSON(JSON.parse(JSON.stringify(stored)));verifiedHistoryArchives.set(ref.digest,stored);queue.push(stored.journal);
   }
   if(stored.journal.phase!=='adopted'||stored.journal.nonce!==ref.nonce||!sameReconnectFence(stored.journal.newFence,ref.endFence)||reconnectCanonical(stored.journal.history.at(-1))!==reconnectCanonical(cursor.history[0]))throw reconnectJournalRefuse('lineageInvalid');
   checkedArchives.set(ref.digest,ref.endFence);cursor=stored.journal;remaining--;
  }
  if(remaining!==0)throw reconnectJournalRefuse('lineageInvalid');
 }
 const pendingNonces=new Map(),completedNonces=new Map();
 for(const root of roots){
  if(root.phase==='pending'){const prior=pendingNonces.get(root.nonce),canonical=reconnectCanonical(root);if(prior!==undefined&&prior!==canonical)throw reconnectJournalRefuse('lineageInvalid');pendingNonces.set(root.nonce,canonical);}
  for(const entry of reconnectLogicalHistory(root)){const canonical=reconnectCanonical(entry),prior=completedNonces.get(entry.nonce);if(prior!==undefined&&prior!==canonical)throw reconnectJournalRefuse('lineageInvalid');completedNonces.set(entry.nonce,canonical);}
 }
 for(const nonce of pendingNonces.keys())if(completedNonces.has(nonce))throw reconnectJournalRefuse('lineageInvalid');
 for(const [digest,endFence]of checkedArchives)if(!reconnectJournalValid(verifiedHistoryArchives.get(digest).journal,endFence))throw reconnectJournalRefuse('lineageInvalid');
}
// This is the exact eligible renderer set selected before prepare, not a claim
// that protected, inaccessible or non-website documents were inspected.
function reconnectSourceInventoryValid(value) {
  if(!value||reconnectRecordKeys(value)!=="documents,kind,version"||value.version!==1||value.kind!=="eligibleDocuments"||
     !Array.isArray(value.documents)||value.documents.length>MAX_INVENTORY_DOCUMENTS)return false;
  const seen=new Set();
  for(const item of value.documents){
    if(!item||reconnectRecordKeys(item)!=="browserInstance,documentGeneration,documentId,frameId,origin,profileChannel,tabId"||
       ![item.profileChannel,item.browserInstance,item.documentId].every(channelShape)||!Number.isSafeInteger(item.tabId)||item.tabId<1||
       !Number.isSafeInteger(item.frameId)||item.frameId<0||!Number.isSafeInteger(item.documentGeneration)||item.documentGeneration<1||
       typeof item.origin!=="string")return false;
    try{const url=new URL(item.origin);if(!["http:","https:"].includes(url.protocol)||url.origin!==item.origin||url.username||url.password)return false;}catch{return false;}
    const key=`${item.tabId}:${item.frameId}:${item.documentId}`;if(seen.has(key))return false;seen.add(key);
  }
  return true;
}
function reconnectCoreKeys(record,recovery){
  const keys=["history","newFence","nonce","oldFence","phase","version"];
  if(recovery)keys.push("recovery");
  if(activeReconnectJournal(record)){
    if(!activeReconnectShape(record))return false;
    keys.push('format','recoveryFences');if(record.audit!==undefined)keys.push('audit');
  }
  if(Object.hasOwn(record||{},"sourceInventory")){
    if(!reconnectSourceInventoryValid(record.sourceInventory))return false;
    keys.push("sourceInventory");
  }
  return reconnectRecordKeys(record)===keys.sort().join();
}
function reconnectBooleanValidation(validate){
 const reason=reconnectDiagnosticReason,journal=reconnectJournalDiagnostic,journalReason=journal?.reason;
 try{return validate()===true;}catch{return false;}finally{reconnectDiagnosticReason=reason;if(journal)journal.reason=journalReason;}
}
function pendingReconnectValid(value,lastGrant){return reconnectBooleanValidation(()=>pendingReconnectValidCore(value,lastGrant));}
function pendingReconnectValidCore(value,lastGrant,allowSameFenceRetirement=false) {
  if(value?.archive!==undefined&&!reconnectArchiveReferenceValid(value.archive,value.history))return false;
  try{reconnectCanonical(value);}catch{return false;}
  const nonces=new Set();
  const validate=(record,expectedOld,depth)=>{
    if(record?.archive!==undefined&&!reconnectArchiveReferenceValid(record.archive,record.history))return false;
    const sourceRecord=record,history=activeReconnectJournal(record)?record.history:reconnectLogicalHistory(record);record=reconnectWithoutArchive(record);
    const recovery=record?.version>1;
    if(depth>=MAX_RECONNECT_VERSION||!record||!reconnectVersionValid(record.version)||!reconnectCoreKeys(record,recovery)||record.phase!=="pending"||
       typeof record.nonce!=="string"||!/^[a-f0-9]{64}$/.test(record.nonce)||nonces.has(record.nonce)||!reconnectFenceValid(record.oldFence)||!reconnectFenceValid(record.newFence)||
       !sameReconnectFence(record.oldFence,expectedOld)||record.oldFence.scopeHash!==record.newFence.scopeHash||sameReconnectFence(record.oldFence,record.newFence)&&!(allowSameFenceRetirement&&depth===0&&record.version===1&&!recovery)||
       !Array.isArray(record.history)||record.history.length>=64||history.some(entry=>entry?.nonce===record.nonce))return false;
    nonces.add(record.nonce);
    if(activeReconnectJournal(record)&&!reconnectAuditConsistent(sourceRecord))return false;
    if(recovery){
      const original=reconnectOriginalPending(record.recovery);
      if(!reconnectRecoveryShape(record.recovery)||original?.version!==record.version-1||!validate(original,original?.oldFence,depth+1))return false;
      const originalHistory=reconnectLogicalHistory(original);
      if(history.length===originalHistory.length&&reconnectHistoryPrefix(history,originalHistory))return sameReconnectFence(record.oldFence,original.oldFence);
      // A later ordinary reconnect carries the previously adopted recovery
      // lineage unchanged. Its intervening history must independently bridge
      // the original recovery to the current old fence.
      if(history.length<=originalHistory.length||!reconnectHistoryPrefix(history,originalHistory)||
         !sameReconnectFence(history[originalHistory.length]?.oldFence,original.oldFence)||record.recovery.kind==="emptySetupDocuments"&&history[originalHistory.length]?.executors?.length!==0)return false;
      const tail=record.history.at(-1);
      return reconnectJournalValid({version:1,phase:"adopted",nonce:tail.nonce,oldFence:tail.oldFence,newFence:tail.newFence,history:record.history,...(sourceRecord.archive?{archive:sourceRecord.archive}:{})},expectedOld);
    }
    const tail=record.history.at(-1);
    return !tail||reconnectJournalValid({version:1,phase:"adopted",nonce:tail.nonce,oldFence:tail.oldFence,newFence:tail.newFence,history:record.history,...(sourceRecord.archive?{archive:sourceRecord.archive}:{})},expectedOld);
  };
  const valid=validate(value,lastGrant,0);
  return valid&&!(activeReconnectJournal(value)?value.history:reconnectLogicalHistory(value)).some(entry=>nonces.has(entry.nonce));
}
// Legacy pending records contain no complete original renderer inventory. Recovery
// is deliberately limited to no tabs or only our known browser setup surfaces.
// An exact built-in New Tab additionally needs independent browser-frame proof.
// Any website, unknown URL, foreign extension, or other document stays inhibited.
// Missing tabs.url is expected for Chrome-internal tabs without the broad tabs
// permission. This fallback is census metadata only: Chrome-owned root scheme,
// exact document IDs and parentage, no URL/content export and no executor grant.
function reconnectFrameState(frame,allowMissing=false,allowInactiveChild=false){
 const prefix=frame.frameId===0?'root':'child',lifecycle=frame.documentLifecycle;
 const inactiveChild=allowInactiveChild&&frame.frameId>0&&channelShape(frame.documentId)&&['prerender','cached'].includes(lifecycle);
 if(lifecycle!=='active'&&!inactiveChild&&!(allowMissing&&lifecycle===undefined)){
  const suffix=lifecycle===undefined?'Missing':lifecycle==='prerender'?'Prerender':lifecycle==='cached'?'Cached':lifecycle==='pending_deletion'?'PendingDeletion':'Invalid';
  throw reconnectInventoryRefuse(prefix+'Lifecycle'+suffix);
 }
 const expected=frame.frameId===0?'outermost_frame':'sub_frame';
 const fencedChild=frame.frameId>0&&frame.frameType==='fenced_frame'&&channelShape(frame.documentId);
 const inactiveRoot=inactiveChild&&frame.frameType==='outermost_frame';
 if(frame.frameType!==expected&&!fencedChild&&!inactiveRoot&&!(allowMissing&&frame.frameType===undefined)){
  const kind=frame.frameType===undefined?'Missing':frame.frameType==='outermost_frame'?'OuterMost':frame.frameType==='sub_frame'?'SubFrame':frame.frameType==='fenced_frame'?'Fenced':'Invalid';
  throw reconnectInventoryRefuse(prefix+'FrameType'+kind);
 }
 return inactiveChild;
}
// A prerendered/cached page is an additional tree, not a subframe of the
// primary page. Keep every identity, and never infer disappearance from state.
function reconnectFrameForest(frames,allowMissingParents=false){
 const byFrame=new Map(),docs=new Set();
 for(const f of frames){
  if(!f||!Number.isSafeInteger(f.frameId)||f.frameId<0||byFrame.has(f.frameId))throw reconnectInventoryRefuse('frameIDInvalid');
  if(!Number.isSafeInteger(f.parentFrameId))throw reconnectInventoryRefuse('frameParentInvalid');
  if(f.documentId){if(docs.has(f.documentId))throw reconnectInventoryRefuse('frameDocumentUnavailable');docs.add(f.documentId);}
  byFrame.set(f.frameId,f);
 }
 const root=byFrame.get(0);if(!root)throw reconnectInventoryRefuse('frameRootMissing');if(root.parentFrameId!==-1)throw reconnectInventoryRefuse('frameParentInvalid');
 const result=new Map();
 for(const f of frames){
  const seen=new Set();let cursor=f;
  while(cursor.parentFrameId!==-1){
   if(seen.has(cursor.frameId))throw reconnectInventoryRefuse('frameCycle');seen.add(cursor.frameId);
   if(cursor.frameId>0&&cursor.frameType==='outermost_frame')throw reconnectInventoryRefuse('inactiveRootParentDenied');
   const parent=byFrame.get(cursor.parentFrameId);if(!parent){if(allowMissingParents){cursor=null;break;}throw reconnectInventoryRefuse('frameParentMissing');}
   if(cursor.parentDocumentId!==undefined&&cursor.parentDocumentId!==parent.documentId)throw reconnectInventoryRefuse('frameParentDocumentMismatch');cursor=parent;
  }
  if(!cursor){result.set(f.frameId,null);continue;}
  if(cursor.frameId!==0&&!(cursor.frameType==='outermost_frame'&&channelShape(cursor.documentId)&&['prerender','cached'].includes(cursor.documentLifecycle)))throw reconnectInventoryRefuse('inactiveRootParentDenied');
  if(cursor.parentDocumentId!==undefined&&cursor.parentDocumentId!==null)throw reconnectInventoryRefuse('frameParentDocumentMismatch');
  result.set(f.frameId,cursor);
 }
 return result;
}
// getAllFrames can straddle a child/parent removal. Reread that tab once within
// the original qualification deadline. Unresolved orphans remain observed,
// non-executable identities; this incomplete tree cannot prove source absence.
async function reconnectTabFrames(tabId,qualification){
 const read=()=>qualification?qualificationRead(qualification,()=>chrome.webNavigation.getAllFrames({tabId})):chrome.webNavigation.getAllFrames({tabId});
 const first=await read();
 const observed=qualification?.orphanFrameEvidence||[];
 if(observed.some(f=>f.tabId===tabId&&(!Array.isArray(first)||!first.some(n=>n.frameId===f.frameId&&n.documentId===f.documentId))))throw reconnectInventoryRefuse('childSourceIdentityUnavailable');
 if(!Array.isArray(first)||!first.length||first.length>200)return first;
 if(!first.every(f=>f&&Number.isSafeInteger(f.frameId)&&Number.isSafeInteger(f.parentFrameId))||!first.some(f=>f.parentFrameId>=0&&!first.some(p=>p.frameId===f.parentFrameId)))return first;
 const forest=reconnectFrameForest(first,true);
 if(![...forest.values()].includes(null))return first;
 if(qualification){
  for(const f of first)if(!forest.get(f.frameId)&&!observed.some(n=>n.tabId===tabId&&n.frameId===f.frameId&&n.documentId===f.documentId))observed.push({tabId,frameId:f.frameId,documentId:f.documentId});
  if(observed.length>200)throw reconnectInventoryRefuse('frameLimitExceeded');
  qualification.orphanFrameEvidence=observed;
 }
 const second=await read();
 if(!Array.isArray(second)||!second.length||second.length>200)return second;
 reconnectFrameForest(second,true);
 // Do not lose a first-read identity merely because the reread omitted it.
 // Retaining the first tree is conservative and later census checks still
 // require the same evidence before any adoption can commit.
 return first.every(f=>second.some(n=>n.frameId===f.frameId&&n.documentId===f.documentId&&n.parentFrameId===f.parentFrameId))?second:first;
}
async function reconnectInternalTabCensus(tab,qualification){
  if(!tab||tab.status!=="complete"||tab.pendingUrl||tab.incognito||tab.discarded)throw reconnectInventoryRefuse("tabURLUnavailable");
  let frames;
  try{frames=await reconnectTabFrames(tab.id,qualification);}catch(error){if(error?.code==='storedFenceMismatch'||error?.code==='inventoryChanged')throw error;throw reconnectInventoryRefuse("frameQueryUnavailable");}
  if(!Array.isArray(frames)||!frames.length||frames.length>200)throw reconnectInventoryRefuse("frameListUnavailable");
  const byFrame=new Map(),documents=new Set();
  for(const f of frames){
    if(!f||!Number.isSafeInteger(f.frameId)||f.frameId<0||byFrame.has(f.frameId)||!Number.isSafeInteger(f.parentFrameId))throw reconnectInventoryRefuse("frameMetadataInvalid");
    if(typeof f.documentId!=="string"||!/^[A-Za-z0-9._:-]{1,128}$/.test(f.documentId)||documents.has(f.documentId))throw reconnectInventoryRefuse("frameDocumentUnavailable");
    reconnectFrameState(f,false,true);
    if(f.errorOccurred!==undefined&&typeof f.errorOccurred!=="boolean")throw reconnectInventoryRefuse("frameMetadataInvalid");
    documents.add(f.documentId);byFrame.set(f.frameId,f);
  }
  const root=byFrame.get(0);
  if(!root||root.parentFrameId!==-1)throw reconnectInventoryRefuse("frameRootMissing");
  if(root.errorOccurred)throw reconnectInventoryRefuse("rootFrameError");
  let rootURL;try{rootURL=new URL(root.url);}catch{throw reconnectInventoryRefuse("tabURLUnavailable");}
  if(rootURL.protocol!=="chrome:"||!rootURL.hostname||rootURL.username||rootURL.password||rootURL.port)throw reconnectInventoryRefuse("tabURLUnavailable");
  const forest=reconnectFrameForest(frames,true);
  return frames.map(f=>({tabId:tab.id,frameId:f.frameId,documentId:f.documentId,parentFrameId:f.parentFrameId,origin:null,executable:false,protected:false,...(!forest.get(f.frameId)?{parentageIncomplete:true}:{}),...(inactiveExecutorFrame(f)?{documentLifecycle:f.documentLifecycle}:{}),...(f.frameType==='fenced_frame'||f.frameId>0&&f.frameType==='outermost_frame'?{frameType:f.frameType}:{})})).sort((a,b)=>a.frameId-b.frameId);
}
async function emptyReconnectInventory(knownTabs,qualification) {
  reconnectInventoryReason="none";
  let tabs;try{tabs=knownTabs===undefined?await chrome.tabs.query({}):knownTabs;}catch{throw reconnectInventoryRefuse("tabQueryUnavailable");}
  if(!Array.isArray(tabs))throw reconnectInventoryRefuse("tabListInvalid");
  if(tabs.length>200)throw reconnectInventoryRefuse("tabLimitExceeded");
  const seen=new Set(),result=[];
  for(const tab of tabs) {
    if(!tab||typeof tab!=='object')throw reconnectInventoryRefuse("tabMetadataInvalid");
    if(!Number.isSafeInteger(tab.id)||tab.id<0)throw reconnectInventoryRefuse("tabIDInvalid");
    if(seen.has(tab.id))throw reconnectInventoryRefuse("tabIDDuplicate");
    if(typeof tab.url!=="string"){await reconnectInternalTabCensus(tab,qualification);throw reconnectInventoryRefuse("nonSetupTab");}
    if(tab.pendingUrl)throw reconnectInventoryRefuse("pendingNavigation");
    if(tab.incognito)throw reconnectInventoryRefuse("incognitoTab");
    if(tab.discarded)throw reconnectInventoryRefuse("discardedTab");
    seen.add(tab.id);
    let url;try{url=new URL(tab.url);}catch{throw reconnectInventoryRefuse("tabURLInvalid");}
    if(tab.url==='chrome://newtab/') {
      // tabs.url is a virtual URL and can conceal an extension override. The
      // browser-owned frame tree must independently exclude every injectable
      // website/extension renderer before treating this tab as setup-only.
      let frames;
      try{frames=await reconnectTabFrames(tab.id,qualification);}catch(error){if(error?.code==='storedFenceMismatch'||error?.code==='inventoryChanged')throw error;throw reconnectInventoryRefuse("frameQueryUnavailable");}
      if(!Array.isArray(frames)||!frames.length)throw reconnectInventoryRefuse("frameListUnavailable");
      if(frames.length>32)throw reconnectInventoryRefuse("frameLimitExceeded");
      const byFrame=new Map();let requiresBindingCensus=false;
      for(const frame of frames){
        if(!frame||typeof frame!=='object')throw reconnectInventoryRefuse("frameMetadataInvalid");
        if(!Number.isSafeInteger(frame.frameId)||frame.frameId<0)throw reconnectInventoryRefuse("frameIDInvalid");
        if(byFrame.has(frame.frameId))throw reconnectInventoryRefuse("frameIDDuplicate");
        if(!Number.isSafeInteger(frame.parentFrameId))throw reconnectInventoryRefuse("frameParentInvalid");
        if(!channelShape(frame.documentId))throw reconnectInventoryRefuse("frameDocumentUnavailable");
        if(frame.errorOccurred&&frame.frameId===0)throw reconnectInventoryRefuse("builtInRootFrameError");
        if(reconnectFrameState(frame,true,true))requiresBindingCensus=true;
        if(frame.frameId===0&&frame.parentFrameId!==-1)throw reconnectInventoryRefuse("frameParentInvalid");
        if(frame.frameId===0&&!['chrome://newtab/','chrome://new-tab-page/'].includes(frame.url))throw reconnectInventoryRefuse("builtInRootURLDenied");
        byFrame.set(frame.frameId,frame);
      }
      const forest=reconnectFrameForest(frames,true);
      for(const frame of frames){
        // Independent inactive page trees are metadata only. Do not parse or
        // publish their potentially unrelated URLs as setup-page authority.
        if(forest.get(frame.frameId)?.frameId!==0){requiresBindingCensus=true;continue;}
        const builtinChild=typeof frame.url==='string'&&frame.url.length<=4096&&(frame.url==='chrome-untrusted://new-tab-page/'||/^chrome-untrusted:\/\/new-tab-page\/one-google-bar(?:\?paramsencoded=[A-Za-z0-9%+/_=-]*)?$/.test(frame.url));
        const opaqueChild=frame.frameId!==0&&['about:blank','about:srcdoc'].includes(frame.url);
        const fencedChild=frame.frameId!==0&&frame.frameType==='fenced_frame';
        if(fencedChild)requiresBindingCensus=true;
        if(frame.frameId!==0&&!builtinChild&&!opaqueChild&&!fencedChild)throw reconnectInventoryRefuse("frameChildURLDenied");
        if(opaqueChild||frame.errorOccurred){reconnectFrameState(frame,false,true);requiresBindingCensus=true;}
      }
      // A failed or opaque built-in child must pass the complete binding/source census;
      // the setup-only shortcut cannot claim an original document absent.
      if(requiresBindingCensus&&knownTabs===undefined)throw reconnectInventoryRefuse("nonSetupTab");
      result.push({tabId:tab.id,url:tab.url,frames:frames.map(frame=>({frameId:frame.frameId,parentFrameId:frame.parentFrameId,documentId:frame.documentId,url:frame.frameType==='fenced_frame'||forest.get(frame.frameId)?.frameId!==0?null:frame.url,...(!forest.get(frame.frameId)?{parentageIncomplete:true}:{}),...(inactiveExecutorFrame(frame)?{documentLifecycle:frame.documentLifecycle}:{}),...(frame.frameType==='fenced_frame'||frame.frameId>0&&frame.frameType==='outermost_frame'?{frameType:frame.frameType}:{})})).sort((a,b)=>a.frameId-b.frameId)});
      continue;
    }
    if(!(url.protocol==="chrome:" && url.hostname==="extensions" || url.protocol==="chrome-extension:" && url.hostname===chrome.runtime.id && url.pathname==="/options.html") || url.username || url.password)throw reconnectInventoryRefuse("nonSetupTab");
    result.push({tabId:tab.id,url:tab.url});
  }
  return JSON.stringify(result.sort((a,b)=>a.tabId-b.tabId));
}
function reconnectJournalValid(value,lastGrant){return reconnectBooleanValidation(()=>reconnectJournalValidInner(value,lastGrant));}
function reconnectJournalValidInner(value,lastGrant) {
  if(value===undefined)return true;
  if(value?.archive!==undefined&&!reconnectArchiveReferenceValid(value.archive,value.history))return false;
  return reconnectJournalCoreValid(reconnectWithoutArchive(value),lastGrant,activeReconnectJournal(value)?value.history:reconnectLogicalHistory(value));
}
function reconnectJournalCoreValid(value,lastGrant,history=value?.history) {
  if(value===undefined)return true;
  try{reconnectCanonical(value);}catch{return false;}
  const fence=reconnectFenceValid;
  const hasRecovery=value?.version>1;
  if(!value || !reconnectCoreKeys(value,hasRecovery) || !reconnectVersionValid(value.version) || value.phase!=="adopted" ||
     typeof value.nonce!=="string" || !/^[a-f0-9]{64}$/.test(value.nonce) || !fence(value.oldFence)||!fence(value.newFence) || !Array.isArray(value.history) ||
     !value.history.length||value.history.length>64||!sameReconnectFence(value.newFence,lastGrant)||value.history.at(-1)?.nonce!==value.nonce) return false;
  if(hasRecovery) {
    const recovery=value.recovery,original=reconnectOriginalPending(recovery);
    if(!reconnectRecoveryShape(recovery) || original?.version!==value.version-1 || !pendingReconnectValid(original,original?.oldFence))return false;
    const originalHistory=reconnectLogicalHistory(original);
    if(history.length<=originalHistory.length || !reconnectHistoryPrefix(history,originalHistory) ||
       history.some(entry=>entry?.nonce===original.nonce) || !sameReconnectFence(history[originalHistory.length]?.oldFence,original.oldFence) || recovery.kind==="emptySetupDocuments"&&history[originalHistory.length]?.executors?.length!==0)return false;
  }
  if(activeReconnectJournal(value)&&!reconnectAuditConsistent(value))return false;
  const lineageNonces=new Set();
  for(let cursor=reconnectOriginalPending(value.recovery);cursor;cursor=reconnectOriginalPending(cursor.recovery)){
    if(lineageNonces.has(cursor.nonce))return false;lineageNonces.add(cursor.nonce);
  }
  if(history.some(entry=>lineageNonces.has(entry?.nonce)))return false;
  const seen=new Set();let prior;
  for(const entry of history) {
    if(!entry||Object.keys(entry).sort().join()!=="executors,newFence,nonce,oldFence"||typeof entry.nonce!=="string"||!/^[a-f0-9]{64}$/.test(entry.nonce)||seen.has(entry.nonce)||
       !fence(entry.oldFence)||!fence(entry.newFence)||entry.oldFence.scopeHash!==entry.newFence.scopeHash||prior&&!sameReconnectFence(prior,entry.oldFence)||
       !Array.isArray(entry.executors)||entry.executors.length>MAX_INVENTORY_DOCUMENTS)return false;
    seen.add(entry.nonce);prior=entry.newFence;
    for(const item of entry.executors){const i=item?.identity;
      if(!item||Object.keys(item).sort().join()!=="identity,receiptCount,receiptRevision"||!i||Object.keys(i).sort().join()!=="browserInstance,documentGeneration,documentId,frameId,profileChannel,tabId"||
        ![i.profileChannel,i.browserInstance,i.documentId].every(channelShape)||!Number.isSafeInteger(i.tabId)||i.tabId<=0||!Number.isSafeInteger(i.frameId)||i.frameId<0||!Number.isSafeInteger(i.documentGeneration)||i.documentGeneration<1||
        !Number.isSafeInteger(item.receiptRevision)||item.receiptRevision<0||item.receiptRevision>512||item.receiptCount!==item.receiptRevision)return false;
    }
  }
  return sameReconnectFence(prior,value.newFence)&&sameReconnectFence(value.history.at(-1).oldFence,value.oldFence)&&new TextEncoder().encode(JSON.stringify(value)).length<=MechanizeProtocol.MAX_BYTES;
}
const reconnectBindingWaiters=new Map();
function receiveReconnectBindings(command){
 if(!['reconnectBindingsResult','reconnectBindingsCommitReady','reconnectBindingsFailure'].includes(command?.type))return false;
 const waiter=reconnectBindingWaiters.get(command.requestId);
 if(waiter&&waiter.port===port){const resolve=waiter.resolve;waiter.resolve=null;resolve?.(command);}return true;
}
function reconnectPendingWireBound(pending){
 reconnectCanonical(pending);
 const largest={type:'reconnectBindings',requestId:'f'.repeat(64),executorChallenge:'x'.repeat(128),brokerEpoch:'x'.repeat(128),channelEpoch:'x'.repeat(128),scopeHash:'f'.repeat(64),deadlineUnixMs:Number.MAX_SAFE_INTEGER,pending};
 if(new TextEncoder().encode(JSON.stringify(largest)).length>MechanizeProtocol.MAX_BYTES)throw reconnectJournalRefuse('historyLimit');
}
async function reconnectBindingSnapshot(journal,command,ownPort,qualification,targetRetirementAttempts){
 if(command.reconnectBindingsVersion!==1)throw reconnectRefuse('executorRefused');
 reconnectPendingWireBound(journal);
 const requestId=Array.from(crypto.getRandomValues(new Uint8Array(32)),b=>b.toString(16).padStart(2,'0')).join('');
 const serialized=JSON.stringify(journal),hash=await crypto.subtle.digest('SHA-256',new TextEncoder().encode(serialized));
 const digest=Array.from(new Uint8Array(hash),b=>b.toString(16).padStart(2,'0')).join('');
 const waiter={port:ownPort,resolve:null};reconnectBindingWaiters.set(requestId,waiter);
 async function next(send){
  let timer;try{return await Promise.race([new Promise(resolve=>{waiter.resolve=resolve;send();}),new Promise((_,reject)=>{timer=setTimeout(()=>reject(reconnectRefuse('deadline')),Math.max(0,qualification.deadline-Date.now()));})]);}finally{clearTimeout(timer);waiter.resolve=null;}
 }
 const cancel=()=>{if(port===ownPort)ownPort.postMessage({type:'reconnectBindingsDone',requestId,complete:false});reconnectBindingWaiters.delete(requestId);};
 qualification.cancelReconnectBindings=cancel;
 try{
  const request={type:'reconnectBindings',requestId,executorChallenge:command.executorChallenge,brokerEpoch:command.brokerEpoch,channelEpoch:command.channelEpoch,scopeHash:command.scopeHash,deadlineUnixMs:qualification.deadline,pending:journal,...(targetRetirementAttempts?{targetRetirementAttempts}:{})};
  if(new TextEncoder().encode(JSON.stringify(request)).length>MechanizeProtocol.MAX_BYTES)throw reconnectJournalRefuse('historyLimit');
  let send=()=>ownPort.postMessage(request);
  const bindings=[];let total,bindingsDigest;
  do{
   const reply=await next(send);
   if(reply?.type==='reconnectBindingsFailure')throw reconnectJournalRefuse('bindingSnapshotUnavailable');
   if(port!==ownPort||reconnectRecordKeys(reply)!=='bindings,bindingsDigest,nextOffset,offset,pendingDigest,requestId,total,type'||reply.type!=='reconnectBindingsResult'||reply.pendingDigest!==digest||
    !Number.isSafeInteger(reply.total)||reply.total<0||reply.total>4096||reply.offset!==bindings.length||!Array.isArray(reply.bindings)||reply.bindings.length>128||reply.nextOffset!==reply.offset+reply.bindings.length||reply.nextOffset>reply.total||reply.nextOffset<reply.total&&!reply.bindings.length||
    !/^[a-f0-9]{64}$/.test(reply.bindingsDigest)||total!==undefined&&(total!==reply.total||bindingsDigest!==reply.bindingsDigest))throw reconnectJournalRefuse('bindingSnapshotUnavailable');
   total=reply.total;bindingsDigest=reply.bindingsDigest;bindings.push(...reply.bindings);
   send=()=>ownPort.postMessage({type:'reconnectBindingsNext',requestId,nextOffset:bindings.length});
  }while(bindings.length<total);
  const encoded=await crypto.subtle.digest('SHA-256',new TextEncoder().encode(JSON.stringify(bindings)));
  if(Array.from(new Uint8Array(encoded),b=>b.toString(16).padStart(2,'0')).join('')!==bindingsDigest)throw reconnectJournalRefuse('bindingSnapshotUnavailable');
  let released=false;return {bindings,digest,release:async()=>{
   if(released)return;
   const ack=await next(()=>ownPort.postMessage({type:'reconnectBindingsDone',requestId,complete:true}));
   if(port!==ownPort||reconnectRecordKeys(ack)!=='complete,requestId,type'||ack.type!=='reconnectBindingsCommitReady'||ack.complete!==true)throw reconnectJournalRefuse('bindingSnapshotUnavailable');
   reconnectBindingWaiters.delete(requestId);qualification.cancelReconnectBindings=null;released=true;
  }};
 }catch(error){cancel();throw error;}
}
// Browser-owned frame metadata, not public DOM inventory, proves exact source
// absence. Every accessible website frame is retained, including protected ones.
// A discarded tab is retained as an unavailable, non-executable owner scope.
// It never supplies document absence for bindings/private records on that tab.
// Keep any browser-provided document IDs so moved sources remain detectable.
async function reconnectDiscardedTabCensus(tab,qualification){
 suspendDiscardedTab(tab);
 let frames;try{frames=await qualificationRead(qualification,()=>chrome.webNavigation.getAllFrames({tabId:tab.id}));}catch{qualificationCurrent(qualification);frames=null;}
 if(frames!==null&&frames!==undefined&&!Array.isArray(frames))throw reconnectInventoryRefuse('frameListUnavailable');
 frames=frames||[];if(frames.length>200)throw reconnectInventoryRefuse('frameLimitExceeded');
 const result=[{tabId:tab.id,discarded:true,identityUnknown:true,origin:null,executable:false,protected:false}],ids=new Set();
 for(const frame of frames){
  if(!frame||!Number.isSafeInteger(frame.frameId)||frame.frameId<0||ids.has(frame.frameId))throw reconnectInventoryRefuse('frameIDInvalid');ids.add(frame.frameId);
  if(!Number.isSafeInteger(frame.parentFrameId)||frame.frameId===0&&frame.parentFrameId!==-1)throw reconnectInventoryRefuse('frameParentInvalid');
  if(!channelShape(frame.documentId))throw reconnectInventoryRefuse('frameDocumentUnavailable');
  result.push({tabId:tab.id,frameId:frame.frameId,parentFrameId:frame.parentFrameId,documentId:frame.documentId,origin:null,executable:false,protected:false,discarded:true});
 }
 if(frames.length)reconnectFrameForest(frames);
 return result;
}
async function reconnectCurrentCensus(enrollment,qualification){
 const tabs=await qualificationRead(qualification,()=>chrome.tabs.query({}));
 if(!Array.isArray(tabs)||tabs.length>200)throw reconnectInventoryRefuse('tabLimitExceeded');
 const result=[],seen=new Set();
 for(const tab of tabs){
  if(!tab||!Number.isSafeInteger(tab.id)||tab.id<1||seen.has(tab.id))throw reconnectInventoryRefuse('tabIDInvalid');seen.add(tab.id);
  if(tab.discarded!==undefined&&typeof tab.discarded!=='boolean')throw reconnectInventoryRefuse('tabMetadataInvalid');
  if(tab.incognito||tab.pendingUrl)throw reconnectInventoryRefuse(tab.pendingUrl?'pendingNavigation':'incognitoTab');
  if(tab.discarded===true){result.push(...await reconnectDiscardedTabCensus(tab,qualification));continue;}
  if(typeof tab.url!=='string'){result.push(...await reconnectInternalTabCensus(tab,qualification));continue;}
  if(tab.incognito||tab.discarded||tab.pendingUrl)throw reconnectInventoryRefuse(tab.pendingUrl?'pendingNavigation':tab.incognito?'incognitoTab':'discardedTab');
  let url;try{url=new URL(tab.url);}catch{throw reconnectInventoryRefuse('tabURLInvalid');}
  if(url.username||url.password)throw reconnectInventoryRefuse('tabURLInvalid');
  const setup=url.protocol==='chrome:'&&url.hostname==='extensions'||url.protocol==='chrome-extension:'&&url.hostname===chrome.runtime.id&&url.pathname==='/options.html';
  if(setup||tab.url==='chrome://newtab/'){
   const proof=await emptyReconnectInventory([tab],qualification);result.push({tabId:tab.id,setup:proof});
   // Preserve browser-owned child identities as well as the root: matching a
   // retained source anywhere in this tree is presence, never absence.
   for(const frame of JSON.parse(proof)[0]?.frames||[])result.push({tabId:tab.id,frameId:frame.frameId,documentId:frame.documentId,parentFrameId:frame.parentFrameId,origin:null,executable:false,protected:false,...(frame.parentageIncomplete?{parentageIncomplete:true}:{}),...(frame.documentLifecycle?{documentLifecycle:frame.documentLifecycle}:{}),...(frame.frameType?{frameType:frame.frameType}:{})});
   continue;
  }
  if(!['http:','https:'].includes(url.protocol))throw reconnectInventoryRefuse('tabSchemeDenied');
  const frames=await reconnectTabFrames(tab.id,qualification);
  if(!Array.isArray(frames)||!frames.length||frames.length>200)throw reconnectInventoryRefuse('frameListUnavailable');
  const forest=reconnectFrameForest(frames,true);
  const frameIDs=new Set();let roots=0;
  for(const f of frames){
   if(!f||!Number.isSafeInteger(f.frameId)||f.frameId<0||frameIDs.has(f.frameId))throw reconnectInventoryRefuse('frameDocumentUnavailable');frameIDs.add(f.frameId);
   if(f.errorOccurred!==undefined&&typeof f.errorOccurred!=='boolean')throw reconnectInventoryRefuse('frameMetadataInvalid');
   const failedChild=f.frameId!==0&&f.errorOccurred===true,knownDocument=channelShape(f.documentId);
   if(!knownDocument&&!failedChild)throw reconnectInventoryRefuse('frameDocumentUnavailable');
   if(f.errorOccurred&&f.frameId===0)throw reconnectInventoryRefuse('rootFrameError');
   const inactiveChild=reconnectFrameState(f,false,true);
   if(!Number.isSafeInteger(f.parentFrameId))throw reconnectInventoryRefuse('frameParentInvalid');
   if(!forest.get(f.frameId)){
    result.push({tabId:tab.id,frameId:f.frameId,documentId:knownDocument?f.documentId:null,parentFrameId:f.parentFrameId,origin:null,executable:false,protected:false,parentageIncomplete:true,identityUnknown:!knownDocument});continue;
   }
   if(failedChild){
    // A failed child remains a census entry. It can never receive an executor.
    // Missing identity is explicit and later prevents any source-absence proof
    // that could depend on this frame; a healthy unrelated root is not dropped.
    result.push({tabId:tab.id,frameId:f.frameId,documentId:knownDocument?f.documentId:null,parentFrameId:f.parentFrameId,origin:null,executable:false,protected:false,frameError:true,identityUnknown:!knownDocument});
    continue;
   }
   if(forest.get(f.frameId).frameId!==0){
    result.push({tabId:tab.id,frameId:f.frameId,documentId:f.documentId,parentFrameId:f.parentFrameId,origin:null,executable:false,protected:false,frameType:f.frameType,documentLifecycle:f.documentLifecycle,inactivePageRoot:forest.get(f.frameId).documentId});continue;
   }
   if(f.frameType==='fenced_frame'){
    // A known fenced child is observed, never injectable. Its exact identity
    // remains in every source-presence comparison even when URL is opaque.
    result.push({tabId:tab.id,frameId:f.frameId,documentId:f.documentId,parentFrameId:f.parentFrameId,origin:null,executable:false,protected:false,frameType:'fenced_frame',documentLifecycle:f.documentLifecycle});continue;
   }
   const prefix=f.frameId===0?'rootFrame':'childFrame';
   let frameURL;try{frameURL=new URL(f.url);}catch{throw reconnectInventoryRefuse(prefix+'URLInvalid');}
   if(frameURL.username||frameURL.password)throw reconnectInventoryRefuse(prefix+'UserinfoDenied');
   const web=['http:','https:'].includes(frameURL.protocol),executable=web&&!inactiveChild;
   // An active opaque/non-web child is still a real document in the census.
   // Retain its exact browser identity/parentage without injecting an executor,
   // inventing an origin, or treating an old source in that frame as absent.
   if(!executable&&f.frameId===0)throw reconnectInventoryRefuse('rootFrameSchemeDenied');
   if(web&&!(enrollment.allWebsites===true||(enrollment.origins||[]).includes(frameURL.origin)))throw reconnectInventoryRefuse(prefix+'OriginNotGranted');
   if(f.frameId===0){roots++;if(f.parentFrameId!==-1)throw reconnectInventoryRefuse('frameParentInvalid');if(frameURL.origin!==url.origin)throw reconnectInventoryRefuse('rootTabOriginMismatch');}
   result.push({tabId:tab.id,frameId:f.frameId,documentId:f.documentId,parentFrameId:f.parentFrameId,origin:web?frameURL.origin:null,executable,...(inactiveChild?{documentLifecycle:f.documentLifecycle}:{}),protected:web&&isProtectedURL(f.url,{profileChannel:enrollment.profileChannel,browserInstance:enrollment.browserInstance,tabId:tab.id,frameId:f.frameId,documentId:f.documentId})});
  }
  if(roots!==1)throw reconnectInventoryRefuse('frameRootMissing');

 }
 if(result.length>200)throw reconnectInventoryRefuse('frameLimitExceeded');
 return result.sort((a,b)=>a.tabId-b.tabId||(a.frameId??-1)-(b.frameId??-1));
}
function reconnectRows(rows,enrollment,scopeHash){
 const ids=new Set();for(const row of rows){const i=row?.identity,f=row?.fence;
  if(!['attemptId,dispatchState,fence,fingerprintSHA256,identity','attemptId,controlLease,dispatchState,fence,fingerprintSHA256,identity'].includes(reconnectRecordKeys(row))||row.controlLease!==undefined&&(reconnectRecordKeys(row.controlLease)!=='generation,id'||!channelShape(row.controlLease.id)||!Number.isSafeInteger(row.controlLease.generation)||row.controlLease.generation<1)||reconnectRecordKeys(i)!=='browserInstance,documentGeneration,documentId,frameId,profileChannel,tabId'||
   i.profileChannel!==enrollment.profileChannel||i.browserInstance!==enrollment.browserInstance||!channelShape(i.documentId)||!Number.isSafeInteger(i.tabId)||i.tabId<1||i.frameId!==0||!Number.isSafeInteger(i.documentGeneration)||i.documentGeneration<1||
   !reconnectFenceValid(f)||f.scopeHash!==scopeHash||!/^[a-f0-9]{64}$/.test(row.attemptId)||!/^[a-f0-9]{64}$/.test(row.fingerprintSHA256)||!['dispatched','notDispatched','unknown'].includes(row.dispatchState)||ids.has(row.attemptId))throw reconnectJournalRefuse('bindingSnapshotUnavailable');
  ids.add(row.attemptId);
 }return rows;
}
async function reconnectRendererReceipts(identity,fence,deadline){
 let first,offset=0;const rows=[];
 do{
  const request={requestId:'reconnect-export-'+offset,action:'executor.receipts',identity,...fence,deadlineUnixMs:deadline,args:{offset,limit:64,...(first?{expectedRevision:first.revision}:{})}};
  let timer,page;try{page=await Promise.race([chrome.tabs.sendMessage(identity.tabId,request,{documentId:identity.documentId}),new Promise((_,reject)=>{timer=setTimeout(()=>reject(reconnectRefuse('deadline')),Math.max(0,deadline-Date.now()));})]);}finally{clearTimeout(timer);}
  // The preceding closed inspect proved this document pristine if no binding
  // exists. A live durable attempt is still rejected below for missing receipt.
  if(!first&&page?.error?.code==='notEnrolled')return {revision:0,rows:[]};
  if(page?.error||page?.version!==2||!page.identity||['profileChannel','browserInstance','tabId','frameId','documentId'].some(k=>page.identity[k]!==identity[k])||
    !Number.isSafeInteger(page.total)||page.total<0||page.total>512||page.revision!==page.total||page.offset!==offset||!Array.isArray(page.receipts)||page.receipts.length>64||page.nextOffset!==offset+page.receipts.length||page.nextOffset>page.total||page.truncated!==(page.nextOffset<page.total)||page.truncated&&!page.receipts.length||
    first&&(first.total!==page.total||first.revision!==page.revision||reconnectCanonical(first.readiness)!==reconnectCanonical(page.readiness)))throw reconnectRefuse('executorRefused');
  first||=page;rows.push(...page.receipts);offset=page.nextOffset;
 }while(offset<first.total);
 return {revision:first.revision,rows};
}
async function reconnectReceiptSnapshot(){
 const session=await chrome.storage.session.get(null),durable=await playwrightWorker.journalSnapshot();
 for(const key of Object.keys(session))if(key.startsWith('playwrightAttempt:'))delete session[key];
 return {...session,...durable};
}
async function reconnectMatchReceipts(rows,census,renderer,session){
 const key=i=>`${i.tabId}:${i.frameId}:${i.documentId}`,live=new Set(census.filter(x=>x.documentId).map(x=>x.documentId)),byAttempt=new Map(rows.map(r=>[r.attemptId,r])),receipts=new Map();
 const add=(identity,r,fence)=>{const b=byAttempt.get(r?.attemptId);
  if(!b||key(b.identity)!==key(identity)||fence&&!sameReconnectFence(b.fence,fence)||r.fingerprintVersion!==2||r.fingerprintSHA256!==b.fingerprintSHA256||!['dispatched','notDispatched','unknown'].includes(r.dispatchState)||r.dispatchState!==b.dispatchState||(r.dispatchState==='unknown'?r.effectState!=='unknown'||!currentRetiredUnknown(r.attemptId)||live.has(identity.documentId):r.effectState==='unknown')||r.errorDispatchState&&r.errorDispatchState!==r.dispatchState||receipts.has(r.attemptId))throw reconnectRefuse('unknownReceipts');
  receipts.set(r.attemptId,true);
 };
 for(const x of renderer)for(const r of x.export.rows)add(x.identity,r);
 for(const [k,record] of Object.entries(session))if(k.startsWith('playwrightAttempt:')){
  if(record?.phase!=='done'||!record.receipt||k!=='playwrightAttempt:'+record.attemptId)throw reconnectRefuse('unknownReceipts');
  add(record.identity,record.receipt,reconnectFence(record));
 }
 const missing=new Map();for(const row of rows)if(live.has(row.identity.documentId)&&!receipts.has(row.attemptId))missing.set(key(row.identity),row.identity);
 if(missing.size){
  const hashes=await Promise.all([...missing.values()].map(async i=>{const bytes=new TextEncoder().encode(JSON.stringify(['mechanize.reconnect.missing-document.v1',i.profileChannel,i.browserInstance,i.tabId,i.frameId,i.documentId]));const digest=await crypto.subtle.digest('SHA-256',bytes);return Array.from(new Uint8Array(digest),b=>b.toString(16).padStart(2,'0')).join('');}));
  reconnectMissingDocuments=[...missing.values()].map(i=>({tabId:i.tabId,frameId:i.frameId,documentId:i.documentId}));
  reconnectMissingReceiptSources={version:1,count:missing.size,hashes:hashes.sort().slice(0,16),truncated:missing.size>16};
  reconnectRecoveryDiagnostic.missingLiveReceipts=missing.size;throw reconnectRefuse('unknownReceipts');
 }
 // Absent original documents cannot execute. Their original ledger outcomes
 // and journal receipts remain untouched; absence never proves business success.
}
async function prepareNativeReconnect(previous,candidate,enrollment,command,ownPort,qualification) {
  reconnectDiagnosticPhase = "scope"; reconnectDiagnosticReason = "none";reconnectInventoryReason="none";reconnectJournalDiagnostic=null;reconnectRecoveryDiagnostic=null;reconnectMissingReceiptSources=null;reconnectMissingDocuments=[];
  if(!ownPort || reconnectPorts.has(ownPort) || qualifiedNativePorts.has(ownPort) || command.type!=="processQualified" || command.fixtureOnly!==false ||
    previous.leaseRequired!==true || previous.mutationFingerprintVersion!==2 || candidate.mutationFingerprintVersion!==2 ||
    previous.scopeHash!==candidate.scopeHash || previous.trustScope!==candidate.trustScope || previous.scopeQualified!==true ||
    previous.profileQualified!==candidate.profileQualified || !fenceKeys.every(k=>channelShape(previous[k])&&channelShape(candidate[k])) ||
    !/^[a-f0-9]{64}$/.test(previous.scopeHash))throw reconnectRefuse("scopeChanged");
  reconnectPorts.add(ownPort);reconnectBusy=true;
  const deadline=qualification?.deadline||Date.now()+10000,nonce=Array.from(crypto.getRandomValues(new Uint8Array(32)),b=>b.toString(16).padStart(2,"0")).join("");
  const scope=reconnectCanonical(enrollment),oldFence=reconnectFence(previous),newFence=reconnectFence(candidate);
  // Origin quarantine survives reconnect. It blocks document access, not the
  // metadata transport; active or uncertain private operations still block it.
  const quarantine = JSON.stringify([...protectedOrigins].sort());
  function retainedQuarantine(value) {
    if (value === undefined) return true;
    if (!Array.isArray(value) || value.length > 256 || new Set(value).size !== value.length ||
        value.some(origin => typeof origin !== "string" || !origin.startsWith("https://") || (() => { try { return new URL(origin).origin !== origin; } catch { return true; } })())) return false;
    return JSON.stringify([...value].sort()) === quarantine;
  }
  function current() {
    if(port!==ownPort)throw reconnectRefuse("portChanged");
    if(Date.now()>=deadline)throw reconnectRefuse("deadline");
    if(mutationBusy || setupActiveCommands!==1)throw reconnectRefuse("busy");
    if(unknownAttempts.size)throw reconnectRefuse("unknownReceipts");
    if(lifecycleGuardId)throw reconnectRefuse("lifecycle");
    if(privatePending || privateAdmission || privateFlow || privatePrivacy || privateRedactions.length || JSON.stringify([...protectedOrigins].sort())!==quarantine || ownPort===privateSilencedPort)throw reconnectRefuse("privateProtection");
  }
  let quarantineStorage;
  async function barriers() {
    current();await revalidateRetiredUnknownTargets(current);if(reconnectCanonical(await reconnectStorage(()=>config(),qualification))!==scope)throw reconnectRefuse("scopeChanged");
    const session=await reconnectStorage(()=>chrome.storage.session.get(null),qualification),durable=await reconnectStorage(()=>chrome.storage.local.get("mechanizeProtectedOrigins"),qualification),retired=await reconnectStorage(()=>chrome.storage.local.get(MechanizeRetirement.KEY),qualification);
    if(session.mechanizeLifecycleInhibited || retired[MechanizeRetirement.KEY]!==undefined)throw reconnectRefuse("lifecycle");
    if(!retainedQuarantine(session.mechanizeProtectedOrigins) || !retainedQuarantine(durable.mechanizeProtectedOrigins) ||
       quarantine!=="[]" && session.mechanizeProtectedOrigins===undefined && durable.mechanizeProtectedOrigins===undefined)throw reconnectRefuse("privateProtection");
    const retained = reconnectCanonical({session:session.mechanizeProtectedOrigins??null,durable:durable.mechanizeProtectedOrigins??null});
    if(quarantineStorage!==undefined && retained!==quarantineStorage)throw reconnectRefuse("privateProtection");
    quarantineStorage=retained;
    const attempts=new Set(Object.keys(session).filter(k=>k.startsWith("browserIntent:")||k.startsWith("browserReceipt:")).map(k=>k.slice(k.indexOf(":")+1)));
    for(const attempt of attempts) {
      if(!session["browserIntent:"+attempt])throw reconnectRefuse("unknownReceipts");
      const receipt=session["browserReceipt:"+attempt],state=receipt?.dispatchState??receipt?.error?.dispatchState;
      if(!["dispatched","notDispatched"].includes(state)||receipt?.effectState==="unknown"||receipt?.error?.dispatchState==="unknown"||receipt?.error?.effectState==="unknown")throw reconnectRefuse("unknownReceipts");
    }
    current();
  }
  reconnectDiagnosticPhase = "barriers";
  await barriers();
  reconnectDiagnosticPhase = "journal";
  const stored=await reconnectStorage(()=>chrome.storage.local.get(reconnectKey),qualification);let journal=stored[reconnectKey];
  captureReconnectJournal(journal,previous);
  await verifyReconnectArchives(journal,qualification);
  const recovering=pendingReconnectValid(journal,previous);
  if(recovering && sameReconnectFence(previous,candidate))throw reconnectRefuse("scopeChanged");
  if(!recovering&&!reconnectJournalValid(journal,previous))throw reconnectJournalRefuse("lineageInvalid");
  if(recovering)reconnectDiagnosticPhase="inventory";
  let recoveryInventory=null,recoveryBinding=null,recoveryCensus=null,recoverySession=null;
  if(recovering||qualification.retirementSnapshot){
    try{if(qualification.retirementSnapshot){reconnectInventoryReason="nonSetupTab";throw reconnectRefuse("inventoryChanged");}recoveryInventory=await emptyReconnectInventory(undefined,qualification);}
    catch(error){
      if(!["nonSetupTab","discardedTab"].includes(reconnectInventoryReason)||command.reconnectBindingsVersion!==1)throw error;
      reconnectRecoveryDiagnostic={missingLiveReceipts:0,unknownLiveReceipts:0,unavailableExecutors:0,privateSources:0};
      recoveryBinding=qualification.retirementSnapshot||await reconnectBindingSnapshot(journal,command,ownPort,qualification);
      reconnectRows(recoveryBinding.bindings,enrollment,previous.scopeHash);
      recoveryCensus=await reconnectCurrentCensus(enrollment,qualification);
      recoverySession=await reconnectStorage(reconnectReceiptSnapshot,qualification);
      const unknown=new Set(),privateSources=new Set(),unavailable=new Set();
      const discardedTabs=new Set(recoveryCensus.filter(i=>i.discarded&&i.identityUnknown).map(i=>i.tabId));
      for(const row of recoveryBinding.bindings){
       const source=recoveryCensus.find(i=>i.documentId===row.identity.documentId),discarded=discardedTabs.has(row.identity.tabId)?row.identity.tabId:source?.discarded?source.tabId:null;
       if(discarded!==null){const key='discarded:'+discarded;unavailable.add(key);if(row.dispatchState==='unknown')unknown.add(key);}
       else if(source){if(row.dispatchState==='unknown')unknown.add(source.documentId);if(source.protected)privateSources.add(source.documentId);if(!source.executable||source.tabId!==row.identity.tabId||source.frameId!==row.identity.frameId)unavailable.add(source.documentId);}
      }
      for(const record of protectionScopes.records())if(record.identity.profileChannel===enrollment.profileChannel&&record.identity.browserInstance===enrollment.browserInstance){
       const tabId=discardedTabs.has(record.identity.tabId)?record.identity.tabId:recoveryCensus.find(i=>i.discarded&&i.documentId===record.identity.documentId)?.tabId;
       if(tabId!==undefined){privateSources.add('discarded:'+tabId);unavailable.add('discarded:'+tabId);}
      }
      reconnectRecoveryDiagnostic.unknownLiveReceipts=Math.min(200,unknown.size);reconnectRecoveryDiagnostic.privateSources=Math.min(200,privateSources.size);reconnectRecoveryDiagnostic.unavailableExecutors=Math.min(200,unavailable.size);
      // Generic unidentified children retain the existing global absence guard.
      // Discarded markers instead deny every retained owner on that exact tab.
      const unidentified=recoveryCensus.filter(i=>i.identityUnknown&&!i.discarded),knownIDs=new Set(recoveryCensus.filter(i=>i.documentId).map(i=>i.documentId));
      if(unidentified.length&&recoveryBinding.bindings.some(row=>!knownIDs.has(row.identity.documentId))){reconnectRecoveryDiagnostic.unavailableExecutors=unidentified.length;throw reconnectInventoryRefuse('childSourceIdentityUnavailable');}
      const incompleteTabs=new Set(recoveryCensus.filter(i=>i.parentageIncomplete).map(i=>i.tabId));
      const absentOnIncompleteTab=i=>incompleteTabs.has(i.tabId)&&!knownIDs.has(i.documentId);
      if(recoveryBinding.bindings.some(row=>absentOnIncompleteTab(row.identity))||protectionScopes.records().some(record=>record.identity.profileChannel===enrollment.profileChannel&&record.identity.browserInstance===enrollment.browserInstance&&absentOnIncompleteTab(record.identity))){
       reconnectRecoveryDiagnostic.unavailableExecutors=Math.min(200,Math.max(1,unavailable.size));throw reconnectInventoryRefuse('childSourceIdentityUnavailable');
      }
      if(privateSources.size)throw reconnectRefuse('privateProtection');if(unknown.size)throw reconnectRefuse('unknownReceipts');if(unavailable.size)throw reconnectRefuse('executorRefused');
      reconnectInventoryReason="none";
    }
  }
  const originalJournal=reconnectCanonical(journal);
  async function recoveryCheck(afterCommit=false) {
    await barriers();await verifyReconnectArchives(journal,qualification);await verifyReconnectArchives(pending,qualification);
    if(recovering||recoveryBinding) {
      if(recoveryBinding){
        if(reconnectCanonical(await reconnectCurrentCensus(enrollment,qualification))!==reconnectCanonical(recoveryCensus))throw reconnectInventoryRefuse("inventoryDrift");
        if(reconnectCanonical(await reconnectStorage(reconnectReceiptSnapshot,qualification))!==reconnectCanonical(recoverySession))throw reconnectRefuse("unknownReceipts");
      }else if(await emptyReconnectInventory(undefined,qualification)!==recoveryInventory)throw reconnectInventoryRefuse("inventoryDrift");
      if(reconnectCanonical((await reconnectStorage(()=>chrome.storage.local.get("lastGrant"),qualification)).lastGrant)!==reconnectCanonical(afterCommit?candidate:previous))throw reconnectRefuse("journalChanged");
    }
    current();
  }
  reconnectDiagnosticPhase = "inventory";
  const snapshot=await inventory(enrollment,qualification);
  if(snapshot.truncated || snapshot.documents.length>MAX_INVENTORY_DOCUMENTS)throw reconnectInventoryRefuse("frameLimitExceeded");
  const stable=items=>JSON.stringify(items.map(i=>({tabId:i.tabId,frameId:i.frameId,documentId:i.documentId,origin:i.origin})).sort((a,b)=>a.tabId-b.tabId||a.frameId-b.frameId));
  const inventoryKey=stable(snapshot.documents);
  const sourceInventory={version:1,kind:"eligibleDocuments",documents:snapshot.documents.map(item=>Object.fromEntries(["profileChannel","browserInstance","tabId","frameId","documentId","documentGeneration","origin"].map(key=>[key,item[key]])))};
  if(!reconnectSourceInventoryValid(sourceInventory))throw reconnectInventoryRefuse('frameMetadataInvalid');
  const audit=await archiveReconnectAudit(journal,previous,barriers,qualification);
  const candidateFences=[oldFence,newFence];
  if(activeReconnectJournal(journal)&&journal.phase==='pending')candidateFences.push(...journal.recoveryFences);
  else for(let cursor=journal;cursor;cursor=reconnectOriginalPending(cursor.recovery))candidateFences.push(cursor.oldFence,cursor.newFence);
  const uniqueFences=items=>[...new Map(items.map(f=>[reconnectCanonical(f),reconnectFence(f)])).values()];
  let pending={format:'activeHandoff',sourceInventory,version:1,phase:"pending",nonce,oldFence,newFence,history:[],recoveryFences:uniqueFences(candidateFences),...(audit?{audit}:{})};
  // Reserve the largest permitted adoption proof BEFORE writing pending or
  // asking any renderer to retire/adopt. The actual generation/counts can grow
  // during preparation, but their numeric bounds cannot exceed this budget.
  const committedBudget=record=>({...record,phase:'adopted',history:[...record.history,{nonce,oldFence,newFence,executors:snapshot.documents.map(item=>({identity:{...Object.fromEntries(['profileChannel','browserInstance','tabId','frameId','documentId'].map(key=>[key,item[key]])),documentGeneration:Number.MAX_SAFE_INTEGER},receiptRevision:512,receiptCount:512}))}]});
  const checkCandidateBudget=()=>{reconnectPendingWireBound(pending);reconnectCanonical(committedBudget(pending));};
  checkCandidateBudget();
  if(!pendingReconnectValid(pending,previous))throw reconnectJournalRefuse("lineageInvalid");
  await verifyReconnectArchives(pending,qualification);
  if(!reconnectJournalValid(committedBudget(pending),candidate))throw reconnectJournalRefuse('lineageInvalid');
  const proofs=[];
  async function exchange(identity,phase,revision,sourceFence=oldFence,allowRefusal=false) {
    await barriers();
    const newBinding={identity,...newFence,leaseRequired:true,mutationFingerprintVersion:2};
    const request={type:"brokerReconnect",phase,nonce,deadlineUnixMs:deadline,oldFence:sourceFence,newBinding,...(phase==="adopt"?{receiptRevision:revision}:{})};
    let timer,result;
    try { result=await Promise.race([chrome.tabs.sendMessage(identity.tabId,request,{documentId:identity.documentId}),new Promise((_,reject)=>{timer=setTimeout(()=>reject(reconnectFail()),Math.max(0,deadline-Date.now()));})]); }
    catch {throw reconnectRefuse(Date.now()>=deadline?"deadline":"rendererUnavailable");}
    finally {clearTimeout(timer);}
    if(result?.error){if(allowRefusal)return null;throw reconnectRefuse("executorRefused");}
    current();
    if(phase==="inspect") {
      if(!result || Object.keys(result).sort().join()!=="identity,nonce,phase,version" || result.version!==1 || result.phase!=="inspected" || result.nonce!==nonce)throw reconnectRefuse('executorRefused');
      if(!result.identity || ["profileChannel","browserInstance","tabId","frameId","documentId"].some(k=>result.identity[k]!==identity[k]))throw reconnectRefuse('documentChanged');
      return result;
    }
    if(!result || Object.keys(result).sort().join()!=="identity,nonce,phase,quiescent,receiptCount,receiptRevision" || result.nonce!==nonce ||
       result.phase!==(phase==="prepare"?"prepared":"adopted") || result.quiescent!==true)throw reconnectRefuse('executorRefused');
    if(!result.identity || Object.keys(result.identity).sort().join()!=="browserInstance,documentGeneration,documentId,frameId,profileChannel,tabId" ||
       ["profileChannel","browserInstance","tabId","frameId","documentId"].some(k=>result.identity[k]!==identity[k]) ||
       !Number.isSafeInteger(result.identity.documentGeneration)||result.identity.documentGeneration<1)throw reconnectRefuse('documentChanged');
    if(!Number.isSafeInteger(result.receiptRevision)||result.receiptRevision<0||result.receiptRevision>512||result.receiptCount!==result.receiptRevision)throw reconnectRefuse('unknownReceipts');
    return result;
  }
  const recoveryRenderers=[],currentFences=[];
  reconnectDiagnosticPhase = "inspect";
  for(const item of snapshot.documents) {
    const identity=Object.fromEntries(["profileChannel","browserInstance","tabId","frameId","documentId","documentGeneration"].map(key=>[key,item[key]]));
    try {await chrome.scripting.executeScript({target:{tabId:identity.tabId,documentIds:[identity.documentId]},world:"ISOLATED",files:["protocol.js","fingerprint.js","accessibility-provider.js","dom.js","recorder.js","secure-input.js","content.js"]});}
    catch (error) {throw reconnectRefuse(injectionFailureReason(error));}
    if(recoveryBinding){
      const fences=[oldFence,...recoveryBinding.bindings.filter(r=>r.identity.tabId===identity.tabId&&r.identity.documentId===identity.documentId).map(r=>r.fence),...candidateFences];
      const unique=[...new Map(fences.map(f=>[reconnectCanonical(f),f])).values()];
      let selected;
      for(const fence of unique){if(sameReconnectFence(fence,newFence))continue;if(await exchange(identity,"inspect",undefined,fence,true)){selected=fence;break;}}
      if(!selected){reconnectRecoveryDiagnostic.unavailableExecutors++;throw reconnectRefuse("executorRefused");}
      currentFences.push(selected);
      recoveryRenderers.push({identity,fence:selected,export:await reconnectRendererReceipts(identity,selected,deadline)});
    }else{await exchange(identity,"inspect");currentFences.push(oldFence);}
  }
  if(recoveryBinding)await reconnectMatchReceipts(recoveryBinding.bindings,recoveryCensus,recoveryRenderers,recoverySession);
  // Keep only fences actually witnessed on current documents plus this new
  // candidate. Failed historical candidates remain immutable audit evidence.
  pending.recoveryFences=uniqueFences([...currentFences,newFence]);
  reconnectDiagnosticPhase = "barriers";
  await barriers();
  await recoveryCheck();
  if(reconnectCanonical((await reconnectStorage(()=>chrome.storage.local.get(reconnectKey),qualification))[reconnectKey])!==originalJournal)throw reconnectRefuse("journalChanged");
  await reconnectStorage(()=>chrome.storage.local.set({[reconnectKey]:pending}));
  if(reconnectCanonical((await reconnectStorage(()=>chrome.storage.local.get(reconnectKey),qualification))[reconnectKey])!==reconnectCanonical(pending))throw reconnectRefuse("journalChanged");
  reconnectDiagnosticPhase = "prepare";
  for(const item of snapshot.documents) {
    const identity=Object.fromEntries(["profileChannel","browserInstance","tabId","frameId","documentId","documentGeneration"].map(key=>[key,item[key]]));
    const source=recoveryRenderers.find(r=>r.identity.tabId===identity.tabId&&r.identity.documentId===identity.documentId),fence=source?.fence||oldFence;
    const proof=await exchange(identity,"prepare",undefined,fence);
    if(source&&proof.receiptRevision!==source.export.revision)throw reconnectRefuse("unknownReceipts");
    proofs.push({identity,proof,fence});
  }
  const fresh=await inventory(enrollment,qualification);if(fresh.truncated||stable(fresh.documents)!==inventoryKey)throw reconnectInventoryRefuse("inventoryDrift");
  reconnectDiagnosticPhase = "adopt";
  for(const item of proofs) {
    const {identity,proof,fence}=item,adopted=await exchange(identity,"adopt",proof.receiptRevision,fence);
    // Mutation generation may advance while the executor is quiesced. The
    // document, prepared binding and receipt revision may not change. Adoption
    // publishes the current generation; it never transfers the retired lease.
    if(["profileChannel","browserInstance","tabId","frameId","documentId"].some(k=>adopted.identity[k]!==proof.identity[k])||
       adopted.identity.documentGeneration<proof.identity.documentGeneration)throw reconnectRefuse('documentChanged');
    if(adopted.receiptRevision!==proof.receiptRevision||adopted.receiptCount!==proof.receiptCount)throw reconnectRefuse('unknownReceipts');
    item.proof=adopted;
  }
  const history=[...pending.history,{nonce,oldFence,newFence,executors:proofs.map(({proof})=>({identity:proof.identity,receiptRevision:proof.receiptRevision,receiptCount:proof.receiptCount}))}];
  const committed={...pending,phase:"adopted",history,recoveryFences:[newFence]};
  reconnectCanonical(committed); // Preserve the finite resource-budget cause.
  if(!reconnectJournalValid(committed,candidate))throw reconnectJournalRefuse('lineageInvalid');
  await recoveryCheck();const final=await inventory(enrollment,qualification);if(final.truncated||stable(final.documents)!==inventoryKey)throw reconnectInventoryRefuse('inventoryDrift');
  for(const {proof} of proofs){const key=`${proof.identity.tabId}:${proof.identity.documentId}`;documents.set(key,proof.identity);documentControlLeases.delete(key);inactiveLeaseDocuments.delete(key);documentFingerprintVersions.set(key,2);documentOrigins.set(key,snapshot.documents.find(i=>i.tabId===proof.identity.tabId&&i.documentId===proof.identity.documentId).origin);}
  reconnectDiagnosticPhase = "commit";
  if(recovering) {
    await recoveryCheck();
    if(reconnectCanonical((await reconnectStorage(()=>chrome.storage.local.get(reconnectKey),qualification))[reconnectKey])!==reconnectCanonical(pending))throw reconnectRefuse("journalChanged");
  }
  if(recovering||recoveryBinding||committed.archive||committed.recovery||committed.audit)reconnectRecoveryChecks.set(committed,async afterCommit=>{
    await recoveryCheck(afterCommit);
    if(reconnectCanonical((await reconnectStorage(()=>chrome.storage.local.get(reconnectKey),qualification))[reconnectKey])!==reconnectCanonical(afterCommit?committed:pending))throw reconnectRefuse("journalChanged");
    current();
  });
  reconnectPendingRecords.set(committed,{pending:freezeReconnectJSON(JSON.parse(JSON.stringify(pending))),previous:freezeReconnectJSON(JSON.parse(JSON.stringify(previous)))});
  if(recoveryBinding)qualification.releaseReconnectBindings=recoveryBinding.release;
  qualification.recoveryUsesCurrentDocuments=Boolean(recoveryBinding);
  return committed;
}
async function restoreOwnedReconnectPending(committed,candidate,qualification){
 const original=reconnectPendingRecords.get(committed);if(!original)return;
 qualificationCurrent(qualification);
 const stored=await qualificationRead(qualification,()=>chrome.storage.local.get([reconnectKey,'lastGrant']));
 qualificationCurrent(qualification);
 if(reconnectCanonical(stored[reconnectKey])!==reconnectCanonical(committed)||reconnectCanonical(stored.lastGrant)!==reconnectCanonical(candidate)||!pendingReconnectValid(original.pending,original.previous))return;
 // The single qualification lane still owns this exact committed pair. Restore
 // its actual pre-commit record and old grant, never a phase-flipped committed
 // record containing its own nonce in history, nor a foreign/replacement value.
 await qualificationRead(qualification,()=>chrome.storage.local.set({[reconnectKey]:original.pending,lastGrant:original.previous}));
}
const extensionMaintenance=MechanizeExtensionMaintenance.create(chrome,{
 config,busy:()=>Boolean(privatePending||mutationBusy||activeBrowserInputs.size||setupActiveCommands||reconnectBusy),
 hold:value=>{maintenanceBusy=value;}
});
let lifecycleLane = Promise.resolve();
async function receive(command) {
  if(['extension.reload','extension.reloadStatus'].includes(command?.type)){
    const ownPort=port,fence=setupFence;
    const reply=await extensionMaintenance.handle(command,fence,()=>Boolean(ownPort&&port===ownPort&&setupFence===fence&&port!==startupFailurePort));
    if(reply&&port===ownPort&&setupFence===fence)ownPort.postMessage(reply);return;
  }
  if(maintenanceBusy){if(port&&command?.requestId)port.postMessage({requestId:command.requestId,error:MechanizeProtocol.error('executorNotQuiescent','Extension maintenance in progress','notDispatched')});return;}

  if(receiveReconnectBindings(command))return;
  if(['enrolled','processQualified'].includes(command?.type)){
    const ownPort=port;if(!ownPort)return;
    if(qualificationFlight){
      if(qualificationFlight.port!==ownPort)queuedQualification={port:ownPort,command};
      connectionAttention='executorNotQuiescent';
      ownPort.postMessage({type:'attention',error:MechanizeProtocol.error('executorNotQuiescent','Previous executor qualification is draining')});
      return;
    }
    const owner={port:ownPort,deadline:Date.now()+10000,expired:false};qualificationFlight=owner;setupActiveCommands++;
    const timer=setTimeout(()=>qualificationDeadline(owner),Math.max(0,owner.deadline-Date.now()));
    try{return await receiveCommand(command,owner);}
    finally{
      clearTimeout(timer);qualificationFlight===owner&&owner.cancelReconnectBindings?.();setupActiveCommands--;
      if(qualificationFlight===owner){
        qualificationFlight=null;reconnectBusy=false;verifiedPendingArchives.clear();verifiedHistoryArchives.clear();verifiedReconnectAudits.clear();
        const queued=queuedQualification;queuedQualification=null;
        if(queued?.port===port)void receive(queued.command);
        else if(owner.expired&&owner.port===port)scheduleInventoryRecovery(true);
      }
    }
  }

  if(command?.type==='browser.activationStatus'){
   const heldPort=port,heldFence=setupFence;
   // Reserve the same lane used by activation and renderer input. A terminal
   // receipt plus this drained lane is proof; elapsed wall time is not.
   const idle=()=>heldPort&&port===heldPort&&setupFence===heldFence&&!!heldFence&&!privatePending&&!activeBrowserInputs.size&&!setupActiveCommands&&!lifecycleGuardId;
   if(mutationBusy||!idle()){
    const result=await MechanizeTabMetadata.activationStatus(chrome,command,heldFence,await config(),()=>false);
    if(result&&port===heldPort)heldPort.postMessage(result);
    return;
   }
   mutationBusy=true;
   try{const result=await MechanizeTabMetadata.activationStatus(chrome,command,heldFence,await config(),()=>Boolean(mutationBusy&&idle()));
    if(result?.quiescent){retainUnknown(command.attemptId,command);visibilityUnknown.set(command.attemptId,{action:'browser.activateTab',attemptId:command.attemptId,port:heldPort,...heldFence});}
    if(result&&port===heldPort)heldPort.postMessage(result);
   }finally{mutationBusy=false;}
   return;
  }
  if(command?.type==='controlBadgeMetadata'){
    const heldPort=port,heldFence=setupFence;
    try{const reply=await MechanizeControlBadgeMetadata.respond(chrome,command,heldFence,await config(),()=>Boolean(heldPort&&port===heldPort&&setupFence===heldFence));if(reply&&port===heldPort)heldPort.postMessage(reply);}catch{}return;
  }

  if(command?.type==='browser.openOrigin'||command?.type==='browser.activateTab'){
    const heldPort=port,heldGrant=grant,heldFence=setupFence,activation=command.type==='browser.activateTab';
    if(mutationBusy||setupActiveCommands)return;
    // Visibility is browser metadata authority; creating a tab still requires
    // the separately qualified executor grant. Neither route admits DOM input.
    const allowed=()=>Boolean(heldPort&&heldFence&&(activation||heldGrant)&&port===heldPort&&grant===heldGrant&&setupFence===heldFence&&!setupActiveCommands&&!reconnectBusy&&!privatePending&&(!activation||!privateAdmission)&&!lifecycleGuardId&&!unknownAttempts.size&&!activeBrowserInputs.size&&port!==startupFailurePort);
    if(!allowed())return;
    mutationBusy=true;
    try{const result=await (command.type==='browser.openOrigin'?MechanizeBrowser.openOrigin(chrome,command,await config(),heldFence,allowed):MechanizeTabMetadata.activate(chrome,command,heldFence,await config(),allowed));if(result?.dispatchState==='unknown')retainUnknown(command.attemptId,command);if(result&&port===heldPort)heldPort.postMessage(result);}finally{mutationBusy=false;}
    return;
  }

  if(command?.type==='credentialScope'){
   const heldPort=port,heldFence=setupFence,heldPrivacy=privatePrivacy,heldAdmission=privateAdmission,heldFlow=privateFlow;let retiringPrivacy=null;try{
    const current=()=>{if(!heldPort||port!==heldPort||setupFence!==heldFence||!heldFence||['brokerEpoch','channelEpoch','scopeHash'].some(k=>command[k]!==heldFence[k])||privatePending||mutationBusy||activeBrowserInputs.size||command.mode==='publicRead'&&(lifecycleGuardId||reconnectBusy||setupActiveCommands))throw 'scopeChanged';if(['absent','retire'].includes(command.mode)&&(privatePrivacy!==heldPrivacy||privateAdmission!==heldAdmission||privateFlow!==heldFlow))throw 'scopeChanged';retiringPrivacy=privacyForSourceRetirement(command,heldPrivacy);};
    const captureAllowed=q=>Boolean(privateAdmission?.port===heldPort&&q.sourceIdentity&&['profileChannel','browserInstance','tabId','frameId','documentId','documentGeneration'].every(k=>q.sourceIdentity[k]===privateAdmission.identity[k])&&documentControlLeases.get(`${q.sourceIdentity.tabId}:${q.sourceIdentity.documentId}`)?.id===q.controlLease?.id&&documentControlLeases.get(`${q.sourceIdentity.tabId}:${q.sourceIdentity.documentId}`)?.generation===q.controlLease?.generation);
    if(command.mode==='publicRead')for(const [key,value]of publicReadScopes)if(value.proof.identity.tabId===command.targetTabId)publicReadScopes.delete(key);
    // The optional proof belongs to worker capability retirement, not the
    // protection record schema. The existing module still validates every
    // other field and independently proves source absence before persistence.
    const scopeCommand={...command};delete scopeCommand.retirementProof;
    const reply=await protectionScopes.respond(scopeCommand,current,captureAllowed);current();
    if(reply?.ready&&command.mode==='publicRead'&&reply.publicDocument){for(const [key,value]of publicReadScopes)if(value.port!==heldPort||Date.now()>=value.deadline)publicReadScopes.delete(key);if(publicReadScopes.size>=200)throw 'scopeLimit';publicReadScopes.set(`${reply.publicDocument.identity.tabId}:${reply.publicDocument.identity.documentId}`,{port:heldPort,fence:heldFence,origin:command.targetOrigin,deadline:command.deadlineUnixMs,proof:reply.publicDocument});}
    if(reply?.ready&&command.mode==='disjoint'&&reply.targetIdentity)disjointDocuments.set(`${reply.targetIdentity.tabId}:${reply.targetIdentity.documentId}`,{port:heldPort,origin:command.targetOrigin});
    if(reply?.ready&&command.mode==='retire'){
     const same=i=>i&&['profileChannel','browserInstance','tabId','frameId','documentId'].every(k=>i[k]===command.sourceIdentity[k]);
     if(same(privateAdmission?.identity))privateAdmission=null;if(same(privateFlow?.identity))privateFlow=null;if(retiringPrivacy&&privatePrivacy===retiringPrivacy){
      // Remove only volatile admission caches. The successor's content realm
      // and persistent credential redactor remain installed; no input lease
      // exists here, and later reads/control require fresh qualification.
      const successorKey=`${retiringPrivacy.identity.tabId}:${retiringPrivacy.identity.documentId}`;
      documents.delete(successorKey);documentOrigins.delete(successorKey);documentFingerprintVersions.delete(successorKey);publicReadScopes.delete(successorKey);privateRecipients.delete(successorKey);privatePrivacy=null;
     }
     if(!privateAdmission&&!privateFlow&&!privatePrivacy)privateSilencedPort=null;
     const key=`${command.sourceIdentity.tabId}:${command.sourceIdentity.documentId}`;documents.delete(key);documentControlLeases.delete(key);documentOrigins.delete(key);privateRecipients.delete(key);
    }
    if(reply?.ready&&command.mode==='capture')disjointDocuments.delete(`${command.sourceIdentity.tabId}:${command.sourceIdentity.documentId}`);
    if(reply)heldPort.postMessage(reply);
   }catch{if(['absent','retire'].includes(command.mode)&&heldPort&&port===heldPort&&setupFence===heldFence&&/^[a-f0-9]{64}$/.test(command.requestId)&&['brokerEpoch','channelEpoch','scopeHash'].every(k=>command[k]===heldFence?.[k]))try{heldPort.postMessage({type:'credentialScopeResult',requestId:command.requestId,brokerEpoch:command.brokerEpoch,channelEpoch:command.channelEpoch,scopeHash:command.scopeHash,ready:false,reason:'scopeChanged',loginRouteSHA256:'',targetIdentity:null});}catch{}}return;
  }
  if(command?.type==='tabInventory'){
    const heldPort=port,heldFence=setupFence;
    try{const reply=await MechanizeTabMetadata.inventory(chrome,command,heldFence,()=>config(),()=>Boolean(heldPort&&port===heldPort&&setupFence===heldFence));if(reply&&port===heldPort&&setupFence===heldFence&&new TextEncoder().encode(JSON.stringify(reply)).length<=4096)heldPort.postMessage(reply);}catch{}return;
  }
  if(command?.type==='tabLocation'){
    const heldPort=port,heldFence=setupFence;try{const reply=await MechanizeTabMetadata.match(chrome,command,heldFence,await config(),()=>Boolean(heldPort&&port===heldPort&&setupFence===heldFence));if(reply&&port===heldPort)heldPort.postMessage(reply);}catch{}return;
  }
  if(command?.type==='focusedLocation'){
    const heldPort=port,heldFence=setupFence;
    try{const enrollment=await config();const reply=await MechanizeFocusedLocation.respond(chrome,command,heldFence,enrollment,()=>port===heldPort&&setupFence===heldFence&&Boolean(heldPort));if(reply&&port===heldPort&&setupFence===heldFence)heldPort.postMessage(reply);}catch{}return;
  }
  if(command?.action==='executor.retire'&&command.attemptId!==undefined&&command.fingerprintVersion===2)return receiveUnknownTargetRetirement(command);
  if(reconnectBusy)return;
  if(['credentialTabAbsent','credentialManualPrivacy','credentialManualPrivacyCommit'].includes(command?.type))return receiveCredentialManualPrivacy(command);
  if(["credentialPrivacy","credentialPrivacyCommit","credentialPrivacyVerify"].includes(command?.type))return receiveCredentialPrivacy(command);
  if(command?.type==="credentialSubmit")return receiveCredentialSubmit(command);
  if(command?.type==="credentialRetire")return receiveCredentialRetire(command);
  if(command?.type==="credentialAdvance")return receiveCredentialAdvance(command);
  if (command?.type === "credentialDelivery") return receiveCredential(command);
  if (command?.type === "credentialInspect") return receiveCredentialInspect(command);
  if(command?.publicRead!==undefined)return receiveScopedPublicRead(command);
  if(command?.action==='executor.retire'&&await retireAbsentPlaywrightSource(command))return;
  const metadataQualification=["enrolled","processQualified"].includes(command?.type);
  if (!metadataQualification&&(privatePending||port===privateSilencedPort&&!ordinaryDisjoint(command?.identity))) return;
  if (!metadataQualification&&privateAdmission && !ordinaryDisjoint(command?.identity) && !(command?.action === "executor.acquire" && privateAdmission.port === port && privateAdmission.deadline > Date.now() &&
      ["profileChannel","browserInstance","tabId","frameId","documentId","documentGeneration"].every(k => command.identity?.[k] === privateAdmission.identity[k]))) return;
  if (command?.type === "setupMetadata") {
    const currentPort = port, currentFence = setupFence;
    try {
      const reply = await MechanizeSetupMetadata.respond(command, currentFence, setupState);
      if (port === currentPort && setupFence === currentFence && currentPort) send(reply);
    } catch { /* Read-only setup refusal never changes grants or unknown effects. */ }
    return;
  }
  setupActiveCommands++;
  try {
    if (command?.type !== "lifecycle") return await receiveCommand(command);
    const operation = lifecycleLane.then(() => receiveCommand(command));
    lifecycleLane = operation.catch(() => {});
    return await operation;
  } finally { setupActiveCommands--; }
}
async function proveTabTargetAbsent(identity,current){
 for(let sample=0;sample<2;sample++){
  current();if(!MechanizeCDP.idle(chrome))throw Error();
  const tabs=await chrome.tabs.query({});current();
  if(!Array.isArray(tabs)||tabs.length>200||tabs.some(tab=>!tab||!Number.isSafeInteger(tab.id)||tab.id<1)||new Set(tabs.map(tab=>tab.id)).size!==tabs.length||tabs.some(tab=>tab.id===identity.tabId))throw Error();
  if(typeof chrome.debugger?.getTargets!=='function')throw Error();
  const targets=await chrome.debugger.getTargets();current();
  if(!Array.isArray(targets)||targets.length>2000||targets.some(target=>!target||!channelShape(target.id)||typeof target.type!=='string'||!target.type||target.type.length>64||target.tabId!==undefined&&(!Number.isSafeInteger(target.tabId)||target.tabId<1)||target.type==='page'&&target.tabId===undefined)||new Set(targets.map(target=>target.id)).size!==targets.length||targets.some(target=>target.tabId===identity.tabId)||!MechanizeCDP.idle(chrome))throw Error();
 }
}
async function receiveUnknownTargetRetirement(command){
 const ownPort=port,ownFence=setupFence,flight=qualificationFlight;
 const inSnapshot=()=>Boolean(flight&&qualificationFlight===flight&&flight.retiringTargets&&flight.retirementBindings?.some(row=>row.attemptId===command.attemptId&&row.dispatchState==='unknown'&&reconnectCanonical(row.identity)===reconnectCanonical(command.identity)&&reconnectCanonical(row.controlLease)===reconnectCanonical(command.controlLease)&&row.fingerprintSHA256===command.fingerprintSHA256));
 const current=()=>{if(!ownPort||port!==ownPort||!ownFence||!setupFence||['brokerEpoch','channelEpoch','scopeHash'].some(k=>command[k]!==ownFence[k]||setupFence[k]!==ownFence[k])||ownPort===startupFailurePort||mutationBusy||(setupActiveCommands!==0&&!(setupActiveCommands===1&&inSnapshot()))||privatePending||privateAdmission||privateFlow||privatePrivacy||activeBrowserInputs.size||lifecycleGuardId||reconnectBusy&&!inSnapshot()||Date.now()>=command.deadlineUnixMs)throw Error();};
 try{
  MechanizeProtocol.validate(command);if(command.type!==undefined&&command.type!=='command'||!manualIdentity(command.identity))throw Error();current();
  const enrollment=await config();current();if(command.identity.profileChannel!==enrollment.profileChannel||command.identity.browserInstance!==enrollment.browserInstance)throw Error();
  const record=await playwrightWorker.retireUnknownTarget(command,()=>proveTabTargetAbsent(command.identity,current));current();
  retiredUnknownTargets.set(command.attemptId,{port:ownPort,fence:{...ownFence},record});unknownAttempts.delete(command.attemptId);
  ownPort.postMessage({requestId:command.requestId,attemptId:command.attemptId,identity:{...command.identity},controlLease:{...command.controlLease},fingerprintVersion:2,fingerprintSHA256:command.fingerprintSHA256,retiredAuthorityQuiesced:true,dispatchState:'unknown',effectState:'unknown'});
 }catch{if(ownPort&&port===ownPort&&typeof command.requestId==='string')try{ownPort.postMessage({requestId:command.requestId,identity:command.identity,error:MechanizeProtocol.error('retirementUnknown','Exact original target death and drained input proof required','unknown')});}catch{}}
}
// This exchange is metadata-only. The existing Host admission/snapshot remains
// held through executorPrepared; Done acknowledges rows, never business outcomes.
async function retireReconnectUnknownTargets(journal,previous,candidate,enrollment,command,ownPort,qualification){
 if(!unknownAttempts.size)return;
 if(command.type!=='processQualified'||!previous||!setupFence||mutationBusy||privatePending||privateAdmission||privateFlow||privatePrivacy||lifecycleGuardId||activeBrowserInputs.size||setupActiveCommands!==1)throw reconnectRefuse('unknownReceipts');
 const sameFence=sameReconnectFence(previous,candidate);
 let pending=journal;
 if(sameFence || !pendingReconnectValid(pending,previous)){
  pending={version:sameFence?1:activeReconnectJournal(journal)?1:journal?.version||1,phase:'pending',nonce:Array.from(crypto.getRandomValues(new Uint8Array(32)),b=>b.toString(16).padStart(2,'0')).join(''),oldFence:reconnectFence(previous),newFence:reconnectFence(candidate),history:journal?.history||[],...(journal?.archive?{archive:journal.archive}:{}),...(!sameFence&&journal?.recovery?{recovery:journal.recovery}:{})};
 }
 // Same-fence snapshots are transient retirement metadata, never persisted or
 // adopted. Ordinary handoff validation still rejects an identical fence.
 if(!(sameFence?reconnectBooleanValidation(()=>pendingReconnectValidCore(pending,previous,true)):pendingReconnectValid(pending,previous)))throw reconnectJournalRefuse('lineageInvalid');
 await verifyReconnectArchives(pending,qualification);
 const attempts=[...unknownAttempts.keys()].sort();
 if(attempts.length>512||attempts.some(id=>!/^[a-f0-9]{64}$/.test(id)))throw reconnectRefuse('unknownReceipts');
 const snapshot=await reconnectBindingSnapshot(pending,command,ownPort,qualification,attempts);
 reconnectRows(snapshot.bindings,enrollment,previous.scopeHash);
 if(attempts.some(id=>!snapshot.bindings.some(row=>row.attemptId===id&&row.dispatchState==='unknown'&&row.controlLease)))throw reconnectRefuse('unknownReceipts');
 qualification.retirementBindings=snapshot.bindings.filter(row=>attempts.includes(row.attemptId));qualification.retiringTargets=true;
 try{await snapshot.release();}finally{qualification.retiringTargets=false;qualification.retirementBindings=null;}
 qualificationCurrent(qualification);
 if(unknownAttempts.size)throw reconnectRefuse('unknownReceipts');
 qualification.retirementSnapshot=snapshot;qualification.releaseReconnectBindings=snapshot.release;
}
async function revalidateRetiredUnknownTargets(current){
 for(const [attempt,proof]of retiredUnknownTargets){
  if(!currentRetiredUnknown(attempt))throw reconnectRefuse('unknownReceipts');
  try{await proveTabTargetAbsent(proof.record.identity,current);}catch{retainUnknown(attempt,proof.record);retiredUnknownTargets.delete(attempt);throw reconnectRefuse('unknownReceipts');}
 }
}
// Existing retirement protocol, using immutable known receipt evidence when
// navigation destroyed the original renderer. No current-page DOM is inspected.
async function retireAbsentPlaywrightSource(command) {
 const ownPort=port,ownGrant=grant,i=command.identity,key=i&&`${i.tabId}:${i.documentId}`;
 try{
  MechanizeProtocol.validate(command);
  if(command.type!==undefined&&command.type!=='command'||command.action!=='executor.retire'||!command.controlLease||command.locator!==undefined||command.args!==undefined||command.attemptId!==undefined||!manualIdentity(i))return false;
  const current=()=>{if(!ownPort||port!==ownPort||!ownGrant||grant!==ownGrant||!qualifiedNativePorts.has(ownPort)||!ownGrant.leaseRequired||ownPort===startupFailurePort||mutationBusy||privatePending||activeBrowserInputs.size||domUnknownBlocked('',command.identity)||lifecycleGuardId||Date.now()>=command.deadlineUnixMs||['brokerEpoch','channelEpoch','scopeHash'].some(k=>command[k]!==ownGrant[k])||documents.has(key)||documentControlLeases.has(key)||!inactiveLeaseDocuments.has(key))throw Error();};
  current();const enrollment=await config();current();if(i.profileChannel!==enrollment.profileChannel||i.browserInstance!==enrollment.browserInstance)return false;
  const proved=await playwrightWorker.retireKnownSource(command,()=>protectionScopes.proveSourceAbsent(i,current));current();if(!proved)return false;
  // Keep the suspended-document tombstone: cached/reactivated content cannot
  // borrow this old lease. Only normal fresh qualification can replace it.
  ownPort.postMessage({requestId:command.requestId,identity:{...i},retiredAuthorityQuiesced:true,controlLease:{...command.controlLease}});return true;
 }catch{return false;}
}
async function receiveCommand(command, qualification) {
  const commandPort = port;
  const admission = privateAdmission;
  const replyTo = value => {
    if (port !== commandPort) return;
    if(value?.type==='attention'&&['enrolled','processQualified'].includes(command?.type)){
      if(qualification?.expired){reconnectDiagnosticReason='deadline';value={type:'attention',error:reconnectFail()};}
      const code=value.error?.code;
      connectionAttention=['websiteScopeMismatch','lifecycleInhibited','storedFenceMismatch','inventoryUnavailable','inventoryIncomplete','executorInjectionFailed','executorBindingFailed','executorNotQuiescent'].includes(code)?code:'inventoryUnavailable';
      chrome.runtime.sendMessage({type:'nativeConnectionStatus',connected:Boolean(port),qualified:Boolean(grant),attentionCode:connectionAttention}).catch(()=>{});
      commandPort?.postMessage(reconnectAttention({type:'attention',error:MechanizeProtocol.error(connectionAttention,'Executor qualification requires attention')}));return;
    }
    if (admission && privateAdmission === admission && !ordinaryDisjoint(command?.identity)) {
      if(command.action==='executor.acquire'&&value?.error&&command.controlLease){
        const sameDocument=value.identity&&['profileChannel','browserInstance','tabId','frameId','documentId'].every(k=>value.identity[k]===admission.identity[k]);
        const stale=value.error.code==='staleGeneration'&&value.error.dispatchState==='notDispatched'&&sameDocument&&Number.isSafeInteger(value.identity.documentGeneration)&&value.identity.documentGeneration>admission.identity.documentGeneration;
        // Return only a closed refusal tied to this original private request.
        // No renderer error text, changed identity, or form metadata is exported.
        commandPort.postMessage({requestId:command.requestId,identity:{...command.identity},validated:false,controlLease:{...command.controlLease},errorCode:stale?'staleGeneration':'acquisitionRejected'});
        return;
      }
      if (command.action === "executor.acquire" && value && Object.keys(value).sort().join() === "controlLease,identity,requestId,validated" &&
          value.validated === true && value.requestId === command.requestId &&
          ["profileChannel","browserInstance","tabId","frameId","documentId","documentGeneration"].every(k => value.identity?.[k] === admission.identity[k]) &&
          value.controlLease?.id === command.controlLease?.id && value.controlLease?.generation === command.controlLease?.generation) commandPort.postMessage(value);
      return;
    }
    if(value?.type==='attention'){
      const code=value.error?.code;
      connectionAttention=['websiteScopeMismatch','lifecycleInhibited','storedFenceMismatch','inventoryUnavailable','inventoryIncomplete','executorInjectionFailed','executorBindingFailed','executorNotQuiescent'].includes(code)?code:'inventoryUnavailable';
      chrome.runtime.sendMessage({type:'nativeConnectionStatus',connected:Boolean(port),qualified:Boolean(grant),attentionCode:connectionAttention}).catch(()=>{});
    }
    if(ordinaryDisjoint(command?.identity)&&commandPort){commandPort.postMessage(privacySanitize(reconnectAttention(value)));return;}
    send(reconnectAttention(value));
  };
  if (command?.type === "enrolled" || command?.type === "processQualified") {
    reconnectMissingReceiptSources=null;reconnectMissingDocuments=[];
    playwrightWorker.invalidate();
    MechanizeCDP.invalidate(chrome);
    grant = null;
    const metadataTrust=command.trustScope===undefined||command.trustScope===''?'profile':command.trustScope;
    const metadataScopeQualified=metadataTrust==='desktop'?command.scopeQualified===true&&command.profileQualified===false:metadataTrust==='profile'&&command.scopeQualified===true&&command.profileQualified===true;
    const nextSetupFence = command.type === "processQualified" && metadataScopeQualified && command.fixtureOnly === false && command.executorQualified!==true &&
      typeof command.executorChallenge==='string'&&command.executorChallenge!==''&&
      ["brokerEpoch", "channelEpoch", "scopeHash"].every(k => typeof command[k] === "string" && command[k]) ?
      {brokerEpoch: command.brokerEpoch, channelEpoch: command.channelEpoch, scopeHash: command.scopeHash} : null;
    // Controller discovery owns the signed process/scope connection, not a
    // renderer grant. Changing that connection still revokes document sessions.
    if (setupFence && (!nextSetupFence || ["brokerEpoch","channelEpoch","scopeHash"].some(k=>setupFence[k]!==nextSetupFence[k]))) controllers.reset();
    publicReadScopes.clear();
    if(retiredUnknownTargets.size&&(!nextSetupFence||[...retiredUnknownTargets.values()].some(proof=>proof.port!==commandPort||['brokerEpoch','channelEpoch','scopeHash'].some(k=>proof.fence[k]!==nextSetupFence[k]))))rearmRetiredUnknownTargets();
    setupFence = nextSetupFence;
    const controllerBinding = controllers.fence();
    if (controllerBinding) sendController({type:"controllerSync",...controllerBinding});
    if(metadataStartupBarrier){replyTo({type:'attention',error:MechanizeProtocol.error(metadataStartupBarrier,'Retained executor evidence requires recovery')});return;}
    if (lifecycleGuardId) { replyTo({type: "attention", error: MechanizeProtocol.error("lifecycleInhibited", "Retained lifecycle cannot be replaced by enrollment")}); return; }
    if (!["brokerEpoch", "channelEpoch", "scopeHash"].every(k => typeof command[k] === "string" && command[k])) return;
    try {
      const scope = await qualificationRead(qualification,config);
      const permissions=scope.allWebsites===true?['http://*/*','https://*/*']:scope.origins.map(origin=>origin+'/*');
      if(!await qualificationRead(qualification,()=>chrome.permissions.contains({origins:permissions}))){replyTo({type:'attention',error:MechanizeProtocol.error('websiteScopeMismatch','Saved website permission is unavailable')});return;}
      if (command.allWebsites !== undefined && typeof command.allWebsites !== "boolean" ||
          (command.allWebsites === true) !== (scope.allWebsites === true)) {
        replyTo({type: "attention", error: MechanizeProtocol.error("websiteScopeMismatch", "Browser and broker website scopes do not match")});
        chrome.runtime.sendMessage({type: "nativeConnectionStatus", connected: Boolean(port), attentionCode: "websiteScopeMismatch"}).catch(() => {});
        return;
      }
      const {lastGrant} = await qualificationRead(qualification,()=>chrome.storage.local.get("lastGrant"));
      const savedReconnect=(await qualificationRead(qualification,()=>chrome.storage.local.get(reconnectKey)))[reconnectKey];
      await verifyReconnectArchives(savedReconnect,qualification);
      if(!reconnectJournalValid(savedReconnect,lastGrant) && !pendingReconnectValid(savedReconnect,lastGrant))throw reconnectFail();
      const changedFence=lastGrant && (!sameReconnectFence(lastGrant,command) || savedReconnect?.phase==="pending");
      let reconnectRecord;
      const mutationFingerprintVersion = command.mutationFingerprintVersion === undefined ? 1 : command.mutationFingerprintVersion;
      if (![1,2].includes(mutationFingerprintVersion)) { replyTo({type:"attention", error:MechanizeProtocol.error("executorBindingFailed", "Supported mutation fingerprint negotiation required")}); return; }
      const candidate = {mutationFingerprintVersion, brokerEpoch: command.brokerEpoch, channelEpoch: command.channelEpoch, scopeHash: command.scopeHash};
      if(changedFence && command.type!=="processQualified"){replyTo({type:"attention",error:reconnectFail()});return;}
      // Unbound/legacy unknowns keep the original conservative readiness barrier.
      // Only exact retained target tuples can use same-fence retirement metadata.
      const sameFenceTargets=lastGrant&&[...unknownAttempts].every(([id,record])=>record&&/^[a-f0-9]{64}$/.test(id));
      if(unknownAttempts.size&&(changedFence||sameFenceTargets))await retireReconnectUnknownTargets(savedReconnect,lastGrant,candidate,scope,command,commandPort,qualification);
      if(mutationBusy||unknownAttempts.size||privatePending||privateAdmission||privateFlow||privatePrivacy||privateRedactions.length){replyTo({type:'attention',error:changedFence?reconnectFail():MechanizeProtocol.error('executorNotQuiescent','Active executor work requires reconciliation')});return;}
      if (command.type === "processQualified") {
        const trustScope = command.trustScope === undefined || command.trustScope === "" ? "profile" : command.trustScope;
        const scopeQualified = trustScope === "desktop" ? command.scopeQualified === true && command.profileQualified === false :
          trustScope === "profile" && command.profileQualified === true && (command.scopeQualified === undefined || command.scopeQualified === true);
        if (!scopeQualified || command.executorQualified || typeof command.executorChallenge !== "string" || !command.executorChallenge || mutationBusy || unknownAttempts.size || privatePending || privateAdmission || privateFlow || privatePrivacy || privateRedactions.length) {
          replyTo({type: "attention", error: changedFence ? reconnectFail() : MechanizeProtocol.error("executorNotQuiescent", "Qualified browser scope and idle reconciled executor required")}); return;
        }
        candidate.trustScope = trustScope;
        candidate.scopeQualified = true;
        candidate.profileQualified = trustScope === "profile";
        if(changedFence) {
          try {reconnectRecord=await prepareNativeReconnect(lastGrant,candidate,scope,command,commandPort,qualification);}
          catch {if(port===commandPort&&qualificationFlight===qualification){connectionAttention="storedFenceMismatch";chrome.runtime.sendMessage({type:"nativeConnectionStatus",connected:true,attentionCode:"storedFenceMismatch"}).catch(()=>{});}replyTo({type:"attention",error:reconnectFail()});return;}
        }
        const snapshot = await inventory(await qualificationRead(qualification,config),qualification);
        if (snapshot.truncated) { replyTo({type: "attention", error: MechanizeProtocol.error("inventoryIncomplete", "Complete root inventory required")}); return; }
        for (const identity of (reconnectRecord ? [] : snapshot.documents.filter(d => d.frameId === 0))) {
          reconnectDiagnosticPhase='inspect';
          try {
            await chrome.scripting.executeScript({target: {tabId: identity.tabId, documentIds: [identity.documentId]}, world: "ISOLATED", files: ["protocol.js", "fingerprint.js", "accessibility-provider.js", "dom.js", "recorder.js", "secure-input.js", "content.js"]});
          } catch { replyTo({type: "attention", error: MechanizeProtocol.error("executorInjectionFailed", "Packaged executor injection could not be confirmed")}); return; }
          qualificationCurrent(qualification);
          let bound;
          try {
            bound = await chrome.tabs.sendMessage(identity.tabId, {type: "bind", binding: {identity, ...candidate, leaseRequired: true}}, {documentId: identity.documentId});
          } catch { replyTo({type: "attention", error: MechanizeProtocol.error("executorBindingFailed", "Exact document executor binding could not be confirmed")}); return; }
          qualificationCurrent(qualification);
          if (bound?.error || !validBoundIdentity(bound?.identity,identity) || (mutationFingerprintVersion === 2 && bound.mutationFingerprintVersion !== 2)) {
            replyTo({type: "attention", error: MechanizeProtocol.error("executorBindingFailed", "Exact document executor binding could not be confirmed")}); return;
          }
          documents.set(`${identity.tabId}:${identity.documentId}`, bound.identity);
          documentOrigins.set(`${identity.tabId}:${identity.documentId}`,identity.origin);
          documentFingerprintVersions.set(`${identity.tabId}:${identity.documentId}`, bound.mutationFingerprintVersion || 1);
        }
      }
      candidate.leaseRequired = command.type === "processQualified";
      const snapshot = await inventory(await qualificationRead(qualification,config),qualification);
      if (snapshot.truncated) { replyTo({type: "attention", error: MechanizeProtocol.error("inventoryIncomplete", "Complete root inventory required")}); return; }
      if(port!==commandPort)throw reconnectFail();
      const emptyRecovery=Boolean(reconnectRecord)&&savedReconnect?.phase==="pending";
      const verifyCommit=Boolean(reconnectRecord)&&(emptyRecovery||Boolean(reconnectRecord.archive||reconnectRecord.recovery||reconnectRecord.audit||qualification.retirementSnapshot));
      try {
        if(verifyCommit)await reconnectRecoveryChecks.get(reconnectRecord)(false);
        // Obtain commit readiness while Host admission stays held. Lost
        // acknowledgement leaves the existing pending record/old grant intact;
        // no executor is published and a future exact recovery can retry proof.
        if(qualification.releaseReconnectBindings){await qualification.releaseReconnectBindings();qualification.releaseReconnectBindings=null;}
        if(port!==commandPort)throw reconnectFail();
        const publish={lastGrant:candidate,...(reconnectRecord?{[reconnectKey]:reconnectRecord}:{})};
        if(reconnectRecord)await reconnectStorage(()=>chrome.storage.local.set(publish),qualification);
        else await chrome.storage.local.set(publish);
        if(reconnectRecord){
          const saved=await chrome.storage.local.get("lastGrant"),journal=await chrome.storage.local.get(reconnectKey);
          if(reconnectCanonical(saved.lastGrant)!==reconnectCanonical(candidate)||reconnectCanonical(journal[reconnectKey])!==reconnectCanonical(reconnectRecord)||port!==commandPort)throw reconnectFail();
        }
        if(verifyCommit) {
          await reconnectRecoveryChecks.get(reconnectRecord)(true);
          if(port!==commandPort)throw reconnectFail();
        }
      } catch(error) {
        // A commit racing native-port loss or inventory change must remain
        // durably inhibited, retaining the original pending journal and history.
        if(emptyRecovery&&!qualification.recoveryUsesCurrentDocuments)try{await restoreOwnedReconnectPending(reconnectRecord,candidate,qualification);}catch{}
        throw error;
      }
      qualificationCurrent(qualification);
      await revalidateRetiredUnknownTargets(()=>qualificationCurrent(qualification));
      grant = candidate;connectionAttention='none';chrome.runtime.sendMessage({type:'nativeConnectionStatus',connected:true,qualified:true,attentionCode:'none'}).catch(()=>{});
      qualificationDeadlineRecoveryUsed=false;
      if(command.type==="processQualified")qualifiedNativePorts.add(commandPort);
      // Complete awaited setup before acknowledging renderer qualification. An
      // empty inventory remains explicitly empty; it proves no available tab.
      if (command.type === "processQualified") replyTo({type: "executorPrepared", executorChallenge: command.executorChallenge, mutationFingerprintVersion});
      replyTo({type: "documents", ...snapshot, capabilities: [...MechanizeProtocol.actions], inputSemantics: chrome.runtime.getManifest().permissions?.includes("debugger") ? "Browser protocol pointer input v1; DOM text and selection" : "DOM activation; isTrusted=false", unsupported: ["browser-protocol credential input", "browser-protocol text input", "file selection", "custom editors", "closed shadow roots", "network response bodies", "capture", "tab open/close", "production signed-parent enrollment"]});
      // Failure-generation dedup lasts across port loss and failed proofs. Only
      // committed authenticated qualification starts a new recovery budget.
      if(command.type==='processQualified')missingReceiptRecoveryEvents.clear();
    } catch(error) {
      if(port===commandPort&&qualificationFlight===qualification)grant = null;
      replyTo({type: "attention", error: error?.code==='storedFenceMismatch'?reconnectFail():MechanizeProtocol.error("inventoryUnavailable", "Enrollment storage or document inventory unavailable")});
    } finally {if(qualificationFlight===qualification)reconnectBusy=false;}
    return;
  }
  try {
    const lifecycle = command?.type === "lifecycle";
    let guardId;
    if (lifecycle) {
      guardId = command.lifecycleGuardId;
      if (typeof guardId !== "string" || !/^[A-Za-z0-9._:-]{1,128}$/.test(guardId) ||
          !["executor.retire", "executor.quiesce", "record.stop", "executor.receipts", "retirement.intend", "retirement.prepare", "retirement.status"].includes(command.action))
        throw MechanizeProtocol.error("lifecycleDenied", "Closed lifecycle receipt operation required");
      const {type, lifecycleGuardId: omittedGuard, ...payload} = command;
      command = payload;
    }
    const journal = lifecycle && command.action.startsWith("retirement.");
    if (journal) validateRetirementCommand(command); else MechanizeProtocol.validate(command, lifecycle);
    if(command.locator&&(Object.hasOwn(command.locator,'index')||Object.hasOwn(command.locator,'order')))throw MechanizeProtocol.error('unsupportedSelector','Indexed locators require the qualified Playwright relay');
    const enrollment = await config();
    if (!grant || command.identity.profileChannel !== enrollment.profileChannel || command.identity.browserInstance !== enrollment.browserInstance || ["brokerEpoch", "channelEpoch", "scopeHash"].some(k => command[k] !== grant[k])) throw MechanizeProtocol.error("notEnrolled", "Authenticated broker channel/scope does not match");
    const admittedPort = port, admittedGrant = grant;
    const requireCurrentLifecycle = () => {
      if (!lifecycle) return;
      if (!admittedPort || port !== admittedPort || grant !== admittedGrant ||
          command.deadlineUnixMs <= Date.now())
        throw MechanizeProtocol.error("lifecycleDenied", "Original lifecycle connection or deadline no longer valid");
    };
    const handoff = journal && command.action === "retirement.status" && lifecycleGuardId && lifecycleGuardId !== guardId;
    if (lifecycle) {
      if (mutationBusy || unknownAttempts.size || (lifecycleGuardId && lifecycleGuardId !== guardId && !handoff))
        throw MechanizeProtocol.error("lifecycleDenied", "Idle exact lifecycle guard required");
      if (!journal && !documents.has(`${command.identity.tabId}:${command.identity.documentId}`))
        throw MechanizeProtocol.error("lifecycleDenied", "Existing bound document required");
      // Persist inhibition before forwarding any lifecycle command. Restart
      // recovery must explicitly reconcile it; ordinary enrollment cannot clear it.
      if (!handoff) lifecycleGuardId = guardId;
      await chrome.storage.session.set({mechanizeLifecycleInhibited: true});
      requireCurrentLifecycle();
    } else if (lifecycleGuardId) {
      throw MechanizeProtocol.error("lifecycleInhibited", "Channel is retained for lifecycle reconciliation");
    }
    if (requests.has(command.requestId)) throw MechanizeProtocol.error("requestReplay", "Request IDs are single-use; query the original attempt receipt");
    if (requests.size >= 4096) throw MechanizeProtocol.error("requestCapacity", "Channel request quota exhausted; explicitly reconcile before replacing channel");
    requests.add(command.requestId);
    if (journal) {
      const input = command.args;
      const channel = {profileChannel: enrollment.profileChannel, browserInstance: enrollment.browserInstance};
      let result;
      if (command.action === "retirement.status") {
        if (!input || Object.keys(input).sort().join(",") !== "browserInstance,profileChannel" || input.profileChannel !== channel.profileChannel || input.browserInstance !== channel.browserInstance) throw MechanizeProtocol.error("lifecycleDenied", "Exact retirement channel required");
        result = await retirementJournal.status(channel);
        requireCurrentLifecycle();
        // The private lane has drained all predecessor lifecycle operations.
        // Transfer only inspection authority; input stays inhibited.
        if (handoff && (result.confirmed || result.reason === "retirementNotFound")) lifecycleGuardId = guardId;
      } else {
        if (!input || input.channel?.profileChannel !== channel.profileChannel || input.channel?.browserInstance !== channel.browserInstance ||
            ["brokerEpoch", "channelEpoch", "scopeHash"].some(k => input.oldFence?.[k] !== grant[k]))
          throw MechanizeProtocol.error("lifecycleDenied", "Exact predecessor journal fence required");
        result = command.action === "retirement.intend" ? await retirementJournal.intend(input) : await retirementJournal.prepare(input);
      }
      requireCurrentLifecycle();
      replyTo({requestId: command.requestId, identity: command.identity, retirement: result});
      return;
    }
    if(privatePrivacy&&!ordinaryDisjoint(command.identity)&&protectedOrigins.has(documentOrigins.get(`${command.identity.tabId}:${command.identity.documentId}`))&&(!privacyDocument(command.identity)||command.action.startsWith("record.")))throw MechanizeProtocol.error("secureDocumentRequired","Exact DOM privacy permit required");
    const mutation = MechanizeProtocol.mutations.has(command.action);
    if (mutation && (command.fingerprintVersion || 1) !== (grant.mutationFingerprintVersion || 1)) throw MechanizeProtocol.error("fingerprintMismatch", "Mutation version differs from negotiated worker");
    if (grant.leaseRequired && mutation && !command.controlLease) throw MechanizeProtocol.error("rendererAuthorityRequired", "Production mutation requires an admitted renderer lease");
    if (mutation) {
      if(visibilityUnknown.has(command.attemptId))throw MechanizeProtocol.error('attemptConflict','Attempt belongs to a retained browser visibility operation','notDispatched');
      const retained=await playwrightWorker.query(command);
      if(retained){
        if(command.fingerprintVersion!==2||retained.fingerprintSHA256!==command.fingerprintSHA256)throw MechanizeProtocol.error('attemptConflict','Original Playwright mutation fingerprint required');
        replyTo(retained);return;
      }
    }
    if (["executor.acquire", "executor.retire"].includes(command.action) && domUnknownBlocked('',command.identity)) throw MechanizeProtocol.error("unknownEffect", "Unresolved mutation prevents renderer lease transitions", "unknown");
    if (mutation && domUnknownBlocked('',command.identity)) throw MechanizeProtocol.error("unknownEffect", "A previous receipt was lost; query and reconcile its attempt before another mutation", "unknown");
    if (mutationBusy) throw MechanizeProtocol.error("mutationBusy", "One browser mutation at a time; wait for its receipt");
    if (mutation) mutationBusy = true;
    try {
      if (command.action === "receipt.query") {
        const retained=await playwrightWorker.query(command);
        if(retained){if(retained.dispatchState!=='unknown')unknownAttempts.delete(command.attemptId);replyTo(retained);return;}
      }
      if (!lifecycle) await attach(command, enrollment);
      if (command.action === "receipt.query") {
        const receipt = await MechanizeBrowser.query(command,{isProtected:isProtectedURL});
        if (receipt) { if (receipt.dispatchState !== "unknown" && receipt.error?.dispatchState !== "unknown") unknownAttempts.delete(command.attemptId); replyTo(receipt); return; }
      }
      if (command.action === "record.start") {
        if (!chrome.action) throw MechanizeProtocol.error("recordingIndicatorUnavailable", "Visible recording badge is required before capture starts");
        await chrome.action.setBadgeText({tabId: command.identity.tabId, text: "REC"});
        await chrome.action.setBadgeBackgroundColor({tabId: command.identity.tabId, color: "#B42318"});
      }
      if(command.action==='element.press' && command.fingerprintVersion===2 && command.identity.frameId===0) {
        // Pointer targeting requires an active tab: background Chrome throttles
        // both animation frames and timers. Focus only the already admitted tab,
        // then revalidate its exact document before requesting click geometry.
        let activationTimer;
        try {
          await Promise.race([
            chrome.tabs.update(command.identity.tabId,{active:true}),
            new Promise((_,reject)=>{activationTimer=setTimeout(()=>reject(MechanizeProtocol.error('dispatchExpired','Target tab activation expired','notDispatched')),Math.max(0,command.deadlineUnixMs-Date.now()));})
          ]);
        } finally {clearTimeout(activationTimer);}
        if(port!==admittedPort||grant!==admittedGrant||Date.now()>=command.deadlineUnixMs)throw MechanizeProtocol.error('staleAuthority','Target tab activation authority changed','notDispatched');
        await attach(command,enrollment);
        if(port!==admittedPort||grant!==admittedGrant||Date.now()>=command.deadlineUnixMs)throw MechanizeProtocol.error('staleAuthority','Target document activation authority changed','notDispatched');
        activeBrowserInputs.set(command.requestId,{command,admittedPort,admittedGrant,used:false});
      }
      const result = command.action==='executor.receipts' ? await playwrightWorker.exportReceipts(command, c=>chrome.tabs.sendMessage(c.identity.tabId,c,{documentId:c.identity.documentId})) : command.action.startsWith("browser.") ? await MechanizeBrowser.execute(command, privacyDocument(command.identity)?{...enrollment,allWebsites:false,origins:[privatePrivacy.origin]}:enrollment, {isProtected:(value,i)=>privacyDocument(i)&&!protectionScopes.loginRoute(value,i)?false:isProtectedURL(value,i),allowsPrivateURL:(value,i)=>protectionScopes.loginRoute(value,i)},
        () => port===admittedPort && grant===admittedGrant && !privatePending && !privateAdmission && !lifecycleGuardId,
        () => documentControlLeases.delete(`${command.identity.tabId}:${command.identity.documentId}`),privacySanitize) : await chrome.tabs.sendMessage(command.identity.tabId, command, {documentId: command.identity.documentId});
      requireCurrentLifecycle();
      if (result.recordingState && chrome.action) { await chrome.action.setBadgeText({tabId: command.identity.tabId, text: result.recordingState === "recording" ? "REC" : result.recordingState === "paused" ? "PAUSE" : ""}); await chrome.action.setBadgeBackgroundColor({tabId: command.identity.tabId, color: "#B42318"}); }
      if (command.action === "executor.acquire" && result.validated === true && result.controlLease?.id === command.controlLease?.id && result.controlLease?.generation === command.controlLease?.generation && result.identity?.documentId === command.identity.documentId) documentControlLeases.set(`${command.identity.tabId}:${command.identity.documentId}`, {...command.controlLease});
      if (["executor.retire","executor.quiesce"].includes(command.action) && !result.error) {const key=`${command.identity.tabId}:${command.identity.documentId}`;documentControlLeases.delete(key);inactiveLeaseDocuments.delete(key);}
      if(result.newDocument && result.newDocument.documentId!==command.identity.documentId) {if(privatePrivacy&&privacyDocument(command.identity))privatePrivacy.active=false;const key=`${command.identity.tabId}:${command.identity.documentId}`;documents.delete(key);documentControlLeases.delete(key);documentFingerprintVersions.delete(key);documentOrigins.delete(key);}
      if (result.identity && !result.newDocument) documents.set(`${command.identity.tabId}:${command.identity.documentId}`, result.identity);
      if (command.action === "receipt.query" && result.receiptAvailable !== false && result.dispatchState !== "unknown" && result.error?.dispatchState !== "unknown") unknownAttempts.delete(command.attemptId);
      if (mutation && (result.dispatchState === "unknown" || result.error?.dispatchState === "unknown")) retainUnknown(command.attemptId,command);
      replyTo(result);
    } catch (error) {
      if (error.code) throw error;
      if (mutation) {
        retainUnknown(command.attemptId,command);
        if(activeBrowserInputs.has(command.requestId))await chrome.storage.session.set({['browserProtocolInput:'+command.attemptId]:{state:'unknown',tabId:command.identity.tabId,documentId:command.identity.documentId}}).catch(()=>{});
      }
      replyTo({requestId: command.requestId, attemptId: command.attemptId, error: MechanizeProtocol.error("receiptLost", "Renderer receipt unavailable; query original document receipt, then reconcile; never replay", "unknown")});
    } finally { activeBrowserInputs.delete(command.requestId); if (mutation) mutationBusy = false; }
  } catch (error) { replyTo({requestId: command?.requestId, attemptId: command?.attemptId, identity: command?.identity, error: error.code ? error : MechanizeProtocol.error("transportFailure", "Browser command unavailable")}); }
}
// Multiple setup pages may request connection while enrollment is loading.
// Share one attempt so a second request cannot orphan the first native port.
// This does not retry inputs or bypass retained recovery barriers.
let connectionPending = null, connectionAttention = "nativeHostDisconnected", startupFailurePort = null,metadataStartupBarrier=null;
const nativeHostStartupCodes = new Set(["brokerPeerUnavailable","brokerPeerAuditUnavailable","brokerProcessUnqualified","brokerHelloUnavailable","brokerHelloRejected","brokerEnrollmentRefused","brokerChannelBusy","brokerScopeUnqualified","brokerHandshakeUnavailable","configUnavailable","processTrustUnavailable","runningImageMismatch","nativeHostSignatureUnavailable","chromeSignatureUnavailable","nativeHostProcessUnavailable","nativeHostUIDUnavailable","nativeHostDynamicSignatureUnavailable","chromeImagePathMismatch","chromeAncestryUnavailable","chromeParentUnavailable","ancestryChanged","launchScopeUnavailable","socketUnavailable","brokerUnavailable","brokerTrustUnavailable","enrollmentCredentialUnavailable","helloIdentityMismatch"]);
function nativeAttention(message) {
  return new Map([
    ["Specified native messaging host not found.","hostNotRegistered"],
    ["Failed to start native messaging host.","hostLaunchFailed"],
    ["Native host has exited.","hostExited"],
    ["Access to the specified native messaging host is forbidden.","hostAccessDenied"]
  ]).get(message) || "nativeHostDisconnected";
}
async function connectionSettings(){
 try{
  const saved=await chrome.storage.local.get('connectionEnabled');
  if(saved.connectionEnabled!==undefined&&saved.connectionEnabled!==true)return {enabled:false,configured:true};
  try{await config();return {enabled:true,configured:true};}catch(error){connectionAttention='enrollmentUnavailable';reconnectDiagnosticPhase='scope';reconnectDiagnosticReason=error?.code==='notEnrolled'?'scopeChanged':'storageFailure';return {enabled:true,configured:error?.code!=='notEnrolled',blocked:error?.code!=='notEnrolled'};}
 }catch{connectionAttention='enrollmentUnavailable';reconnectDiagnosticPhase='scope';reconnectDiagnosticReason='storageFailure';return {enabled:true,configured:true,blocked:true};}
}
function closeNativeConnection(expected=port){
 if(!expected||port!==expected)return;
 reconnectMissingReceiptSources=null;reconnectMissingDocuments=[];
 verifiedPendingArchives.clear();verifiedHistoryArchives.clear();
 if(queuedQualification?.port===expected)queuedQualification=null;
 playwrightWorker.invalidate();MechanizeCDP.invalidate(chrome);controllers.reset();
 rearmRetiredUnknownTargets();disjointDocuments.clear();publicReadScopes.clear();port=null;grant=null;setupFence=null;privateAdmission=null;privateFlow=null;privatePrivacy=null;manualPrivacyFlow=null;privateRedactions=[];privateRecipients.clear();privateSilencedPort=null;
 try{expected.disconnect();}catch{}
}
const connectionLifecycle=MechanizeConnectionLifecycle.create(chrome,{
 settings:connectionSettings,isOpen:()=>Boolean(port),close:()=>closeNativeConnection(),
 async open(token,valid){connectionPending=connectNativeOnce(token,valid);try{await connectionPending;return Boolean(port&&port!==startupFailurePort);}finally{connectionPending=null;}},
 changed(){chrome.runtime.sendMessage({type:'nativeConnectionStatus',connected:Boolean(port&&port!==startupFailurePort),qualified:Boolean(grant),attentionCode:connectionAttention}).catch(()=>{});}
});
function idleUnqualifiedReconnect(){
 return Boolean(port&&!grant&&connectionAttention==='storedFenceMismatch'&&!reconnectBusy&&!mutationBusy&&!setupActiveCommands&&!unknownAttempts.size&&!activeBrowserInputs.size&&!lifecycleGuardId&&!privatePending&&!privateAdmission&&!privateFlow&&!privatePrivacy&&!privateRedactions.length&&port!==privateSilencedPort);
}
let inventoryRecoveryTimer=null,inventoryRecoveryLast=0,qualificationDeadlineRecoveryUsed=false;
function scheduleInventoryRecovery(deadline=false){
 deadline=deadline===true; // Chrome event listeners pass tab IDs, not a retry mode.
 const eligible=()=>idleUnqualifiedReconnect()&&(deadline?reconnectDiagnosticReason==='deadline'&&!qualificationDeadlineRecoveryUsed:reconnectDiagnosticPhase==='inventory'&&reconnectDiagnosticReason==='inventoryChanged');
 if(inventoryRecoveryTimer||!eligible())return;
 const expected=port,delay=Math.max(100,1000-(Date.now()-inventoryRecoveryLast));
 inventoryRecoveryTimer=setTimeout(()=>{
  inventoryRecoveryTimer=null;
  if(port!==expected||!eligible())return;
  // One metadata retry for this unresolved deadline generation. A fresh port
  // obtains a fresh authenticated broker challenge; never replay the command.
  if(deadline)qualificationDeadlineRecoveryUsed=true;
  inventoryRecoveryLast=Date.now();void connect().catch(()=>{});
 },delay);inventoryRecoveryTimer?.unref?.();
}
// A missing receipt is never resolved by a navigation event. The event only
// requests a new complete authenticated census after its exact source changes.
let missingReceiptRecoveryTimer=null;
const missingReceiptRecoveryEvents=new Set();
function missingReceiptRecoveryEligible(){
 const d=reconnectRecoveryDiagnostic;
 return idleUnqualifiedReconnect()&&reconnectDiagnosticPhase==='inspect'&&reconnectDiagnosticReason==='unknownReceipts'&&
  d?.missingLiveReceipts>0&&d.unknownLiveReceipts===0&&d.privateSources===0&&d.unavailableExecutors===0&&reconnectMissingDocuments.length>0;
}
function scheduleMissingReceiptRecovery(event,removed=false){
 if(missingReceiptRecoveryTimer||!missingReceiptRecoveryEligible())return;
 const tabId=removed?event:event?.tabId;
 if(!Number.isSafeInteger(tabId)||tabId<1||!removed&&(event?.frameId!==0||!channelShape(event.documentId)))return;
 const source=reconnectMissingDocuments.find(i=>i.tabId===tabId&&(removed||i.frameId===event.frameId&&i.documentId!==event.documentId));
 if(!source)return;
 const eventKey=JSON.stringify([source.tabId,source.frameId,source.documentId,removed?'removed':event.documentId]);
 if(missingReceiptRecoveryEvents.has(eventKey)||missingReceiptRecoveryEvents.size>=200)return;
 missingReceiptRecoveryEvents.add(eventKey);
 const expected=port;
 missingReceiptRecoveryTimer=setTimeout(()=>{
  missingReceiptRecoveryTimer=null;
  if(port!==expected||!missingReceiptRecoveryEligible())return;
  void connect().catch(()=>{});
 },100);missingReceiptRecoveryTimer?.unref?.();
}
async function connect(){
 const settings=await connectionSettings();
 if(!settings.enabled){connectionAttention='connectionDisabled';await connectionLifecycle.reconfigure();return;}
 // Explicit retry can renegotiate a blocked, idle metadata port after the
 // independent recovery conditions change. It never replaces active authority.
 if(idleUnqualifiedReconnect())closeNativeConnection();
 return connectionLifecycle.request();
}
async function connectNativeOnce(token,valid=()=>true) {
  if (port) return;
  connectionAttention = "enrollmentUnavailable"; startupFailurePort = null;metadataStartupBarrier=null;
  reconnectDiagnosticPhase="scope";reconnectDiagnosticReason="none";reconnectInventoryReason="none";reconnectJournalDiagnostic=null;
  try {
    let enrollment;
    try{enrollment=await config();}
    catch(error){
      reconnectDiagnosticReason=error?.code==='notEnrolled'?'scopeChanged':'storageFailure';
      throw error;
    }
    try{
    reconnectDiagnosticPhase="journal";reconnectDiagnosticReason="none";reconnectInventoryReason="none";reconnectJournalDiagnostic=null;
    const reconnect=await chrome.storage.local.get(reconnectKey),last=await chrome.storage.local.get("lastGrant");
    captureReconnectJournal(reconnect[reconnectKey],last.lastGrant);
    await verifyReconnectArchives(reconnect[reconnectKey]);
    if(!reconnectJournalValid(reconnect[reconnectKey],last.lastGrant)) {
      connectionAttention="storedFenceMismatch";
      if(!pendingReconnectValid(reconnect[reconnectKey],last.lastGrant))throw reconnectJournalRefuse("lineageInvalid");
      // Recovery inventory is proved only in executor handoff, after the
      // metadata channel exists. Pending history never authorizes a renderer.
    }
    const retained = await chrome.storage.local.get(MechanizeRetirement.KEY);
    if (retained[MechanizeRetirement.KEY] !== undefined) {
      lifecycleGuardId = "restart-reconciliation-required";

    }
    const session = await chrome.storage.session.get(null);
    const durableProtection = await chrome.storage.local.get("mechanizeProtectedOrigins");
    const origins = durableProtection.mechanizeProtectedOrigins ?? session.mechanizeProtectedOrigins;
    if (origins !== undefined) {
      if (!Array.isArray(origins) || origins.length > 256 || origins.some(value => typeof value !== "string" || !value.startsWith("https://") || new URL(value).origin !== value)) throw Error();
      for (const origin of origins) protectedOrigins.add(origin);
    }
    const legacy=(await chrome.storage.local.get('mechanizeLegacyProtectedOriginsV1')).mechanizeLegacyProtectedOriginsV1;
    if(legacy!==undefined&&(!Array.isArray(legacy)||legacy.length>256||legacy.some(o=>typeof o!=='string'||!protectedOrigins.has(o))))throw Error();
    for(const o of legacy===undefined?protectedOrigins:legacy)legacyProtectedOrigins.add(o);
    if(legacy===undefined)await chrome.storage.local.set({mechanizeLegacyProtectedOriginsV1:[...legacyProtectedOrigins]});
    await protectionScopes.load();
    for(const o of protectedOrigins)if(!protectionScopes.boundOrigin(o))legacyProtectedOrigins.add(o);
    if (session.mechanizeLifecycleInhibited) {
      lifecycleGuardId = "restart-reconciliation-required";

    }
    for(const [key,value] of Object.entries(session))if(key.startsWith('browserProtocolInput:')&&value?.state!=='released')retainUnknown(key.slice('browserProtocolInput:'.length));
    for (const key of Object.keys(session)) if (key.startsWith("browserIntent:") && (!session[key.replace("browserIntent:", "browserReceipt:")] || session[key.replace("browserIntent:", "browserReceipt:")].dispatchState === "unknown" || session[key.replace("browserIntent:", "browserReceipt:")].error?.dispatchState === "unknown")) retainUnknown(key.slice("browserIntent:".length),session[key]);
    await playwrightWorker.recover();
    }catch(error){
      metadataStartupBarrier=connectionAttention==='storedFenceMismatch'?'storedFenceMismatch':'inventoryUnavailable';
    }
    if(!valid())return;
    connectionAttention = "hostLaunchFailed";
    try { port = chrome.runtime.connectNative("com.viant.mechanize"); }
    catch (error) { connectionAttention = nativeAttention(error?.message); throw Error(); }
    const connectedPort = port;
    let forwardingStarted = false, startupCause = null;
    port.onMessage.addListener(command => {
      if (port !== connectedPort) return;
      if (command?.type === "nativeHostError") {
        // Only a startup frame from this exact own native port can diagnose
        // startup. Once forwarding/private work begins this lane is closed.
        if (forwardingStarted || privatePending || privateAdmission || connectedPort === privateSilencedPort) return;
        const code = command && Object.keys(command).sort().join() === "code,type" && typeof command.code === "string" && nativeHostStartupCodes.has(command.code)
          ? command.code : "nativeHostStartupUnavailable";
        if (!startupCause || startupCause === "nativeHostStartupUnavailable") startupCause = code;
        startupFailurePort = connectedPort; connectionAttention = startupCause;
        chrome.runtime.sendMessage({type:"nativeConnectionStatus",connected:false,attentionCode:startupCause}).catch(()=>{});
        return;
      }
      if (startupCause) return; // Failed startup cannot qualify later traffic.
      if(['enrolled','processQualified'].includes(command?.type)&&['brokerEpoch','channelEpoch','scopeHash'].every(key=>typeof command[key]==='string'&&command[key])){connectionAttention='none';void connectionLifecycle.acknowledged(token);}
      forwardingStarted = true;
      if (!maintenanceBusy && typeof command?.type === "string" && command.type.startsWith("playwright.")) { void playwrightWorker.receive(command, connectedPort); return; }
      if (!controllers.receive(command)) receive(command);
    });
    port.onDisconnect.addListener(() => {
      // Reading lastError consumes Chrome's transport diagnostic; only a public
      // disconnected flag is sent to extension UI, never native-host output.
      const transportCause = nativeAttention(chrome.runtime.lastError?.message);
      const attentionCode = startupCause || transportCause;
      if (port !== connectedPort) return;
      closeNativeConnection(connectedPort);
      connectionAttention=attentionCode;
      void connectionLifecycle.failed(token);
      chrome.runtime.sendMessage({type:'nativeConnectionStatus',connected:false,attentionCode}).catch(()=>{});
    });
    if (!startupCause) connectionAttention = "none";
    let lastGrant;try{
      const saved=(await chrome.storage.local.get('lastGrant')).lastGrant;
      if(saved!==undefined){
        const keys=['brokerEpoch','channelEpoch','scopeHash','mutationFingerprintVersion','leaseRequired','trustScope','scopeQualified','profileQualified'];
        const valid=saved&&typeof saved==='object'&&!Array.isArray(saved)&&Object.keys(saved).every(key=>keys.includes(key))&&fenceKeys.every(key=>channelShape(saved[key]))&&/^[a-f0-9]{64}$/.test(saved.scopeHash)&&
          (saved.mutationFingerprintVersion===undefined||[1,2].includes(saved.mutationFingerprintVersion))&&['leaseRequired','scopeQualified','profileQualified'].every(key=>saved[key]===undefined||typeof saved[key]==='boolean')&&(saved.trustScope===undefined||['desktop','profile'].includes(saved.trustScope));
        if(valid)lastGrant=Object.fromEntries(keys.filter(key=>Object.hasOwn(saved,key)).map(key=>[key,saved[key]]));else metadataStartupBarrier='inventoryUnavailable';
      }
    }catch{metadataStartupBarrier='inventoryUnavailable';}
    // This fixed metadata hello is independent of secret/document visibility.
    // No retained document or input payload is replayed on a replacement port.
    if(port===connectedPort&&valid())connectedPort.postMessage({type:'hello',protocolVersion:1,playwrightTargetRetirementVersion:1,selectOptionVersion:1,privacySourceRetirementVersion:1,setupMetadataVersion:1,manualPrivacyDocumentVersion:1,focusedLocationVersion:1,tabMetadataVersion:1,tabInventoryVersion:1,extensionMaintenanceVersion:1,openOriginVersion:1,protectionScopeVersion:1,credentialPublicReadVersion:2,controllerResultChunkVersion:1,privateInspectionDiagnosticVersion:1,controlBadgeVersion:2,visibilityUnknownVersion:1,workerBuild:34,...(chrome.runtime.getManifest().permissions?.includes('debugger')?{playwrightRelayVersion:1,playwrightLocatorVersion:1}:{}),extensionVersion:chrome.runtime.getManifest().version,profileChannel:enrollment.profileChannel,browserInstance:enrollment.browserInstance,lastGrant,documents:[]});

  } catch {
    if (lifecycleGuardId) connectionAttention = "lifecycleInhibited";
    const failedPort = port;
    controllers.reset();
    rearmRetiredUnknownTargets();publicReadScopes.clear();port = null; grant = null; setupFence = null; privateAdmission = null; privateFlow=null;privatePrivacy=null;manualPrivacyFlow=null;privateRedactions=[];
    try { failedPort?.disconnect(); } catch {}
    // The transport scheduler decides the next bounded attempt; no command is replayed.
  }
}
chrome.runtime.onMessage.addListener((message,sender,reply)=>{
 if(message?.type!=='browserInputLocal')return;
 const held=activeBrowserInputs.get(message.requestId),c=held?.command;
 const allowed=()=> Boolean(held&&!held.used&&c&&c.action==='element.press'&&c.fingerprintVersion===2&&
  port===held.admittedPort&&grant===held.admittedGrant&&!ordinaryPrivateBlocked(c.identity)&&(!privatePrivacy||ordinaryDisjoint(c.identity)||privatePrivacy.committed&&privacyDocument(c.identity))&&!lifecycleGuardId&&!domUnknownBlocked(c.attemptId,c.identity)&&
  documentControlLeases.get(`${c.identity.tabId}:${c.identity.documentId}`)?.id===c.controlLease?.id&&
  documentControlLeases.get(`${c.identity.tabId}:${c.identity.documentId}`)?.generation===c.controlLease?.generation&&
  (!isProtectedURL(documentOrigins.get(`${c.identity.tabId}:${c.identity.documentId}`),c.identity)||privatePrivacy?.committed&&privacyDocument(c.identity)));
 const refuse=errorCode=>reply({dispatchState:'notDispatched',effectState:'none',errorCode});
 if(!c){refuse('browserInputPermitUnavailable');return;}
 if(sender?.id!==chrome.runtime.id||sender.tab?.id!==c.identity.tabId||sender.frameId!==0||sender.documentId!==c.identity.documentId){refuse('browserInputSenderMismatch');return;}
 if(Object.keys(message).sort().join()!=='action,attemptId,deadlineUnixMs,point,requestId,type'||message.action!=='click'||message.attemptId!==c.attemptId||message.deadlineUnixMs!==c.deadlineUnixMs){refuse('browserInputRequestMismatch');return;}
 if(!allowed()){refuse('browserInputAuthorityChanged');return;}
 // Admission is single-use. Later checks retain the same command and authority.
 held.used=true;
 const current=()=>activeBrowserInputs.get(c.requestId)===held&&port===held.admittedPort&&grant===held.admittedGrant&&!ordinaryPrivateBlocked(c.identity)&&(!privatePrivacy||ordinaryDisjoint(c.identity)||privatePrivacy.committed&&privacyDocument(c.identity))&&!lifecycleGuardId&&
  documentControlLeases.get(`${c.identity.tabId}:${c.identity.documentId}`)?.id===c.controlLease?.id&&
  documentControlLeases.get(`${c.identity.tabId}:${c.identity.documentId}`)?.generation===c.controlLease?.generation;
 const key='browserProtocolInput:'+c.attemptId;
 (async()=>{
  await chrome.storage.session.set({[key]:{state:'pending',tabId:c.identity.tabId,documentId:c.identity.documentId}});
  const result=current()?await browserInput.click(c.identity,message.point,Math.min(c.deadlineUnixMs,Date.now()+3000),current):
    {dispatchState:'notDispatched',effectState:'none',errorCode:'browserInputAuthorityChanged'};
  if(result.dispatchState==='unknown')retainUnknown(c.attemptId,c);
  await chrome.storage.session.set({[key]:{state:result.dispatchState==='unknown'?'unknown':'released',tabId:c.identity.tabId,documentId:c.identity.documentId}});
  return result;
 })().then(reply,()=>{retainUnknown(c.attemptId,c);reply({dispatchState:'unknown',effectState:'unknown',errorCode:'browserInputUnavailable'});});
 return true;
});
chrome.runtime.onMessage.addListener((message, sender, reply) => {
  // Only the extension options page can request connection. No page bridge.
  // Chrome includes sender.tab for an options_page opened in a normal tab.
  // The authenticated top-level frame and exact extension URL/origin matter.
  if (sender?.id !== chrome.runtime.id || sender.url !== chrome.runtime.getURL("options.html") || !["connect","connectionStatusLocal"].includes(message?.type)||Object.keys(message).length!==1) return;
  if (sender.origin !== chrome.runtime.getURL("").replace(/\/$/, "") || sender.frameId !== 0 ||
      !Number.isInteger(sender.tab?.id) || sender.tab.id < 0) {
    // A refused options-page context never opens the native host. Keep this
    // distinct from host failure without returning any sender or error data.
    reply({connected: false, attentionCode: "setupContextUnqualified"});
    return;
  }
  if(message.type==='connectionStatusLocal'){
    connectionSettings().then(settings=>reply({connected:Boolean(port&&port!==startupFailurePort),qualified:Boolean(grant),enabled:settings.enabled,retryScheduled:connectionLifecycle.status().retryScheduled,attentionCode:settings.enabled?connectionAttention:'connectionDisabled'}));return true;
  }
  connect().then(() => reply(port && port !== startupFailurePort ? {connected:true,qualified:Boolean(grant),attentionCode:connectionAttention} : {connected:false,attentionCode:connectionAttention}));
  return true;
});
chrome.webNavigation.onCommitted.addListener(event => {
  noteInactiveFrame(event.tabId,event);
  for(const [key,value]of publicReadScopes)if(value.proof.identity.tabId===event.tabId)publicReadScopes.delete(key);
  for(const key of disjointDocuments.keys())if(key.startsWith(event.tabId+":")&&key!==`${event.tabId}:${event.documentId}`)disjointDocuments.delete(key);
  playwrightWorker.invalidate(held=>held.identity.tabId===event.tabId&&event.frameId===0&&held.identity.documentId!==event.documentId,true);
  for (const [key, identity] of documents) if (identity.tabId === event.tabId && identity.frameId === event.frameId && identity.documentId !== event.documentId) { if(documentControlLeases.has(key))inactiveLeaseDocuments.add(key);documents.delete(key); documentFingerprintVersions.delete(key); documentControlLeases.delete(key); documentOrigins.delete(key); }
  if (grant && !privatePending) { const admitted = port; config().then(inventory).then(result => { if (port === admitted) send({type: "documents", ...result}); }).catch(() => {}); }
});
const refreshInventory = event => {if(event?.tabId)for(const [key,value]of publicReadScopes)if(value.proof.identity.tabId===event.tabId)publicReadScopes.delete(key);  if(event?.url&&privatePrivacy?.active&&event.tabId===privatePrivacy.identity.tabId&&protectionScopes.loginRoute(event.url,privatePrivacy.identity)&&new URL(event.url).origin+new URL(event.url).pathname!==privatePrivacy.publicRoute){privatePrivacy.active=false;}
 if (grant && !privatePending) { const admitted = port; config().then(inventory).then(result => { if (port === admitted) send({type: "documents", ...result}); }).catch(() => {}); } };
for (const event of [chrome.webNavigation.onHistoryStateUpdated, chrome.webNavigation.onReferenceFragmentUpdated, chrome.webNavigation.onCompleted, chrome.tabs.onUpdated, chrome.tabs.onActivated]) event?.addListener(refreshInventory);
chrome.tabs.onRemoved.addListener(tabId => { for(const [key,value]of publicReadScopes)if(value.proof.identity.tabId===tabId)publicReadScopes.delete(key); playwrightWorker.invalidate(held=>held.identity.tabId===tabId); for (const [key, identity] of documents) if (identity.tabId === tabId) { documents.delete(key); documentFingerprintVersions.delete(key); documentControlLeases.delete(key); documentOrigins.delete(key); } refreshInventory(); });
chrome.storage.onChanged?.addListener((changes,area)=>{if(area==='local'&&(changes.enrollment||changes.connectionEnabled))void connectionLifecycle.reconfigure();});
for(const event of [chrome.permissions?.onAdded,chrome.permissions?.onRemoved])event?.addListener(()=>{void connectionLifecycle.reconfigure();});
chrome.runtime.onStartup?.addListener(()=>{void connectionLifecycle.request();});
globalThis.addEventListener?.('online',()=>{void connectionLifecycle.request();});
chrome.runtime.onInstalled?.addListener(()=>{void connectionLifecycle.reconfigure();});
void connectionLifecycle.start();

// The toolbar is a trusted user entry point, not a page-message command.
// Reuse our own setup tab and never inspect or navigate website tabs.
let setupPagePending = null;
async function openSetupPage() {
  if (setupPagePending) return setupPagePending;
  setupPagePending = (async () => {
    const address = chrome.runtime.getURL("options.html");
    const ownTabs = await chrome.tabs.query({url: address});
    const existing = ownTabs.find(tab => Number.isInteger(tab.id) && tab.id >= 0 &&
      typeof tab.url === "string" && tab.url.split("#")[0] === address);
    if (existing) {
      await chrome.tabs.update(existing.id, {active: true});
      if (Number.isInteger(existing.windowId)) await chrome.windows.update(existing.windowId, {focused: true});
    } else {
      await chrome.tabs.create({url: address, active: true});
    }
  })().catch(() => {}).finally(() => { setupPagePending = null; });
  return setupPagePending;
}
// A material tab lifecycle change can remove an inventory blocker. Request a
// fresh authenticated handshake only through the existing idle recovery gate.
chrome.tabs.onRemoved?.addListener(scheduleInventoryRecovery);
chrome.tabs.onRemoved?.addListener(tabId=>scheduleMissingReceiptRecovery(tabId,true));
for(const event of [chrome.webNavigation.onCommitted,chrome.webNavigation.onCompleted])event?.addListener(details=>{if(details?.frameId===0){scheduleInventoryRecovery();scheduleMissingReceiptRecovery(details);}});
chrome.tabs.onUpdated?.addListener((_id,change)=>{if(change?.status==='complete')scheduleInventoryRecovery();});
chrome.action?.onClicked?.addListener(() => { void openSetupPage(); });
