function setConnectionStatus(message, state = "idle") {
  const status = document.getElementById("status");
  if (!status) return;
  status.textContent = message;
  status.setAttribute("aria-label", message);
  status.dataset.state = state;
}
// Bootstrap a public website when no ordinary web tab exists yet. Opening a
// tab grants no broker/tool authority and never transports credentials.
document.getElementById("open-website")?.addEventListener("click", async event => {
  if (event.isTrusted !== true || typeof location === "undefined" ||
      location.protocol !== "chrome-extension:" || location.host !== chrome.runtime.id || location.pathname !== "/options.html") return;
  const status = document.getElementById("open-website-status");
  try {
    const input = document.getElementById("website-origin").value.trim();
    const url = new URL(input);
    if (!["http:", "https:"].includes(url.protocol) || url.username || url.password || url.search || url.hash ||
        !["", "/"].includes(url.pathname) || ![url.origin, url.origin + "/"].includes(input)) throw Error();
    const {enrollment} = await chrome.storage.local.get("enrollment");
    if (!MechanizeProtocol.websiteScopeValid(enrollment) || !MechanizeProtocol.websiteAllowed(url.href, enrollment) ||
        !await chrome.permissions.contains({origins: [url.origin + "/*"]})) throw Error();
    // Leave the setup tab visible for a verifiable completion status. The MCP
    // client can discover and activate the new tab by its opaque handle.
    await chrome.tabs.create({url: url.origin + "/", active: false});
    status.textContent = "Website opened in a new tab.";
    status.setAttribute("aria-label", "Website opened in a new tab");
  } catch {
    status.textContent = "Could not open the website. Use an approved HTTP or HTTPS origin without a path, query, or login details.";
    status.setAttribute("aria-label", "Website opening unavailable");
  }
});
// Maintenance is available only through a trusted click in our own options
// document. No website message or background timer can request a reload.
document.getElementById("reload-extension")?.addEventListener("click", async event => {
  if (event.isTrusted !== true || typeof location === "undefined" ||
      location.protocol !== "chrome-extension:" || location.host !== chrome.runtime.id || location.pathname !== "/options.html") return;
  try {
    // Chrome closes extension-owned pages on reload. Keep the exact public
    // management page available so the user can see the resulting version.
    await chrome.tabs.create({url: `chrome://extensions/?id=${chrome.runtime.id}`, active: true});
    chrome.runtime.reload();
  } catch {
    setConnectionStatus("Extension reload is unavailable. Open Chrome extension settings to reload.", "error");
  }
});
document.getElementById("read-connection-diagnostics")?.addEventListener("click", async () => {
  const view = document.getElementById("connection-diagnostics");
  const details = document.getElementById("connection-diagnostics-detail");
  view.textContent = "Reading connection diagnostics…";
  view.setAttribute("aria-label", "Connection diagnostics reading");
  details.textContent = "";
  details.setAttribute("aria-label", "Connection diagnostic details not read");
  try {
    const {diagnostics: d} = await chrome.runtime.sendMessage({type: "connectionDiagnosticsLocal"});
    const phases = ["idle", "scope", "barriers", "journal", "inventory", "inspect", "prepare", "adopt", "commit"];
    const reasons = ["none", "portChanged", "deadline", "busy", "unknownReceipts", "privateProtection", "lifecycle", "scopeChanged", "journalChanged", "inventoryChanged", "storageFailure", "rendererUnavailable", "executorRefused", "injectionUnavailable", "restrictedBrowserPage", "packagedExecutorUnavailable", "documentChanged", "websitePermissionMissing", "extensionContextInvalidated", "restrictedFrame", "injectionArgumentsRejected", "executorEvaluationFailed"];
    const inventoryReasons=["none","tabQueryUnavailable","tabListInvalid","tabLimitExceeded","tabMetadataInvalid","tabIDInvalid","tabIDDuplicate","tabURLUnavailable","tabURLInvalid","pendingNavigation","incognitoTab","discardedTab","nonSetupTab","frameQueryUnavailable","frameListUnavailable","frameLimitExceeded","frameMetadataInvalid","frameIDInvalid","frameIDDuplicate","frameParentInvalid","frameDocumentUnavailable","frameError","frameLifecycleInactive","frameTypeDenied","frameRootURLDenied","frameChildURLDenied","frameRootMissing","frameParentMissing","frameCycle","inventoryDrift"];
    const validInventoryLimit=value=>Boolean(value&&Object.keys(value).sort().join()==='bound,count,limit'&&['setupFrames','perTabFrames','censusTotal','eligibleDocuments','orphanEvidence','inventoryBytes'].includes(value.bound)&&Number.isSafeInteger(value.count)&&value.count>=0&&value.count<=4294967295&&Number.isSafeInteger(value.limit)&&value.limit>0&&value.limit<=(value.bound==='inventoryBytes'?262144:4096)&&value.count>value.limit);
    const validMissingReceiptSources=value=>Boolean(value&&Object.keys(value).sort().join()==='count,hashes,truncated,version'&&value.version===1&&Number.isInteger(value.count)&&value.count>0&&value.count<=200&&Array.isArray(value.hashes)&&value.hashes.length===Math.min(value.count,16)&&value.hashes.every(h=>typeof h==='string'&&/^[a-f0-9]{64}$/.test(h))&&new Set(value.hashes).size===value.hashes.length&&value.hashes.every((h,i)=>i===0||value.hashes[i-1]<h)&&value.truncated===(value.count>16));
    if (!d || Object.keys(d).filter(key=>!['inventoryReason','inventoryLimit','missingReceiptSources'].includes(key)).sort().join() !== "credentialProtection,grantRelation,journalVersion,lifecyclePending,phase,reason,reconnectJournal,retirementPending,version" ||
        Object.hasOwn(d,'inventoryReason')&&(d.reason!=='inventoryChanged'||!inventoryReasons.includes(d.inventoryReason)) ||
        Object.hasOwn(d,'inventoryLimit')&&(d.reason!=='inventoryChanged'||!validInventoryLimit(d.inventoryLimit)) ||
        Object.hasOwn(d,'missingReceiptSources')&&(d.phase!=='inspect'||d.reason!=='unknownReceipts'||!validMissingReceiptSources(d.missingReceiptSources)) ||
        d.version !== 3 || ![-1,0,1,2,3,4,5,6].includes(d.journalVersion) || !["none", "unavailable", "both", "old", "new", "neither"].includes(d.grantRelation) ||
        !phases.includes(d.phase) || !reasons.includes(d.reason) || !["absent", "pending", "adopted", "unrecognized"].includes(d.reconnectJournal) ||
        ![d.credentialProtection, d.lifecyclePending, d.retirementPending].every(v => typeof v === "boolean")) throw Error();
    const text = `Reconnect phase: ${d.phase}. Reason: ${d.reason}. Credential protection: ${d.credentialProtection}. Lifecycle pending: ${d.lifecyclePending}. Retirement pending: ${d.retirementPending}. Reconnect journal: ${d.reconnectJournal}. Journal version: ${d.journalVersion}. Grant relation: ${d.grantRelation}.${d.inventoryReason?' Inventory reason: '+d.inventoryReason+'.':''}${d.inventoryReason==='tabURLUnavailable'?' Chrome withheld a tab URL. Mechanize cannot confirm that only setup pages remain. No recovery state was changed.':''}`;
    const annotated=text+(d.inventoryLimit?` Inventory bound: ${d.inventoryLimit.bound}. Observed: ${d.inventoryLimit.count}. Limit: ${d.inventoryLimit.limit}.`: '')+(d.missingReceiptSources?` Missing receipt source hashes (${d.missingReceiptSources.count}${d.missingReceiptSources.truncated?", truncated":""}): ${d.missingReceiptSources.hashes.join(", ")}.`:"");
    details.textContent = annotated;
    details.setAttribute("aria-label", annotated);
    view.textContent = "Connection diagnostics ready.";
    view.setAttribute("aria-label", "Connection diagnostics ready");
  } catch {
    view.textContent = "Connection diagnostics unavailable. No state was changed.";
    view.setAttribute("aria-label", "Connection diagnostics unavailable");
  }
});
function setWebsiteMode(all) {
  document.getElementById("all-sites").checked = all;
  document.getElementById("selected-sites").checked = !all;
  document.getElementById("selected-websites").hidden = all;
  document.getElementById("origins").disabled = all;
}
document.getElementById("all-sites").addEventListener("change", () => setWebsiteMode(true));
document.getElementById("selected-sites").addEventListener("change", () => setWebsiteMode(false));

// Public setup hints only. They never grant access or carry credential bytes.
// The human still saves the scope and approves any missing Chrome permission.
(() => {
  if (typeof location === "undefined" || !location.hash) return;
  const status = document.getElementById("status");
  try {
    const base = chrome.runtime.getURL("options.html");
    const actual = new URL(location.href), expected = new URL(base);
    if (actual.protocol !== expected.protocol || actual.host !== expected.host || actual.pathname !== expected.pathname || actual.search || location.hash.length > 4096) throw Error();
    const hints = new URLSearchParams(location.hash.slice(1));
    const keys = [...hints.keys()];
    if (keys.length !== 3 || new Set(keys).size !== 3 || keys.some(key => !["channel", "instance", "origins", "access"].includes(key)) || keys.includes("origins") === keys.includes("access")) throw Error();
    const channel = hints.get("channel"), instance = hints.get("instance"), rawOrigins = hints.get("origins");
    const allWebsites = hints.get("access") === "all";
    if (![channel, instance].every(value => /^[A-Za-z0-9._-]{1,128}$/.test(value || "")) || keys.includes("access") && !allWebsites || !allWebsites && (!rawOrigins || rawOrigins.length > 2048)) throw Error();
    const origins = allWebsites ? [] : rawOrigins.split("\n");
    if (!MechanizeProtocol.websiteScopeValid({origins, allWebsites})) throw Error();
    // Remove setup hints so worker sender.url retains its exact enrolled page.
    history.replaceState(null, "", base);
    document.getElementById("channel").value = channel;
    document.getElementById("instance").value = instance;
    document.getElementById("origins").value = origins.join("\n");
    setWebsiteMode(allWebsites);
    setConnectionStatus("Connection details prepared. Review and save website access.", "prepared");
    const details = document.getElementById("connection-details");
    if (details) details.open = false;
  } catch {
    setConnectionStatus("Setup link unavailable. Enter the connection details supplied locally by Mechanize.", "error");
  }
})();

const disconnectedStatus = "Native host disconnected. Saved website access is separate; review the broker and native-host enrollment.";
function connectionFailure(code) {
  // Closed public vocabulary only: never display Chrome/native error text.
  const messages = {
    websiteScopeMismatch: "Mechanize’s local browser scope must match the saved website scope before connection can finish.",
    connectionDisabled: "Automatic connection is disabled. Enable it to connect using saved details.",
    hostNotRegistered: "Chrome cannot find Mechanize’s local connector. Repair Chrome registration in Mechanize.",
    hostLaunchFailed: "Chrome could not start Mechanize’s local connector. Check the local installation in Mechanize.",
    hostExited: "Mechanize’s local connector stopped before connection completed. Website permission is retained.",
    hostAccessDenied: "Chrome refused access to Mechanize’s local connector. Check extension enrollment in Mechanize.",
    storedFenceMismatch: "The previous executor could not be independently quiesced. Keep receipt history and review recovery in Mechanize; do not repeat an uncertain action.",
    lifecycleInhibited: "Connection is held for recovery of an earlier operation. Review recovery in Mechanize; do not repeat the operation.",
    enrollmentUnavailable: "Saved connection details are unavailable. Review Chrome enrollment in Mechanize.",
    configUnavailable: "The local connector could not read its configuration. Repair the connector installation in Mechanize.",
    processTrustUnavailable: "The local connector could not verify its Chrome process. Review the signed connector installation in Mechanize.",
    runningImageMismatch: "The running connector does not match the enrolled executable. Repair the local connector installation in Mechanize.",
    nativeHostSignatureUnavailable: "The connector’s installed signature could not be verified. Repair the local connector installation in Mechanize.",
    chromeSignatureUnavailable: "Chrome’s signing identity could not be verified. Review the Chrome installation in Mechanize.",
    nativeHostProcessUnavailable: "The running connector’s process identity could not be read. Review the local connector in Mechanize.",
    nativeHostUIDUnavailable: "The connector is running under an unexpected user. Review the local connector installation in Mechanize.",
    nativeHostDynamicSignatureUnavailable: "The running connector’s signing identity could not be verified. Repair the local connector installation in Mechanize.",
    chromeImagePathMismatch: "Chrome is running from a different executable location. Quit Chrome normally and reopen it from Applications, then connect again. If this persists, repair the Chrome connection in Mechanize.",
    chromeAncestryUnavailable: "The connector’s Chrome process ancestry could not be verified. Review how Chrome launched the connector in Mechanize.",
    chromeParentUnavailable: "The connector’s direct Chrome parent could not be verified. Review how Chrome launched the connector in Mechanize.",
    ancestryChanged: "The connector’s process ancestry changed during verification. Review the current Chrome connection in Mechanize.",
    launchScopeUnavailable: "The local connector could not verify Chrome’s launch scope. Review Chrome enrollment in Mechanize.",
    socketUnavailable: "The local connector could not open the broker connection. Check that Mechanize’s broker is running.",
    brokerPeerUnavailable: "The broker could not identify the local connector process.",
    brokerPeerAuditUnavailable: "The broker could not read the local connector process identity.",
    brokerProcessUnqualified: "The broker rejected the local connector process identity.",
    brokerHelloUnavailable: "The broker did not receive a valid connection handshake.",
    brokerHelloRejected: "The broker rejected the connection handshake.",
    brokerEnrollmentRefused: "The broker did not accept the saved connector enrollment.",
    brokerChannelBusy: "The browser channel already has an active connector.",
    brokerScopeUnqualified: "The broker could not qualify the saved browser scope.",
    brokerHandshakeUnavailable: "The local connector could not complete the broker handshake.",
    brokerUnavailable: "Mechanize’s broker is unavailable. Check the local broker in Mechanize.",
    brokerTrustUnavailable: "The local connector could not verify the broker’s signing identity. Repair the matched local installation in Mechanize.",
    enrollmentCredentialUnavailable: "The local connector’s enrollment credential is unavailable. Repair connector enrollment in Mechanize.",
    helloIdentityMismatch: "The local connector’s enrolled identity does not match this extension. Review Chrome enrollment in Mechanize.",
    nativeHostStartupUnavailable: "The local connector reported an unrecognized startup failure. Review the local installation in Mechanize."
  };
  return typeof code === "string" && Object.prototype.hasOwnProperty.call(messages, code) ? messages[code] : disconnectedStatus;
}
let nativeStatusChanges = 0;
let connectionAttempts = 0;
let websiteScopeMismatch = false, nativeStartupFailure = null;
const startupFailureCodes = new Set(["brokerPeerUnavailable","brokerPeerAuditUnavailable","brokerProcessUnqualified","brokerHelloUnavailable","brokerHelloRejected","brokerEnrollmentRefused","brokerChannelBusy","brokerScopeUnqualified","brokerHandshakeUnavailable","configUnavailable","processTrustUnavailable","runningImageMismatch","nativeHostSignatureUnavailable","chromeSignatureUnavailable","nativeHostProcessUnavailable","nativeHostUIDUnavailable","nativeHostDynamicSignatureUnavailable","chromeImagePathMismatch","chromeAncestryUnavailable","chromeParentUnavailable","ancestryChanged","launchScopeUnavailable","socketUnavailable","brokerUnavailable","brokerTrustUnavailable","enrollmentCredentialUnavailable","helloIdentityMismatch","nativeHostStartupUnavailable"]);
function rememberedConnectionFailure(code) {
  if (!nativeStartupFailure && typeof code === "string" && startupFailureCodes.has(code)) nativeStartupFailure = code;
  return connectionFailure(nativeStartupFailure || code);
}
function showConnectedStatus(state) {
  if (state.qualified === true) { websiteScopeMismatch = false; nativeStartupFailure = null; }
  if (typeof state.attentionCode === "string" && state.attentionCode !== "none") {
    if (state.attentionCode === "websiteScopeMismatch") websiteScopeMismatch = true;
    setConnectionStatus(connectionFailure(state.attentionCode), "error");
  } else if (state.qualified === true) {
    setConnectionStatus("Connected; executor qualified.", "ready");
  } else if (!websiteScopeMismatch) {
    nativeStartupFailure = null;
    setConnectionStatus("Native host connection opened; broker authorization is still required. Protected operations and recovery barriers must qualify separately.", "pending");
  }
}
chrome.runtime.onMessage.addListener((message, sender) => {
  if (sender?.id !== chrome.runtime.id || sender.url !== chrome.runtime.getURL("worker.js") || message?.type !== "nativeConnectionStatus") return;
  if (message.connected === true) {
    nativeStatusChanges++;
    showConnectedStatus(message);
  } else if (message.connected === false) {
    nativeStatusChanges++;
    if (message.attentionCode === "websiteScopeMismatch") {
      websiteScopeMismatch = true;
      setConnectionStatus(connectionFailure(message.attentionCode), "error");
      return;
    }
    // Preserve a diagnosed scope refusal over a subsequent generic port exit.
    if (websiteScopeMismatch) return;
    setConnectionStatus(rememberedConnectionFailure(message.attentionCode), "error");
  }
});
function ownOptionsDocument() {
  return typeof location !== "undefined" &&
    location.protocol === "chrome-extension:" && location.host === chrome.runtime.id && location.pathname === "/options.html";
}
function trustedOptionsGesture(event) {
  return event?.isTrusted === true && ownOptionsDocument();
}
function enrollmentValid(enrollment) {
  return !!enrollment && Object.keys(enrollment).every(key => ["profileChannel", "browserInstance", "origins", "allWebsites"].includes(key)) &&
    [enrollment.profileChannel, enrollment.browserInstance].every(value => typeof value === "string" && /^[A-Za-z0-9._-]{1,128}$/.test(value)) &&
    MechanizeProtocol.websiteScopeValid(enrollment);
}
function permissionScope(enrollment) {
  return {origins: enrollment.allWebsites === true ? ["https://*/*", "http://*/*"] : enrollment.origins.map(origin => origin + "/*")};
}
function setWebsiteAccessStatus(message, state = "idle") {
  const status = document.getElementById("website-access-status");
  if (!status) return;
  status.textContent = message;
  status.setAttribute("aria-label", message);
  status.dataset.state = state;
}
let accessStatusReads = 0;
async function refreshSavedWebsiteAccess() {
  const read = ++accessStatusReads;
  try {
    const {enrollment} = await chrome.storage.local.get("enrollment");
    const valid = enrollmentValid(enrollment);
    const granted = valid && await chrome.permissions.contains(permissionScope(enrollment));
    if (read !== accessStatusReads) return;
    setWebsiteAccessStatus(!valid ? "No valid website access settings are saved." : granted ?
      "Saved website access is approved in Chrome. Connection readiness is shown separately." :
      "Chrome permission is missing for the saved website scope. Review and save website access to approve it.", valid && granted ? "approved" : "missing");
  } catch {
    if (read === accessStatusReads) setWebsiteAccessStatus("Saved website access could not be checked.", "error");
  }
}
function clearConnectionDiagnostics() {
  const view = document.getElementById("connection-diagnostics");
  const details = document.getElementById("connection-diagnostics-detail");
  view.textContent = "Read connection diagnostics for this attempt.";
  view.setAttribute("aria-label", "Connection diagnostics not read");
  details.textContent = "";
  details.setAttribute("aria-label", "Connection diagnostic details not read");
}
let savingWebsiteAccess = false;
document.getElementById("enroll").addEventListener("click", async event => {
  if (!trustedOptionsGesture(event) || savingWebsiteAccess) return;
  savingWebsiteAccess = true;
  try {
    const profileChannel = document.getElementById("channel").value.trim();
    const browserInstance = document.getElementById("instance").value.trim();
    const allWebsites = document.getElementById("all-sites").checked;
    const origins = allWebsites ? [] : [...new Set(document.getElementById("origins").value.split(/\s+/).filter(Boolean))];
    const enrollment = {profileChannel, browserInstance, origins, ...(allWebsites ? {allWebsites: true} : {})};
    if (!enrollmentValid(enrollment)) throw Error("Valid channel, browser instance and exact website origins required");
    const scope = permissionScope(enrollment);
    if (!await chrome.permissions.contains(scope) && !await chrome.permissions.request(scope)) throw Error("Website permission denied");
    await chrome.storage.local.set({enrollment});
    await refreshSavedWebsiteAccess();
  } catch (error) {
    // Invalidate older asynchronous reads before rendering this save result.
    accessStatusReads++;
    const publicErrors = ["Valid channel, browser instance and exact website origins required", "Website permission denied"];
    setWebsiteAccessStatus(publicErrors.includes(error?.message) ? error.message : "Website access could not be saved. Review origins and extension permissions.", "error");
  } finally { savingWebsiteAccess = false; }
});
document.getElementById("connect").addEventListener("click", async event => {
  if (!trustedOptionsGesture(event)) return;
  const attempt = ++connectionAttempts;
  const status = document.getElementById("status");
  clearConnectionDiagnostics();
  websiteScopeMismatch = false; nativeStartupFailure = null;
  try {
    const {enrollment, connectionEnabled} = await chrome.storage.local.get(["enrollment", "connectionEnabled"]);
    if (!enrollmentValid(enrollment)) { setConnectionStatus(connectionFailure("enrollmentUnavailable"), "error"); return; }
    if (connectionEnabled === false) { setConnectionStatus(connectionFailure("connectionDisabled"), "idle"); return; }
    const disconnectVersion = nativeStatusChanges;
    const connection = await chrome.runtime.sendMessage({type: "connect"});
    if (attempt !== connectionAttempts || nativeStatusChanges !== disconnectVersion) return;
    if (connection?.attentionCode === "setupContextUnqualified") {
      setConnectionStatus("Chrome could not verify this setup page. The native host was not opened.", "error");
      return;
    }
    if (connection?.connected !== true) { setConnectionStatus(rememberedConnectionFailure(connection?.attentionCode), "error"); return; }
    showConnectedStatus(connection);
  } catch {
    if (attempt === connectionAttempts) setConnectionStatus(disconnectedStatus, "error");
  } finally {
    if (attempt === connectionAttempts) status.dataset.processedAttempt = String(attempt);
  }
});
let preferenceEdits = 0;
document.getElementById("connection-enabled").addEventListener("change", async event => {
  if (!trustedOptionsGesture(event)) return;
  ++preferenceEdits;
  const changes = nativeStatusChanges;
  const enabled = document.getElementById("connection-enabled").checked;
  try {
    await chrome.storage.local.set({connectionEnabled: enabled});
    if (document.getElementById("connection-enabled")?.checked === enabled && changes === nativeStatusChanges) setConnectionStatus(enabled ?
      "Automatic connection enabled. Saved details will be used; protected operations and recovery barriers still apply." :
      "Automatic connection disabled. Saved website access is retained.", "idle");
  } catch {
    if (document.getElementById("connection-enabled")?.checked === enabled) setConnectionStatus("The automatic connection setting could not be saved.", "error");
  }
});
chrome.permissions.onAdded?.addListener(refreshSavedWebsiteAccess);
chrome.permissions.onRemoved?.addListener(refreshSavedWebsiteAccess);
chrome.storage.onChanged?.addListener((changes, area) => {
  if (area !== "local") return;
  if (changes.enrollment) void refreshSavedWebsiteAccess();
  if (changes.connectionEnabled) {
    preferenceEdits++;
    document.getElementById("connection-enabled").checked = changes.connectionEnabled.newValue !== false;
  }
});
void refreshSavedWebsiteAccess();
(async () => {
  const version = preferenceEdits;
  try {
    const {connectionEnabled} = await chrome.storage.local.get("connectionEnabled");
    if (version === preferenceEdits) document.getElementById("connection-enabled").checked = connectionEnabled !== false;
  } catch { /* No permission request or connection follows a failed read. */ }
})();

// Read transport state without opening a port or changing permissions.
(async () => {
  if (!ownOptionsDocument()) return;
  const changes = nativeStatusChanges, attempts = connectionAttempts, preference = preferenceEdits;
  try {
    const state = await chrome.runtime.sendMessage({type: "connectionStatusLocal"});
    if (changes !== nativeStatusChanges || attempts !== connectionAttempts || preference !== preferenceEdits || !state ||
        Object.keys(state).sort().join() !== "attentionCode,connected,enabled,qualified,retryScheduled" ||
        ![state.connected, state.enabled, state.qualified, state.retryScheduled].every(value => typeof value === "boolean") || typeof state.attentionCode !== "string") return;
    if (!state.enabled) setConnectionStatus(connectionFailure("connectionDisabled"), "idle");
    else if (state.connected) showConnectedStatus(state);
    else if (state.attentionCode !== "none") setConnectionStatus(rememberedConnectionFailure(state.attentionCode), "error");
    else if (state.retryScheduled) setConnectionStatus("Automatic connection retry is scheduled. Protected operations and recovery barriers still apply.", "pending");
  } catch { /* A read failure cannot request permission or open a connection. */ }
})();

// Restore public connection settings for toolbar-opened pages. Never overwrite
// setup-link values or human edits, and never read a credential storage key.
(async () => {
  if (typeof chrome.storage?.local?.get !== "function") return;
  const fields = ["channel", "instance", "origins"].map(id => document.getElementById(id));
  if (fields.some(field => field.value.trim())) return;
  try {
    const {enrollment} = await chrome.storage.local.get("enrollment");
    if (fields.some(field => field.value.trim()) || !enrollment ||
        Object.keys(enrollment).some(key => !["profileChannel", "browserInstance", "origins", "allWebsites"].includes(key)) ||
        ![enrollment.profileChannel, enrollment.browserInstance].every(value => typeof value === "string" && /^[A-Za-z0-9._-]{1,128}$/.test(value)) ||
        !MechanizeProtocol.websiteScopeValid(enrollment)) return;
    for (const origin of enrollment.origins) {
      if (typeof origin !== "string" || origin.length > 512) return;
      const url = new URL(origin);
      if (url.origin !== origin || url.username || url.password || (url.protocol !== "https:" && !(url.protocol === "http:" && ["localhost", "127.0.0.1"].includes(url.hostname)))) return;
    }
    fields[0].value = enrollment.profileChannel;
    fields[1].value = enrollment.browserInstance;
    fields[2].value = enrollment.origins.join("\n");
    setWebsiteMode(enrollment.allWebsites === true);
    const details = document.getElementById("connection-details");
    if (details) details.open = false;
  } catch {
    // Storage errors cannot become page content or trigger connection.
  }
})();


// Metadata bootstrap remains available with the old broker or no website executor.
document.getElementById("read-setup-metadata")?.addEventListener("click", async () => {
  const view = document.getElementById("setup-metadata");
  view.setAttribute("aria-label", "Setup metadata reading");
  view.textContent = "Reading setup metadata…";
  try {
    const reply = await chrome.runtime.sendMessage({type: "setupMetadataLocal"});
    const m = reply?.metadata;
    if (!m || m.version !== 1 || m.extensionId !== chrome.runtime.id || !/^[a-p]{32}$/.test(m.extensionId) || !/^[a-f0-9]{64}$/.test(m.storageSHA256) ||
        m.storageScope !== "extension-local-v1" || m.storageStable !== true ||
        ![m.activeCommands, m.unknownAttempts].every(v => Number.isSafeInteger(v) && v >= 0 && v <= 4096) ||
        ![m.mutationBusy, m.lifecycleInhibited, m.nativeConnected, m.executorQualified].every(v => typeof v === "boolean")) throw Error();
    view.textContent = ["Extension ID: " + m.extensionId, "Storage SHA-256 (extension local): " + m.storageSHA256,
      "Active worker commands: " + m.activeCommands, "Unknown attempts: " + m.unknownAttempts,
      "Mutation busy: " + m.mutationBusy, "Lifecycle inhibited: " + m.lifecycleInhibited,
      "Native port present: " + m.nativeConnected, "Website binding present: " + m.executorQualified,
      "Loaded directory: verify in Chrome extension details"].join("\n");
    view.setAttribute("aria-label", "Setup metadata ready");
  } catch {
    view.textContent = "Setup metadata is unavailable. No state was changed.";
    view.setAttribute("aria-label", "Setup metadata unavailable");
  }
});

// Fixed local maintenance page; no caller URL, website content or credential access.
document.getElementById("open-accessibility")?.addEventListener("click", async event => {
  if(event.isTrusted!==true||typeof location==="undefined"||location.protocol!=="chrome-extension:"||location.host!==chrome.runtime.id||location.pathname!=="/options.html")return;
  try {await chrome.tabs.create({url:"chrome://accessibility/",active:true});}catch{setConnectionStatus("Chrome accessibility settings could not be opened.","error");}
});
