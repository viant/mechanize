// Private persistence only. This module neither releases browser authority nor
// verifies business effects. The authenticated host must bind hostResolutionDigest
// to actual durable reconciliation before any future worker lifecycle invocation.
globalThis.MechanizeRetirement = (() => {
  const KEY = "mechanizeRetirementV1", MAX_BYTES = 2 * 1024 * 1024;
  const phases = ["intended", "prepared", "released", "adopted"];
  let lane = Promise.resolve();
  const opaque = value => typeof value === "string" && /^[A-Za-z0-9._:-]{1,128}$/.test(value);
  const hash = value => typeof value === "string" && /^[0-9a-f]{64}$/.test(value);
  const safe = value => Number.isSafeInteger(value) && value >= 0;
  const errors = new Set(["unclassified", "ambiguousTarget", "coverageIncomplete", "invalidLocator", "invalidRequest", "targetNotActionable", "targetNotFound", "unsupportedAction", "unsupportedAttribute", "unsupportedControl", "unsupportedSelector", "userActivationRequired", "dispatchFailure"]);
  function fail(code) { const error = new Error("Private retirement state requires confirmed exact evidence"); error.code = code; error.inhibited = true; error.needsAttention = true; throw error; }
  function object(value, required, optional = []) {
    if (!value || typeof value !== "object" || Array.isArray(value) || required.some(key => !Object.hasOwn(value, key)) || Object.keys(value).some(key => !required.includes(key) && !optional.includes(key))) fail("retirementInvalidSchema");
  }
  function canonical(value) {
    if (Array.isArray(value)) return "[" + value.map(canonical).join(",") + "]";
    if (value && typeof value === "object") return "{" + Object.keys(value).sort().map(key => JSON.stringify(key) + ":" + canonical(value[key])).join(",") + "}";
    return JSON.stringify(value);
  }
  const detached = value => JSON.parse(canonical(value));
  function channel(value) {
    object(value, ["profileChannel", "browserInstance"]);
    if (!opaque(value.profileChannel) || !opaque(value.browserInstance)) fail("retirementInvalidSchema");
    return {profileChannel: value.profileChannel, browserInstance: value.browserInstance};
  }
  function fence(value) {
    object(value, ["brokerEpoch", "channelEpoch", "scopeHash"]);
    if (!opaque(value.brokerEpoch) || !opaque(value.channelEpoch) || !hash(value.scopeHash)) fail("retirementInvalidSchema");
    return {brokerEpoch: value.brokerEpoch, channelEpoch: value.channelEpoch, scopeHash: value.scopeHash};
  }
  function executor(value) {
    object(value, ["version", "identity", "receiptRevision", "receipts", "readiness"]);
    const i = value.identity;
    object(i, ["profileChannel", "browserInstance", "tabId", "frameId", "documentId"]);
    if (![1, 2].includes(value.version) || !opaque(i.profileChannel) || !opaque(i.browserInstance) || !opaque(i.documentId) || !Number.isInteger(i.tabId) || i.tabId <= 0 || i.tabId > 2147483647 || i.frameId !== 0 || !safe(value.receiptRevision) || !Array.isArray(value.receipts) || value.receipts.length > 512 || value.receiptRevision !== value.receipts.length) fail("retirementInvalidSchema");
    const r = value.readiness;
    object(r, ["quiesced", "controlLeaseHeld", "recordingState", "recordingLastSequence", "recordingDroppedThrough", "recordingLeaseExpiresUnixMs"]);
    if (typeof r.quiesced !== "boolean" || typeof r.controlLeaseHeld !== "boolean" || !["none", "recording", "paused", "stopped"].includes(r.recordingState) || !safe(r.recordingLastSequence) || !safe(r.recordingDroppedThrough) || !safe(r.recordingLeaseExpiresUnixMs)) fail("retirementInvalidSchema");
    if (!r.quiesced || r.controlLeaseHeld || !["none", "stopped"].includes(r.recordingState) || r.recordingDroppedThrough !== 0 || r.recordingLeaseExpiresUnixMs !== 0) fail("retirementExecutorActive");
    const seen = new Set();
    const receipts = value.receipts.map(receipt => {
      object(receipt, ["attemptId", "fingerprintSHA256", "dispatchState", "effectState", ...(value.version === 2 ? ["fingerprintVersion"] : [])], ["errorCode", "errorDispatchState"]);
      if (value.version === 2 && receipt.fingerprintVersion !== 2) fail("retirementInvalidSchema");
      if (!opaque(receipt.attemptId) || seen.has(receipt.attemptId) || !hash(receipt.fingerprintSHA256) || !["dispatched", "notDispatched", "unknown"].includes(receipt.dispatchState) || !["none", "unverified", "verified", "unknown"].includes(receipt.effectState) || Object.hasOwn(receipt, "errorCode") !== Object.hasOwn(receipt, "errorDispatchState")) fail("retirementInvalidSchema");
      if (receipt.errorCode !== undefined && (!errors.has(receipt.errorCode) || !["dispatched", "notDispatched", "unknown"].includes(receipt.errorDispatchState))) fail("retirementInvalidSchema");
      if (receipt.dispatchState === "unknown" || receipt.effectState === "unknown" || receipt.errorDispatchState === "unknown") fail("retirementHistoryUnknown");
      seen.add(receipt.attemptId);
      return detached(receipt);
    }).sort((a, b) => a.attemptId < b.attemptId ? -1 : a.attemptId > b.attemptId ? 1 : 0);
    return {version: value.version, identity: detached(i), receiptRevision: value.receiptRevision, receipts, readiness: detached(r)};
  }
  function compareIdentity(a, b) {
    for (const key of ["profileChannel", "browserInstance", "tabId", "frameId", "documentId"]) {
      if (a.identity[key] !== b.identity[key]) return a.identity[key] < b.identity[key] ? -1 : 1;
    }
    return 0;
  }
  function envelope(value, expectedChannel) {
    object(value, ["version", "complete", "executors"]);
    if (![1, 2].includes(value.version) || value.complete !== true || !Array.isArray(value.executors) || value.executors.length > 64) fail("retirementInventoryIncomplete");
    const executors = value.executors.map(executor).sort(compareIdentity);
    let total = 0;
    for (let index = 0; index < executors.length; index++) {
      const current = executors[index];
      if (current.version !== value.version) fail("retirementInvalidSchema");
      if (expectedChannel && (current.identity.profileChannel !== expectedChannel.profileChannel || current.identity.browserInstance !== expectedChannel.browserInstance)) fail("retirementChannelMismatch");
      if (index && compareIdentity(current, executors[index - 1]) === 0) fail("retirementInvalidSchema");
      total += current.receipts.length;
    }
    if (total > 4096) fail("retirementCapacity");
    const result = {version: value.version, complete: true, executors};
    if (new TextEncoder().encode(canonical(result)).length > MAX_BYTES) fail("retirementCapacity");
    return result;
  }
  async function digest(value, crypto) {
    try {
      const bytes = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(canonical(value)));
      if (bytes.byteLength !== 32) fail("retirementCryptoUnavailable");
      return [...new Uint8Array(bytes)].map(byte => byte.toString(16).padStart(2, "0")).join("");
    } catch { fail("retirementCryptoUnavailable"); }
  }
  function create(storage, options = {}) {
    if (!storage || typeof storage.get !== "function" || typeof storage.set !== "function") fail("retirementStorageUnavailable");
    object(options, [], ["crypto"]);
    const crypto = options.crypto || globalThis.crypto;
    // One module-wide lane also covers distinct adapter wrappers for the same
    // Chrome store. This is in-process serialization, not a cross-process CAS.
    function serialized(work) { const task = lane.then(work); lane = task.catch(() => {}); return task; }
    async function validateRecord(raw) {
      object(raw, ["version", "channel", "transitionId", "oldFence", "phase", "revision"], ["manifest", "envelopeDigest", "hostResolutionDigest", "adoptedFence"]);
      const bound = channel(raw.channel), oldFence = fence(raw.oldFence), index = phases.indexOf(raw.phase);
      if (raw.version !== 1 || !opaque(raw.transitionId) || index < 0 || raw.revision !== index + 1) fail("retirementInvalidSchema");
      const result = {version: 1, channel: bound, transitionId: raw.transitionId, oldFence, phase: raw.phase, revision: raw.revision};
      if (index === 0) {
        if (["manifest", "envelopeDigest", "hostResolutionDigest", "adoptedFence"].some(key => Object.hasOwn(raw, key))) fail("retirementInvalidSchema");
      } else {
        if (!hash(raw.envelopeDigest) || !hash(raw.hostResolutionDigest)) fail("retirementInvalidSchema");
        result.manifest = envelope(raw.manifest, bound);
        if (await digest(result.manifest, crypto) !== raw.envelopeDigest || canonical(result.manifest) !== canonical(raw.manifest)) fail("retirementChangedProof");
        result.envelopeDigest = raw.envelopeDigest; result.hostResolutionDigest = raw.hostResolutionDigest;
        if (index === 3) {
          result.adoptedFence = fence(raw.adoptedFence);
          if (result.adoptedFence.scopeHash !== oldFence.scopeHash || result.adoptedFence.brokerEpoch === oldFence.brokerEpoch || result.adoptedFence.channelEpoch === oldFence.channelEpoch) fail("retirementChangedProof");
        } else if (Object.hasOwn(raw, "adoptedFence")) fail("retirementInvalidSchema");
      }
      return result;
    }
    async function validateStore(raw) {
      object(raw, ["version", "channel", "revision", "activeTransitionId", "transitions"]);
      const bound = channel(raw.channel);
      if (raw.version !== 1 || !safe(raw.revision) || !Array.isArray(raw.transitions) || raw.transitions.length < 1 || raw.transitions.length > 32) fail("retirementInvalidSchema");
      const transitions = [], seen = new Set(); let revision = 0, manifestVersion = 1;
      for (const entry of raw.transitions) {
        const record = await validateRecord(entry), previous = transitions.at(-1);
        if (seen.has(record.transitionId) || canonical(record.channel) !== canonical(bound) || previous && (previous.phase !== "adopted" || canonical(previous.adoptedFence) !== canonical(record.oldFence))) fail("retirementInvalidSchema");
        if (record.manifest) {
          if (record.manifest.version < manifestVersion) fail("retirementVersionIncompatible");
          manifestVersion = record.manifest.version;
        }
        transitions.push(record); seen.add(record.transitionId); revision += record.revision;
      }
      if (revision !== raw.revision || raw.activeTransitionId !== transitions.at(-1).transitionId) fail("retirementInvalidSchema");
      const store = {version: 1, channel: bound, revision, activeTransitionId: raw.activeTransitionId, transitions};
      if (new TextEncoder().encode(canonical(store)).length > 4 * MAX_BYTES) fail("retirementCapacity");
      return store;
    }
    async function load() {
      let saved;
      try { saved = await storage.get(KEY); } catch { fail("retirementReadUnavailable"); }
      if (!saved || typeof saved !== "object" || Array.isArray(saved)) fail("retirementInvalidSchema");
      if (!Object.hasOwn(saved, KEY)) return null;
      return validateStore(saved[KEY]);
    }
    function confirmed(store) {
      return {confirmed: true, inhibited: true, needsAttention: false, record: detached(store.transitions.at(-1)), history: detached(store.transitions.slice(0, -1)), storeRevision: store.revision};
    }
    async function write(candidate) {
      if (new TextEncoder().encode(canonical(candidate)).length > 4 * MAX_BYTES) fail("retirementCapacity");
      try { await storage.set({[KEY]: detached(candidate)}); } catch { fail("retirementWriteUnconfirmed"); }
      let saved;
      try { saved = await load(); } catch { fail("retirementWriteUnconfirmed"); }
      if (!saved || canonical(saved) !== canonical(candidate)) fail("retirementWriteUnconfirmed");
      return confirmed(saved);
    }
    function transition(phase, input) {
      // Detach authenticated arguments before async work, preventing caller edits
      // from changing the proof while storage/digest promises are pending.
      let request;
      try {
        object(input, ["channel", "transitionId", "oldFence", "expectedRevision"], phase === "intended" ? [] : phase === "prepared" ? ["manifest", "envelopeDigest", "hostResolutionDigest"] : phase === "adopted" ? ["envelopeDigest", "hostResolutionDigest", "newFence"] : ["envelopeDigest", "hostResolutionDigest"]);
        if (!opaque(input.transitionId) || input.expectedRevision !== phases.indexOf(phase)) fail("retirementRevisionConflict");
        request = {channel: channel(input.channel), transitionId: input.transitionId, oldFence: fence(input.oldFence), expectedRevision: input.expectedRevision};
        if (phase !== "intended") {
          if (!hash(input.envelopeDigest) || !hash(input.hostResolutionDigest)) fail("retirementChangedProof");
          request.envelopeDigest = input.envelopeDigest; request.hostResolutionDigest = input.hostResolutionDigest;
          if (phase === "prepared") request.manifest = envelope(input.manifest, request.channel);
          if (phase === "adopted") request.newFence = fence(input.newFence);
        }
      } catch (error) { return Promise.reject(error); }
      return serialized(async () => {
        const store = await load(), previous = store?.transitions.at(-1), revision = phases.indexOf(phase) + 1;
        if (store && canonical(store.channel) !== canonical(request.channel)) fail("retirementChannelMismatch");
        const nextCycle = phase === "intended" && previous && previous.transitionId !== request.transitionId;
        if (nextCycle) {
          if (previous.phase !== "adopted" || store.transitions.some(record => record.transitionId === request.transitionId)) fail("retirementTransitionConflict");
          if (canonical(previous.adoptedFence) !== canonical(request.oldFence)) fail("retirementChangedProof");
          if (store.transitions.length >= 32) fail("retirementCapacity");
        } else if (previous && (previous.transitionId !== request.transitionId || canonical(previous.oldFence) !== canonical(request.oldFence))) fail("retirementTransitionConflict");
        if (phase === "prepared" && store?.transitions.some(record => record.manifest?.version === 2) && request.manifest.version !== 2) fail("retirementVersionIncompatible");
        if (phase === "prepared" && await digest(request.manifest, crypto) !== request.envelopeDigest) fail("retirementChangedProof");
        if (phase !== "intended" && previous && previous.phase !== "intended" && (previous.envelopeDigest !== request.envelopeDigest || previous.hostResolutionDigest !== request.hostResolutionDigest || phase === "prepared" && canonical(previous.manifest) !== canonical(request.manifest))) fail("retirementChangedProof");
        if (phase === "adopted" && (request.newFence.scopeHash !== request.oldFence.scopeHash || request.newFence.brokerEpoch === request.oldFence.brokerEpoch || request.newFence.channelEpoch === request.oldFence.channelEpoch)) fail("retirementChangedProof");
        if (!nextCycle && previous?.phase === phase) {
          if (phase === "adopted" && canonical(previous.adoptedFence) !== canonical(request.newFence)) fail("retirementChangedProof");
          return confirmed(store);
        }
        if (phase === "intended" ? previous && !nextCycle : !previous || previous.revision !== request.expectedRevision || previous.phase !== phases[revision - 2]) fail("retirementPhaseConflict");
        const candidate = phase === "intended" ? {version: 1, channel: request.channel, transitionId: request.transitionId, oldFence: request.oldFence} : detached(previous);
        candidate.phase = phase; candidate.revision = revision;
        if (phase === "prepared") { candidate.manifest = request.manifest; candidate.envelopeDigest = request.envelopeDigest; candidate.hostResolutionDigest = request.hostResolutionDigest; }
        if (phase === "adopted") candidate.adoptedFence = request.newFence;
        const updated = store ? detached(store) : {version: 1, channel: request.channel, revision: 0, transitions: []};
        if (phase === "intended") updated.transitions.push(candidate); else updated.transitions[updated.transitions.length - 1] = candidate;
        updated.activeTransitionId = request.transitionId; updated.revision++;
        return write(updated);
      });
    }
    return {
      status: expected => serialized(async () => {
        try {
          const bound = channel(expected), store = await load();
          if (!store) return {confirmed: false, inhibited: true, needsAttention: true, reason: "retirementNotFound"};
          if (canonical(store.channel) !== canonical(bound)) fail("retirementChannelMismatch");
          return confirmed(store);
        } catch (error) { return {confirmed: false, inhibited: true, needsAttention: true, reason: error.code || "retirementInvalidSchema"}; }
      }),
      intend: input => transition("intended", input), prepare: input => transition("prepared", input),
      release: input => transition("released", input), adopt: input => transition("adopted", input)
    };
  }
  return {KEY, create, canonicalExecutor: value => canonical(executor(value)),
    envelopeDigest: async (value, crypto = globalThis.crypto) => digest(envelope(value), crypto)};
})();
if (typeof module !== "undefined") module.exports = globalThis.MechanizeRetirement;
