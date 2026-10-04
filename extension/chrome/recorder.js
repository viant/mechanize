// Isolated-world recording. Raw secrets/keystrokes never enter the event buffer.
globalThis.MechanizeRecorder = class {
  constructor(doc, identity, origin) {
    this.doc = doc; this.identity = identity; this.origin = origin;
    this.id = null; this.active = false; this.stopped = false;
    this.sequence = 0; this.events = []; this.droppedThrough = 0;
    this.expiresAt = 0; this.expiryTimer = null;
    this.seenEvents = new WeakSet();
    this.listener = event => this.capture(event);
    for (const kind of ["click", "input", "change"]) doc.addEventListener(kind, this.listener, true);
  }
  control(action, args = {}) {
    if (this.active && Date.now() >= this.expiresAt) this.expire();
    if (Object.keys(args).some(k => !["recordingId", "afterSequence", "limit", "leaseExpiresUnixMs"].includes(k)) || typeof args.recordingId !== "string" || !args.recordingId || args.recordingId.length > 128) throw MechanizeProtocol.error("invalidRecording", "Bounded recordingId required");
    let expiry;
    if (action === "record.start" || (action === "record.events" && this.active)) {
      const now = Date.now();
      if (!Number.isSafeInteger(args.leaseExpiresUnixMs) || args.leaseExpiresUnixMs <= now || args.leaseExpiresUnixMs > now + 30000) throw MechanizeProtocol.error("recordingExpired", "A bounded broker consent expiry is required");
      expiry = args.leaseExpiresUnixMs;
    }
    if (action === "record.start") {
      if (this.id && this.id !== args.recordingId) throw MechanizeProtocol.error("recordingConflict", "This document already retains a different recording; persist/export it first");
      if (this.stopped) throw MechanizeProtocol.error("recordingStopped", "A stopped recording cannot silently restart");
      if (!this.id) { this.id = args.recordingId; this.push({kind: "start", trusted: false}); }
      this.active = true;
      this.renew(expiry);
    } else {
      if (this.id !== args.recordingId) throw MechanizeProtocol.error("recordingNotFound", "Recording is not attached to this document");
      if (action === "record.pause") { if (this.active) this.push({kind: "pause", trusted: false}); this.active = false; this.doc.defaultView.clearTimeout(this.expiryTimer); }
      if (action === "record.stop") { if (!this.stopped) this.push({kind: "stop", trusted: false}); this.active = false; this.stopped = true; this.doc.defaultView.clearTimeout(this.expiryTimer); }
      if (action === "record.events" && this.active) this.renew(expiry);
    }
    const after = args.afterSequence ?? 0, limit = args.limit ?? 64;
    if (!Number.isSafeInteger(after) || after < 0 || !Number.isInteger(limit) || limit < 1 || limit > 64) throw MechanizeProtocol.error("invalidRecording", "Nonnegative cursor and limit 1–64 required");
    const events = this.events.filter(event => event.sequence > after).slice(0, limit);
    const gaps = after < this.droppedThrough ? [{kind: "gap", reason: "bufferOverflow", fromSequence: after + 1, toSequence: this.droppedThrough, lost: this.droppedThrough - after}] : [];
    return {recordingId: this.id, recordingState: this.stopped ? "stopped" : (this.active ? "recording" : "paused"), recordingLeaseExpiresUnixMs: this.active ? this.expiresAt : 0, events, gaps, lastSequence: this.sequence, truncated: this.events.filter(event => event.sequence > after).length > events.length};
  }
  renew(expiry) {
    this.doc.defaultView.clearTimeout(this.expiryTimer);
    this.expiresAt = expiry;
    this.expiryTimer = this.doc.defaultView.setTimeout(() => this.expire(), Math.max(0, expiry - Date.now()));
  }
  expire() { if (this.active) { this.push({kind: "gap", reason: "recordingLeaseExpired", trusted: false}); this.active = false; } }
  push(event) {
    const identity = this.identity(), sequence = ++this.sequence;
    this.events.push({...event, recordingId: this.id, sequence, timestampUnixMs: Date.now(), identity, origin: this.origin, source: "chromeDOM", lineage: `${this.id}:${identity.documentId}:${sequence}`});
    if (this.events.length > 128) this.droppedThrough = this.events.shift().sequence;
  }
  capture(event) {
    if (this.active && Date.now() >= this.expiresAt) this.expire();
    if (!this.active || !event.isTrusted) return; // Excludes Mechanize/page-injected DOM events.
    if (this.seenEvents.has(event)) return;
    this.seenEvents.add(event); // Deduplicate event-object lineage, never similar clicks.
    let el = event.composedPath?.()[0] || event.target;
    if (!el || el.nodeType !== 1 || el.ownerDocument !== this.doc) return;
    if (event.type === "click") el = el.closest("button,a,input,select,textarea,[role]") || el;
    const secret = MechanizeDOM.secret(el), role = MechanizeDOM.role(el), name = MechanizeDOM.name(el, this.doc);
    let locator;
    if (el.getAttribute("data-testid")) locator = {strategy: "testId", value: el.getAttribute("data-testid").slice(0, 256), exact: true};
    else if (el.id) locator = {strategy: "id", value: el.id.slice(0, 256), exact: true};
    else if (role !== "generic") locator = {strategy: "role", value: role, name, exact: true};
    let confidence = "unresolved";
    if (locator) { try { if (MechanizeDOM.resolve(this.doc, locator) === el) confidence = "uniqueDOM"; } catch {} }
    const record = {kind: event.type === "click" ? "press" : (el.tagName === "SELECT" ? "select" : "fill"), trusted: true, locator, selectorConfidence: confidence, redacted: secret};
    const rect = el.getBoundingClientRect();
    record.bounds = {x: rect.x, y: rect.y, width: rect.width, height: rect.height, coordinateSpace: "viewportCSSPixels"};
    if (event.type !== "click" && !secret && "value" in el) { record.value = String(el.value).slice(0, 1024); record.valueTruncated = String(el.value).length > 1024; }
    // No keydown/keypress listener: password keystrokes cannot be retained.
    this.push(record);
  }
};
if (typeof module !== "undefined") module.exports = globalThis.MechanizeRecorder;
