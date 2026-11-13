// Container-owned contexts. IDs are supplied by the trusted MCP transport,
// never selected from tool arguments.
export class BrowserSessions {
  constructor({launch, idleMs = 300000, maxSessions = 32, storageState,
    setTimer = setTimeout, clearTimer = clearTimeout}) {
    if (typeof launch !== 'function' || !Number.isSafeInteger(idleMs) || idleMs <= 0 ||
        !Number.isSafeInteger(maxSessions) || maxSessions <= 0) throw Error('Invalid browser session configuration');
    Object.assign(this, {launch, idleMs, maxSessions, storageState, setTimer, clearTimer});
    this.entries = new Map();
    this.browser = null;
    this.closed = false;
  }

  register(id) {
    if (this.closed) throw Error('Browser runtime closed');
    if (typeof id !== 'string' || !id) throw Error('Transport session required');
    if (this.entries.has(id)) throw Error('Session already registered');
    if (this.entries.size >= this.maxSessions) throw Error('Browser session capacity reached');
    this.entries.set(id, {context: null, page: null, busy: false, terminated: false, timer: null, closing: null});
  }

  async browserFor() {
    if (!this.browser) {
      const launching = Promise.resolve().then(() => this.launch());
      this.browser = launching;
      try {
        const browser = await launching;
        browser.on('disconnected', () => {
          if (this.browser === launching) this.browser = null;
          for (const entry of this.entries.values()) {
            if (entry.browser === browser) {
              entry.context = null;
              entry.page = null;
            }
          }
        });
      } catch (error) {
        if (this.browser === launching) this.browser = null;
        throw error;
      }
    }
    return this.browser;
  }

  async use(id, operation) {
    const entry = this.entries.get(id);
    if (!entry || entry.terminated || this.closed) throw Error('Session terminated or unavailable');
    // Refuse overlap rather than enqueue unbounded browser work.
    if (entry.busy) throw Error('Session operation already active');
    entry.busy = true;
    if (entry.timer) this.clearTimer(entry.timer);
    entry.timer = null;
    try {
      if (entry.closing) await entry.closing;
      if (entry.terminated) throw Error('Session terminated');
      if (!entry.context) {
        entry.creating = this.create(entry);
        try { await entry.creating; } finally { entry.creating = null; }
      }
      if (entry.terminated) throw Error('Session terminated');
      return await operation(entry.page, entry.context);
    } finally {
      entry.busy = false;
      if (!entry.terminated) {
        const timer = this.setTimer(() => {
          if (entry.timer !== timer || entry.busy || entry.terminated) return;
          entry.timer = null;
          // Retain failed cleanup for subsequent calls; never reuse uncertain state.
          this.release(entry).catch(() => {});
        }, this.idleMs);
        entry.timer = timer;
        timer?.unref?.();
      }
    }
  }

  async create(entry) {
    try {
        const browser = await this.browserFor();
        if (entry.terminated) throw Error('Session terminated');
        const context = await browser.newContext(this.storageState ? {storageState: structuredClone(this.storageState)} : {});
        entry.browser = browser;
        entry.context = context;
        if (entry.terminated) throw Error('Session terminated');
        const page = await context.newPage();
        if (entry.terminated) throw Error('Session terminated');
        entry.page = page;
        context.on('page', extra => {
          if (extra !== entry.page) extra.close().catch(() => {});
        });
    } catch (error) {
      try { await this.release(entry); } catch (cleanup) {
        throw new AggregateError([error, cleanup], 'Browser creation and cleanup failed');
      }
      throw error;
    }
  }

  release(entry) {
    if (entry.closing) return entry.closing;
    const context = entry.context;
    entry.context = null;
    entry.page = null;
    if (!context) return Promise.resolve();
    const closing = Promise.resolve().then(() => context.close());
    entry.closing = closing;
    closing.then(() => {
      if (entry.closing === closing) entry.closing = null;
    }, () => {});
    return closing;
  }

  async terminate(id) {
    const entry = this.entries.get(id);
    if (!entry) return;
    entry.terminated = true;
    if (entry.timer) this.clearTimer(entry.timer);
    entry.timer = null;
    // Creation may already have sent newContext/newPage. Wait for its cleanup
    // before acknowledging termination, but never wait on active page work.
    if (entry.creating) await entry.creating.catch(() => {});
    await this.release(entry);
    this.entries.delete(id);
  }

  async close() {
    this.closed = true;
    const outcomes = await Promise.allSettled([...this.entries.keys()].map(id => this.terminate(id)));
    if (this.browser) {
      const browser = await this.browser;
      await browser.close();
      this.browser = null;
    }
    const failure = outcomes.find(outcome => outcome.status === 'rejected');
    if (failure) throw failure.reason;
  }
}
