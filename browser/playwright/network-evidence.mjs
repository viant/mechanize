const maxRequests = 100;
const maxValueLength = 128;
export const navigationResponses = new WeakMap();

export class NetworkEvidence {
  constructor(rules = []) {
    if (!Array.isArray(rules) || rules.length > 20) throw Error('Invalid network rules');
    this.rules = rules.map(rule => {
      const url = new URL(rule.origin);
      if (!['http:', 'https:'].includes(url.protocol) || url.origin !== rule.origin ||
          typeof rule.path !== 'string' || !rule.path.startsWith('/') || /[?#]/.test(rule.path) ||
          !rule.parameters || Object.keys(rule.parameters).length > 20 ||
          Object.entries(rule.parameters).some(([key, mode]) => !/^[A-Za-z0-9_.-]{1,64}$/.test(key) || !['value', 'presence'].includes(mode))) throw Error('Invalid network rule');
      return structuredClone(rule);
    });
    this.records = [];
    this.requests = new WeakMap();
    this.dropped = 0;
  }

  attach(context) {
    context.on('request', request => this.capture(request));
    context.on('response', response => this.complete(response.request(), response.status()));
    context.on('requestfailed', request => this.complete(request, undefined, true));
  }

  complete(request, status, failed = false) {
    const record = this.requests.get(request);
    if (!record) return;
    const navigation = navigationResponses.get(request);
    if (navigation || status !== undefined) record.status = navigation?.status ?? status;
    if (navigation?.redirectHandled) record.redirectHandled = true;
    if (failed) record.failed = true;
    record.elapsedMs = Date.now() - record.startedAt;
  }

  capture(request) {
    try {
      const url = new URL(request.url());
      const rule = this.rules.find(rule => rule.origin === url.origin && rule.path === url.pathname);
      if (!rule) return;
      if (this.records.length >= maxRequests) { this.dropped++; return; }
      const parameters = new URLSearchParams(url.search);
      // Parse only bounded supported payloads; raw data never enters evidence.
      const body = request.postData();
      const bodyBytes = body ? Buffer.byteLength(body, 'utf8') : 0;
      let payloadStatus = body ? (bodyBytes > 16384 ? 'too-large' : 'unsupported') : 'not-present';
      if (body && bodyBytes <= 16384) {
        const type = request.headers()['content-type']?.split(';')[0];
        if (type === 'application/x-www-form-urlencoded') {
          for (const [key, value] of new URLSearchParams(body)) parameters.append(key, value);
          payloadStatus = 'parsed';
        } else if (type === 'application/json') {
          try {
            const object = JSON.parse(body);
            if (object && typeof object === 'object' && !Array.isArray(object) && Object.values(object).every(value => ['string', 'number', 'boolean'].includes(typeof value))) {
              for (const [key, value] of Object.entries(object)) parameters.append(key, String(value));
              payloadStatus = 'parsed';
            }
          } catch { payloadStatus = 'malformed'; }
        }
      }
      const projected = Object.create(null);
      for (const [key, mode] of Object.entries(rule.parameters)) {
        const values = parameters.getAll(key);
        projected[key] = mode === 'presence' ? {present: values.length > 0, nonempty: values.some(Boolean)} : {
          values: values.slice(0, 5).map(value => value.slice(0, maxValueLength)),
          truncated: values.length > 5 || values.some(value => value.length > maxValueLength)
        };
        if (!values.length && !['parsed', 'not-present'].includes(payloadStatus)) projected[key].unknown = true;
      }
      let frameOrigin;
      try { frameOrigin = new URL(request.frame().url()).origin; } catch {}
      const record = {origin: rule.origin, path: rule.path, method: request.method(),
        resourceType: request.resourceType(), parameters: projected, payloadStatus, frameOrigin, startedAt: Date.now()};
      this.records.push(record);
      this.requests.set(request, record);
    } catch {
      // A malformed page request must not leak its raw payload through errors.
      this.dropped++;
    }
  }

  snapshot() {
    const requests = [];
    let bytes = 0, omitted = 0;
    for (const {startedAt, ...record} of this.records) {
      const size = Buffer.byteLength(JSON.stringify(record), 'utf8');
      if (bytes + size > 512 * 1024) { omitted++; continue; }
      requests.push(structuredClone(record));
      bytes += size;
    }
    return {requests, dropped: this.dropped + omitted, truncated: this.dropped + omitted > 0,
      limit: maxRequests, captureConfigured: this.rules.length > 0};
  }
}
