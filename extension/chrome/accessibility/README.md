# Accessible names

Pinned `dom-accessibility-api@0.7.1` (MIT) runs on one inert, sanitized projection per observation or resolution. Rebuild with `npm run build-accessibility`. The generated asset is loaded before dom.js.

Projection is bounded to 20,000 nodes, depth 64 and 20,000 style reads. It strips executable/resource attributes and all editable values before invoking the dependency. Designated-secret elements are replaced without traversing their attributes or descendants. Known-value redaction remains active.

Names depending on editable values, private references, redacted text, oversized names, or scoped shadow ID references are unavailable; observed ID targeting remains possible under normal guards. Open shadow content and assigned slots are projected as composed children. Closed shadow roots and canvas remain unsupported. BR display is normalized to a block boundary to align Playwright name whitespace. This is tested canonical-name coverage, not a claim of every Playwright extension to AccName.
