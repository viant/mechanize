# MCP browser reverse bridge

A browser controller uses this path:

Browser application → Chrome extension external port → native messaging host →
local Mechanize broker → canonical MCP handlers → Chrome executor or native helper.

RobotGo remains the native pointer backend behind Mechanize's capture-bound
`window.clickFrame` action. The website receives neither OS input privileges nor
Vault values directly. The broker binds each conversation to its approved origin,
document and authenticated user, and each automation session to that controller.

Agently's existing generic browser configuration is sufficient:

```yaml
name: mechanize
executionLocation: browser
browserTransport:
  type: chrome-extension
  extensionId: <installed-32-letter-id>
  portName: mechanize-controller-v1
  requestTimeoutMs: 9000
browserTools:
  - '*'
```

Keep credentials, transport JWTs and local filesystem paths out of this public
configuration. Trusted controller origins are configured in Mechanize. Chrome
extension external-origin matching and broker authorization both apply.

Controller-origin settings are saved through the authenticated native panel in
private runtime storage outside Git. They are restored for the exact enrolled
owner, profile, browser and extension before a new Chrome connection can sync.
An absent store defaults to disabled; corrupt or unsafe storage fails closed.
Live controller sessions are never restored from disk. An enabled saved exact
origin automatically authorizes a fresh, bounded document connection. This does
not approve tool actions or bypass Agently approval, Mechanize consent, or Vault
protection. Policy disable/removal revokes connections; identical sync never
extends their expiry.

Agently distinguishes transport failures from approval messages from older
peers. Such approval waits remain bounded; current trusted-origin connections
receive an immediate automatic admission response. Neither setup path dispatches
tools or submits a model request before the catalog is ready. Failed tool-catalog setup is reported to the subscribed conversation
instead of leaving an empty transcript.

The reverse bridge advertises MCP `2025-11-25` and accepts `initialize`,
`tools/list` and `tools/call`; it is not an unrestricted HTTP proxy or raw CDP
endpoint. Its complete tool results contain only `content`, `structuredContent`
and optional `isError`. The canonical upstream may negotiate a newer version;
upstream cache hints and host-only `_meta` stay behind the bridge. Unsupported
`input_required` or future result variants are refused without being converted
to completed results or replayed. Existing registered tool handlers
perform execution, consent, private credential delivery and reconciliation.
Compatibility skill tools use that same catalog. Additional protocol methods
such as `resources/read` are not forwarded by this controller transport yet.

## RobotGo capture and click

The controller catalog includes `mechanize_capture_windows`, `mechanize_capture`
and `mechanize_capture_window_frame` when the canonical host registers them.
Capture requests require a controller-owned automation session and retain the
host's normal consent and Vault protection checks. The human permission console
is excluded as a capture or action target.

Browser responses stay below the native messaging result budget. A frame capture
returns a display preview of at most 96 KiB encoded image bytes, plus the original
metadata and encrypted artifact references. `imageIsPreview` and `preview` identify
that derivative. Preview creation does not extend the 30-second capture permit.

`window.clickFrame` still consumes original integer frame pixels, not preview
pixels or global coordinates. Convert a point selected in the preview as follows:

```text
frameX = round(previewX * metadata.widthPixels / preview.widthPixels)
frameY = round(previewY * metadata.heightPixels / preview.heightPixels)
```

Reuse the returned purpose, grant and owned session. The helper still enforces
one-use capture reference, target process/birth, window, fence and hit recipient.
An unavailable preview grants no basis for choosing a click location. Normal
capture can return metadata only if its image exceeds the browser inline budget;
use frame capture for the preview-and-click flow.

## Validation

Tests exercise the actual canonical MCP frame handler through the controller
adapter, image preview size and original-coordinate preservation, rejection of
foreign sessions and permission-console targeting, and exact registered skill
resource access. These are source-level integration tests; they do not establish
a live browser/Agently deployment or successful completion of a website task.
