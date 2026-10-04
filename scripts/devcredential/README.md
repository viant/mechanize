# Local development credential renewal

This operator-only tool renews the existing local `development-agent` credential
for 24 hours. It uses Scy signing and the real Mechanize verifier. Identity is
derived from the private development configuration and current OS UID, never
from the old token's claims. Only the original observe/control scopes are issued.
It cannot renew OIDC, tenant, console-admin, or arbitrary-client credentials.

From the repository root, first validate without writing:

```sh
go run ./scripts/devcredential --config '/absolute/installation/config.json'
```

Add `--apply` to atomically replace the existing private `credentials/stdio.jwt`
after signing and verification. Configuration, signing key, and grants remain
unchanged. Only renewal status, client ID, and expiry are printed. The same Scy
resource URL continues to work; clients that cache the old token must reconnect.
Applying renewal takes a private advisory lock; another cooperating renewal is
rejected without replacing the token. Cancellation is checked before publication.
The final rename is atomic, but no cross-process compare-and-swap guarantee is
claimed against unrelated tools that ignore the lock and rewrite enrollment files.
Run the authenticated Endly smoke check after renewal. Never paste token or key
bytes into a chat, command argument, workflow, or log.
