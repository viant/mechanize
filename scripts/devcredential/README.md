# Local development credential renewal

The MCP relay checks the existing enrolled local `development-agent` credential
before each request. Within one hour of expiry it renews the credential for
24 hours using Scy signing and the real Mechanize verifier. It also renews after
an idle laptop has allowed the token to expire, only when Scy verifies the old
signature against the current configured key and expiration is the sole failed
verification check. Issuer, audience, OS UID subject, client, exact observe/control
scopes, not-before, and issued-at remain required. The old claims never supply
issued authority.

A removed client, rotated key, invalid signature, future token, changed scope,
missing file, or unsafe resource disables automatic renewal. Other identity
providers retain their existing credential loading. Renewal occurs before
transport dispatch; an authentication failure never causes request replay.

The operator CLI uses the same renewal implementation and supports expired local
credentials without deriving authority from the old token. From the repository
root, first validate without writing:

```sh
go run ./scripts/devcredential --config '/absolute/installation/config.json'
```

Add `--apply` to atomically replace only the existing configured `stdio.jwt` after
signing and verification. The configured key and token must be canonical, private,
owned, single-link files in the same owned directory with basenames `hmac` and
`stdio.jwt`. That directory can be retained from an earlier installation; it need
not sit beside the current configuration. Configuration, signing key, and grants
remain unchanged. Only renewal status, client ID, and expiry are printed.

Cooperating renewal processes use a private, nonblocking advisory lock. A concurrent
relay request may use its still-valid verified token while another process renews;
an expired token never crosses transport while renewal is busy. Enrollment bytes
are compared before publication and cancellation is checked. Rename is atomic;
no cross-process compare-and-swap guarantee is claimed against unrelated tools
that ignore the lock and rewrite enrollment files.

Run the authenticated Endly smoke check after an operator renewal. Never paste
token or key bytes into a chat, command argument, workflow, or log.
