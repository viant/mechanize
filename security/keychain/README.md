# Enrolled Keychain resources

This project's `mechanize-keychain` scheme is implemented by a read-only AFS
`storage.Manager` registered explicitly through `keychain.Register`. Scy's
public `scy.New().Load` implementation uses AFS and therefore resolves this
provider without any Scy or AFS changes.

Trusted operator configuration supplies `Options.Items`, an alias map to exact
generic-password `Service` and `Account` pairs. `keychain.Reference("console")`
returns `mechanize-keychain://generic-password/console`. The URL selects only an
enrolled alias; service/account overrides, credentials, query parameters,
fragments, percent escapes, traversal, and resource storage options are denied.
Register before constructing consumers. Re-registration is denied. No global
automatic registration or general-purpose Keychain URL is provided.

Example enrollment uses service `com.viant.mechanize.console.enrollment` and the
operator's configured account. The item must already exist and authorize the
signed broker. This provider performs only `SecItemCopyMatching`, with
`LAContext.interactionNotAllowed = true`, no synchronization, and one exact
generic-password match. Missing, locked, or unauthorized items fail closed;
there are no permission prompts, Keychain writes, ACL changes, or secret logs.
macOS with cgo is required. Other builds return `ErrUnsupported`.

Tests inject a fixture lookup to prove Scy's actual provider dispatch and input
denials. They never read or write the employee's Keychain. Actual signed broker
Keychain access remains a separate enrollment integration gate.
