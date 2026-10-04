# Mechanize browser fixture

This small local page supports future real Chrome MCP checks of semantic press,
fill, and read behavior. It does not simulate or qualify a Chrome backend.

Run it from this directory with:

```sh
go run .
```

The server binds only to `127.0.0.1:18771`. Open
`http://127.0.0.1:18771/`; `GET /healthz` returns `ok`. The increment button
changes `#counter` from `0` to `1`, and typing in the labelled `#report-title`
input updates the read-only `#echo` output.

The fixture serves only its embedded HTML and JavaScript, accepts only GET and
HEAD, has no database, authentication, filesystem serving, or outbound network
access, and exits cleanly on SIGTERM. Endly owns any automation that uses it.
