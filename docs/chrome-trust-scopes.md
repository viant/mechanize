# Chrome trust scopes

Mechanize distinguishes desktop-wide browser authority from per-profile
isolation. Both require the verified user, exact enrolled native-host and Chrome
images, current kernel peer/process identity, explicit extension/origin enrollment,
human operation consent, and a qualified renderer/document before control.
Credentials remain encrypted Scy resources read by the native bridge after reverse
broker authentication; neither a scope label nor extension message grants access.

| Scope | What is verified | Profile isolation |
| --- | --- | --- |
| `profile` (default) | All normal process/origin checks plus actual Chrome profile launch evidence matching the enrolled directory | Required; unavailable evidence rejects |
| `desktop` (explicit) | The signed Chrome process and native-host channel belong to the enrolled desktop-wide user; origin and renderer restrictions still apply | Not claimed; all profiles reached through that signed browser process are within the selected desktop scope |

Desktop mode is the implementation of the user's requested blanket desktop/browser
access. It cannot be selected by a workflow, web page or client hello. Operator
enrollment must select it explicitly, the host user must already have
`DesktopAccess`, and fixture process trust cannot enable it. Desktop enrollments
carry no authenticated profile-directory claim. Public channel metadata reports
the selected scope, `scopeQualified`, and `profileQualified=false` for desktop.
Profile mode never falls back to desktop when its proof is missing.

Scope selection is included in channel/authority binding. Renderer acquisition,
document identity, unknown-effect barriers, retirement acknowledgements, scoped
credentials and per-operation consent remain required in either mode. Switching
scope is an operator change while the broker and owned native hosts are stopped,
with configuration backups and exact consistency checks.

## Why the distinction is necessary

The current MV3 extension cannot use the reconnect-command proof originally
selected for profile mode. Chromium's native-connection eligibility gate requires
`natively_connectable`, `transientBackground` and an `onConnectNative` listener;
its background manifest handler requires a lazy background page for that
permission, which is distinct from an MV3 service worker. The desktop
`connectNative` target object has no alternative reconnect-proof option.
Sources for the tested Chromium 154.0.8037.97 build:
[eligibility gate](https://raw.githubusercontent.com/chromium/chromium/154.0.8037.97/chrome/browser/extensions/api/messaging/native_messaging_launch_from_native.cc),
[background validation](https://raw.githubusercontent.com/chromium/chromium/154.0.8037.97/extensions/common/manifest_handlers/background_info.cc),
[launch argument generation](https://raw.githubusercontent.com/chromium/chromium/154.0.8037.97/chrome/browser/extensions/api/messaging/launch_context.cc).

Mechanize does not infer a profile from a process name, extension-supplied label,
or parent command line, and does not convert its extension to MV2 to obtain that
proof. A supported persistent pairing mechanism is still needed before claiming
per-profile isolation for MV3. This remains a separate acceptance requirement.
