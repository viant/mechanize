# Discover the actual OpenOffice surface

Use current `mechanize_capabilities` and `mechanize_describe`, then an owned session and approved exact purpose. Reuse the active grant for actions within its target and purpose; do not ask again when it already covers the next action. Observe native bundle `org.openoffice.script`. Two installed copies were seen with that same bundle ID; the ID does not select a unique running process. Resolve the current intended document/window and bind the paired PID and process start token from fresh discovery. Never copy a fixture PID, birth token, window ID, or element ref into a saved recipe.

Prefer a complete narrow observation. In the October 3, 2026 fixture, the full app tree was truncated while the `menuBar` native root was complete. The `focusedElement` root exposed the Writer editor as an editable `AXTextArea` with no identifier. These are typed native-root scopes, not guessed DSL methods. Obtain their current schema from discovery, and do not combine a root scope with incompatible window selectors. Re-observe after menus, dialogs, focus, or document state change.

Use observed role/name/action, exact window scope and a single match. Starting-center buttons exposed no AX actions in that fixture; do not equate a visible button with a usable semantic press. The observed menu item **Text Document** exposed `AXPress`; pressing it created an untitled Writer window. Treat the menu label as evidence to look for, not a persistent selector or localization guarantee.

## Read failure decision

1. Read the exact selected document/control from a complete scoped observation. Check structured failure, truncation, unavailable state, and process identity.
2. If a semantic control or AX action is unavailable or unreliable, try an app shortcut only when it is observed or qualified for this app/version/context. Do not assume a universal Writer or Calc shortcut.
3. For fixable scope/locator issues, refresh and correct one concrete issue, then make at most one second bounded semantic read attempt. Known unsupported behavior skips repeated attempts. If AX or the shortcut route remains unavailable or unreliable, capture the fresh exact owned window and preserve crop/scale metadata. Use a pointer action only if the current Mechanize catalog advertises a capture-bound route and its schema binds the input to that fresh image and window. Never infer coordinates or reuse a stale capture target.
4. Verify the requested result independently. AX readback can prove a literal value, file inspection can prove persisted content, and an image can prove visible layout; an image alone does not prove hidden content or persistence. If no current route is advertised and qualified, stop at the checkpoint and explain the missing capability.

If a mutation's outcome is uncertain, inspect and reconcile that exact run and
fresh state before replaying it or switching routes. A later action does not
relabel the earlier receipt. Reuse the current consent grant while the next
action remains within its target and purpose; request another grant only if the
needed authority is not already covered.

Current Calc observation: the Sheet1 tab and Name Box reported `focusSettable`,
but focus writes returned `focusNotObserved`. Both original attempts remain
unknown and were not replayed. Select the current sheet via an independently
observed route; if AX focus remains unreliable, use a fresh window capture and
only a currently advertised capture-bound pointer action. A capability to set
focus does not prove that focus moved, and no raw-pointer fallback is assumed.
The evidence record is `examples/endly/openoffice-mortgage/evidence.json`,
under `remainingControlFailures`; the run references are historical evidence,
not reusable targets.

## Writer text replacement and evidence provenance

One narrow Writer text-replacement case is live-qualified: on OpenOffice 4.1.16, a newly created Writer document whose focused editor was a single-paragraph `AXTextArea`, the Mechanize/Endly typed route using `office.focusedElement().getByRole("textbox", exact:true).replaceText(publicLiteral)` succeeded. Treat this as qualification for that observed one-element case only. `replaceText` replaces the entire targeted accessibility text element; it does not mean “replace the whole document.” Establish that the exact target element is the intended edit scope before dispatch. This does not qualify other documents, multi-paragraph coverage, or saving. One exact existing ODT copy/edit exception is separately documented in [Writer and file workflows](writer-files.md#one-existing-odt-copy-and-edit-case); it does not make opening or editing other existing documents generally qualified.

The qualified attempt first checked `native.literalValueMatches` against the expected empty value using the exact fresh process PID and birth token, target control, and consent scope. It then performed one text-write and obtained byte-exact helper readback; an independent Mechanize capture showed the full paragraph. Discover current capabilities and method schemas, then validate the actual typed workflow before running it. Do not turn the example into a runnable recipe without fresh process/window/control scope and the required consent. Do not hardcode fixture IDs or retain a run ID in this guide; Keep transient run evidence in the local execution record, separate from this portable guide.

An earlier AXValue `.fill` attempt was dispatched but remained unknown, with no effect observed. That unresolved attempt is not relabeled by either later successful replacement. Do not rely on AXValue `.fill` for text replacement based on this evidence. `editable` and `valueSettable` metadata alone are not replacement proof.

The observed replacement route and its independent readback qualify only this case, not every Mechanize runtime or document shape. Keep the original effect record and exact predicate for any unknown mutation; never infer insertion or saving from a later successful action or enabled Save As observation.

## Writer ODT save evidence

Saving the newly created, single-paragraph Writer case as ODT is also qualified on OpenOffice 4.1.16. `AXPress` on **FileSaveAs** showed a Save panel, but the app/panel accessibility became unresponsive. In that observed state, a no-AX `Escape` through the window-key route on the freshly observed modal recovered the UI. Refresh transient foreground state before resuming; activation alone did not establish that Writer remained foreground. Do not treat the failed menu route as a saved file or as proof of a specific internal cause.

The verified save used the documented `Cmd+S` route from the focused Writer textbox, which opened a responsive native Save panel. The observed filename field was `saveAsNameTextField`; filling the literal filename with `exact:true` was verified. `Cmd+Shift+G` opened the observed `PathTextField`; filling the existing destination folder and pressing Return restored `saveAsNameTextField`, and a final Return saved the document. In this installed version's ID-based selectors, `exact:true` was required. These identifiers and the route are version-qualified observations, not persistent selectors: rediscover capabilities and schemas, observe each dialog/control afresh, and validate the typed workflow before use. Never hardcode a PID, window ID, or run ID.

The save was verified by body-literal readback and read-only ZIP inspection of the resulting ODT: its MIME type was `application/vnd.oasis.opendocument.text`, and the exact summary paragraph was present. This qualifies saving that newly created one-paragraph Writer case as ODT only. The separate existing ODT copy has an unresolved Save As confirmation despite independent file verification; neither example qualifies general existing-document saving, other document shapes, Word formats, Calc, or PDF.
