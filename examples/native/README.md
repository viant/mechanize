# Live Calculator and Finder acceptance

The requested acceptance is to use Mechanize MCP to calculate `17 × 23`, verify
that Calculator displays `391`, then find a document in Finder. It has not yet
been demonstrated live.

`open-calculator-finder.dsl` illustrates the two target selectors. Validation
alone does not make it runnable: external effects also require a typed business
key. `open-calculator.json` supplies that key for the first opening action.
Neither example performs the calculation or document search by itself.

After native-panel connection and an observe/control session approval:

1. Run `open-calculator.json` through `mechanize_script_run` with `format: "json"`.
2. Observe Calculator through `mechanize_observe`. Inspect current identifiers,
   roles, supported actions and result attributes before constructing locators.
3. Declare independent `native.valueEquals` postconditions for each press. A
   successful AX return alone does not confirm a calculator state change.
4. Read the final numeric result from a positively permitted nonsecure display
   identifier, or another actual exposed field. Verify `391` independently.
5. Observe Finder, resolve its current search field, fill the requested filename
   and use `submit()` only if the field advertises AXConfirm. An unsupported
   action must be reported; no keyboard substitution is inferred.
6. Verify the result row and close the owned automation session.

`test.txt` was visible in the user's Documents folder during permission setup;
it is a candidate for this demonstration. The requested task is to find it,
not edit, move or delete it.

No UI selectors are hardcoded here without a live observation. The Calculator
and Finder identities are `com.apple.calculator` and `com.apple.finder`.
Desktop permission covers both without a separate per-app approval.
