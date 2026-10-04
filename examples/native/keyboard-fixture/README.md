# Native keyboard qualification fixture

This disposable, inert AppKit app is a fresh target for qualifying Mechanize's explicit native session-key route on a modal sheet. It avoids replaying input whose outcome is uncertain in an old Chrome session. A fixture result does not prove production readiness or completion of the broader release gates.

From the repository root, build with the local macOS SDK and ad-hoc sign:

```sh
bash examples/native/keyboard-fixture/build.sh
```

The script compiles and verifies the signature without launching or registering the app, sending UI input, or changing Mechanize configuration. The output is:

```text
/private/tmp/mechanize-keyboard-fixture/Mechanize Keyboard Fixture.app
```

The bundle identifier is `com.viant.mechanize.keyboardfixture`. Its compact titled window has a **Choose folder** button with accessibility identifier `choose-folder` and a static status label with identifier `fixture-status`, initially **Ready**. The button opens the standard `NSOpenPanel` as a sheet, allowing one directory selection and disabling directory creation. Once the sheet closes, the status becomes **Cancelled** or **Selected**. The app never reads, retains, displays, or logs the selected path and performs no file changes in the selected directory.

An explicitly authorized disposable fixture integration gate can launch the app through Mechanize, activate **Choose folder**, then send Command–Shift–G through the explicit native session-key route to exercise AppKit's standard **Go to Folder** UI. Launch and UI qualification are separate from this build script; they must be run by the integration gate, not default tests. No launch or keyboard qualification is implied by a successful compile and signature verification.
