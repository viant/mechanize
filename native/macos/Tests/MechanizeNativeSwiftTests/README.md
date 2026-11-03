# Focused Swift Testing checks

This target covers attached-sheet membership, semantic action budgets, and exact focused-window matching. It is not the full native XCTest
suite. On a Command Line Tools installation with Swift Testing but no XCTest:

```sh
MECHANIZE_NATIVE_SWIFT_TESTS_ONLY=1 swift test --disable-xctest \
  -Xswiftc -F/Library/Developer/CommandLineTools/Library/Developer/Frameworks \
  -Xlinker -rpath -Xlinker /Library/Developer/CommandLineTools/Library/Developer/Frameworks \
  -Xlinker -rpath -Xlinker /Library/Developer/CommandLineTools/Library/Developer/usr/lib
```

Run from `native/macos` after building the RobotGo archive. On a full Xcode
installation, the default `swift test` includes this target and the XCTest targets.
