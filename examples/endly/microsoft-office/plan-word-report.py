"""Emit a bounded two-paragraph Word plan; execution belongs to Endly/MCP.

The caller supplies fresh identities for an owned empty document. This uses the
GUI clipboard and changes Find text. It never creates a DOCX itself or grants
permissions. A failed/uncertain run must be inspected and resumed, not regenerated
under a new case ID to bypass its ledger.
"""
import json
import re
import sys


def build(settings):
    required = {"processId", "processStartToken", "windowId", "windowTitle",
                "caseId", "headingIdentifier", "normalIdentifier", "title", "body"}
    if set(settings) != required:
        raise ValueError("Supply exactly the documented report parameters")
    for name, maximum in [("processId", 2147483647), ("windowId", 4294967295)]:
        if type(settings[name]) is not int or not 0 < settings[name] <= maximum:
            raise ValueError(f"{name} must be a positive bounded integer")
    for name in required - {"processId", "windowId"}:
        value = settings[name]
        if not isinstance(value, str) or not value.strip() or len(value.encode("utf-8")) > 255:
            raise ValueError(f"{name} must be a nonempty string of at most 255 UTF-8 bytes")
        if any(ord(c) < 32 or 127 <= ord(c) <= 159 or c in "\u2028\u2029" for c in value):
            raise ValueError(f"{name} must be single-line text without controls")
    if not re.fullmatch(r"[1-9][0-9]*:[0-9]+", settings["processStartToken"]):
        raise ValueError("A freshly discovered process birth token is required")

    surface = {"kind": "native", "bundleId": "com.microsoft.Word",
               "processId": settings["processId"], "processStartToken": settings["processStartToken"]}
    window = settings["windowId"]
    window_expr = "word.window(title: " + json.dumps(settings["windowTitle"]) + ")"
    steps = []

    def string(value):
        return {"kind": "string", "string": value}

    def predicate(selector, attribute, expected, *, focused=False, literal=False, strategy="id"):
        inputs = {"bundleID": string(surface["bundleId"]),
                  "processId": {"kind": "number", "number": surface["processId"]},
                  "processStartToken": string(surface["processStartToken"]),
                  "strategy": string(strategy), "selector": string(selector),
                  "attribute": string(attribute),
                  "expected": {"kind": "boolean", "boolean": expected} if isinstance(expected, bool) else string(expected)}
        inputs.update({"nativeRoot": string("focusedElement")} if focused else
                      {"windowTitle": string(settings["windowTitle"])})
        return {"kind": "adapter", "adapter": "native",
                "name": "literalValueMatches" if literal else "valueEquals",
                "scope": {"surfaceRef": "word"}, "timeoutMs": 7000,
                "freshnessMs": 1000, "requiredAuthority": "observational", "inputs": inputs}

    def body_is(text):
        return predicate("AXTextArea", "value", text, focused=True, literal=True, strategy="role")

    def add(name, command, post=None, pre=None):
        step = {"id": name, "command": command, "timeoutMs": 15000,
                "effect": {"businessKey": {"case": string(settings["caseId"]), "step": string(name)}}}
        if post is not None:
            step["postcondition"] = post
        if pre is not None:
            step["precondition"] = pre
        steps.append(step)

    def window_key(name, key, post, pre=None):
        add(name, f"word.pressWindowKey(windowId: {window}, key: {json.dumps(key)})", post, pre)

    def stage_text(prefix, text, current):
        # The explicit window-key route fails before input if another Word
        # document, modal or tooltip owns the keyboard window. Never fall back
        # to an app-wide Find action after that rejection.
        field = 'word.focusedElement().getByRole("AXTextField", exact: true)'
        window_key(prefix + "-find", "Cmd+F",
                   predicate("AXTextField", "role", "AXTextField", focused=True, strategy="role"), body_is(current))
        match = predicate("AXTextField", "value", text, focused=True, literal=True, strategy="role")
        add(prefix + "-stage", field + ".fill(" + json.dumps(text) + ")", match)
        add(prefix + "-select", field + '.pressKey("Cmd+A")', match, match)
        add(prefix + "-copy", field + '.pressKey("Cmd+C")', match, match)
        add(prefix + "-return", field + '.pressKey("Escape")', body_is(current))

    add("activate", "word.activate()")
    stage_text("title", settings["title"], "")
    # A global Paste menu can follow a changed active document. Bind each
    # document-changing paste to the captured physical window instead.
    window_key("paste-title", "Cmd+V", body_is(settings["title"]), body_is(""))
    heading = settings["headingIdentifier"]
    add("heading", window_expr + ".getById(" + json.dumps(heading) + ").click()",
        predicate(heading, "checked", True), predicate(heading, "checked", False))
    window_key("new-paragraph", "Return", predicate(settings["normalIdentifier"], "checked", True), body_is(settings["title"]))
    prefix = settings["title"] + "\n"
    stage_text("body", settings["body"], prefix)
    # Find may change the document selection. Restore the caret explicitly.
    window_key("select-document", "Cmd+A", body_is(prefix), body_is(prefix))
    window_key("caret-to-end", "ArrowRight", body_is(prefix), body_is(prefix))
    window_key("paste-body", "Cmd+V", body_is(prefix + settings["body"]), body_is(prefix))
    return {"schemaVersion": 1, "name": "Create verified disposable Word report",
            "surfaces": {"word": surface}, "requires": {"adapters": ["native"]}, "steps": steps}


if __name__ == "__main__":
    try:
        json.dump(build(json.load(sys.stdin)), sys.stdout, indent=2)
        print()
    except (ValueError, TypeError, KeyError) as error:
        raise SystemExit(str(error))
