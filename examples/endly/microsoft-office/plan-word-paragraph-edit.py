"""Emit the narrow final-paragraph edit case; Endly/MCP owns execution.

Use only disposable two-paragraph, single-page documents with freshly observed
AXTextArea content. Stages public agent-authored text in Find and overwrites the
clipboard. This is not a credential-entry route or an arbitrary Word editor.
"""
import json
import re
import sys


def build(settings):
    required = {"processId", "processStartToken", "windowId", "caseId",
                "heading", "originalBody", "replacementBody"}
    if not isinstance(settings, dict) or set(settings) != required:
        raise ValueError("Supply exactly the documented paragraph-edit parameters")
    for key, limit in [("processId", 2147483647), ("windowId", 4294967295)]:
        if type(settings[key]) is not int or not 0 < settings[key] <= limit:
            raise ValueError("Fresh bounded process/window integers required")
    for key in required - {"processId", "windowId"}:
        value = settings[key]
        if not isinstance(value, str) or not value.strip() or len(value.encode("utf-8")) > 1024:
            raise ValueError("Nonempty bounded text required")
        if any(ord(c) < 32 or 127 <= ord(c) <= 159 or c in "\u2028\u2029" for c in value):
            raise ValueError("Only single-line text without controls is qualified")
    if not re.fullmatch(r"[1-9][0-9]*:[0-9]+", settings["processStartToken"]):
        raise ValueError("Fresh process birth token required")
    if settings["originalBody"] == settings["replacementBody"]:
        raise ValueError("Replacement must change the final paragraph")
    surface = {"kind": "native", "bundleId": "com.microsoft.Word",
               "processId": settings["processId"], "processStartToken": settings["processStartToken"]}
    before = settings["heading"] + "\n" + settings["originalBody"]
    after = settings["heading"] + "\n" + settings["replacementBody"]
    steps = []
    string = lambda value: {"kind": "string", "string": value}

    def match(role, value, attribute="value"):
        return {"kind": "adapter", "adapter": "native",
                "name": "literalValueMatches" if attribute == "value" else "valueEquals",
                "scope": {"surfaceRef": "word"}, "timeoutMs": 7000,
                "freshnessMs": 1000, "requiredAuthority": "observational",
                "inputs": {"bundleID": string(surface["bundleId"]),
                           "processId": {"kind": "number", "number": surface["processId"]},
                           "processStartToken": string(surface["processStartToken"]),
                           "nativeRoot": string("focusedElement"), "strategy": string("role"),
                           "selector": string(role), "attribute": string(attribute), "expected": string(value)}}

    def add(name, command, post, pre=None, mutation=True):
        step = {"id": name, "command": command, "timeoutMs": 15000, "postcondition": post}
        if pre is not None:
            step["precondition"] = pre
        if mutation:
            step["effect"] = {"businessKey": {"case": string(settings["caseId"]), "step": string(name)}}
        steps.append(step)

    body_before, body_after = match("AXTextArea", before), match("AXTextArea", after)
    staged = match("AXTextField", settings["replacementBody"])
    field = 'word.focusedElement().getByRole("AXTextField", exact: true)'
    window_key = lambda key: f'word.pressWindowKey(windowId: {settings["windowId"]}, key: {json.dumps(key)})'
    add("verify-original", 'word.focusedElement().getByRole("AXTextArea", exact: true).read("role")', body_before, mutation=False)
    add("find", window_key("Cmd+F"), match("AXTextField", "AXTextField", "role"), body_before)
    add("stage-new-body", field + ".fill(" + json.dumps(settings["replacementBody"]) + ")", staged)
    add("select-staged", field + '.pressKey("Cmd+A")', staged, staged)
    add("copy-staged", field + '.pressKey("Cmd+C")', staged, staged)
    add("leave-find", field + '.pressKey("Escape")', body_before, staged)
    for name, key in [("select-document", "Cmd+A"), ("caret-end", "ArrowRight"),
                      ("select-last-paragraph", "Cmd+Shift+ArrowUp")]:
        add(name, window_key(key), body_before, body_before)
    add("replace-paragraph", window_key("Cmd+V"), body_after, body_before)
    add("save-edited-copy", window_key("Cmd+S"), body_after, body_after)
    return {"schemaVersion": 1, "name": "Edit final paragraph of disposable two-paragraph Word document",
            "surfaces": {"word": surface}, "requires": {"adapters": ["native"]}, "steps": steps}


if __name__ == "__main__":
    try:
        json.dump(build(json.load(sys.stdin)), sys.stdout, indent=2)
        print()
    except (ValueError, TypeError, KeyError) as error:
        raise SystemExit(str(error))
