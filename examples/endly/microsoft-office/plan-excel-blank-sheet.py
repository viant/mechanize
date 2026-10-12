"""Emit one inspected Excel blank-sheet control click. Does not capture, authorize or execute."""
import json
import re
import sys


def build(settings):
    fields = {"processId", "processStartToken", "windowId", "captureRef",
              "widthPixels", "heightPixels", "x", "y", "caseId", "windowTitle", "newSheet"}
    if not isinstance(settings, dict) or set(settings) != fields:
        raise ValueError("Supply exactly the documented frame-focus parameters")
    for name, maximum in [("processId", 2147483647), ("windowId", 4294967295),
                          ("widthPixels", 65536), ("heightPixels", 65536)]:
        if type(settings[name]) is not int or not 0 < settings[name] <= maximum:
            raise ValueError(name + " must be a positive bounded integer")
    for axis, dimension in [("x", "widthPixels"), ("y", "heightPixels")]:
        if type(settings[axis]) is not int or not 0 <= settings[axis] < settings[dimension]:
            raise ValueError(axis + " must be an original-image pixel inside the frame")
    if not isinstance(settings["captureRef"], str) or not re.fullmatch(r"[0-9a-f]{32}", settings["captureRef"]):
        raise ValueError("A current capture permit reference is required")
    if not isinstance(settings["processStartToken"], str) or len(settings["processStartToken"]) > 27 or not re.fullmatch(r"[1-9][0-9]*:[0-9]+", settings["processStartToken"]):
        raise ValueError("A freshly discovered process birth token is required")
    case = settings["caseId"]
    if not isinstance(case, str) or not case.strip() or len(case.encode()) > 255 or any(ord(c) < 32 or 127 <= ord(c) <= 159 or c in "\u2028\u2029" for c in case):
        raise ValueError("A stable bounded case ID is required")
    title = settings["windowTitle"]
    if not isinstance(title, str) or not title.strip() or len(title.encode()) > 255 or any(ord(c) < 32 or 127 <= ord(c) <= 159 or c in "\u2028\u2029" for c in title):
        raise ValueError("Fresh exact captured window title required")
    sheet = settings["newSheet"]
    if not isinstance(sheet, str) or not re.fullmatch(r"Sheet[1-9][0-9]{0,3}", sheet):
        raise ValueError("Expected newly allocated default Sheet name required")
    string = lambda value: {"kind": "string", "string": value}
    surface = {"kind": "native", "bundleId": "com.microsoft.Excel",
               "processId": settings["processId"], "processStartToken": settings["processStartToken"]}
    post = {"kind": "adapter", "adapter": "native", "name": "valueEquals",
            "scope": {"surfaceRef": "excel"}, "timeoutMs": 7000, "freshnessMs": 1000,
            "requiredAuthority": "observational", "inputs": {
                "bundleID": string(surface["bundleId"]),
                "processId": {"kind": "number", "number": surface["processId"]},
                "processStartToken": string(surface["processStartToken"]),
                "windowTitle": string(title), "windowRole": string("AXWindow"), "strategy": string("id"),
                "selector": string(sheet), "attribute": string("identifier"), "expected": string(sheet)}}
    return {"schemaVersion": 1, "name": "Insert one inspected blank Excel sheet with one frame click",
            "surfaces": {"excel": surface}, "requires": {"adapters": ["native"]}, "steps": [{
                "id": "insert-blank-sheet",
                "command": "excel.clickWindowFrame(captureRef: " + json.dumps(settings["captureRef"]) +
                           ", x: " + str(settings["x"]) + ", y: " + str(settings["y"]) + ")",
                "postcondition": post,
                "effect": {"businessKey": {"case": string(case),
                           "capturedWindow": {"kind": "number", "number": settings["windowId"]}, "newSheet": string(sheet)}}}]}


if __name__ == "__main__":
    try:
        json.dump(build(json.load(sys.stdin)), sys.stdout, indent=2)
        print()
    except (ValueError, TypeError, KeyError) as error:
        raise SystemExit(str(error))
