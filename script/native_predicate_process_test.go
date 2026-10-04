package script

import (
	"strings"
	"testing"
)

const nativeProcessEnvelope = `schemaVersion: 1
name: exact-native-read
requires: {adapters: [native]}
surfaces:
  chrome: {kind: native, bundleId: com.google.Chrome, processId: 4464, processStartToken: '1790000000:1'}
steps:
  - id: inspect
    command: 'chrome.getById("display").read("name")'
    postcondition:
      kind: adapter
      adapter: native
      name: valueEquals
      scope: {surfaceRef: chrome}
      timeoutMs: 1000
      freshnessMs: 1000
      requiredAuthority: observational
      inputs:
        bundleID: {kind: string, string: com.google.Chrome}
        processId: {kind: number, number: 4464}
        processStartToken: {kind: string, string: '1790000000:1'}
        strategy: {kind: string, string: id}
        selector: {kind: string, string: display}
        attribute: {kind: string, string: name}
        expected: {kind: string, string: ready}
`

func TestNativeProcessPostconditionEnvelope(t *testing.T) {
	p, err := DecodeYAML(strings.NewReader(nativeProcessEnvelope))
	if err != nil {
		t.Fatal(err)
	}
	post := p.Steps[0].Postcondition
	if post == nil || post.Inputs["processId"].Number != 4464 || post.Inputs["processStartToken"].String != "1790000000:1" || p.Steps[0].Target.Surface.ProcessID != 4464 {
		t.Fatalf("process postcondition lost: %+v", p)
	}
	for _, line := range []string{"        processId: {kind: number, number: 4464}\n", "        processStartToken: {kind: string, string: '1790000000:1'}\n"} {
		if _, err := DecodeYAML(strings.NewReader(strings.Replace(nativeProcessEnvelope, line, "", 1))); err == nil {
			t.Fatal("partial native postcondition accepted")
		}
	}
}
