package script

import "testing"

func TestNativeInstanceNarrowing(t *testing.T) {
	plan, err := Compile(`app("com.google.Chrome", processId: 4464, processStartToken: "1790000000:123").getByRole("button", name: "Save").click()`)
	if err != nil {
		t.Fatal(err)
	}
	surface := plan.Steps[0].Target.Surface
	if surface.ProcessID != 4464 || surface.ProcessStartToken != "1790000000:123" {
		t.Fatalf("identity lost: %+v", surface)
	}
	for _, source := range []string{
		`app("com.google.Chrome", processId: 4464).activate()`,
		`app("com.google.Chrome", processStartToken: "1790000000:123").activate()`,
		`app("com.google.Chrome", processId: 4464, processStartToken: "1790000000:123").open()`,
		`app("com.google.Chrome", processId: 0, processStartToken: "1790000000:123").activate()`,
		`app("com.google.Chrome", processId: 2147483648, processStartToken: "1790000000:123").activate()`,
		`app("com.google.Chrome", processId: 4464, processStartToken: "invalid").activate()`,
	} {
		if _, err := Compile(source); err == nil {
			t.Fatalf("invalid instance accepted: %s", source)
		}
	}
}
