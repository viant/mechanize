package script

import "testing"

func TestWebDocumentNthRequiresQualifiedLocalIndexedReads(t *testing.T) {
	plan, e := Compile(`web.tab(origin:"https://fixture.test").getByRole("button",name:"Expand current row",exact:true).nth(0,order:"document").read("text")`)
	if e != nil {
		t.Fatal(e)
	}
	caps := map[string]bool{"web:attributeRead": true, "web:roleLocator": true, "web:indexedQuery": true}
	if e = (Registry{}).CheckCapabilities(plan, caps); e != nil {
		t.Fatal(e)
	}
	delete(caps, "web:indexedQuery")
	caps["web:orderedQuery"] = true
	if (Registry{}).CheckCapabilities(plan, caps) == nil {
		t.Fatal("generic plural capability silentlyenabled local nth")
	}
	caps["web:indexedQuery"] = true
	delete(caps, "web:orderedQuery")
	all, e := Compile(`web.tab(origin:"https://fixture.test").getByRole("button",exact:true).all(limit:10,order:"document").read("text")`)
	if e != nil {
		t.Fatal(e)
	}
	if (Registry{}).CheckCapabilities(all, caps) == nil {
		t.Fatal("nth qualification advertised unimplemented pluralall reads")
	}
}
