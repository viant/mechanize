package chrome

import (
	"os"
	"regexp"
	"strconv"
	"testing"
)

func TestPackagedWorkerBuildHasBrokerQualification(t *testing.T) {
	source, err := os.ReadFile("../../extension/chrome/worker.js")
	if err != nil {
		t.Fatal(err)
	}
	matches := regexp.MustCompile(`\bworkerBuild:\s*([0-9]+)`).FindAllSubmatch(source, -1)
	if len(matches) != 1 {
		t.Fatal("expected one explicit packaged worker build")
	}
	build, err := strconv.Atoi(string(matches[0][1]))
	if err != nil || build != maxQualifiedWorkerBuild {
		t.Fatalf("packaged worker build %d is not the reviewed broker build %d", build, maxQualifiedWorkerBuild)
	}
}
