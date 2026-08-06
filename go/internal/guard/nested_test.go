package guard

import (
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"strings"
	"testing"
)

// TestNestedLayerAgainstPython replays the heredoc rewriting and the nested
// regions through the Go layer.
//
// This layer is the one that is NOT a translation. Two Python patterns close on
// a backreference to the heredoc marker, which RE2 cannot express at all, so
// the body is found by scanning instead. A restructuring of a control hardened
// over nineteen rounds is exactly what has to be compared rather than read.
func TestNestedLayerAgainstPython(t *testing.T) {
	raw, err := os.ReadFile("testdata/python_decisions.json")
	if err != nil {
		t.Fatalf("fixture missing — run gen_fixture.py: %v", err)
	}
	var cases []decision
	if err := json.Unmarshal(raw, &cases); err != nil {
		t.Fatalf("unreadable fixture: %v", err)
	}

	byCause := map[string]int{}
	examples := map[string]string{}
	note := func(cause, input string) {
		byCause[cause]++
		if _, seen := examples[cause]; !seen {
			examples[cause] = input
		}
	}

	rewritten, withRegions := 0, 0
	for _, c := range cases {
		if got := canonicaliseProgram(neutraliseHeredocs(c.Input)); got != c.Canonised {
			note(fmt.Sprintf("heredoc: python=%q go=%q", c.Canonised, got),
				c.Input)
		} else if got != c.Input {
			rewritten++
		}

		got, err := nestedRegions(Normalize(c.Input))
		if err != nil {
			t.Fatalf("the grammar is a PREREQUISITE of the analysis: %v", err)
		}
		if len(got) > 0 {
			withRegions++
		}
		if strings.Join(got, "\x00") != strings.Join(c.Regions, "\x00") {
			note(fmt.Sprintf("regions: python=%q go=%q", c.Regions, got), c.Input)
		}
	}

	// A corpus with no heredoc and no substitution would agree with a layer
	// that does nothing at all.
	if rewritten < 5 || withRegions < 50 {
		t.Fatalf("%d heredoc rewrites and %d inputs with nested regions: "+
			"too little to prove anything", rewritten, withRegions)
	}

	if len(byCause) == 0 {
		t.Logf("%d heredoc/here-string rewrites, %d inputs carrying nested "+
			"regions: identical", rewritten, withRegions)
		return
	}
	causes := make([]string, 0, len(byCause))
	for cause := range byCause {
		causes = append(causes, cause)
	}
	sort.Strings(causes)
	shown := 0
	for _, cause := range causes {
		if shown++; shown > 20 {
			t.Errorf("… and %d more distinct causes", len(causes)-20)
			break
		}
		t.Errorf("%-70s %4d cases, e.g. %q",
			cause, byCause[cause], examples[cause])
	}
}
