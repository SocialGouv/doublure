package guard

import (
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"testing"
)

// TestProgramLayerAgainstPython replays the program positions and the env-dump
// verdict through the Go layer.
//
// Both are judged PER OCCURRENCE, so the comparison is too: a wrapper grammar
// that skips one token too many does not change the number of positions, it
// changes which word is examined. `env PATH=/x env` is the case that made this
// layer index-based in the first place.
func TestProgramLayerAgainstPython(t *testing.T) {
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

	positionsSeen, dumpsSeen := 0, 0
	for _, c := range cases {
		if len(c.Positions) != len(c.Tokens) {
			t.Fatalf("malformed fixture on %q", c.Input)
		}
		for i, words := range c.Tokens {
			got := programPositions(words)
			positionsSeen += len(got)
			if fmt.Sprint(got) != fmt.Sprint(c.Positions[i]) {
				note(fmt.Sprintf("positions: python=%v go=%v",
					c.Positions[i], got), c.Input)
				continue
			}
			for j, at := range got {
				base := basename(words[at])
				dump := isEnvDump(base, words, at)
				// Counted only where the answer MEANS something. The function
				// ends on `return True`, so on any other program it is that
				// default speaking — a count including those would be
				// satisfied by a layer that never decides anything.
				if envDumpPrograms[base] {
					dumpsSeen++
				}
				if dump != c.Dumps[i][j] {
					note(fmt.Sprintf("dump on %q: python=%v go=%v",
						words[at], c.Dumps[i][j], dump), c.Input)
				}
			}
		}
	}

	// A corpus where nothing dumps would agree with a layer that never fires.
	if positionsSeen < 500 || dumpsSeen < 20 {
		t.Fatalf("%d positions and %d dumps: too little to prove anything",
			positionsSeen, dumpsSeen)
	}

	if len(byCause) == 0 {
		t.Logf("%d program positions, %d of them naming an env-dump builtin: "+
			"identical", positionsSeen, dumpsSeen)
		return
	}
	causes := make([]string, 0, len(byCause))
	for cause := range byCause {
		causes = append(causes, cause)
	}
	sort.Strings(causes)
	shown := 0
	for _, cause := range causes {
		if shown++; shown > 25 {
			t.Errorf("… and %d more distinct causes", len(causes)-25)
			break
		}
		t.Errorf("%-56s %4d cases, e.g. %q",
			cause, byCause[cause], examples[cause])
	}
}
