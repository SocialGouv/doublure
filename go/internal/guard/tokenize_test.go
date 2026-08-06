package guard

import (
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"strings"
	"testing"
)

// TestTokenizeAgainstPython replays the Python split through the Go one.
//
// This layer is the one that cannot be reviewed by reading. Fourteen rounds of
// heuristics were replaced by a grammar precisely because a human — me — kept
// judging the splitting correct and kept missing a bash mechanism. Comparing
// the two implementations on the same corpus is the only check that does not
// depend on my judgement.
//
// Any difference is a finding. A word that Go loses is a program that escapes
// analysis; a word it invents is a false positive waiting to block a session.
func TestTokenizeAgainstPython(t *testing.T) {
	raw, err := os.ReadFile("testdata/python_decisions.json")
	if err != nil {
		t.Fatalf("fixture missing — run gen_fixture.py: %v", err)
	}
	var cases []decision
	if err := json.Unmarshal(raw, &cases); err != nil {
		t.Fatalf("unreadable fixture: %v", err)
	}
	if len(cases) < 500 {
		t.Fatalf("fixture too small (%d): the corpus did not load, and a test "+
			"that checks nothing is worse than no test", len(cases))
	}

	byCause := map[string]int{}
	examples := map[string]string{}
	note := func(cause, input string) {
		byCause[cause]++
		if _, seen := examples[cause]; !seen {
			examples[cause] = input
		}
	}

	exercised := 0
	for _, c := range cases {
		got, err := Tokenize(c.Input)
		if err != nil {
			t.Fatalf("the grammar is a PREREQUISITE of the analysis: %v", err)
		}
		if len(c.Tokens) > 0 {
			exercised++
		}
		if len(got) != len(c.Tokens) {
			note(fmt.Sprintf("commands: python=%d go=%d",
				len(c.Tokens), len(got)), c.Input)
			continue
		}
		for i := range got {
			if strings.Join(got[i], "\x00") != strings.Join(c.Tokens[i], "\x00") {
				note(fmt.Sprintf("words: python=%q go=%q",
					c.Tokens[i], got[i]), c.Input)
				break
			}
		}
	}

	// A corpus that split nothing would agree with anything.
	if exercised < len(cases)/4 {
		t.Fatalf("only %d/%d inputs produce a command: the comparison proves "+
			"nothing", exercised, len(cases))
	}

	if len(byCause) == 0 {
		t.Logf("%d inputs, %d of which split into commands: identical",
			len(cases), exercised)
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
		t.Errorf("%-60s %4d cases, e.g. %q",
			cause, byCause[cause], examples[cause])
	}
}
