package guard

import (
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"testing"
)

// TestCheckBashAgainstPython replays the whole shell analysis.
//
// This is the layer that matters: everything else feeds it. The exact REASON is
// compared, not merely the verdict — the reason is the sentence the model
// receives and quotes back, and `tests/phase4_e2e.sh` asserts on it. Two
// refusals for different reasons are two different behaviours.
func TestCheckBashAgainstPython(t *testing.T) {
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

	refused, distinct := 0, map[string]bool{}
	for _, c := range cases {
		got, err := CheckBash(c.Input)
		if err != nil {
			t.Fatalf("the grammar is a PREREQUISITE of the analysis: %v", err)
		}
		if c.Bash != "" {
			refused++
			distinct[c.Bash] = true
		}
		if got == c.Bash {
			continue
		}
		switch {
		case c.Bash != "" && got == "":
			// The only direction that opens the channel.
			note("LEAK: python refuses, go allows — "+c.Bash, c.Input)
		case c.Bash == "" && got != "":
			note("false positive: go refuses — "+got, c.Input)
		default:
			note(fmt.Sprintf("different reason: python=%q go=%q", c.Bash, got),
				c.Input)
		}
	}

	// A corpus that refuses little, or always for the same reason, would agree
	// with a control far weaker than this one.
	if refused < 100 || len(distinct) < 15 {
		t.Fatalf("%d refusals for %d distinct reasons: too little to prove "+
			"anything", refused, len(distinct))
	}

	if len(byCause) == 0 {
		t.Logf("%d refusals for %d distinct reasons, and %d allowed: identical",
			refused, len(distinct), len(cases)-refused)
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
		t.Errorf("%-72s %4d cases, e.g. %q",
			cause, byCause[cause], examples[cause])
	}
}
