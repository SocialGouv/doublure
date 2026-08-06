package guard

import (
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"testing"
)

// decision is one Python answer, exported by gen_fixture.py.
type decision struct {
	Input     string     `json:"input"`
	Vault     bool       `json:"vault"`
	Files     bool       `json:"files"`
	Deny      string     `json:"deny"`
	Variable  string     `json:"variable"`
	Tokens    [][]string `json:"tokens"`
	Positions [][]int    `json:"positions"`
	Dumps     [][]bool   `json:"dumps"`
	Canonised string     `json:"canonised"`
	Regions   []string   `json:"regions"`
	Bash      string     `json:"bash"`
}

// TestAgainstPython replays the Python answers through the Go layer.
//
// This is the only thing that makes a port worth anything. Reading the Go and
// judging it correct is how nineteen rounds of defects were introduced in the
// first place; replaying the SAME inputs through both and comparing is not.
//
// The corpus is the hook's own test suite — the commands that encode those
// nineteen rounds. Any disagreement here is a finding, in one implementation
// or the other.
func TestAgainstPython(t *testing.T) {
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

	// Grouped by cause rather than one failure per input: a systematic
	// difference shows up as one line, not as four hundred.
	byCause := map[string]int{}
	examples := map[string]string{}
	note := func(cause, input string) {
		byCause[cause]++
		if _, seen := examples[cause]; !seen {
			examples[cause] = input
		}
	}

	// Counted per layer: a layer that fires nowhere in the corpus agrees with
	// anything, and three of the four started out exactly like that.
	fired := map[string]int{}

	for _, c := range cases {
		normalised := Normalize(c.Input)
		for layer, positive := range map[string]bool{
			"vault": c.Vault, "files": c.Files,
			"deny": c.Deny != "", "variable": c.Variable != "",
		} {
			if positive {
				fired[layer]++
			}
		}

		if got := firstMatch(vaultRules, normalised) != ""; got != c.Vault {
			note(fmt.Sprintf("vault: python=%v go=%v", c.Vault, got), c.Input)
		}
		if got := checkSensitiveFiles(normalised) != ""; got != c.Files {
			note(fmt.Sprintf("files: python=%v go=%v", c.Files, got), c.Input)
		}
		// The variable layer is the one where round 13 INVERTED the burden of
		// proof: it refuses unless the name read can be shown harmless. A Go
		// port that proves too much is a silent leak, so the offending NAME is
		// compared and not merely the verdict.
		if got := sensitiveVariable(normalised); got != c.Variable {
			note(fmt.Sprintf("variable: python=%q go=%q", c.Variable, got),
				c.Input)
		}

		got := firstMatch(denyRules, normalised)
		if (got != "") != (c.Deny != "") {
			note(fmt.Sprintf("deny: python=%q go=%q", c.Deny, got), c.Input)
		} else if got != c.Deny {
			// Same verdict, different rule: not a security difference, but it
			// means the rules fire in a different ORDER, and order is how the
			// reason reaching the model is chosen.
			note("deny: same verdict, different rule", c.Input)
		}
	}

	for _, layer := range []string{"vault", "files", "deny", "variable"} {
		if fired[layer] < 10 {
			t.Fatalf("the %s layer fires on %d inputs: agreeing with Python "+
				"there proves nothing", layer, fired[layer])
		}
	}

	if len(byCause) == 0 {
		t.Logf("%d inputs, identical on all four layers "+
			"(vault %d, files %d, deny %d, variable %d fired)", len(cases),
			fired["vault"], fired["files"], fired["deny"], fired["variable"])
		return
	}
	causes := make([]string, 0, len(byCause))
	for cause := range byCause {
		causes = append(causes, cause)
	}
	sort.Strings(causes)
	for _, cause := range causes {
		t.Errorf("%-46s %4d cases, e.g. %q",
			cause, byCause[cause], examples[cause])
	}
}
