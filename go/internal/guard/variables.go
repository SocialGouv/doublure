package guard

import (
	"regexp"
	"strings"
)

var (
	// The dereferenced NAME, isolated from its syntax (`$X`, `${X}`, `${!X}`).
	variableNameRe = regexp.MustCompile(`\$\{?!?\s*([A-Za-z_][A-Za-z0-9_]*)`)

	// INDIRECT reference: `x=AWS_SECRET_ACCESS_KEY; echo ${!x}`. The name that
	// counts is not in the expansion but in the assignment before it.
	//
	// The expansion must be WELL FORMED — closing brace nearby, no regex
	// metacharacter in between. Settling for the prefix made any regex QUOTING
	// this syntax suspect, and prose became code again: the defect rounds 5
	// and 8 had eliminated elsewhere.
	//
	// An array SUBSCRIPT is tolerated: `${!m[k1]}` is a full indirection — the
	// element's VALUE names the target. Excluding the opening bracket dropped
	// it between this guard and the subscript exemption, which requires `[@]`
	// or `[*]`: any other subscript was covered by NEITHER.
	indirectRefRe = regexp.MustCompile(
		`\$\{!\s*([A-Za-z_]\w*|\d+|[@*])(?:\[[^\]}]{0,32}\])?[^}\\\[(?]{0,32}\}`)

	// `${!arr[@]}` and `${!arr[*]}` yield an array's INDICES: no variable value
	// comes out. It is the only harmless form of indirection.
	//
	// The BRACKETS are required: `${!PREFIX@}`, without them, ENUMERATES THE
	// NAMES of variables starting with PREFIX — that is, the list of secrets
	// present in the environment.
	arrayIndicesRe = regexp.MustCompile(`\$\{!\s*[A-Za-z_]\w*\[[@*]\]\}`)

	// Reference by ALIAS: `declare -n r=AWS_SECRET_ACCESS_KEY; echo $r`. Same
	// mechanism as indirection, other syntax — and `$r` carries no sensitive
	// name, only the alias designates one.
	namerefRe = regexp.MustCompile(
		`\b(?:declare|typeset|local)\b[^|;&\n]*?\s-[A-Za-z]*n[A-Za-z]*\s+` +
			`([A-Za-z_]\w*)(?:=(\$?\{?[\w@*]+\}?))?`)

	// The three ways of setting a variable. `read` and `printf -v` escaped the
	// index entirely, which only admitted a literal on the right-hand side.
	// The value stops at the separator: `\S*` swallowed the `;` of
	// `x=$y; echo ${!x}` and the hop to `y` was lost.
	assignmentRe = regexp.MustCompile(`\b([A-Za-z_]\w*)=([^\s|;&]*)`)
	printfVRe    = regexp.MustCompile(
		`\bprintf\b(?:\s+-\S+)*\s+-v\s+([A-Za-z_]\w*)\s+([^|;&\n]*)`)
	readHereStringRe = regexp.MustCompile(
		`\bread\b(?:\s+-\S+)*\s+([A-Za-z_]\w*)\s*<<<\s*([^|;&\n]*)`)

	// Constructs that BIND a variable at run time: the value comes from a
	// list, from standard input, from a descriptor, from an option line. The
	// name it will carry is therefore as unknown as an indirection's.
	//
	// Enumerating those mechanisms is endless — `for`, `select`, `while read …
	// done <<< …`, `read -u`, `getopts` fell one after another — so the
	// variable is marked OPAQUE and the proof indirection requires fails by
	// itself.
	opaqueBindingRe = regexp.MustCompile(
		`\bfor\s+([A-Za-z_]\w*)\s+in\b` +
			`|\bselect\s+([A-Za-z_]\w*)\s+in\b` +
			`|\bgetopts\s+\S+\s+([A-Za-z_]\w*)`)

	// `read` binds EVERY name that follows it, and its options can carry a
	// variable value (`read -u $COPROC A`): requiring the name right after the
	// options missed the interposed descriptor.
	readBindingRe = regexp.MustCompile(`\bread\b((?:\s+(?:-\S+|\$\S+|[A-Za-z_]\w*))*)`)

	// A right-hand side whose value is not known before execution.
	opaqueValueRe = regexp.MustCompile(`\$\(|` + "`" + `|` + substitutionMarker)

	// In arithmetic context, `$((PORT))` reads the variable WITHOUT a dollar:
	// the name control, which requires the sigil, saw nothing there.
	arithmeticRe = regexp.MustCompile(`(?s)\$\(\((.*?)\)\)`)

	bareNameRe = regexp.MustCompile(`[A-Za-z_]\w*`)
)

// chainBudget bounds the assignment chain walk. A thirty-hop chain is legal
// bash; an unbounded walk on hostile input is a denial of service, and this
// runs before EVERY tool call.
const chainBudget = 512

// sensitiveVariable returns the name of the sensitive variable a command reads,
// or "". It takes ALREADY-normalised text.
func sensitiveVariable(normalized string) string {
	for _, m := range arithmeticRe.FindAllStringSubmatch(normalized, -1) {
		for _, name := range bareNameRe.FindAllString(m[1], -1) {
			if sensitiveName(name) {
				return name
			}
		}
	}

	// `${!arr[@]}` yields only INDICES: the array's name, sensitive or not,
	// exposes no value.
	normalized = arrayIndicesRe.ReplaceAllString(normalized, " ")
	for _, m := range variableNameRe.FindAllStringSubmatch(normalized, -1) {
		if sensitiveName(m[1]) {
			return m[1]
		}
	}

	// `${!x}` names only `x`: the name actually read is the VALUE of `x`. An
	// alias `declare -n r=TARGET` designates its target the same way, but that
	// one is written IN CLEAR — so the two are not handled alike: for the
	// alias the target is read, for the indirection it must be PROVEN.
	var indirections []string
	for _, m := range indirectRefRe.FindAllStringSubmatch(normalized, -1) {
		indirections = append(indirections, m[1])
	}
	var aliases []string
	for _, m := range namerefRe.FindAllStringSubmatch(normalized, -1) {
		target := m[2]
		if target == "" {
			target = m[1]
		}
		aliases = append(aliases, strings.TrimLeft(target, "${"))
	}
	if len(indirections) == 0 && len(aliases) == 0 {
		return ""
	}

	assignments, opaque := bindings(normalized)

	// INDIRECTION: bash reads the variable NAMED by the value of `x`. That
	// value can come from a `for` loop, a `select`, a positional parameter, a
	// `set --`, a function argument, a `read` inside a block… Enumerating the
	// mechanisms is endless — every round found new ones. The burden of proof
	// is therefore INVERTED: we refuse unless the name read is shown to be
	// harmless. The list of harmless indirections is short and boundable; the
	// list of dangerous ones is not.
	for _, target := range indirections {
		if !provenHarmless(target, true, assignments, opaque) {
			return target
		}
	}
	// ALIAS: the target is normally written IN CLEAR and can be read. But
	// `declare -n r=$1` makes it come from a positional parameter, whose value
	// is as unknown as an indirection's — and routing that to the direct
	// reading declared it harmless for want of a visible assignment.
	for _, target := range aliases {
		literal := plainIdentifierRe.MatchString(target)
		if !provenHarmless(target, !literal, assignments, opaque) {
			return target
		}
	}
	return ""
}

// bindings indexes the assignments in ONE pass, and collects the names bound at
// run time.
//
// Searching each target across the whole command cost O(targets × length): five
// thousand aliases hung the hook for seconds and twenty thousand for a minute —
// before EVERY tool call, using bash primitives alone.
func bindings(normalized string) (map[string][]string, map[string]bool) {
	assignments := map[string][]string{}
	for _, re := range []*regexp.Regexp{assignmentRe, printfVRe, readHereStringRe} {
		for _, m := range re.FindAllStringSubmatch(normalized, -1) {
			values := strings.Fields(m[2])
			if len(values) == 0 {
				values = []string{""}
			}
			assignments[m[1]] = append(assignments[m[1]], values...)
		}
	}
	opaque := map[string]bool{}
	for _, m := range opaqueBindingRe.FindAllStringSubmatch(normalized, -1) {
		for _, name := range m[1:] {
			if name != "" {
				opaque[name] = true
			}
		}
	}
	for _, m := range readBindingRe.FindAllStringSubmatch(normalized, -1) {
		for _, word := range strings.Fields(m[1]) {
			if plainIdentifierRe.MatchString(word) {
				opaque[word] = true
			}
		}
	}
	return assignments, opaque
}

// provenHarmless follows the assignment chain and proves the name read is
// innocuous. Anything it cannot prove is a refusal.
func provenHarmless(start string, needsAnAssignment bool,
	assignments map[string][]string, opaque map[string]bool) bool {
	seen := map[string]bool{}
	pending := []string{start}
	for len(pending) > 0 && len(seen) < chainBudget {
		target := pending[len(pending)-1]
		pending = pending[:len(pending)-1]
		if seen[target] {
			continue
		}
		seen[target] = true
		if sensitiveName(target) || opaque[target] {
			return false
		}
		values, known := assignments[target]
		if !known || len(values) == 0 {
			// No visible assignment: NOTHING can be proven.
			return !needsAnAssignment
		}
		for _, value := range values {
			if opaqueValueRe.MatchString(value) || sensitiveName(value) {
				return false
			}
			if next := strings.Trim(strings.TrimLeft(value, "$"), "{}"); next != value {
				pending = append(pending, next)
			}
		}
	}
	return len(pending) == 0
}
