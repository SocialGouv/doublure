package guard

import (
	"regexp"
	"strings"
)

// Normalize neutralises the shell's escaping before any analysis.
//
// Without this step a literal pattern is trivially bypassed: several spellings
// designate the same target for bash but match no pattern. Quotes, backslashes
// and single-character glob classes are therefore removed.
//
// It does NOT split anything: splitting is the grammar's job and works on the
// RAW command, because quoting is what says where an argument ends. Getting
// that order wrong revives structure the quotes had suppressed — the nine
// false positives of round 17.
func Normalize(command string) string {
	out := reduceExpansions(command)
	out = expandBracesOutsideQuotes(out)
	return stripComments(stripQuoting(out))
}

// reduceToken is what bash gets out of ONE word, once its quoting is resolved.
//
// The same reductions as Normalize, applied word by word: the grammar did the
// splitting, so the boundaries are exact and there is nothing left to guess
// about where a quoted argument ends. A node yields exactly ONE word — brace
// expansion, the only thing that produces several, has already happened before
// the parse.
func reduceToken(word string) string {
	return stripQuoting(reduceExpansions(word))
}

// stripQuoting removes what only serves to spell a name differently.
func stripQuoting(text string) string {
	out := removeInfixReference(text)
	out = strings.ReplaceAll(out, "''", "")
	out = strings.ReplaceAll(out, `""`, "")
	out = globClassRe.ReplaceAllString(out, "$1")
	// A literal dollar: bash sees no expansion there. Reducing it to `$` turned
	// a regex quoting the indirection syntax into a real indirection.
	out = strings.ReplaceAll(out, `\$`, "")
	out = backslashRe.ReplaceAllString(out, "$1")
	out = strings.ReplaceAll(out, "'", "")
	return strings.ReplaceAll(out, `"`, "")
}

var (
	// Parameter expansion with an operator. The name may be POSITIONAL or
	// SPECIAL: requiring it alphabetic let `${1:-env}` through, which bash runs.
	expansionRe = regexp.MustCompile(`\$\{(#?)([A-Za-z_]\w*|\d+|[@*])([^}]*)\}`)
	// `[o]` is a glob class of one character; `[@]` and `[*]` are ARRAY
	// subscripts and must survive — reducing them confused the indices form
	// with the one that enumerates variable NAMES.
	globClassRe = regexp.MustCompile(`\[([^\]/@*])\]`)
	backslashRe = regexp.MustCompile(`\\(.)`)
	// A reference glued INSIDE a word only serves to split it, including in
	// its indirect form.
	infixRefRe = regexp.MustCompile(`\w\$\{!?[A-Za-z_]\w*\}\w`)
	// A brace expansion. The preceding `$` is EXCLUDED: `${IFS,,}` is a
	// parameter expansion whose comma is a case operator, not an alternative.
	bracesRe = regexp.MustCompile(`\{([^{}$\s]*,[^{}$\s]*)\}`)
)

// reduceExpansions rewrites each expansion to what bash gets out of it, never
// removing it: erasing one carried away the variable NAME, and reading a
// secret through a default-value form then passed.
func reduceExpansions(text string) string {
	return expansionRe.ReplaceAllStringFunc(text, func(m string) string {
		groups := expansionRe.FindStringSubmatch(m)
		prefix, name, rest := groups[1], groups[2], groups[3]
		switch {
		case strings.HasPrefix(rest, "@P"):
			// Prompt expansion EXECUTES what the variable contains. Reducing it
			// to `$VAR` made the operator vanish before any rule could see it.
			return m
		case name == "IFS":
			// IFS is a SEPARATOR — except with `+` or `:+`, which yield the
			// text on the right: that is how a split name gets rebuilt.
			if after, ok := afterOperator(rest, ":+", "+"); ok {
				return after
			}
			return " "
		case rest == "" && prefix == "":
			return m // plain `${VAR}`: unchanged
		}
		// `${VAR+text}` and `${VAR:+text}` yield the LITERAL text when VAR is
		// set — and `_` or `PATH` always are.
		if after, ok := afterOperator(rest, ":+", "+"); ok {
			return after
		}
		// Fallback forms yield the reference HERE. The "variable is empty"
		// branch, which bash executes, is analysed separately: injecting the
		// fallback into the text — even behind a separator — cut the
		// `[^|;&]*` class of every deny pattern.
		return "$" + name
	})
}

func afterOperator(rest string, operators ...string) (string, bool) {
	for _, op := range operators {
		if strings.HasPrefix(rest, op) {
			return rest[len(op):], true
		}
	}
	return "", false
}

// removeInfixReference replaces `(?<=\w)\$\{!?NAME\}(?=\w)`.
//
// RE2 has no lookaround, so the surrounding word characters are captured and
// re-emitted. Matching them without re-emitting would weld the two halves of
// the next match together and could miss an adjacent occurrence.
func removeInfixReference(text string) string {
	for {
		loc := infixRefRe.FindStringIndex(text)
		if loc == nil {
			return text
		}
		// Keep the first and last bytes: they belong to the word, not to the
		// reference.
		text = text[:loc[0]+1] + text[loc[1]-1:]
	}
}

// stripComments replaces `(?<![^\s])#[^\n]*`.
//
// A `#` at the START of a word opens a comment and bash ignores the rest of
// the line. Keeping it made a trailing comment look like the program executed
// by the command before it, hence a legitimate prefix. Glued to a word
// (`report#2.txt`) it is not a comment.
func stripComments(text string) string {
	var b strings.Builder
	b.Grow(len(text))
	atWordStart := true
	for i := 0; i < len(text); i++ {
		c := text[i]
		if c == '#' && atWordStart {
			b.WriteByte(' ')
			for i < len(text) && text[i] != '\n' {
				i++
			}
			if i < len(text) {
				b.WriteByte('\n')
			}
			atWordStart = true
			continue
		}
		b.WriteByte(c)
		atWordStart = c == ' ' || c == '\t' || c == '\n' || c == '\r'
	}
	return b.String()
}

// Budgets for brace expansion.
//
// Bounding the DEPTH alone let the product of alternatives explode; counting
// the alternatives alone let a hundred small groups produce megabytes, whose
// re-reading froze the agent for twenty seconds per tool call. Both are needed,
// and both are shared across the whole command.
const (
	braceAlternativeBudget = 64
	braceCharacterBudget   = 16384
	braceDepthBudget       = 4
)

type braceBudget struct{ alternatives, characters int }

// expandBracesOutsideQuotes expands each word carrying a brace expansion,
// leaving quoted regions alone.
//
// Bash produces SEVERAL words, prefix and suffix reattached to each
// alternative — keeping only the longest was wrong, since the discarded one
// runs too.
func expandBracesOutsideQuotes(text string) string {
	if !strings.Contains(text, "{") || !strings.Contains(text, ",") {
		return text
	}
	budget := &braceBudget{braceAlternativeBudget, braceCharacterBudget}
	var b strings.Builder
	last := 0
	for _, span := range unquotedSpans(text) {
		b.WriteString(text[last:span[0]])
		b.WriteString(expandWords(text[span[0]:span[1]], budget))
		last = span[1]
	}
	b.WriteString(text[last:])
	return b.String()
}

// unquotedSpans returns the regions OUTSIDE quotes, by a lexical scan.
//
// The grammar cannot help here: it is brace expansion itself that makes the
// grammar fail, since the unexpanded form is not valid bash. A scan is enough
// to know what is quoted — and a quoted brace is text, a JSON body is full of
// them.
func unquotedSpans(text string) [][2]int {
	var spans [][2]int
	start, i := 0, 0
	for i < len(text) {
		switch text[i] {
		case '\\':
			i += 2
			continue
		case '\'', '"':
			quote := text[i]
			spans = append(spans, [2]int{start, i})
			end := i + 1
			for end < len(text) && text[end] != quote {
				if quote == '"' && text[end] == '\\' {
					end++
				}
				end++
			}
			i = min(end+1, len(text))
			start = i
			continue
		}
		i++
	}
	return append(spans, [2]int{start, len(text)})
}

func expandWords(text string, budget *braceBudget) string {
	fields := splitKeepingSeparators(text)
	for i, word := range fields {
		if i%2 == 1 || !strings.Contains(word, "{") || !strings.Contains(word, ",") {
			continue
		}
		fields[i] = expandWord(word, 0, budget)
	}
	return strings.Join(fields, "")
}

// splitKeepingSeparators splits on whitespace, keeping the separators at odd
// indices so the text can be rebuilt exactly.
func splitKeepingSeparators(text string) []string {
	var out []string
	i := 0
	for i < len(text) {
		j := i
		for j < len(text) && !isSpace(text[j]) {
			j++
		}
		out = append(out, text[i:j])
		k := j
		for k < len(text) && isSpace(text[k]) {
			k++
		}
		out = append(out, text[j:k])
		i = k
	}
	return out
}

func isSpace(b byte) bool {
	return b == ' ' || b == '\t' || b == '\n' || b == '\r' || b == '\v' || b == '\f'
}

func expandWord(word string, depth int, budget *braceBudget) string {
	loc := bracesRe.FindStringSubmatchIndex(word)
	if loc == nil || depth > braceDepthBudget ||
		budget.alternatives <= 0 || budget.characters <= 0 {
		return word
	}
	// A `$` immediately before the brace makes it a parameter expansion.
	if loc[0] > 0 && word[loc[0]-1] == '$' {
		return word
	}
	alternatives := strings.Split(word[loc[2]:loc[3]], ",")
	budget.alternatives -= len(alternatives)
	budget.characters -= len(word) * len(alternatives)
	before, after := word[:loc[0]], word[loc[1]:]
	parts := make([]string, 0, len(alternatives))
	for _, alt := range alternatives {
		parts = append(parts, expandWord(before+alt+after, depth+1, budget))
	}
	return strings.Join(parts, " ")
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
