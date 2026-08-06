package guard

import (
	"fmt"
	"regexp"
	"strings"

	ts "github.com/tree-sitter/go-tree-sitter"
	bash "github.com/tree-sitter/tree-sitter-bash/bindings/go"
)

// Tokenize splits a command into simple commands, the way the bash GRAMMAR
// cuts them rather than the way a denylist approximates it.
//
// Fourteen rounds of adversarial review measured the limit of heuristic
// splitting: a comment taken for a program, a brace that stopped the analysis,
// a `case` whose body vanished, a function name with unexpected characters, a
// quoted argument whose end nobody knew. The grammar answers all of those by
// construction.
//
// What it does NOT do is evaluate. Expansions, wrappers and indirections are
// still handled here — that is bash semantics, not syntax.
func Tokenize(command string) ([][]string, error) {
	parser := ts.NewParser()
	defer parser.Close()
	if err := parser.SetLanguage(ts.NewLanguage(bash.Language())); err != nil {
		return nil, fmt.Errorf("bash grammar unavailable, the split cannot be "+
			"verified: %w", err)
	}
	return commandsFromAST(parser, command, 0), nil
}

// Nodes of the grammar that carry a PROGRAM. `declare`, `export`, `readonly`,
// `typeset` and `local` are NOT `command` but `declaration_command`, and
// `unset` has its own node: omitting them missed the WHOLE family of dumpers.
var commandNodes = map[string]bool{
	"command": true, "declaration_command": true, "unset_command": true,
}

// Children that are not WORDS of the command: the target of a redirection is
// not a program, a comment is not executed. A heredoc BODY is set aside here
// and routed separately — it is code, not an argument.
var nonWordChildren = map[string]bool{
	"file_redirect": true, "heredoc_redirect": true,
	"herestring_redirect": true, "comment": true,
}

// Maximum re-analysis depth for a nested script (`bash -c 'bash -c …'`, a
// heredoc inside a heredoc).
const scriptDepthBudget = 4

// Options of `find` whose value is a command, terminated by `\;` or `+`.
var execClauses = map[string]bool{
	"-exec": true, "-execdir": true, "-ok": true, "-okdir": true,
}

const neutralFunctionName = "fonction_au_nom_inattendu"

var (
	// `-c` of a shell, possibly at the end of a short-option group, with its
	// value ATTACHED: `bash -c"env"`, `bash -xcenv`. Bash concatenates the
	// word, and it is the called shell that separates option from value.
	optCAttachedRe = regexp.MustCompile(`^-[A-Za-z]*c(.*)$`)
	emptyParensRe  = regexp.MustCompile(`\(\s*\)`)
	plainNameRe    = regexp.MustCompile(`^[A-Za-z_]\w*$`)
	// A CLOSED vocabulary of signal specifications, which end a `trap`.
	signalRe = regexp.MustCompile(`(?i)^(?:\d+|(SIG)?(EXIT|ERR|DEBUG|RETURN|` +
		`HUP|INT|QUIT|ILL|TRAP|ABRT|BUS|FPE|KILL|USR[12]|SEGV|PIPE|ALRM|TERM|` +
		`CHLD|CONT|STOP|TSTP|TT(IN|OU)|WINCH))$`)
	// The `(?=\S)` and `(?=\{)` lookaheads only assert what follows, so the
	// character is captured and re-emitted instead.
	coprocNamedRe    = regexp.MustCompile(`\bcoproc\s+([A-Za-z_]\w*)\s+(\S)`)
	coprocGroupRe    = regexp.MustCompile(`\bcoproc\s+(\{)`)
	aliasRe          = regexp.MustCompile(`\balias\s+[A-Za-z_]\w*=(\S+)`)
	envSplitStringRe = regexp.MustCompile(`\benv\s+(?:--split-string=?|-S)\s*`)
)

// wordDelimiters are the characters bash treats as ending a word; a function
// name is delimited by walking back to one of them.
const wordDelimiters = " \t\n|;&<>(){}\"'"

// shellWrappers run their `-c` value as a script. Only for these does `-c`
// introduce a command.
var shellWrappers = map[string]bool{
	"sh": true, "bash": true, "zsh": true, "ksh": true, "dash": true,
	"su": true, "runuser": true, "busybox": true, "script": true,
	"toybox": true, "fish": true, "csh": true, "tcsh": true, "mksh": true,
	"oksh": true, "posh": true, "yash": true, "pwsh": true,
	"powershell": true, "machinectl": true, "systemd-run": true,
}

// commandsFromAST returns the simple commands of one script.
//
// The semantic rewrites are applied at EVERY level: a nested script can itself
// carry a `coproc`, an alias or a brace to expand, and hoisting them one level
// up would be letting them through.
func commandsFromAST(parser *ts.Parser, source string, depth int) [][]string {
	text := semanticRewrites(source)
	tree := parser.Parse([]byte(text), nil)
	defer tree.Close()

	var out [][]string
	stack := []*ts.Node{tree.RootNode()}
	for len(stack) > 0 {
		node := stack[len(stack)-1]
		stack = stack[:len(stack)-1]

		if node.Kind() == "heredoc_body" {
			// A heredoc body is CODE when an interpreter consumes it. Whether
			// it is data or code was settled upstream, by emptying the bodies
			// that are not; what is left here is analysed as a script.
			if depth < scriptDepthBudget {
				out = append(out, commandsFromAST(parser,
					text[node.StartByte():node.EndByte()], depth+1)...)
			}
			continue
		}

		if commandNodes[node.Kind()] {
			if words := wordsOf(node, text); len(words) > 0 {
				out = append(out, words)
				if depth < scriptDepthBudget {
					for _, script := range subScripts(words) {
						out = append(out,
							commandsFromAST(parser, script, depth+1)...)
					}
				}
			}
		}

		for i := int(node.ChildCount()) - 1; i >= 0; i-- {
			stack = append(stack, node.Child(uint(i)))
		}
	}
	return out
}

// wordsOf reduces a command node's children to the words bash would run.
func wordsOf(node *ts.Node, text string) []string {
	var words []string
	hasExecClause := false
	for i := uint(0); i < node.ChildCount(); i++ {
		child := node.Child(i)
		if nonWordChildren[child.Kind()] {
			continue
		}
		word := reduceToken(text[child.StartByte():child.EndByte()])
		if word == "" {
			continue
		}
		hasExecClause = hasExecClause || execClauses[word]
		words = append(words, word)
	}
	if !hasExecClause {
		return words
	}
	// The terminator of an `-exec` clause (`\;` or `+`) is not an argument.
	// The grammar renders it as an ordinary word and the escape that
	// distinguished it drops on reduction: keeping it made `find … -exec env
	// \;` look like `env` running `;`, hence a legitimate execution prefix.
	kept := words[:0]
	for _, word := range words {
		if word != ";" && word != "+" {
			kept = append(kept, word)
		}
	}
	return kept
}

// subScripts returns the arguments whose VALUE is a whole script.
//
// This is the counterpart of what the grammar buys: a quoted argument arrives
// in one piece, so `bash -c 'f() { env; }; f'` no longer shows its inside by
// accident. It has to be opened explicitly — and then its start and end are
// known exactly, which removes the double readings that losing the quoting
// used to force.
func subScripts(words []string) []string {
	bases := make([]string, len(words))
	for i, word := range words {
		bases[i] = basename(word)
	}
	var scripts []string
	for i, word := range words {
		value := ""
		if i+1 < len(words) {
			value = words[i+1]
		}
		switch {
		// `-c` introduces a command for a SHELL only: for `git`, `docker` or
		// `xargs` it means something else.
		case containsAny(bases[:i], shellWrappers):
			if attached := optCAttachedRe.FindStringSubmatch(word); attached != nil {
				if attached[1] != "" {
					scripts = append(scripts, attached[1])
				} else {
					scripts = append(scripts, value)
				}
			}
		// `mapfile -C CALLBACK -c N` runs CALLBACK every N lines read.
		case word == "-C" && containsAny(bases[:i], map[string]bool{
			"mapfile": true, "readarray": true}):
			scripts = append(scripts, value)
		// The value of `env -S` is a whole COMMAND, never a token.
		case word == "-S" && containsAny(bases[:i], map[string]bool{"env": true}):
			scripts = append(scripts, value)
		}
	}
	// `trap CMD SIGNAL`: the signal name FOLLOWS the command, so `trap env
	// EXIT` reads as "env runs EXIT", hence as a legitimate prefix. Signal
	// specifications are a CLOSED vocabulary: everything else is the command.
	if len(bases) > 0 && bases[0] == "trap" {
		for _, word := range words[1:] {
			if word != "--" && !strings.HasPrefix(word, "-") &&
				!signalRe.MatchString(word) {
				scripts = append(scripts, word)
			}
		}
	}
	kept := scripts[:0]
	for _, script := range scripts {
		if script != "" {
			kept = append(kept, script)
		}
	}
	return kept
}

func containsAny(bases []string, set map[string]bool) bool {
	for _, base := range bases {
		if set[base] {
			return true
		}
	}
	return false
}

// basename is the command name with its path removed: `/usr/bin/env` → `env`.
func basename(token string) string {
	if i := strings.LastIndex(token, "/"); i >= 0 {
		return token[i+1:]
	}
	return token
}

// semanticRewrites spells out what bash DOES and the grammar does not show.
//
// The grammar describes SYNTAX; these three forms require knowing what bash
// makes of them at run time.
func semanticRewrites(command string) string {
	// `coproc NAME cmd`: the name is OPTIONAL, so the command sits sometimes
	// first, sometimes second — both readings are emitted. `coproc { cmd; }`
	// is unknown to the grammar, which yields `coproc` with the words `{` and
	// `cmd`, where the body is no longer a program; isolating the group gives
	// it back.
	out := canonicaliseFunctionNames(expandBracesOutsideQuotes(command))
	out = coprocNamedRe.ReplaceAllString(out, "coproc $1 ; $2")
	out = coprocGroupRe.ReplaceAllString(out, "coproc ; $1")
	// `alias e=env` then `e` on ANOTHER line: bash expands the alias. It does
	// not hold on the line that DEFINES it, but it holds on the following
	// ones.
	var aliases strings.Builder
	for _, m := range aliasRe.FindAllStringSubmatch(out, -1) {
		aliases.WriteString(" ; " + m[1])
	}
	out += aliases.String()
	// `env --split-string=CMD`: the ATTACHED long form starts with `-`, so it
	// passed for an ordinary option and the program disappeared.
	return envSplitStringRe.ReplaceAllString(out, "env -S ")
}

// canonicaliseFunctionNames makes a function definition with an unexpected
// name analysable.
//
// Bash accepts almost anything in a function name (`my.fn`, `a@b`, `a%b`,
// `a+b`, `1fn`); the grammar accepts only part of that, and the tree then goes
// to ERROR — the BODY disappears, though the body is what carries the
// programs. Only the name is replaced; the structure becomes readable again.
//
// The name is delimited by walking back from the parenthesis, never by a regex
// searching for it leftwards: a free class at the head backtracks at every
// position of a long word, which cost fifteen seconds on twenty thousand
// characters.
func canonicaliseFunctionNames(text string) string {
	if !strings.Contains(text, "(") {
		return text
	}
	var b strings.Builder
	end := 0
	for _, m := range emptyParensRe.FindAllStringIndex(text, -1) {
		bound := m[0]
		for bound > end && (text[bound-1] == ' ' || text[bound-1] == '\t') {
			bound--
		}
		start := bound
		for start > end &&
			!strings.ContainsRune(wordDelimiters, rune(text[start-1])) {
			start--
		}
		name := text[start:bound]
		// A name that already parses is left alone; with no name at all the
		// parenthesis opens no definition (`echo ()` is not one).
		if name == "" || plainNameRe.MatchString(name) {
			continue
		}
		b.WriteString(text[end:start])
		b.WriteString(neutralFunctionName)
		end = bound
	}
	b.WriteString(text[end:])
	return b.String()
}
