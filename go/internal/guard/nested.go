package guard

import (
	"regexp"
	"sort"
	"strings"
)

// Interpreters: their argument can be a program.
var interpreters = set(
	"sh", "bash", "zsh", "ksh", "dash", "python", "python2", "python3",
	"pypy", "pypy3", "ipython", "ipython3", "bpython",
	"perl", "perl6", "raku", "ruby", "irb",
	"node", "deno", "bun", "php", "lua", "tclsh", "awk", "gawk", "mawk",
	"Rscript", "julia", "psql", "mysql", "sqlite3", "expect", "swift",
	"groovy", "kotlin", "kotlinc", "scala", "elixir", "iex", "erl",
	"crystal", "guile", "scheme", "racket", "clojure", "bb",
	"pwsh", "powershell", "fish", "csh", "tcsh", "mksh", "oksh", "posh",
	"yash", "elvish", "xonsh", "nu",
)

// Interpreters that are NOT shells. The distinction matters: a body handed to
// a shell is a sequence of commands, which splitting on newlines handles
// correctly; one handed to a language is code, where a newline separates
// nothing — `os.system(…)` must stay in the same segment as the interpreter to
// be seen at all.
var languages = set(
	"python", "python2", "python3", "pypy", "pypy3", "ipython", "ipython3",
	"bpython", "perl", "perl6", "raku", "ruby", "irb", "node", "deno", "bun",
	"php", "lua", "tclsh", "awk", "gawk", "mawk", "Rscript", "julia", "expect",
	"swift", "groovy", "kotlin", "kotlinc", "scala", "elixir", "iex", "erl",
	"crystal", "guile", "scheme", "racket", "clojure", "bb",
)

var (
	// SHELL substitutions: they run everywhere, unconditionally. Regions whose
	// CONTENT is itself a command — analysed recursively then removed from the
	// enclosing command, without which their words would pass for ordinary
	// arguments (`perl -e 'system("env")'`).
	nestedRe = regexp.MustCompile(
		`\$\((?P<sub>[^()]*)\)|` + "`(?P<bt>[^`]*)`" + `|[<>]\((?P<proc>[^()]*)\)`)

	// Execution primitives of a LANGUAGE. Reserved for code given IN LINE:
	// `git commit -m 'add system(env) support'` runs nothing, and analysing it
	// refused an ordinary commit message.
	//
	// `exec\w*` and `spawn\w*`: a right-hand `\b` missed `execvp`, `execlp`,
	// `spawnl`, `spawnSync`… A parenthesis is REQUIRED here — it is a call.
	languageCallRe = regexp.MustCompile(`(?i)\b(?:system|shell_exec|passthru|` +
		`popen|Popen|exec\w*|spawn\w*|fork|qx|proc_open|pcntl_exec|` +
		`posix_spawn\w*|Open3\.\w+|pty\.spawn|` +
		`os\.(?:execute|exec\w*|spawn\w*|popen)|IO\.popen|child_process\.\w+|` +
		`subprocess\.\w+|check_output|check_call|getoutput|getstatusoutput)` +
		// one level of parentheses tolerated: `run(("env",))` is a tuple, and
		// inverting `[]` into `()` was enough to escape the character class.
		`\s*\(\s*[\[(]?(?P<appel>[^()]*?)[\])]?\s*,?\s*\)`)

	// Obfuscated payload fed back into an interpreter: the hook sees only
	// `base64 -d`, the real payload appears only at run time. The ASSEMBLY is
	// refused, for want of being able to read what it carries.
	decoderToShellRe = regexp.MustCompile(`(?i)\b(base64|base32|basenc|xxd|od|` +
		`uudecode|openssl\s+enc|printf|echo)\b[^|]*\|\s*(sudo\s+|env\s+)?` +
		`(ba|z|k|da)?sh\b|\b(base64|base32|xxd|od)\b[^|]*\|\s*` +
		`(python3?|perl|ruby|node|php)\b`)

	// An interpreter reading its program on standard input: same problem.
	//
	// `(?m)`: the end of the STRING is not enough. `cat <<EOF | python3` is
	// followed by the heredoc body, so `| python3` was never in last position
	// and the assembly got through.
	stdinInterpreterRe = regexp.MustCompile(`(?im)` +
		`\|\s*(sudo\s+)?(python3?|perl|ruby|node|php|(ba|z|k|da)?sh)\s*(-\s*)?$|` +
		`\b(python3?|perl|ruby|node|(ba|z|k|da)?sh)\s+-\s*$|` +
		`\beval\b|\bsource\s+/dev/stdin\b`)

	// Reading the environment from an interpreter: `env` is blocked, but
	// `node -e process.env` or `perl -e %ENV` did exactly the same thing.
	//
	// Case is SIGNIFICANT: lowercase `environ` is a common word, uppercase
	// `ENVIRON` is awk's table. Ruby has neither sigil nor `ENVIRON`: `ENV[…]`,
	// `ENV.fetch(…)`, or plain `p ENV`.
	//
	// The trailing lookahead is written as a non-capturing group: this pattern
	// is only ever asked whether it matches, so consuming what it looked at
	// changes no answer.
	codeEnvRe = regexp.MustCompile(`(?i)os\s*\.\s*(environ|getenv|putenv)|` +
		`process\s*(\.\s*env\b|\[\s*env\s*\])|` +
		`from\s+os\s+import\s+[\w\s,]*\benviron\b|` +
		`getattr\s*\(\s*os\s*,\s*environ|` +
		`(?-i:\bENVIRON\b)|(?-i:\bENV\b)(?:\s*[\[.)\]]|\s*$)|` +
		`\barray\s+get\s+env\b|` +
		`Sys\.getenv|System\.getenv|\bgetenv\s*\(`)

	// SIGIL forms: `%ENV`, `$ENV`, `@ENV`. Unambiguous — they designate the
	// environment wherever they appear.
	inlineEnvRe = regexp.MustCompile(`(?i)(?-i:[%@]_?ENV)\b|\$_?ENV\b|[%$@]_?ENV\s*[\[{]`)

	segmentSplitRe = regexp.MustCompile(`[|&\n]+`)
	listPunctRe    = regexp.MustCompile(`[,\[\]]`)

	// A heredoc opening. The marker itself is read from the capture; the
	// terminator cannot be expressed here because RE2 has no backreference.
	heredocOpenRe = regexp.MustCompile(`<<-?\s*(['"]?)([A-Za-z_]\w*)`)

	// Options of an interpreter that take a VALUE. Ignoring them cut the chain
	// and the interpreter was no longer seen as receiving a program.
	interpreterOptsRe = `(?:\s+(?:-[XWIMmrEK]\s+\S+|-[\w-]*))*`

	hereStringRe  *regexp.Regexp
	langHeredocRe *regexp.Regexp
)

func init() {
	// Longest first, so `python3` is preferred over `python`. Names of equal
	// length cannot overlap, so their relative order does not matter.
	names := make([]string, 0, len(languages))
	for name := range languages {
		names = append(names, name)
	}
	sort.Slice(names, func(i, j int) bool {
		if len(names[i]) != len(names[j]) {
			return len(names[i]) > len(names[j])
		}
		return names[i] < names[j]
	})
	alternatives := strings.Join(names, "|")
	// A program handed to an interpreter OTHER than in line: a here-string
	// (`python3 <<< 'code'`). Bash pushes it on standard input and the
	// interpreter runs it — exactly like `-c`.
	hereStringRe = regexp.MustCompile(`\b(` + alternatives + `)\b(` +
		interpreterOptsRe + `)\s*<<<\s*('[^']*'|"[^"]*"|\S+)`)
	// The heredoc form. Only the OPENING is matched here; the body and the
	// terminator are found by scanning, since the terminator is a
	// backreference to the marker.
	langHeredocRe = regexp.MustCompile(`\b(` + alternatives + `)\b(` +
		interpreterOptsRe + `)\s*<<-?\s*(['"]?)([A-Za-z_]\w*)`)
}

// heredoc is one heredoc found in a command.
type heredoc struct {
	start, end int    // the whole construct, opening included
	bodyStart  int    // right after the opening marker, as Python's group does
	marker     string // the terminator word
	quoted     bool   // `<<'FIN'`: bash interprets nothing inside
	body       string
}

// findHeredocs locates heredocs and their bodies.
//
// This replaces two Python patterns that closed on a BACKREFERENCE
// (`\1`, `(?P=mark)`), which RE2 does not have. The terminator is therefore
// looked for explicitly: the earliest line at or after the body that holds the
// marker alone. Building that line's pattern from the marker keeps the
// original's tolerance for surrounding whitespace.
//
// bodyOnNextLine reproduces the `[^\n]*\n` the interpreter pattern carries
// after its marker: there, the body starts on the FOLLOWING line, and a
// terminator on the opening line itself is not one.
func findHeredocs(command string, openings [][]int, markerGroup int,
	bodyOnNextLine bool) []heredoc {
	var found []heredoc
	for _, loc := range openings {
		marker := command[loc[2*markerGroup]:loc[2*markerGroup+1]]
		bodyStart := loc[2*markerGroup+1]
		if bodyOnNextLine {
			newline := strings.IndexByte(command[bodyStart:], '\n')
			if newline < 0 {
				continue // the opening never closes its line: no body
			}
			bodyStart += newline + 1
		}
		end := terminatorAfter(command, marker, bodyStart)
		if end < 0 {
			// No terminator: the construct is unfinished, so there is no body
			// to decide about. Skipping it leaves the command to the other
			// checks rather than inventing a boundary.
			continue
		}
		found = append(found, heredoc{
			start:     loc[0],
			end:       end,
			bodyStart: bodyStart,
			marker:    marker,
			quoted:    loc[2*(markerGroup-1)] >= 0 && loc[2*(markerGroup-1)+1] > loc[2*(markerGroup-1)],
			body:      command[bodyStart:terminatorStart(command, marker, bodyStart)],
		})
	}
	return found
}

// terminatorPattern caches one regex per marker: a command rarely holds two
// heredocs, but a hostile one could hold many.
var terminatorCache = map[string]*regexp.Regexp{}

func terminatorPattern(marker string) *regexp.Regexp {
	if re, ok := terminatorCache[marker]; ok {
		return re
	}
	re := regexp.MustCompile(`(?sm)^\s*` + regexp.QuoteMeta(marker) + `\s*$`)
	terminatorCache[marker] = re
	return re
}

// terminatorStart returns where the terminator match begins, hence where the
// body ends; terminatorAfter returns where it ends. Both scan the FULL text
// rather than a slice: slicing would make `^` match mid-line, and the
// terminator has to sit at the beginning of a line.
func terminatorStart(command, marker string, from int) int {
	if loc := terminatorLoc(command, marker, from); loc != nil {
		return loc[0]
	}
	return len(command)
}

func terminatorAfter(command, marker string, from int) int {
	if loc := terminatorLoc(command, marker, from); loc != nil {
		return loc[1]
	}
	return -1
}

func terminatorLoc(command, marker string, from int) []int {
	for _, loc := range terminatorPattern(marker).FindAllStringIndex(command, -1) {
		if loc[0] >= from {
			return loc
		}
	}
	return nil
}

// neutraliseHeredocs empties the body of quoted heredocs that are not executed.
//
// Analysing it as code refused any text containing markdown backticks — taken
// for substitutions — while `cat <<'FIN' > f` only writes a file.
func neutraliseHeredocs(command string) string {
	openings := heredocOpenRe.FindAllStringSubmatchIndex(command, -1)
	var b strings.Builder
	last := 0
	for _, h := range findHeredocs(command, openings, 2, false) {
		if !h.quoted || h.start < last {
			continue
		}
		head := command[:h.start]
		if i := strings.LastIndexAny(head, "|;&\n"); i >= 0 {
			head = head[i+1:]
		}
		// What FOLLOWS the marker on the same line consumes the body:
		// `cat <<'FIN' | bash` does execute what the heredoc holds, and
		// looking only at the head (`cat`) made that invisible.
		rest := h.body
		if i := strings.IndexByte(rest, '\n'); i >= 0 {
			rest = rest[:i]
		}
		// Split on the operators BEFORE whitespace: `<<'FIN' |bash` (glued
		// pipe) yielded the token `|bash`, absent from the interpreter list,
		// and the body was removed although it is executed.
		if runsAnInterpreter(head + " " + rest) {
			continue // the body IS executed: keep it
		}
		b.WriteString(command[last:h.start])
		b.WriteString("<<" + h.marker + "\n" + h.marker + "\n")
		last = h.end
	}
	b.WriteString(command[last:])
	return b.String()
}

var wordSplitRe = regexp.MustCompile(`[|;&<>()]+|\s+`)

func runsAnInterpreter(text string) bool {
	for _, word := range wordSplitRe.Split(text, -1) {
		if word != "" && interpreters[basename(word)] {
			return true
		}
	}
	return false
}

// canonicaliseProgram brings a program delivered by heredoc or here-string back
// to its IN LINE form.
//
// Every control over interpreter code hangs off the `-c`/`-e` flag; delivered
// on standard input, the same code was only analysed as shell, where
// `os.system("env")` is one word among many.
func canonicaliseProgram(command string) string {
	return hereStringRe.ReplaceAllStringFunc(inlineHeredocs(command),
		func(m string) string {
			g := hereStringRe.FindStringSubmatch(m)
			return inlineForm(g[1], g[2], g[3])
		})
}

// inlineHeredocs rewrites `python3 <<EOF … EOF` into `python3 -c …`.
func inlineHeredocs(command string) string {
	openings := langHeredocRe.FindAllStringSubmatchIndex(command, -1)
	var b strings.Builder
	last := 0
	for i, h := range findHeredocs(command, openings, 4, true) {
		if h.start < last {
			continue
		}
		loc := openings[i]
		b.WriteString(command[last:h.start])
		b.WriteString(inlineForm(command[loc[2]:loc[3]], command[loc[4]:loc[5]], h.body))
		last = h.end
	}
	b.WriteString(command[last:])
	return b.String()
}

// inlineForm is the `-c` rendering shared by both deliveries.
//
// A program's newlines do not separate commands: keeping them put the
// primitive in a segment with no interpreter in it.
func inlineForm(interpreter, options, body string) string {
	body = strings.Trim(body, "'\"")
	return interpreter + options + " -c " + strings.ReplaceAll(body, "\n", " ") + " "
}

// interpreterRuns answers whether an interpreter is REALLY launched here.
//
// Testing its mere presence in the text refused
// `git commit -m 'fix perl -e system(env)'`: the message QUOTES a one-liner,
// it runs none. Only program position decides.
func interpreterRuns(command string) (bool, error) {
	// An interpreter whose program arrives by PROCESS substitution runs it as
	// if given in line. The `/dev/fd/…` file exists only at run time; only the
	// text producing it is readable here, and that text is not shell —
	// `python3 <(echo 'os.system("env")')` got through.
	procsub := strings.Contains(command, "<(")
	commands, err := Tokenize(command)
	if err != nil {
		return false, err
	}
	for _, tokens := range commands {
		var programs []string
		for _, at := range programPositions(tokens) {
			programs = append(programs, basename(tokens[at]))
		}
		if !anyIn(programs, interpreters) {
			continue
		}
		// `python3 --version` runs no code: without this requirement it opened
		// the analysis and a neighbouring commit message became suspect.
		if containsOption(tokens, "-e", "-c", "-r", "-E", "-P") {
			return true, nil
		}
		for _, token := range tokens {
			if base := basename(token); base == "awk" || base == "gawk" ||
				base == "mawk" {
				return true, nil
			}
		}
		if procsub && anyIn(programs, languages) {
			return true, nil
		}
	}
	return false, nil
}

func anyIn(names []string, among map[string]bool) bool {
	for _, name := range names {
		if among[name] {
			return true
		}
	}
	return false
}

// nestedRegions returns the nested executable contents, ready to be re-analysed.
//
// The comma becomes a separator: `subprocess.run(["curl", "http://x"])` is a
// command whose words are separated by commas, not by spaces.
func nestedRegions(normalized string) ([]string, error) {
	type source struct {
		re   *regexp.Regexp
		text string
	}
	sources := []source{{nestedRe, normalized}}
	// A language's primitives only count inside the simple command that
	// launches the interpreter: testing the WHOLE command refused
	// `git commit -m '…system(env)…' && python3 --version`.
	for _, segment := range segmentSplitRe.Split(normalized, -1) {
		runs, err := interpreterRuns(segment)
		if err != nil {
			return nil, err
		}
		if runs {
			sources = append(sources, source{languageCallRe, segment})
		}
	}
	var regions []string
	for _, s := range sources {
		for _, loc := range s.re.FindAllStringSubmatchIndex(s.text, -1) {
			content := firstGroup(s.text, loc)
			if strings.TrimSpace(content) == "" {
				continue
			}
			// Commas and brackets delimit a LIST of arguments in code: without
			// neutralising them, `run(["env", "-0"])` yielded the word `[env`,
			// which nothing recognises.
			regions = append(regions, listPunctRe.ReplaceAllString(content, " "))
		}
	}
	return regions, nil
}

// firstGroup returns the first capture group that took part in the match —
// these patterns carry one alternative per syntax, and exactly one fires.
func firstGroup(text string, loc []int) string {
	for i := 2; i+1 < len(loc); i += 2 {
		if loc[i] >= 0 {
			return text[loc[i]:loc[i+1]]
		}
	}
	return ""
}

// metadataOnly reports a SINGLE simple command whose program reads no content.
//
// Uniqueness is essential: listing a key directory and then reading a key must
// stay refused, and a substitution could hide any reader.
func metadataOnly(command string) (bool, error) {
	normalized := Normalize(command)
	if nestedRe.MatchString(normalized) || optReadsFileRe.MatchString(normalized) {
		return false, nil
	}
	commands, err := Tokenize(command)
	if err != nil {
		return false, err
	}
	if len(commands) != 1 {
		return false, nil
	}
	positions := programPositions(commands[0])
	if len(positions) == 0 {
		return false, nil
	}
	for _, at := range positions {
		if !metadataPrograms[basename(commands[0][at])] {
			return false, nil
		}
	}
	return true, nil
}
