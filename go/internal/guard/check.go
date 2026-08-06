package guard

import (
	"net"
	"net/url"
	"regexp"
	"strings"
)

var (
	// Pseudo-file paths that open a socket in the shell.
	shellSocketRe = regexp.MustCompile(`(?i)/dev/(tcp|udp)/`)

	// Network calls embedded in an interpreter (`python3 -c …`, `node -e …`).
	inlineNetworkRe = regexp.MustCompile(`(?i)(urllib|requests\.|httpx\.|` +
		`socket\s*\.\s*(socket|create_connection)|http\.client|HTTP::Tiny|` +
		`LWP::|Net::HTTP|require\s*\(?\s*(https?|net|dgram)\b|fetch\s*\(|` +
		`XMLHttpRequest|axios)`)

	// A simple reference to a variable. Its value is not known before
	// execution: in program position, `$SHELL -c env` launches a shell. The
	// tokenizer used to drop the sigil and leave the word `SHELL`, which
	// nothing recognises.
	simpleRefRe = regexp.MustCompile(`\$\{?(?:[A-Za-z_]\w*|\d+|[@*#?$!-])\}?`)

	// An execution primitive WITHOUT parentheses (`system "env"` in
	// Perl/Ruby, `qx/env/`, `%x[env]`): the nested pattern only sees the
	// parenthesised forms. ONLY what follows the call is inspected —
	// inspecting every word of the inline program refused
	// `print("the curl command is useful")`, hence any prose quoting a network
	// binary.
	execCallRe = regexp.MustCompile(`(?i)\b(?:system|exec\w*|qx|popen|spawn\w*|` +
		`shell_exec|passthru|os\.execute|IO\.popen|subprocess\.\w+|` +
		`check_output|check_call|getoutput|getstatusoutput)\b(?P<args>[^;\n]*)` +
		`|%x[\[({<](?P<pcx>[^\])}>]*)`)

	codeWordsRe = regexp.MustCompile(`[A-Za-z0-9_.-]+`)
	urlRe       = regexp.MustCompile(`(?i)[a-z]+://[^\s'"]+`)

	// Connection to a UNIX SOCKET. The URL that comes with it is decorative:
	// the destination is the socket, not the host. The "local URL" exemption —
	// written so the agent could reach the project's detector — therefore has
	// nothing to exempt here, and it opened access to the arbitration API,
	// which returns the vault's REAL values. That is the OVERFLOWING EXEMPTION
	// pattern: a guard written for one use covers another, unforeseen one.
	unixSocketRe = regexp.MustCompile(`^--(abstract-)?unix-socket(=|$)`)

	// A fallback expansion, as it is written in the RAW command.
	fallbackRe = regexp.MustCompile(`\$\{#?(?:[A-Za-z_]\w*|\d+|[@*]):?[-=?]([^}]*)\}`)

	// Any expansion at all. Bash sometimes gets the EMPTY string out of it
	// (`${IFS//?/}` replaces everything with nothing, `${V:0:0}` is a null
	// slice): the surrounding characters then rejoin into a command name.
	// Rather than enumerating the provably empty forms, the "everything is
	// empty" reading is emitted and analysed as a full command.
	anyExpansionRe = regexp.MustCompile(`\$\{[^{}]*\}|\$[A-Za-z_]\w*`)

	segmentKeepRe = regexp.MustCompile(`[|&\n]+`)

	// Sub-commands carried by an ARGUMENT rather than by program position.
	subCommandRes = []struct {
		re            *regexp.Regexp
		stripsSignals bool
	}{
		{regexp.MustCompile(`\btrap\b([^|;&\n]*)`), true},
		{regexp.MustCompile(`\b(?:mapfile|readarray)\b[^|;&\n]*?\s-C\s+([^|;&\n]*)`), false},
	}
)

// analysisDepth bounds the re-analysis of nested commands.
const analysisDepth = 4

const streamDestination = " destination_de_flux "

// fallbackVariant is the command as bash runs it when the variables are empty.
//
// It is a COMMAND in its own right, analysed as such: substituting the fallback
// into the normalised text would break the deny patterns, which describe a
// simple command from end to end.
func fallbackVariant(command string) string {
	variant := command
	// One pass resolves only ONE level: `${A:-${B:-${C:-env}}}` needs as many
	// as it has nestings, and check's recursion budget ran out first.
	for i := 0; i < 12; i++ {
		next := fallbackRe.ReplaceAllString(variant, "$1")
		if next == variant {
			break
		}
		variant = next
	}
	if variant == command {
		return ""
	}
	return variant
}

// emptyVariant is the command as bash runs it when the expansions yield empty.
func emptyVariant(command string) string {
	variant := anyExpansionRe.ReplaceAllString(command, "")
	if variant == command {
		return ""
	}
	return variant
}

// subCommand trims a sub-command carried by an argument.
func subCommand(text string, stripsSignals bool) string {
	words := strings.Fields(text)
	for len(words) > 0 && words[0] == "--" {
		words = words[1:]
	}
	for stripsSignals && len(words) > 0 && signalRe.MatchString(words[len(words)-1]) {
		words = words[:len(words)-1]
	}
	return strings.Join(words, " ")
}

// bySegment applies transform to each simple command, separators preserved.
func bySegment(text string, transform func(string) string) string {
	var b strings.Builder
	last := 0
	for _, loc := range segmentKeepRe.FindAllStringIndex(text, -1) {
		b.WriteString(transform(text[last:loc[0]]))
		b.WriteString(text[loc[0]:loc[1]])
		last = loc[1]
	}
	b.WriteString(transform(text[last:]))
	return b.String()
}

// CheckBash returns why a shell command is refused, or "".
func CheckBash(command string) (string, error) { return checkBash(command, 0) }

func checkBash(command string, depth int) (string, error) {
	command = canonicaliseProgram(neutraliseHeredocs(command))

	if depth < analysisDepth {
		for _, variant := range []string{fallbackVariant(command), emptyVariant(command)} {
			if variant == "" {
				continue
			}
			if reason, err := checkBash(variant, depth+1); err != nil || reason != "" {
				return reason, err
			}
		}
	}

	normalized := Normalize(command)
	if reason := checkVaultAccess(normalized); reason != "" {
		return reason, nil
	}
	only, err := metadataOnly(command)
	if err != nil {
		return "", err
	}
	if !only {
		if reason := checkSensitiveFiles(normalized); reason != "" {
			return reason, nil
		}
	}

	if reason := firstMatch(denyRules, normalized); reason != "" {
		return reason, nil
	}
	if shellSocketRe.MatchString(normalized) {
		return "socket ouverte par le shell (/dev/tcp) : contourne le proxy (D9)", nil
	}
	if inlineNetworkRe.MatchString(normalized) {
		return "appel réseau embarqué dans un interpréteur : contourne le proxy (D9)", nil
	}
	if inlineEnvRe.MatchString(normalized) {
		return "lecture de l'environnement depuis un interpréteur", nil
	}
	if codeEnvRe.MatchString(normalized) {
		runs, err := interpreterRuns(normalized)
		if err != nil {
			return "", err
		}
		if runs {
			return "lecture de l'environnement depuis un interpréteur", nil
		}
	}
	if sensitiveVariable(normalized) != "" {
		return "lecture d'une variable d'environnement porteuse de secret", nil
	}
	if decoderToShellRe.MatchString(normalized) ||
		stdinInterpreterRe.MatchString(normalized) {
		return "charge décodée puis exécutée : son contenu n'est pas analysable " +
			"avant exécution, la commande est refusée en l'état", nil
	}

	// A nested region is a command in its own right: it is analysed
	// recursively, then REMOVED from the enclosing command — otherwise its
	// words would be read there as arguments (`echo $(find . -name env)`
	// refused) or, worse, ignored (`bash <(env)` accepted).
	if depth < analysisDepth {
		for _, entry := range subCommandRes {
			for _, m := range entry.re.FindAllStringSubmatch(normalized, -1) {
				sub := subCommand(m[1], entry.stripsSignals)
				// TWO readings: the quoting is already gone, so we do not know
				// whether the sub-command fits in one word (`-C env`, followed
				// by mapfile's options) or takes them all (`-C 'sh -c env'`).
				// Emitting only one let the other through.
				for _, reading := range readings(sub) {
					reason, err := checkBash(reading, depth+1)
					if err != nil || reason != "" {
						return reason, err
					}
				}
			}
		}
		regions, err := nestedRegions(normalized)
		if err != nil {
			return "", err
		}
		for _, region := range regions {
			reason, err := checkBash(region, depth+1)
			if err != nil || reason != "" {
				return reason, err
			}
		}
	}

	// What follows an execution primitive is a command, even without
	// parentheses to delimit it. Reserved for code given IN LINE: without that
	// gate, `git commit -m 'fix subprocess.run for curl backend'` was refused —
	// prose became code again, precisely the defect the separation had
	// eliminated. The PARENTHESISED forms stay covered everywhere by the
	// nested pattern.
	for _, segment := range segmentSplitRe.Split(normalized, -1) {
		runs, err := interpreterRuns(segment)
		if err != nil {
			return "", err
		}
		if !runs {
			continue
		}
		for _, loc := range execCallRe.FindAllStringSubmatchIndex(segment, -1) {
			words := codeWordsRe.FindAllString(firstGroup(segment, loc), -1)
			for idx, word := range words {
				base := basename(word)
				if envDumpPrograms[base] && isEnvDump(base, words, idx) {
					return "déversement de l'environnement depuis un interpréteur", nil
				}
				if networkCapable[base] {
					return "`" + base + "` appelé depuis un interpréteur : " +
						"contourne le proxy (D9)", nil
				}
			}
		}
	}

	// Every nested region — shell substitution as well as language call — is
	// REMOVED from the enclosing command after analysis: its words are not
	// arguments there, and its result is not known in advance.
	//
	// The marker is NOT surrounded by spaces: it must stay GLUED where the
	// substitution was. Surrounding it made `A=x $V` (two words, the second is
	// the program) identical to `A=x$V` (one word, an assignment value) — and
	// the exception made for the second covered the first, which does execute.
	//
	// A substitution in WRITE mode (`> >(cmd)`) names a DESTINATION, not a
	// program: its consumer is analysed separately.
	//
	// The split works on the RAW command: quoting is what says where an
	// argument begins and ends, and the grammar relies on it. Normalising
	// first made a structure the quotes had suppressed REAPPEAR.
	outside := nestedRe.ReplaceAllStringFunc(command, func(m string) string {
		if strings.HasPrefix(m, ">") {
			return streamDestination
		}
		return substitutionMarker
	})
	var segErr error
	outside = bySegment(outside, func(segment string) string {
		runs, err := interpreterRuns(segment)
		if err != nil {
			segErr = err
			return segment
		}
		if runs {
			return languageCallRe.ReplaceAllString(segment, substitutionMarker)
		}
		return segment
	})
	if segErr != nil {
		return "", segErr
	}
	// A variable in program position is opaque (`$SHELL -c env`).
	outside = simpleRefRe.ReplaceAllString(outside, substitutionMarker)

	commands, err := Tokenize(outside)
	if err != nil {
		return "", err
	}
	for _, tokens := range commands {
		// The marker may be GLUED to other characters (`a$(cmd)b`): exact
		// membership no longer saw it once the padding was removed.
		opaque := false
		for _, token := range tokens {
			if strings.Contains(token, substitutionMarker) {
				opaque = true
				break
			}
		}
		for _, idx := range programPositions(tokens) {
			base := basename(tokens[idx])
			if strings.Contains(base, substitutionMarker) {
				return "le programme exécuté est produit par une substitution : " +
					"son contenu n'est pas analysable avant exécution", nil
			}
			if envDumpPrograms[base] && isEnvDump(base, tokens, idx) {
				return "déversement de l'environnement (jetons et clés compris)", nil
			}
			if shellStatePrograms[base] && (base == "history" ||
				anyMatch(fcListRe, tokens[idx+1:])) {
				return "l'historique de shell contient des secrets saisis", nil
			}
			if !networkCapable[base] {
				continue
			}
			if isLocalUse(base, tokens[idx+1:]) {
				continue
			}
			if opaque {
				return "`" + base + "` reçoit un argument produit par une " +
					"substitution : la destination n'est pas vérifiable (D9)", nil
			}
			if onlyLocalTargets(tokens) {
				continue // the project's local services
			}
			return "`" + base + "` peut sortir sur le réseau sans passer par le " +
				"proxy (D9)", nil
		}
	}
	return "", nil
}

// readings returns the distinct readings of a sub-command whose extent is
// unknown: the whole tail, and its first word alone.
func readings(sub string) []string {
	if sub == "" {
		return nil
	}
	first := sub
	if i := strings.IndexByte(sub, ' '); i >= 0 {
		first = sub[:i]
	}
	if first == sub {
		return []string{sub}
	}
	return []string{sub, first}
}

func anyMatch(re *regexp.Regexp, tokens []string) bool {
	for _, token := range tokens {
		if loc := re.FindStringIndex(token); loc != nil && loc[0] == 0 {
			return true
		}
	}
	return false
}

// onlyLocalTargets reports that every URL in the command names a local host and
// that no unix-socket flag makes the URL decorative.
func onlyLocalTargets(tokens []string) bool {
	urls := urlRe.FindAllString(strings.Join(tokens, " "), -1)
	if len(urls) == 0 {
		return false
	}
	for _, u := range urls {
		if !isLocalURL(u) {
			return false
		}
	}
	for _, token := range tokens {
		if unixSocketRe.MatchString(token) {
			return false
		}
	}
	return true
}

// isLocalURL is true only if the HOST is local.
//
// Looking for "localhost" anywhere in the URL was enough to get through:
// `https://exfil.test/?to=127.0.0.1` and `http://localhost@exfil.test/` are
// both exits to a third party.
//
// The host is compared as an ADDRESS, never as a string: a `127.` prefix test
// accepts the domain name `127.evil.test`, which resolves wherever its owner
// wants.
func isLocalURL(raw string) bool {
	host := hostOf(raw)
	if host == "localhost" {
		return true
	}
	address := net.ParseIP(host)
	if address == nil {
		return false // a domain name: never local, whatever its shape
	}
	return address.IsLoopback() || address.IsUnspecified()
}

// hostOf extracts a URL's host, lowercased and without its brackets, or "".
// Both callers compare the HOST and nothing else — that is the whole point.
func hostOf(raw string) string {
	parsed, err := url.Parse(raw)
	if err != nil {
		return ""
	}
	return strings.ToLower(parsed.Hostname())
}
