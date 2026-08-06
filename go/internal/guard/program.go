package guard

import (
	"regexp"
	"strings"
)

// Programs that dump the environment, hence every token pasted into it. Spotted
// by TOKENIZATION, not by position: `/usr/bin/env`, `command env`, `bash -c
// env`, `V=$(env)` and `xargs env` must all be blocked. The one exception is
// `env VAR=x cmd`, an execution prefix — recognised by a `NAME=value` argument.
var envDumpPrograms = map[string]bool{
	"env": true, "printenv": true, "set": true, "export": true,
	"declare": true, "typeset": true, "readonly": true, "compgen": true,
}

// Interpreters and binaries able to open a socket: enumerating them all is
// impossible, hence the reminder that the definitive answer is the firewall (D9).
var networkCapable = map[string]bool{
	"curl": true, "wget": true, "nc": true, "ncat": true, "netcat": true,
	"socat": true, "telnet": true, "ftp": true, "sftp": true, "ssh": true,
	"scp": true, "rsync": true, "openssl": true, "dig": true,
	"nslookup": true, "host": true, "getent": true, "ping": true,
	"traceroute": true, "whois": true, "aria2c": true, "httpie": true,
	"http": true, "xh": true,
}

// Builtins that expose the state of the SHELL itself — the record of typed
// commands, where hand-pasted tokens go.
//
// They are recognised in PROGRAM POSITION, like any program. The text pattern
// that used to stand in for them refused "git history", "release history",
// "incident history" — any prose. Measured IN USE: it blocked a sub-agent
// launch twice in a row, on its description field.
var shellStatePrograms = map[string]bool{"history": true, "fc": true}

// Wrappers: their argument is itself a program, so the walk continues.
var wrappers = map[string]bool{
	"command": true, "builtin": true, "exec": true, "nohup": true,
	"timeout": true, "time": true, "sudo": true, "doas": true, "xargs": true,
	"nice": true, "ionice": true, "stdbuf": true, "env": true, "sh": true,
	"bash": true, "zsh": true, "ksh": true, "dash": true, "watch": true,
	"script": true, "busybox": true, "toybox": true, "setsid": true,
	"chroot": true, "unshare": true, "nsenter": true, "flock": true,
	"parallel": true, "su": true, "runuser": true, "machinectl": true,
	"systemd-run": true, "proot": true, "fakeroot": true, "strace": true,
	"ltrace": true, "expect": true, "pwsh": true, "powershell": true,
	// `trap 'CMD' SIGNAL` runs CMD on the signal; `coproc CMD` runs it in the
	// background. In both cases the argument is a PROGRAM.
	"trap": true, "coproc": true,
	// `source f` and `. f` execute the CONTENT of f. Fed by a process
	// substitution (`source <(echo env)`), that content exists only at run
	// time: the marker lands in program position and the command is refused. A
	// literal path stays sourceable — write-then-execute is an accepted
	// non-goal.
	"source": true, ".": true,
	"fish": true, "csh": true, "tcsh": true, "mksh": true, "oksh": true,
	"posh": true, "yash": true,
	"do": true, "then": true, "else": true, "elif": true, "while": true,
	"until": true, "if": true, "for": true,
}

// Wrapper options whose value occupies the NEXT token. Without them, `sudo -u
// root env` made `root` pass for the program and `env` was never examined.
// `-c` is excluded: its value IS the command.
//
// PER WRAPPER: a global set cannot be right. `nice -n 10` takes a value, `sudo
// -n` (non-interactive) does not — and skipping the next token made the real
// program disappear.
var optWithValue = map[string]map[string]bool{
	"sudo": set("-u", "--user", "-g", "--group", "-p", "--prompt", "-h",
		"--host", "-R", "--chroot", "-U", "--other-user", "-D", "--chdir",
		"-C", "--close-from", "-r", "--role", "-T", "--command-timeout"),
	"doas":    set("-u", "-C"),
	"su":      set("-s", "--shell", "-g", "--group"),
	"runuser": set("-u", "--user", "-g", "--group", "-s", "--shell"),
	"xargs": set("-a", "--arg-file", "-d", "--delimiter", "-E", "E", "-I",
		"--replace", "-L", "-n", "--max-args", "-P", "--max-procs", "-s",
		"--max-chars"),
	"nice":    set("-n", "--adjustment"),
	"ionice":  set("-c", "--class", "-n", "--classdata", "-p", "--pid"),
	"timeout": set("-k", "--kill-after", "-s", "--signal"),
	"flock":   set("-w", "--timeout", "-E", "--conflict-exit-code"),
	"chroot":  set("--userspec", "--groups"),
	"nsenter": set("-t", "--target", "-S", "--setuid", "-G", "--setgid"),
	"unshare": set("-S", "--map-user", "-G", "--map-group"),
	"stdbuf":  set("-i", "-o", "-e"),
	// `-S` is deliberately ABSENT: its value is a whole COMMAND
	// (`env -S "printenv KEY"`), not a token. Skipping it hid the program.
	"env":         set("-u", "--unset", "-C", "--chdir"),
	"systemd-run": set("-p", "--property", "-u", "--unit"),
	// `exec -a xxx env`: xxx is argv[0], not the program.
	"exec":     set("-a", "--argv0"),
	"script":   set("-f", "--flush", "-t", "--timing"),
	"strace":   set("-o", "--output", "-E", "-P", "-s"),
	"ltrace":   set("-o", "--output", "-e", "-l"),
	"watch":    set("-n", "--interval"),
	"parallel": set("-j", "--jobs", "-S"),
}

// SANDBOX and trace wrappers. Their options take a variable number of values,
// so the real program can sit anywhere after them: `bwrap --dev-bind / / env`,
// `gdb --batch --ex run --args env`.
var openWrappers = map[string]bool{
	"bwrap": true, "firejail": true, "systemd-nspawn": true, "valgrind": true,
	"gdb": true, "lldb": true, "setpriv": true, "chpst": true, "perf": true,
	"catchsegv": true, "proot": true, "unshare": true, "nsenter": true,
}

// Wrappers whose first argument is a TARGET (directory, lock), not the program.
var targetWrappers = map[string]bool{"chroot": true, "flock": true}

// Commands that expose only METADATA (name, size, date): `ls` and `stat`
// cannot reveal the CONTENT of a secret, and forbidding a check of its
// existence buys nothing.
var metadataPrograms = map[string]bool{
	"ls": true, "stat": true, "file": true, "du": true, "test": true,
	"dirname": true, "basename": true, "realpath": true, "readlink": true,
}

// openssl subcommands that go over the network. Inverted into a DENYLIST:
// openssl has dozens of local subcommands (`help`, `list`, `ciphers`,
// `asn1parse`, `verify`, `dhparam`…) and enumerating the allowlist meant
// refusing legitimate work.
var opensslNetwork = map[string]bool{
	"s_client": true, "s_server": true, "s_time": true, "ocsp": true,
}

// HELP output: it opens no connection.
var helpOptions = map[string]bool{
	"--version": true, "-V": true, "--help": true, "-h": true,
	"--manual": true, "help": true,
}

// Variables whose value carries no secret. `ANONPROXY_STATE_DIR` is
// deliberately absent — the vault's path is itself a secret.
var publicVars = map[string]bool{
	"ANTHROPIC_BASE_URL": true, "ANTHROPIC_MODEL": true,
	"ANTHROPIC_SMALL_FAST_MODEL": true, "AWS_REGION": true,
	"AWS_DEFAULT_REGION": true, "AWS_PROFILE": true, "AWS_PAGER": true,
	"GOOGLE_CLOUD_PROJECT": true, "DOCKER_HOST": true,
	"NPM_CONFIG_REGISTRY": true,
}

var (
	// Anything shaped like a duration (`timeout 5s cmd`), never a program.
	durationRe = regexp.MustCompile(`^\d+(\.\d+)?[smhd]?$`)
	// `fc` only lists with a flag; without one it re-runs or opens an editor.
	fcListRe = regexp.MustCompile(`^-[lnrs]`)
	// One sensitive name, in one list. Two lists diverged: `echo $VAR` omitted
	// `_DSN`, `_URL`, `CONNECTION_STRING`, `SESSION_KEY`… and `printenv
	// DATABASE_URL` was refused while `echo $DATABASE_URL` got through.
	sensitiveNameRe = regexp.MustCompile(`(?i)(AWS|GCP|AZURE|ANTHROPIC|OPENAI|` +
		`GITHUB|GITLAB|SLACK|VAULT|ANONPROXY|DOCKER|NPM|PYPI|DATADOG|SENTRY|` +
		`TOKEN|SECRET|PASSWORD|PASSWD|APIKEY|API_KEY|CREDENTIAL|PRIVATE_KEY|` +
		`SIGNING_KEY|ENCRYPTION_KEY|SESSION_KEY|_DSN|_URL|_URI|` +
		`CONNECTION_STRING|BEARER|COOKIE)`)
	plainIdentifierRe = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*$`)
	// Options that make a metadata command READ a file: they take it out of
	// its category.
	optReadsFileRe = regexp.MustCompile(`--(files0-from|reference)\b`)
)

// substitutionMarker is what a nested region leaves behind. Its result is not
// known before execution: replacing it with a BLANK made an argument disappear
// that the shell will in fact supply.
const substitutionMarker = "substitution_non_evaluable"

func set(items ...string) map[string]bool {
	out := make(map[string]bool, len(items))
	for _, item := range items {
		out[item] = true
	}
	return out
}

func sensitiveName(name string) bool {
	return !publicVars[strings.ToUpper(name)] && sensitiveNameRe.MatchString(name)
}

// programPositions returns the indices of the words that may name a program.
//
// Returning INDICES rather than words is what lets each occurrence be judged
// in its place: with the name alone, `env PATH=/x env` was judged on the first
// `env` — a legitimate execution prefix — and the second, a dump, got through.
func programPositions(tokens []string) []int {
	var positions []int
	// `find … -exec curl {} \;`: what follows `-exec` is a command. This sweep
	// is SEPARATE from the loop below, which stops at the first real program —
	// `find` not being a wrapper, it never reached the `-exec` and the rule was
	// dead. The sub-command is ANALYSED, not merely marked at its first word:
	// `-exec sudo curl …` and `-exec env printenv …` otherwise hid the real
	// program behind a wrapper.
	for i, token := range tokens {
		if execClauses[token] && i+1 < len(tokens) {
			for _, j := range programPositions(tokens[i+1:]) {
				positions = append(positions, i+1+j)
			}
		}
	}

	wrapper := "" // last wrapper unfolded: its options have their own grammar
	for i := 0; i < len(tokens); {
		token := tokens[i]
		if strings.HasPrefix(token, "-") {
			if optWithValue[wrapper][token] {
				i += 2
			} else {
				i++
			}
			continue
		}
		if strings.Contains(token, "=") || durationRe.MatchString(token) {
			// `D=$(ls)`: the marker is GLUED to the assignment, hence in the
			// same token — there is nothing more to skip. `A=x $V` leaves the
			// marker in a SEPARATE token, which does occupy a program position.
			i++
			continue
		}
		base := basename(token)
		if base == "command" && containsOption(tokens[i+1:], "-v", "-V") {
			break // `command -v env`: introspection, nothing is run
		}
		positions = append(positions, i)
		if openWrappers[base] {
			// The real program can be anywhere after: no option grammar holds
			// for these wrappers.
			for j := i + 1; j < len(tokens); j++ {
				if !strings.HasPrefix(tokens[j], "-") &&
					!strings.Contains(tokens[j], "=") {
					positions = append(positions, j)
				}
			}
			break
		}
		if !wrappers[base] {
			break // first real program reached: the rest are its arguments
		}
		wrapper = base
		i++
		if targetWrappers[base] {
			// The TARGET (lock, directory) is not the program; the options
			// before it may themselves take a value.
			for i < len(tokens) && strings.HasPrefix(tokens[i], "-") {
				if optWithValue[base][tokens[i]] {
					i += 2
				} else {
					i++
				}
			}
			i++
		}
	}

	// `su root -c env`: the user occupied the program position and stopped the
	// analysis, yet the value of `-c` is a command. Restricted to SHELL
	// wrappers: for `git`, `docker` or `xargs`, `-c` means something else, and
	// a commit message quoting `sh -c curl` was refused.
	if len(positions) > 0 && shellWrappers[basename(tokens[positions[0]])] {
		if at := indexOf(tokens, "-c"); at >= 0 {
			target := at + 1
			if target < len(tokens) && !containsInt(positions, target) {
				positions = append(positions, target)
			}
		}
	}
	return positions
}

func containsOption(tokens []string, options ...string) bool {
	for _, token := range tokens {
		for _, option := range options {
			if token == option {
				return true
			}
		}
	}
	return false
}

func indexOf(tokens []string, want string) int {
	for i, token := range tokens {
		if token == want {
			return i
		}
	}
	return -1
}

func containsInt(values []int, want int) bool {
	for _, value := range values {
		if value == want {
			return true
		}
	}
	return false
}

// isEnvPrefix reports `env VAR=x cmd`: a legitimate execution prefix, not a dump.
func isEnvPrefix(tokens []string, idx int) bool {
	for _, token := range tokens[idx+1:] {
		if strings.Contains(token, "=") && !strings.HasPrefix(token, "-") {
			return true
		}
	}
	return false
}

// isEnvDump answers whether this program REALLY dumps the environment.
//
// `set -e`, `set -euo pipefail` are the idiomatic header of any clean shell
// script; `declare -f` lists functions; `printenv PATH` prints ONE
// insensitive variable. Blocking those made the agent unusable.
func isEnvDump(base string, tokens []string, idx int) bool {
	suite := tokens[idx+1:]

	// `bash -c env _`: the value of `-c` is the WHOLE SCRIPT, and what follows
	// occupies `$0`, `$1`… rather than being an argument of the program. The
	// quoting having been removed, `bash -c env _` and `bash -c 'env _'` are
	// indistinguishable here: BOTH readings are emitted, as for the branches of
	// an expansion.
	if idx > 0 && tokens[idx-1] == "-c" && len(suite) > 0 &&
		anyShellWrapper(tokens[:idx]) &&
		isEnvDump(base, tokens[:idx+1], idx) {
		return true
	}

	if base == "env" {
		// `env` only dumps if it runs NOTHING. `env -i cmd` and `env -u FOO
		// cmd` reduce the environment instead of exposing it.
		for i := 0; i < len(suite); {
			token := suite[i]
			switch {
			case token == "-u" || token == "--unset":
				i += 2
			case strings.HasPrefix(token, "-") || strings.Contains(token, "="):
				i++
			default:
				return false // a program follows: execution prefix
			}
		}
		return true
	}
	if isEnvPrefix(tokens, idx) {
		return false
	}

	// `+e` is an option just like `-e`: `set +e` turns off strict mode, it
	// prints nothing.
	var options, arguments, named []string
	for _, token := range suite {
		if strings.HasPrefix(token, "-") || strings.HasPrefix(token, "+") {
			options = append(options, token)
		} else {
			named = append(named, token)
		}
		if plainIdentifierRe.MatchString(token) {
			arguments = append(arguments, token)
		}
	}

	switch base {
	case "set":
		return len(options) == 0 // `set -e` is strict mode; `set > f` is a dump

	case "declare", "typeset", "export", "readonly":
		for _, token := range named {
			// `readonly TAG=v1.2.3` ASSIGNS, it prints nothing.
			if strings.Contains(token, "=") {
				return false
			}
		}
		// Short options COMBINE: `-px` is `-p -x`, and strict equality missed
		// them all.
		var short []string
		for _, option := range options {
			if !strings.HasPrefix(option, "--") {
				short = append(short, option)
			}
		}
		if len(named) > 0 {
			// A variable is NAMED: `declare -p AWS_…` prints it, `declare -a
			// my_array` declares it. Only its name decides.
			return anySensitive(named) && anyShortFlag(short, "pxaA")
		}
		// `-f` and `-F` are about FUNCTIONS: `declare -pF` lists only function
		// names, no value.
		if anyShortFlag(short, "fF") {
			return false
		}
		// With no named variable these builtins DUMP: `readonly -a` lists
		// read-only arrays WITH their values, like `declare -p`.
		return true
	}

	for _, token := range suite {
		if token == substitutionMarker {
			// The variable's name is produced at run time: it could be any of
			// them. Fail-closed.
			return true
		}
	}

	switch base {
	case "printenv":
		// A named variable: refused only if its name is sensitive. Same
		// dispensation as `echo $VAR`, otherwise the agent could read its
		// configuration one way and not the other.
		return len(arguments) == 0 || anySensitive(arguments)

	case "compgen":
		// `-v` (variables) and `-e` (exported) dump; `-A function`, `-A alias`
		// and `-c` list names without values.
		if containsOption(options, "-v", "-e") {
			return true
		}
		if at := indexOf(suite, "-A"); at >= 0 {
			if at+1 >= len(suite) {
				return false
			}
			kind := suite[at+1]
			return kind == "variable" || kind == "export" || kind == "exported"
		}
		return len(options) == 0
	}
	return true
}

func anyShellWrapper(tokens []string) bool {
	for _, token := range tokens {
		if shellWrappers[basename(token)] {
			return true
		}
	}
	return false
}

func anySensitive(names []string) bool {
	for _, name := range names {
		if sensitiveName(name) {
			return true
		}
	}
	return false
}

// anyShortFlag reports whether a combined short option carries one of flags.
func anyShortFlag(short []string, flags string) bool {
	for _, option := range short {
		if strings.ContainsAny(strings.TrimLeft(option, "-"), flags) {
			return true
		}
	}
	return false
}

// isLocalUse reports an invocation of a network binary that opens no connection.
func isLocalUse(base string, suite []string) bool {
	var nonOptions []string
	for _, token := range suite {
		if !strings.HasPrefix(token, "-") {
			nonOptions = append(nonOptions, token)
		}
	}
	// A help option only counts when ALONE: `curl --version http://third/`
	// disarmed the control although the behaviour depends on the binary.
	if len(nonOptions) == 0 {
		for _, token := range suite {
			if helpOptions[token] {
				return true
			}
		}
	}
	if base == "openssl" {
		return len(nonOptions) > 0 && !opensslNetwork[nonOptions[0]]
	}
	return false
}
