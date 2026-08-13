package guard

import (
	"os"
	"path/filepath"
	"strings"
)

// The state is the vault, the master key and the policy files. It NEVER lives
// in the project: a repository is shared, cloned and wiped, and the vault is
// none of those things.
//
// One directory per project, named after the project's own path:
//
//	/home/ada/lab/ai/anonproxy-demo
//	  → ~/.doublure/-home-ada-lab-ai-anonproxy-demo/
//
// The rule is DUPLICATED in shell (scripts/lib/state.sh). The hook is launched
// by Claude Code, not by those scripts, so it has to find the same directory on
// its own — ten lines on each side, versus a config file it would have to
// locate first. Same call as the allowlist parser across the D7 boundary: it is
// the rule that matters, not the code that applies it.
//
// Claude Code sets the working directory to the project root, which is what
// makes this derivable at all.

// Slug is the directory name a project path maps to. Every character that is
// not a letter, a digit, an underscore or a dot becomes a dash — including the
// leading slash, hence the leading dash.
func Slug(project string) string {
	return strings.Map(func(r rune) rune {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z',
			r >= '0' && r <= '9', r == '_', r == '.':
			return r
		}
		return '-'
	}, project)
}

// StateDir returns this project's state directory.
//
// ANONPROXY_STATE_DIR wins when set: it is the escape hatch for a test rig or a
// second vault on the same project, and the environment is the troubleshooting
// lever everywhere else in this system. Nothing is created here — the hook only
// READS from this directory, and a hook that makes directories on a path it
// merely guessed would be worse than one that finds nothing.
func StateDir() string {
	if dir := os.Getenv("ANONPROXY_STATE_DIR"); dir != "" {
		return dir
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return ""
	}
	project, err := os.Getwd()
	if err != nil {
		return ""
	}
	return filepath.Join(home, ".doublure", Slug(project))
}

// AuditLogPath names the file every decision is appended to.
func AuditLogPath() string {
	if path := os.Getenv("ANONPROXY_AUDIT_LOG"); path != "" {
		return path
	}
	if dir := StateDir(); dir != "" {
		return filepath.Join(dir, "hook-audit.jsonl")
	}
	return ""
}
