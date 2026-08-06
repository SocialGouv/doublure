// Package guard is the PreToolUse control: it decides whether a tool call may
// run, and refuses when it cannot decide.
//
// # Why Go, and what it costs
//
// Rounds 8, 9 and 10 of the adversarial loop were spent on catastrophic regex
// backtracking: a free class at the head of a pattern cost seven to fifteen
// seconds and could freeze the agent without a single forbidden command being
// written. Go's regexp is RE2 and cannot backtrack, so that whole family stops
// being a defect to hunt and becomes impossible to write.
//
// The price is lookaround: RE2 has none. The four Python patterns that used it
// are re-implemented here as "match, then verify". Nothing else about them
// changes — the pattern tables themselves are generated from the Python
// source (see gen_patterns.py), so the two implementations cannot drift.
package guard

import (
	"regexp"
	"strings"
)

// envTemplateSuffixes are PUBLIC templates, made to be shared.
//
// The exclusion is LOCAL to the suffix, never global to the command. A
// whole-command exclusion of the form "not anywhere in this text" disarms
// itself: merely mentioning a template name elsewhere in the same line would
// exonerate a real secrets file read earlier in it.
var envTemplateSuffixes = []string{"example", "sample", "template", "dist", "schema"}

// markAt returns the offset where the nth stripped assertion stood, or -1 if
// the group carrying it took no part in the match.
func markAt(loc, marks []int, n int) int {
	if group := marks[n]; 2*group < len(loc) {
		return loc[2*group]
	}
	return -1
}

// suffixIsTemplate reports whether a public template name starts at the
// assertion's position.
//
// Replaces the negative lookahead that sat immediately after the variant
// separator, forbidding the variant from BEING a template name. The whole
// remaining text is passed, exactly as a lookahead sees it — only its head
// decides.
func suffixIsTemplate(suffix string) bool {
	for _, template := range envTemplateSuffixes {
		if !strings.HasPrefix(suffix, template) {
			continue
		}
		// The assertion ended on a word boundary: the template name must stop
		// there, otherwise a longer word starting with it would pass for one.
		rest := suffix[len(template):]
		if rest == "" || !isWordByte(rest[0]) {
			return true
		}
	}
	return false
}

func isWordByte(b byte) bool {
	return b == '_' || ('a' <= b && b <= 'z') || ('A' <= b && b <= 'Z') ||
		('0' <= b && b <= '9')
}

// precededBy replaces a negative lookbehind: does text end with one of these
// words just before position i?
func precededBy(text string, i int, words ...string) bool {
	for _, w := range words {
		if i >= len(w) && strings.EqualFold(text[i-len(w):i], w) {
			return true
		}
	}
	return false
}

// tailOfSimpleCommand returns what follows position i up to the end of the
// simple command.
//
// The Python lookaheads were bounded by `[^|;&]*`, so they could not see past
// a separator. Reproducing that boundary explicitly matters: without it,
// `terraform output && git config user.name` would exonerate the first command
// using the second one's tail.
func tailOfSimpleCommand(text string, i int) string {
	if i < 0 || i >= len(text) {
		return ""
	}
	if end := strings.IndexAny(text[i:], "|;&"); end >= 0 {
		return text[i : i+end]
	}
	return text[i:]
}

var (
	jsonNamedOutputRe = regexp.MustCompile(`-json\s+\w`)
	gitIdentityRe     = regexp.MustCompile(`(?i)\buser\.(name|email)\b`)
)

// envFile re-implements the two negative lookbehinds plus the template
// exclusion on the dotted environment-file rule.
//
// The lookbehinds excluded JavaScript CODE — a `process` or `import.meta`
// property access — which is not a secrets file, and blocking it refused a
// plain recursive grep over sources.
func envFile(text string, loc, marks []int) bool {
	if precededBy(text, markAt(loc, marks, 0), "process") ||
		precededBy(text, markAt(loc, marks, 1), ".meta") {
		return false
	}
	// The variant group is optional: absent for the bare form, and the mark
	// inside it then takes no part in the match.
	at := markAt(loc, marks, 2)
	return at < 0 || !suffixIsTemplate(text[at:])
}

// envDotFile handles the undotted Compose convention, where the environment
// file is named by prefix rather than by extension. Same template exclusion;
// this one has no lookbehind.
func envDotFile(text string, loc, marks []int) bool {
	at := markAt(loc, marks, 0)
	return at < 0 || !suffixIsTemplate(text[at:])
}

// terraformOutput re-implements `(?![^|;&]*-json\s+\w)`.
//
// Asking for ONE named output is allowed; a bare `output` dumps them all, and
// outputs can be marked sensitive.
func terraformOutput(text string, loc, marks []int) bool {
	return !jsonNamedOutputRe.MatchString(
		tailOfSimpleCommand(text, markAt(loc, marks, 0)))
}

// gitConfig re-implements `(?![^|;&]*\buser\.(name|email)\b)`.
//
// Reading or setting the commit identity is ordinary; the rest of the config
// can carry a token inside a remote URL.
func gitConfig(text string, loc, marks []int) bool {
	return !gitIdentityRe.MatchString(
		tailOfSimpleCommand(text, markAt(loc, marks, 0)))
}

// sshPrivateExcludingPub re-implements `(?!\.pub)`: a key file in the ssh
// directory is private unless the public extension follows immediately.
func sshPrivateExcludingPub(text string, loc, marks []int) bool {
	at := markAt(loc, marks, 0)
	return at >= 0 && !strings.HasPrefix(text[at:], ".pub")
}

// namesPrivateKey reports whether the text names a PRIVATE key in the ssh
// directory.
//
// EVERY occurrence is examined, not just the first. The Python search
// backtracks to the next position when its assertion fails, so a public key
// named before a private one must not exonerate the private one — and the
// exemption below is the only thing here that ALLOWS, which makes its failure
// mode a silent leak.
func namesPrivateKey(text string) bool {
	for _, loc := range sshPrivateRe.FindAllStringSubmatchIndex(text, -1) {
		if sshPrivateVerify(text, loc, sshPrivateVerifyMarks) {
			return true
		}
	}
	return false
}

// checkVaultAccess and checkSensitiveFiles take ALREADY-normalised text.
//
// Python normalises inside each of the three layers, doing the same work three
// times over one string. Hoisting it to the caller is not only cheaper:
// normalisation is a PASS, and the order of the passes is what round 17 was
// spent on. A function that quietly re-normalises hides where that order is
// decided.

// checkVaultAccess reports why a payload reaches for the vault, or "".
func checkVaultAccess(normalized string) string {
	if firstMatch(vaultRules, normalized) == "" {
		return ""
	}
	return vaultReason
}

// checkSensitiveFiles reports why a payload reaches for credentials or private
// keys, or "".
func checkSensitiveFiles(normalized string) string {
	if sshPublicRe.MatchString(normalized) && !namesPrivateKey(normalized) {
		return ""
	}
	if firstMatch(sensitiveFileRules, normalized) == "" {
		return ""
	}
	return sensitiveFileReason
}

// firstMatch returns the reason of the first rule that fires, or "".
func firstMatch(rules []rule, text string) string {
	for _, r := range rules {
		if fires(r, text) {
			if r.reason != "" {
				return r.reason
			}
			return "match"
		}
	}
	return ""
}

// fires reports whether a rule matches somewhere its verifier accepts.
//
// EVERY occurrence is examined, not just the leftmost. A Python search whose
// assertion fails resumes further along, so `.env.example && cat .env` still
// refuses on the second reference — stopping at the first match let a public
// template name exonerate the real file that followed it.
//
// Scanning the occurrences rather than restarting one character past each
// rejection keeps `^` anchored to the real start of the text, and keeps the
// pass linear: restarting inside a match would re-read the text once per
// rejection, and availability is how this control gets defeated without a
// forbidden command being written.
func fires(r rule, text string) bool {
	if r.verify == nil {
		return r.re.MatchString(text)
	}
	for _, loc := range r.re.FindAllStringSubmatchIndex(text, -1) {
		if r.verify(text, loc, r.marks) {
			return true
		}
	}
	return false
}
