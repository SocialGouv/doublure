// Package policy reads and writes the confidentiality policy.
//
// Closed by default: everything detected is substituted. Only the operator
// opens, at three granularities (value, type, class) and across three scopes
// (global, project, session), each the default for the next. The narrowest and
// nearest win. With no rule at all: anonymise.
//
// Two invariants, and they are not symmetric:
//
//   - A SECRET is never revealable (D4). It is a derived reference, never
//     stored, therefore not restorable. A rule claiming otherwise is refused
//     when written, not ignored when read.
//   - "Reveal" is the only decision that can let a value out. Anonymising is
//     free and its error is visible; revealing is not, and revoking it later
//     does not recall what already left.
//
// The files hold no real value: a per-value decision is indexed by an HMAC
// fingerprint derived from the master key. The operator sees plaintext only at
// arbitration time, because the queue carries the SURROGATE and the vault can
// resolve it.
package policy

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"sync"
)

type Decision string

const (
	Anonymise Decision = "anonymiser"
	Reveal    Decision = "reveler"
)

// ErrInvalid marks a rule or setting refused because it would break an
// invariant, or because it is simply not part of the vocabulary. Refusing is
// the useful behaviour: a misspelt setting would otherwise fall back to a
// default the operator believes they changed.
var ErrInvalid = errors.New("invalid policy request")

// Scopes, farthest to nearest. The order IS the resolution.
var Scopes = []string{"global", "projet", "session"}

// Granularities, widest to narrowest. The order IS the resolution.
var Granularities = []string{"classe", "type", "valeur"}

// Classes whose values can never be revealed (D4).
var neverRevealable = map[string]bool{"secret": true}

type layer struct {
	Classe   map[string]string `json:"classe,omitempty"`
	Type     map[string]string `json:"type,omitempty"`
	Valeur   map[string]string `json:"valeur,omitempty"`
	Settings map[string]any    `json:"reglages,omitempty"`
}

func (l *layer) rules(granularity string) map[string]string {
	switch granularity {
	case "classe":
		return l.Classe
	case "type":
		return l.Type
	case "valeur":
		return l.Valeur
	}
	return nil
}

type Question struct {
	Fingerprint string  `json:"fingerprint"`
	Type        string  `json:"type"`
	Class       string  `json:"class"`
	Surrogate   string  `json:"surrogate"`
	Scope       string  `json:"scope"`
	SeenAt      float64 `json:"seen_at"`
	// Value is filled by the control service from the vault; the queue itself
	// never holds it.
	Value string `json:"value,omitempty"`
	// ValueError says WHY a value could not be shown. An operator who cannot
	// read a value must be told so: `encoding/json` replaces invalid UTF-8
	// with U+FFFD, which would hand them a real value that is not the real
	// value — and three distinct hosts rendering as one identical string, so
	// that revealing A while meaning B becomes possible. Reveal is the one
	// decision that cannot be taken back.
	ValueError string `json:"value_error,omitempty"`
}

type Policy struct {
	root     string
	scopeKey string
	session  string
	indexKey []byte
	mu       sync.RWMutex
}

func New(root, scopeKey, session string, masterKey []byte) *Policy {
	// Domain salt: a policy fingerprint must not coincide with a vault index,
	// both being derived from the same master key.
	mac := hmac.New(sha256.New, masterKey)
	mac.Write([]byte("anonproxy-policy-v1"))
	return &Policy{root: root, scopeKey: scopeKey, session: session, indexKey: mac.Sum(nil)}
}

// nonFileName matches everything that must not end up in a file name. Only the
// READABLE prefix is sanitised this way; what DECIDES is the fingerprint below.
var nonFileName = regexp.MustCompile(`[^A-Za-z0-9_.-]`)

// file names a scope's rule file, and must agree with the Python side BYTE FOR
// BYTE — the two write and read the same directory. When they diverged, the Go
// service wrote the operator's decision into a file the engine never opened:
// the arbitration went through the interface, reported success, and changed
// nothing. Silent, and on the one decision that cannot be taken back.
//
// Substituting characters cannot be injective, and neither can a separator
// that may appear in the data; each field carries its LENGTH. The session only
// enters the session scope, or a project rule would stop applying as soon as
// the session changed.
func (p *Policy) file(scope string) string {
	if scope == "global" {
		return filepath.Join(p.root, "global.json")
	}
	fields := []string{scope, p.scopeKey}
	if scope == "session" {
		// The EMPTY string, not a "sans-id" placeholder: the Python side puts
		// `session or ""` into the fields, and a name that differs by one byte
		// is a different file — so the decision would land where nothing reads
		// it. Length prefixing makes the empty case unambiguous by itself.
		fields = append(fields, p.session)
	}
	var exact strings.Builder
	for _, f := range fields {
		fmt.Fprintf(&exact, "%d:%s", len(f), f)
	}
	sum := sha256.Sum256([]byte(exact.String()))
	readable := strings.Trim(nonFileName.ReplaceAllString(p.scopeKey, "-"), "-.")
	if len(readable) > 40 {
		readable = readable[:40]
	}
	if readable == "" {
		readable = "portee"
	}
	if scope == "session" {
		readable += "-session"
	}
	return filepath.Join(p.root,
		fmt.Sprintf("%s-%s.json", readable, hex.EncodeToString(sum[:])[:16]))
}

// Fingerprint identifies a value WITHOUT containing it. The type is part of it:
// the same string seen as a hostname or as a file path is not the same decision.
func (p *Policy) Fingerprint(etype, value string) string {
	mac := hmac.New(sha256.New, p.indexKey)
	mac.Write([]byte(etype + "\x1f" + value))
	return hex.EncodeToString(mac.Sum(nil))[:32]
}

func (p *Policy) load(scope string) layer {
	var l layer
	raw, err := os.ReadFile(p.file(scope))
	if err != nil {
		return l // absent is not an error: nothing is configured yet
	}
	if err := json.Unmarshal(raw, &l); err != nil {
		// An unreadable policy opens NOTHING — the default is to anonymise.
		// But the failure must be visible.
		fmt.Fprintf(os.Stderr, "anonproxy: policy %s unreadable (%v) — default: anonymise\n",
			p.file(scope), err)
	}
	return l
}

func (p *Policy) save(scope string, l layer) error {
	if err := os.MkdirAll(p.root, 0o700); err != nil {
		return err
	}
	raw, err := json.MarshalIndent(l, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(p.file(scope), append(raw, '\n'), 0o600)
}

// Decide returns the applicable decision and the rule that made it. An empty
// source means no rule matched, and the default applied.
func (p *Policy) Decide(etype, class, value string) (Decision, string) {
	p.mu.RLock()
	defer p.mu.RUnlock()
	if neverRevealable[class] {
		return Anonymise, "invariant:D4"
	}
	keys := map[string]string{
		"valeur": p.Fingerprint(etype, value),
		"type":   etype,
		"classe": class,
	}
	layers := map[string]layer{}
	for _, s := range Scopes {
		layers[s] = p.load(s)
	}
	for g := len(Granularities) - 1; g >= 0; g-- {
		for s := len(Scopes) - 1; s >= 0; s-- {
			l := layers[Scopes[s]]
			if raw, ok := l.rules(Granularities[g])[keys[Granularities[g]]]; ok {
				switch Decision(raw) {
				case Anonymise, Reveal:
					return Decision(raw), Scopes[s] + ":" + Granularities[g]
				}
				fmt.Fprintf(os.Stderr, "anonproxy: unknown decision %q in %s/%s — ignored\n",
					raw, Scopes[s], Granularities[g])
			}
		}
	}
	return Anonymise, ""
}

// Set records a decision. Refusing at write time is deliberate: an invariant
// must not depend on every reader remembering it.
func (p *Policy) Set(scope, granularity, key string, d Decision) error {
	if !contains(Scopes, scope) {
		return fmt.Errorf("%w: unknown scope %q", ErrInvalid, scope)
	}
	if !contains(Granularities, granularity) {
		return fmt.Errorf("%w: unknown granularity %q", ErrInvalid, granularity)
	}
	if d != Anonymise && d != Reveal {
		return fmt.Errorf("%w: unknown decision %q", ErrInvalid, d)
	}
	if d == Reveal && granularity == "classe" && neverRevealable[key] {
		return fmt.Errorf("%w: class %q is never revealable (D4: a secret is a derived "+
			"reference, it is not restorable)", ErrInvalid, key)
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	l := p.load(scope)
	switch granularity {
	case "classe":
		l.Classe = put(l.Classe, key, string(d))
	case "type":
		l.Type = put(l.Type, key, string(d))
	case "valeur":
		l.Valeur = put(l.Valeur, key, string(d))
	}
	if err := p.save(scope, l); err != nil {
		return err
	}
	if d == Reveal {
		// The only decision that can let a value out: it is traced, and
		// revoking it later will recall nothing.
		fmt.Fprintf(os.Stderr, "anonproxy: REVEAL allowed — %s/%s (scope %s)\n",
			granularity, key, scope)
	}
	return nil
}

// Rules exposes the raw layers, for the configuration manager.
func (p *Policy) Rules() map[string]layer {
	p.mu.RLock()
	defer p.mu.RUnlock()
	out := map[string]layer{}
	for _, s := range Scopes {
		out[s] = p.load(s)
	}
	return out
}

func (p *Policy) queueFile() string { return filepath.Join(p.root, "en-attente.jsonl") }

// Questions lists what was anonymised without an explicit rule, oldest first,
// deduplicated, and minus anything already decided since.
func (p *Policy) Questions() []Question {
	p.mu.RLock()
	defer p.mu.RUnlock()
	raw, err := os.ReadFile(p.queueFile())
	if err != nil {
		return nil
	}
	seen := map[string]bool{}
	var out []Question
	for _, line := range strings.Split(string(raw), "\n") {
		if strings.TrimSpace(line) == "" {
			continue
		}
		// The queue is written by the engine, in its own vocabulary.
		var entry struct {
			Fingerprint string  `json:"empreinte"`
			Type        string  `json:"type"`
			Class       string  `json:"classe"`
			Surrogate   string  `json:"substitut"`
			Scope       string  `json:"portee"`
			SeenAt      float64 `json:"vu_le"`
		}
		if json.Unmarshal([]byte(line), &entry) != nil || seen[entry.Fingerprint] {
			continue
		}
		seen[entry.Fingerprint] = true
		if p.alreadyDecided(entry.Fingerprint, entry.Type, entry.Class) {
			continue
		}
		out = append(out, Question{
			Fingerprint: entry.Fingerprint, Type: entry.Type, Class: entry.Class,
			Surrogate: entry.Surrogate, Scope: entry.Scope, SeenAt: entry.SeenAt,
		})
	}
	sort.SliceStable(out, func(i, j int) bool { return out[i].SeenAt < out[j].SeenAt })
	return out
}

func (p *Policy) alreadyDecided(fingerprint, etype, class string) bool {
	for _, s := range Scopes {
		l := p.load(s)
		if _, ok := l.Valeur[fingerprint]; ok {
			return true
		}
		if _, ok := l.Type[etype]; ok {
			return true
		}
		if _, ok := l.Classe[class]; ok {
			return true
		}
	}
	return false
}

func put(m map[string]string, k, v string) map[string]string {
	if m == nil {
		m = map[string]string{}
	}
	m[k] = v
	return m
}

func contains(haystack []string, needle string) bool {
	for _, h := range haystack {
		if h == needle {
			return true
		}
	}
	return false
}
