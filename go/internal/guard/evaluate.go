package guard

import (
	"encoding/json"
	"io"
	"os"
	"strings"
)

// Tools carrying a path or free text: all inspected.
var pathTools = set("Read", "Edit", "Write", "MultiEdit", "NotebookEdit",
	"NotebookRead", "Glob", "Grep", "LS")

const (
	hintBash    = "Reformule sans exposer la valeur (référence, agrégat, ou --dry-run)."
	hintPath    = "Ce chemin est hors de portée de l'agent par conception."
	hintNetwork = "Passe par le proxy, ou demande-moi d'ouvrir le domaine — " +
		"je l'ajoute à config/domaines_ouverts.txt."
	hintOther = "Cette cible est hors de portée de l'agent par conception."
)

// Value mirrors a decoded JSON value, PRESERVING the order of object keys.
//
// Decoding into map[string]any loses that order, and Go randomises map
// iteration on top. The per-field loop below returns the FIRST field that
// refuses, so a lost order means a refusal message that changes from one run to
// the next — and that exact sentence is what the model quotes back and what
// `phase4_e2e.sh` asserts on.
type Value struct {
	keys   []string
	fields map[string]Value
	items  []Value
	scalar string
	null   bool
	object bool
	array  bool
}

// DecodeValue reads one JSON value, keeping object keys in their written order.
func DecodeValue(dec *json.Decoder) (Value, error) {
	dec.UseNumber()
	return decodeValue(dec)
}

func decodeValue(dec *json.Decoder) (Value, error) {
	token, err := dec.Token()
	if err != nil {
		return Value{}, err
	}
	switch t := token.(type) {
	case json.Delim:
		if t == '{' {
			v := Value{object: true, fields: map[string]Value{}}
			for dec.More() {
				keyToken, err := dec.Token()
				if err != nil {
					return v, err
				}
				key, ok := keyToken.(string)
				if !ok {
					return v, io.ErrUnexpectedEOF
				}
				child, err := decodeValue(dec)
				if err != nil {
					return v, err
				}
				v.keys = append(v.keys, key)
				v.fields[key] = child
			}
			_, err := dec.Token() // closing brace
			return v, err
		}
		v := Value{array: true}
		for dec.More() {
			child, err := decodeValue(dec)
			if err != nil {
				return v, err
			}
			v.items = append(v.items, child)
		}
		_, err := dec.Token() // closing bracket
		return v, err
	case nil:
		return Value{null: true}, nil
	case string:
		return Value{scalar: t}, nil
	case bool:
		// Python renders a boolean as `True`/`False`, and these values are
		// matched as TEXT.
		if t {
			return Value{scalar: "True"}, nil
		}
		return Value{scalar: "False"}, nil
	case json.Number:
		return Value{scalar: t.String()}, nil
	}
	return Value{}, nil
}

// PayloadText flattens a tool payload: a field arrives as a list or as an
// object depending on the tool, and rendering a list as-is matches no pattern.
func PayloadText(v Value) string {
	switch {
	case v.object:
		parts := make([]string, 0, len(v.keys))
		for _, key := range v.keys {
			parts = append(parts, PayloadText(v.fields[key]))
		}
		return strings.Join(parts, " ")
	case v.array:
		parts := make([]string, 0, len(v.items))
		for _, item := range v.items {
			parts = append(parts, PayloadText(item))
		}
		return strings.Join(parts, " ")
	case v.null:
		return ""
	}
	return v.scalar
}

// Field returns a named field of an object, or the zero Value if absent —
// which renders as the empty text, exactly like a missing key on the Python
// side.
func (v Value) Field(name string) Value {
	if !v.object {
		return Value{}
	}
	return v.fields[name]
}

// Text renders a value the way the analysis reads it.
func (v Value) Text() string { return PayloadText(v) }

// MarshalJSON writes the value back with its object keys in their original
// order, so the audit log holds what the tool was actually given.
func (v Value) MarshalJSON() ([]byte, error) {
	switch {
	case v.object:
		var b strings.Builder
		b.WriteByte('{')
		for i, key := range v.keys {
			if i > 0 {
				b.WriteByte(',')
			}
			name, err := json.Marshal(key)
			if err != nil {
				return nil, err
			}
			child, err := json.Marshal(v.fields[key])
			if err != nil {
				return nil, err
			}
			b.Write(name)
			b.WriteByte(':')
			b.Write(child)
		}
		b.WriteByte('}')
		return []byte(b.String()), nil
	case v.array:
		return json.Marshal(v.items)
	case v.null:
		return []byte("null"), nil
	}
	return json.Marshal(v.scalar)
}

// Evaluate decides whether a tool call may run. An empty reason allows it.
func Evaluate(tool string, payload Value) (reason, hint string, err error) {
	switch {
	case tool == "Bash":
		// A list is joined: some clients send argv rather than a line.
		reason, err = CheckBash(payload.Field("command").Text())
		return reason, hintBash, err

	case pathTools[tool]:
		text := PayloadText(payload)
		return firstReason(text), hintPath, nil

	case tool == "WebFetch" || tool == "WebSearch":
		text := PayloadText(payload)
		if reason := firstReason(text); reason != "" {
			return reason, hintNetwork, nil
		}
		raw := payload.Field("url").Text()
		// A domain OPENED by the operator stays subject to the checks above:
		// what is allowed is a READ, not an exit channel.
		if raw != "" && !isLocalURL(raw) && !openHost(raw) {
			return "sortie réseau directe hors du proxy (D9) — aucune " +
				"pseudonymisation n'est possible sur ce chemin", hintNetwork, nil
		}
		return "", hintNetwork, nil
	}

	// Any other tool (Task, MCP…). An MCP server commonly exposes a field that
	// IS a command: inspect it as one, or `mcp__x__shell {"cmd": "env"}` would
	// bypass the whole policy.
	text := PayloadText(payload)
	if reason := firstReason(text); reason != "" {
		return reason, hintOther, nil
	}
	// The field's name is not predictable (`exec`, `program`, `bash_command`,
	// `pipeline`…): an allowlist missed half of them. EVERY value is
	// inspected, except `prompt` — that is prose, and analysing it as a command
	// refused any text containing markdown backticks. The sub-agent a prompt
	// drives has its own PreToolUse: its commands are guarded at execution.
	for _, key := range payload.keys {
		value := payload.fields[key]
		if key == "prompt" || value.null {
			continue
		}
		reason, err := CheckBash(PayloadText(value))
		if err != nil || reason != "" {
			return reason, hintOther, err
		}
	}
	return "", hintOther, nil
}

// firstReason runs the two text checks that apply to every tool.
func firstReason(text string) string {
	normalized := Normalize(text)
	if reason := checkVaultAccess(normalized); reason != "" {
		return reason
	}
	return checkSensitiveFiles(normalized)
}

// openDomainsPath names the file listing the domains the operator has opened to
// direct reading.
//
// The environment wins, because that is the troubleshooting lever; the default
// resolves against the working directory, which is the project root both under
// Claude Code and under the test suite. Deriving it from the binary's own path
// would break as soon as the binary is installed outside the project.
//
// This is the ONLY rule in the whole hook that opens a network destination, and
// it reads a file that lives INSIDE the project the agent works in — so the
// agent can write it. Same exposure as the Python hook, stated rather than
// inherited: closing it means moving this file next to the vault, out of the
// agent's reach, which is jo's call.
const (
	openDomainsEnv     = "ANONPROXY_OPEN_DOMAINS"
	openDomainsDefault = "config/domaines_ouverts.txt"
)

// openDomains is read on EVERY call: removing a line closes the domain at once.
func openDomains() map[string]bool {
	path := os.Getenv(openDomainsEnv)
	if path == "" {
		path = openDomainsDefault
	}
	content, err := os.ReadFile(path)
	if err != nil {
		return nil // no file means nothing open
	}
	domains := map[string]bool{}
	for _, line := range strings.Split(string(content), "\n") {
		if trimmed := strings.TrimSpace(line); trimmed != "" &&
			!strings.HasPrefix(line, "#") {
			domains[strings.ToLower(trimmed)] = true
		}
	}
	return domains
}

// openHost reports whether this URL's HOST was opened by the operator.
//
// Compared as a host, never as a substring: an entry `example.test` covers
// `docs.example.test` but not `example.test.attacker.test`, whose owner is not
// the same. That is the round 3 lesson — a prefix test accepted
// `127.evil.test`.
func openHost(raw string) bool {
	host := hostOf(raw)
	if host == "" {
		return false
	}
	for domain := range openDomains() {
		if host == domain || strings.HasSuffix(host, "."+domain) {
			return true
		}
	}
	return false
}
