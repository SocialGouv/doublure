// anonproxy-guard — the PreToolUse hook (plan §5, Phase 4).
//
// PreToolUse is the ONLY hook that can prevent a tool from reaching the
// network: everything else fires after the payload is gone.
//
// This hook BLOCKS, it does not pseudonymise. There is no rewrite channel back
// to the operator on this path (§7): substituting here would create a false
// impression of reversibility.
//
// Protocol: it reads the JSON event from stdin and writes a JSON decision to
// stdout. permissionDecision:"deny" blocks before execution and returns the
// reason to the model in a usable form.
//
// # FAIL-CLOSED
//
// Any failure, any panic, any unreadable event must produce a DENY on stdout
// with exit code 0. A hook that crashes writes no decision, and the tool runs —
// the one failure mode that opens the channel instead of closing it.
package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"time"

	"anonproxy/internal/guard"
)

func auditLogPath() string {
	if path := os.Getenv("ANONPROXY_AUDIT_LOG"); path != "" {
		return path
	}
	// The state directory is a SECRET path: it is read from the environment,
	// never rebuilt here, and never printed.
	if dir := os.Getenv("ANONPROXY_STATE_DIR"); dir != "" {
		return filepath.Join(dir, "canal2_audit.jsonl")
	}
	return ""
}

// record is a struct rather than a map so its fields keep a fixed order: the
// audit log is read line by line after an incident, and a stable shape is what
// makes it greppable.
type record struct {
	TS       float64      `json:"ts"`
	Tool     string       `json:"tool"`
	Session  string       `json:"session"`
	Decision string       `json:"decision"`
	Reason   string       `json:"reason"`
	Input    *guard.Value `json:"input"`
	Digest   *string      `json:"digest"`
}

func deny(reason, hint string) map[string]any {
	message := "Bloqué par la politique de pseudonymisation : " + reason + "."
	if hint != "" {
		message += " " + hint
	}
	// Traceability marker: it proves THIS precise refusal reached the model,
	// where a mere keyword would blend into its prose.
	if marker := os.Getenv("ANONPROXY_DENY_MARKER"); marker != "" {
		message += " [réf. " + marker + "]"
	}
	return map[string]any{
		"hookSpecificOutput": map[string]any{
			"hookEventName":            "PreToolUse",
			"permissionDecision":       "deny",
			"permissionDecisionReason": message,
		},
	}
}

func audit(rec record) {
	path := auditLogPath()
	if path == "" {
		fmt.Fprintln(os.Stderr, "anonproxy: no audit log configured "+
			"(ANONPROXY_AUDIT_LOG or ANONPROXY_STATE_DIR)")
		return
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		fmt.Fprintf(os.Stderr, "anonproxy: audit log unreachable (%s): %v\n", path, err)
		return
	}
	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		fmt.Fprintf(os.Stderr, "anonproxy: audit log unreachable (%s): %v\n", path, err)
		return
	}
	defer f.Close()
	enc := json.NewEncoder(f)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(rec); err != nil {
		fmt.Fprintf(os.Stderr, "anonproxy: audit log write failed: %v\n", err)
	}
}

func writeDecision(decision map[string]any) {
	enc := json.NewEncoder(os.Stdout)
	enc.SetEscapeHTML(false)
	_ = enc.Encode(decision)
}

func digestOf(payload guard.Value) *string {
	sum := sha256.Sum256([]byte(payload.Text()))
	digest := hex.EncodeToString(sum[:])[:16]
	return &digest
}

// roundedNow mirrors the Python timestamp: seconds with three decimals.
func roundedNow() float64 {
	seconds := float64(time.Now().UnixNano()) / 1e9
	rounded, _ := strconv.ParseFloat(strconv.FormatFloat(seconds, 'f', 3, 64), 64)
	return rounded
}

func main() {
	// FAIL-CLOSED. A panic here must still yield a deny on stdout and exit 0.
	defer func() {
		if r := recover(); r != nil {
			fmt.Fprintf(os.Stderr, "anonproxy: analysis impossible (%v)\n", r)
			writeDecision(deny("l'analyse de sécurité a échoué : la commande "+
				"est refusée en l'état", ""))
			os.Exit(0)
		}
	}()

	var event guard.Value
	event, err := guard.DecodeValue(json.NewDecoder(os.Stdin))
	if err != nil {
		// An unreadable event is NOT an authorisation: exiting in error with no
		// decision let the tool run.
		writeDecision(deny(fmt.Sprintf("événement PreToolUse illisible (%s)",
			errorKind(err)), ""))
		os.Exit(0)
	}

	tool := event.Field("tool_name").Text()
	session := event.Field("session_id").Text()
	payload := event.Field("tool_input")

	reason, hint, err := guard.Evaluate(tool, payload)
	if err != nil {
		fmt.Fprintf(os.Stderr, "anonproxy: analysis impossible: %v\n", err)
		reason = "l'analyse de sécurité a échoué : la commande est refusée en l'état"
		audit(record{TS: roundedNow(), Tool: tool, Session: session,
			Decision: "deny", Reason: reason, Input: &payload})
		writeDecision(deny(reason, ""))
		os.Exit(0)
	}

	rec := record{TS: roundedNow(), Tool: tool, Session: session,
		Decision: "allow", Reason: reason}
	if reason != "" {
		rec.Decision = "deny"
		// The command is logged in clear ONLY when refused: the log must not
		// become a copy of all the activity.
		rec.Input = &payload
	} else {
		// For allowances a fingerprint is enough to rebuild a chronology after
		// an incident ("did this exact command get through?") without
		// duplicating the operator's data.
		rec.Digest = digestOf(payload)
	}
	audit(rec)

	if reason != "" {
		writeDecision(deny(reason, hint))
	}
}

// errorKind names the failure the way the Python hook does, by exception type.
func errorKind(err error) string {
	if _, ok := err.(*json.SyntaxError); ok {
		return "JSONDecodeError"
	}
	if _, ok := err.(*json.UnmarshalTypeError); ok {
		return "JSONDecodeError"
	}
	return "IOError"
}
