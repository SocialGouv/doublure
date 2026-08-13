// anonproxy-control — the arbitration API. A CONTROL SURFACE, never an
// enforcement point.
//
// It shows the operator what was anonymised and carries their decisions back.
// It enforces nothing: protection lives in the proxy, and **uninstalling the
// interface must open nothing**. That is the design test to repeat at every
// addition — if something here ever became necessary to confidentiality, that
// would be the defect, not the feature.
//
// # Unix socket, never a port
//
// This API shows REAL values — that is its purpose, one cannot arbitrate
// blind. The agent runs on the same machine, and the hook lets loopback
// through, so a TCP port would have reopened the very mitigation built against
// the "local vault, same user" gap (§3.5): the agent would read the vault over
// HTTP instead of reading the file.
//
// Stated price: a browser cannot speak to a Unix socket. The interface has to
// be a real client — Node does this natively.
//
// # Server push, not polling
//
// /events is a Server-Sent Events stream. SSE rather than WebSocket because
// the need is strictly one-way — events out, decisions in by POST — and SSE
// needs no dependency on either side, carries reconnection semantics in the
// protocol, and is the same mechanism as the model stream this project already
// parses. A WebSocket would add a second concept for no gain.
//
// # No default paths
//
// Every state location is REQUIRED from the environment. Repeating defaults
// here would create a second source of truth that drifts from the launcher's,
// and a security tool silently reading the wrong vault is worse than one that
// refuses to start.
package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"

	"anonproxy/internal/policy"
	"anonproxy/internal/vault"
)

type server struct {
	policy   *policy.Policy
	vault    *vault.Vault
	scopeKey string
	session  string
	hub      *hub
}

func main() {
	log.SetFlags(0)
	log.SetPrefix("anonproxy-control: ")

	socketPath := mustEnv("ANONPROXY_API_SOCKET")
	policyDir := mustEnv("ANONPROXY_POLICY_DIR")
	scopeKey := mustEnv("ANONPROXY_SCOPE")
	session := os.Getenv("ANONPROXY_SESSION")

	masterKey, err := readMasterKey(mustEnv("ANONPROXY_MASTER_KEY_FILE"))
	if err != nil {
		log.Fatalf("%v", err)
	}
	store, err := vault.Open(mustEnv("ANONPROXY_VAULT"), masterKey)
	if err != nil {
		log.Fatalf("%v", err)
	}
	defer store.Close()

	srv := &server{
		policy:   policy.New(policyDir, scopeKey, session, masterKey),
		vault:    store,
		scopeKey: scopeKey,
		session:  session,
		hub:      newHub(),
	}

	mux := http.NewServeMux()
	mux.HandleFunc("GET /health", srv.health)
	mux.HandleFunc("GET /questions", srv.questions)
	mux.HandleFunc("GET /rules", srv.rules)
	mux.HandleFunc("GET /events", srv.events)
	mux.HandleFunc("POST /decide", srv.decide)
	mux.HandleFunc("POST /settings", srv.settings)

	listener, err := listenUnix(socketPath)
	if err != nil {
		log.Fatalf("%v", err)
	}

	go srv.watch(policyDir)

	stop := make(chan os.Signal, 1)
	signal.Notify(stop, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-stop
		listener.Close()
		os.Remove(socketPath)
		os.Exit(0)
	}()

	log.Printf("listening on %s (scope %s)", socketPath, scopeKey)
	if err := http.Serve(listener, mux); err != nil && !errors.Is(err, net.ErrClosed) {
		log.Fatalf("%v", err)
	}
}

// listenUnix binds the socket and locks it down.
//
// A fresh listener is created with the process umask, which commonly yields
// 0755 — any local user could then read real values. Permissions are tightened
// before anything is served, not after.
func listenUnix(path string) (net.Listener, error) {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return nil, err
	}
	// A stale socket from a dead process would block the bind.
	if info, err := os.Stat(path); err == nil && info.Mode()&os.ModeSocket != 0 {
		os.Remove(path)
	}
	listener, err := net.Listen("unix", path)
	if err != nil {
		return nil, fmt.Errorf("cannot bind %s: %w", path, err)
	}
	if err := os.Chmod(path, 0o600); err != nil {
		listener.Close()
		return nil, fmt.Errorf("cannot restrict %s: %w", path, err)
	}
	return listener, nil
}

func (s *server) questionsWithValues() ([]policy.Question, error) {
	questions := s.policy.Questions()
	for i := range questions {
		real, err := s.vault.Real(s.scopeKey, questions[i].Surrogate)
		if errors.Is(err, vault.ErrNotRenderable) {
			// The mapping is intact; only its rendering is impossible. Hiding
			// the whole question would hide that a decision is pending, so the
			// question stays and says why its value is missing. Deciding
			// "anonymise" remains safe without seeing it; "reveal" is exactly
			// what must not be taken on a value one cannot read.
			questions[i].ValueError = err.Error()
			continue
		}
		if err != nil {
			// Never guess. An unreadable value is reported as such, so the
			// operator does not arbitrate on something we invented.
			return nil, err
		}
		questions[i].Value = real
	}
	return questions, nil
}

func (s *server) health(w http.ResponseWriter, _ *http.Request) {
	count, err := s.vault.Count(s.scopeKey)
	if err != nil {
		fail(w, http.StatusServiceUnavailable, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"status":    "ok",
		"scope":     s.scopeKey,
		"session":   s.session,
		"settings":  s.policy.ResolvedSettings(),
		"modes":     policy.Modes,
		"questions": len(s.policy.Questions()),
		"vault":     count,
	})
}

func (s *server) questions(w http.ResponseWriter, _ *http.Request) {
	questions, err := s.questionsWithValues()
	if err != nil {
		fail(w, http.StatusServiceUnavailable, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"questions": questions})
}

func (s *server) rules(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{
		"scopes":        policy.Scopes,
		"granularities": policy.Granularities,
		"rules":         s.policy.Rules(),
	})
}

// decideRequest names the rule's TARGET rather than its "key": a fingerprint,
// a type name or a class name, depending on the granularity.
type decideRequest struct {
	Granularity string `json:"granularity"`
	Target      string `json:"target"`
	Decision    string `json:"decision"`
	Scope       string `json:"scope"`
}

// scopeMessage is not one of policy.Scopes: see Policy.AnswerForMessage.
const scopeMessage = "message"

func (s *server) decide(w http.ResponseWriter, r *http.Request) {
	var req decideRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		fail(w, http.StatusUnprocessableEntity, "unreadable body: "+err.Error())
		return
	}
	if req.Scope == "" {
		req.Scope = "projet"
	}
	// Go's JSON decoder turns a lone surrogate into U+FFFD before we ever see
	// it, so a target carrying one is indistinguishable from a target the
	// client meant to send. Writing it would put a key into the policy that
	// matches nothing the engine will ever compute — a rule that looks taken
	// and never applies. The extension sends fingerprints and never trips
	// this; any other client would, in silence.
	if strings.ContainsRune(req.Target, '\uFFFD') {
		fail(w, http.StatusUnprocessableEntity,
			"target carries a replacement character: it cannot be matched "+
				"against what the engine computes, so the rule would never apply")
		return
	}
	decision := policy.Decision(req.Decision)
	// "message" is offered to the client as a scope because that is how the
	// operator thinks of it — the nearest one there is. It is not a layer:
	// nothing is written into a scope file, so nothing survives the message.
	if req.Scope == scopeMessage {
		if err := s.policy.AnswerForMessage(req.Granularity, req.Target, decision); err != nil {
			fail(w, http.StatusConflict, err.Error())
			return
		}
		s.notify()
		var warning string
		if decision == policy.Reveal {
			warning = "this value leaves in clear for THIS MESSAGE only, and " +
				"nothing is recorded; what has gone will not be recalled"
		}
		writeJSON(w, http.StatusOK, map[string]any{
			"decision": req.Decision, "scope": scopeMessage, "warning": warning,
		})
		return
	}
	if err := s.policy.Set(req.Scope, req.Granularity, req.Target, decision); err != nil {
		// An invariant refusal is not a caller mistake to fix: it is the rule.
		// Passed through verbatim, to be shown to the operator.
		fail(w, http.StatusConflict, err.Error())
		return
	}
	var warning string
	if decision == policy.Reveal {
		warning = "this value now leaves in clear; revoking the rule will not " +
			"recall what has already gone"
	}
	s.notify()
	writeJSON(w, http.StatusOK, map[string]any{
		"decision": req.Decision, "warning": warning,
	})
}

type settingRequest struct {
	Name  string `json:"name"`
	Value any    `json:"value"`
	Scope string `json:"scope"`
}

func (s *server) settings(w http.ResponseWriter, r *http.Request) {
	var req settingRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		fail(w, http.StatusUnprocessableEntity, "unreadable body: "+err.Error())
		return
	}
	if req.Scope == "" {
		req.Scope = "projet"
	}
	if err := s.policy.SetSetting(req.Scope, req.Name, req.Value); err != nil {
		fail(w, http.StatusUnprocessableEntity, err.Error())
		return
	}
	s.notify()
	writeJSON(w, http.StatusOK, map[string]any{"settings": s.policy.ResolvedSettings()})
}

func mustEnv(name string) string {
	value := os.Getenv(name)
	if value == "" {
		log.Fatalf("%s is required — this service has no default state paths, "+
			"on purpose: a second source of truth would drift, and reading the "+
			"wrong store in silence is worse than refusing to start", name)
	}
	return value
}

// readMasterKey reads the master secret. Never logged, never in a response.
func readMasterKey(path string) ([]byte, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("master secret unreadable (%s): start the detector "+
			"first, it generates it", path)
	}
	secret := strings.TrimSpace(string(raw))
	if secret == "" {
		return nil, fmt.Errorf("master secret empty (%s)", path)
	}
	return []byte(secret), nil
}

func writeJSON(w http.ResponseWriter, status int, body any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(body)
}

func fail(w http.ResponseWriter, status int, detail string) {
	writeJSON(w, status, map[string]string{"detail": detail})
}
