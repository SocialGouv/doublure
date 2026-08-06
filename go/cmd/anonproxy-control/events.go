package main

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// hub fans events out to connected interfaces.
//
// Polling was the previous design and it was wrong in the one case that
// matters: in blocking mode the request WAITS, and a three-second poll means
// the operator learns three seconds late that something is stuck on them.
type hub struct {
	mu      sync.Mutex
	clients map[chan []byte]struct{}
}

func newHub() *hub { return &hub{clients: map[chan []byte]struct{}{}} }

func (h *hub) add() chan []byte {
	// Buffered: a slow client must never block the watcher or a POST handler.
	ch := make(chan []byte, 8)
	h.mu.Lock()
	h.clients[ch] = struct{}{}
	h.mu.Unlock()
	return ch
}

func (h *hub) remove(ch chan []byte) {
	h.mu.Lock()
	delete(h.clients, ch)
	close(ch)
	h.mu.Unlock()
}

func (h *hub) broadcast(event string, payload any) {
	body, err := json.Marshal(payload)
	if err != nil {
		log.Printf("cannot encode event %s: %v", event, err)
		return
	}
	frame := []byte(fmt.Sprintf("event: %s\ndata: %s\n\n", event, body))
	h.mu.Lock()
	defer h.mu.Unlock()
	for ch := range h.clients {
		select {
		case ch <- frame:
		default:
			// Client not keeping up. Dropping the frame is the right failure:
			// every event is a hint to re-read state, never state itself, so a
			// lost frame costs at most one refresh — whereas blocking here
			// would stall arbitration for everyone.
		}
	}
}

// events serves the Server-Sent Events stream.
func (s *server) events(w http.ResponseWriter, r *http.Request) {
	flusher, ok := w.(http.Flusher)
	if !ok {
		fail(w, http.StatusInternalServerError, "streaming unsupported")
		return
	}
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	w.WriteHeader(http.StatusOK)

	ch := s.hub.add()
	defer s.hub.remove(ch)

	// The current state first: a client must never have to wait for something
	// to change before it can display anything truthful.
	s.sendState(w, flusher)

	// Keep-alive comments stop an idle stream from being torn down, and let
	// the client notice a dead server.
	ticker := time.NewTicker(20 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-r.Context().Done():
			return
		case frame := <-ch:
			if _, err := w.Write(frame); err != nil {
				return
			}
			flusher.Flush()
		case <-ticker.C:
			if _, err := w.Write([]byte(": keep-alive\n\n")); err != nil {
				return
			}
			flusher.Flush()
		}
	}
}

func (s *server) sendState(w http.ResponseWriter, flusher http.Flusher) {
	questions, err := s.questionsWithValues()
	if err != nil {
		// Never send a reassuring state we have not established.
		fmt.Fprintf(w, "event: error\ndata: %q\n\n", err.Error())
		flusher.Flush()
		return
	}
	body, err := json.Marshal(map[string]any{
		"settings":  s.policy.ResolvedSettings(),
		"questions": questions,
	})
	if err != nil {
		return
	}
	fmt.Fprintf(w, "event: state\ndata: %s\n\n", body)
	flusher.Flush()
}

// notify pushes the current state to every connected interface.
func (s *server) notify() {
	questions, err := s.questionsWithValues()
	if err != nil {
		s.hub.broadcast("error", err.Error())
		return
	}
	s.hub.broadcast("state", map[string]any{
		"settings":  s.policy.ResolvedSettings(),
		"questions": questions,
	})
}

// watch notices what the ENGINE writes.
//
// The queue and the policy files are written by another process, so there is
// nothing in-process to hook. Watching by modification time is deliberately
// dumb: an inotify dependency would buy latency we do not need, and would fail
// silently on the filesystems where it is unavailable.
func (s *server) watch(policyDir string) {
	previous := ""
	for range time.Tick(500 * time.Millisecond) {
		current := fingerprintDir(policyDir)
		if current == previous {
			continue
		}
		if previous != "" { // not the first pass: nothing changed, it appeared
			s.notify()
		}
		previous = current
	}
}

func fingerprintDir(dir string) string {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return ""
	}
	out := ""
	for _, e := range entries {
		info, err := e.Info()
		if err != nil {
			continue
		}
		out += fmt.Sprintf("%s:%d:%d|", filepath.Base(e.Name()),
			info.Size(), info.ModTime().UnixNano())
	}
	return out
}
