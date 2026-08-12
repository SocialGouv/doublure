// Package vault reads the surrogate vault. Read-only, on purpose.
//
// The control service must resolve a surrogate back to its real value so the
// operator can decide; it must never mint or rebind one. Writing is the
// engine's job, and keeping that boundary here means a bug in the control
// surface cannot corrupt the mapping.
//
// The layout is dictated by the existing vault and reproduced exactly: two
// keys derived from the master key by domain-separated HMAC, a length-prefixed
// HMAC index for lookup, and AES-256-GCM for the value itself with the row's
// identity as associated data.
package vault

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/sha256"
	"database/sql"
	"encoding/binary"
	"errors"
	"fmt"
	"unicode/utf8"

	_ "modernc.org/sqlite" // pure Go: no cgo, so the binary stays static
)

// ErrUnavailable is returned whenever a value cannot be read with certainty.
// Never a zero value, never a guess: an unreadable vault is a refusal (D5).
var ErrUnavailable = errors.New("vault unavailable")

type Vault struct {
	db     *sql.DB
	aesgcm cipher.AEAD
}

// Open opens the vault read-only.
func Open(path string, masterKey []byte) (*Vault, error) {
	// Two uses, two derived keys: the index must learn nothing from the
	// cipher, and the other way round.
	cipherKey := derive(masterKey, "anonproxy/vault/cipher")

	block, err := aes.NewCipher(cipherKey)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrUnavailable, err)
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrUnavailable, err)
	}

	db, err := sql.Open("sqlite", "file:"+path+"?mode=ro")
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrUnavailable, err)
	}
	if err := db.Ping(); err != nil {
		db.Close()
		return nil, fmt.Errorf("%w: %s: %v", ErrUnavailable, path, err)
	}
	return &Vault{db: db, aesgcm: aead}, nil
}

func (v *Vault) Close() error { return v.db.Close() }

func derive(masterKey []byte, domain string) []byte {
	mac := hmac.New(sha256.New, masterKey)
	mac.Write([]byte(domain))
	return mac.Sum(nil)
}

// lengthPrefixed encodes parts unambiguously.
//
// A plain separator would not be injective: HMAC(a, b|c) and HMAC(a|b, c)
// collide as soon as a value contains the separator, and swapping two sealed
// rows would become undetectable.
func lengthPrefixed(parts ...string) []byte {
	var out []byte
	for _, p := range parts {
		var n [4]byte
		binary.BigEndian.PutUint32(n[:], uint32(len(p)))
		out = append(out, n[:]...)
		out = append(out, p...)
	}
	return out
}

// ErrNotRenderable marks a value the vault holds but cannot display without
// changing it. It is distinct from ErrUnavailable: the mapping is intact, only
// its rendering is impossible.
var ErrNotRenderable = errors.New("value cannot be rendered")

// Real resolves a surrogate back to the value it stands for.
func (v *Vault) Real(scope, surrogate string) (string, error) {
	var etype string
	var blob []byte
	err := v.db.QueryRow(
		`SELECT etype, real_enc FROM mapping WHERE scope = ? AND surrogate = ?`,
		scope, surrogate).Scan(&etype, &blob)
	if errors.Is(err, sql.ErrNoRows) {
		return "", nil // not in the vault: not an error, just unknown
	}
	if err != nil {
		return "", fmt.Errorf("%w: %v", ErrUnavailable, err)
	}
	return v.open(scope, etype, surrogate, blob)
}

func (v *Vault) open(scope, etype, surrogate string, blob []byte) (string, error) {
	if len(blob) < v.aesgcm.NonceSize()+4 {
		return "", fmt.Errorf("%w: sealed value truncated", ErrUnavailable)
	}
	nonce, body := blob[:v.aesgcm.NonceSize()], blob[v.aesgcm.NonceSize():]
	// The associated data binds the seal to ITS row: without it GCM
	// authenticates each blob in isolation, and anyone able to write the file
	// could swap two real_enc columns and silently invert two mappings.
	payload, err := v.aesgcm.Open(nil, nonce, body, lengthPrefixed(scope, etype, surrogate))
	if err != nil {
		return "", fmt.Errorf(
			"%w: wrong master key, tampered vault, or a mapping moved between rows. "+
				"No value is guessed", ErrUnavailable)
	}
	if len(payload) < 4 {
		return "", fmt.Errorf("%w: sealed payload too short", ErrUnavailable)
	}
	// Deterministic padding hides the exact length of the real value: GCM does
	// not pad, and the ciphertext size alone would leak it.
	size := binary.BigEndian.Uint32(payload[:4])
	if int(size) > len(payload)-4 {
		return "", fmt.Errorf("%w: declared length exceeds payload", ErrUnavailable)
	}
	real := payload[4 : 4+size]
	// A value that is not valid UTF-8 cannot be RENDERED truthfully: Go's JSON
	// encoder silently substitutes U+FFFD for each bad byte, so the operator
	// would read something the vault never held. Python lets such a value
	// through on purpose (`surrogatepass`) because it must still be
	// substituted; showing it is another matter, and here we refuse rather
	// than replace.
	if !utf8.Valid(real) {
		return "", fmt.Errorf("%w: value is not valid UTF-8", ErrNotRenderable)
	}
	return string(real), nil
}

// Count returns how many mappings exist in a scope.
func (v *Vault) Count(scope string) (int, error) {
	var n int
	err := v.db.QueryRow(`SELECT COUNT(*) FROM mapping WHERE scope = ?`, scope).Scan(&n)
	if err != nil {
		return 0, fmt.Errorf("%w: %v", ErrUnavailable, err)
	}
	return n, nil
}
