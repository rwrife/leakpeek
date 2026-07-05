// Package vault is leakpeek's reversible-redaction memory: the piece that
// lets you *un-redact* an AI's reply.
//
// The rest of leakpeek is deliberately one-way — `--fix` masks a secret and
// forgets it. That's perfect for a fire-and-forget paste, but it breaks the
// moment the AI echoes your placeholder back at you: it hands you
// "[LEAKPEEK:ab12cd34]" and you have no way to turn that back into the real
// value. The vault closes that loop. When you redact with the reversible
// strategy, leakpeek swaps each secret for a unique, opaque placeholder and
// remembers the mapping locally; later, `--unredact` reads the AI's response
// and splices the originals back in.
//
// Design constraints (see PLAN.md §8 "Reversible redaction vault"):
//
//   - **Local & ephemeral.** The map is never written to disk *by default*.
//     It lives only in memory for a single process. Because `--fix` and the
//     later `--unredact` are two separate process runs, the caller may opt to
//     persist a session to a private temp file (Save/Load) so the two runs
//     can find each other — but that's an explicit, opt-in step with a short
//     TTL, 0600 perms, and an easy wipe (Clear), so secrets don't linger.
//   - **Reversible, not guessable.** Placeholders are derived from a hash of
//     the secret, so identical secrets collapse to one placeholder (a reader
//     can see two spots hold the same value) while the placeholder itself
//     leaks nothing about the original.
//   - **Clear lifecycle.** A session carries a creation time and TTL;
//     anything older is treated as expired and refused on load, and Clear
//     removes the on-disk copy entirely.
//
// The vault knows nothing about clipboards, flags, or detectors; main.go
// wires it to those. It only speaks in placeholders and originals.
package vault

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

const (
	// placeholderPrefix and placeholderSuffix bracket every reversible token.
	// The form is deliberately unusual so it survives a round-trip through an
	// AI unmangled and is easy to find again for un-redaction. Example:
	// "[LEAKPEEK:ab12cd34]".
	placeholderPrefix = "[LEAKPEEK:"
	placeholderSuffix = "]"

	// tagLen is how many hex chars of the secret's hash go into a placeholder.
	// 8 hex (32 bits) is plenty to avoid collisions for the handful of
	// secrets in a single paste while staying short and readable.
	tagLen = 8

	// DefaultTTL is how long a persisted session stays valid. Short by design:
	// the vault is a bridge between one redact and one un-redact, not a store.
	DefaultTTL = 15 * time.Minute

	// sessionFile is the fixed name of the persisted session inside the vault
	// directory. A single active session is all the workflow needs, and a
	// fixed name means `--unredact` can find it without the user tracking ids.
	sessionFile = "session.json"

	// filePerm / dirPerm keep the on-disk session owner-only. The map holds
	// real secrets while it exists, so nothing about it is world- or
	// group-readable.
	filePerm os.FileMode = 0o600
	dirPerm  os.FileMode = 0o700
)

// Vault is an in-memory, reversible map from placeholder → original secret,
// plus a reverse index so the same secret always yields the same placeholder.
// The zero value is not ready for use; call New.
//
// A Vault is not safe for concurrent use. leakpeek builds and consumes one
// per process run, single-threaded, so no locking is warranted.
type Vault struct {
	// forward maps placeholder → original. This is what un-redaction reads.
	forward map[string]string
	// reverse maps original → placeholder, so Add is idempotent per secret
	// (identical secrets reuse one placeholder rather than minting new ones).
	reverse map[string]string
	// created is when this session began; used with ttl to decide expiry.
	created time.Time
	// ttl is how long the session remains valid once persisted.
	ttl time.Duration
}

// New returns an empty Vault stamped with the current time and DefaultTTL.
func New() *Vault {
	return &Vault{
		forward: map[string]string{},
		reverse: map[string]string{},
		created: time.Now(),
		ttl:     DefaultTTL,
	}
}

// Placeholder returns the opaque token that would stand in for secret, minting
// and remembering it on first sight and returning the same token thereafter.
// The token is stable across a process and derived only from the secret's
// content, so two occurrences of one secret share a placeholder. The mapping
// is recorded so Restore can reverse it later.
//
// An empty secret is never stored and returns "": there is nothing to hide,
// and minting a placeholder for it would corrupt un-redaction.
func (v *Vault) Placeholder(secret string) string {
	if secret == "" {
		return ""
	}
	if p, ok := v.reverse[secret]; ok {
		return p
	}
	p := v.mint(secret)
	v.forward[p] = secret
	v.reverse[secret] = p
	return p
}

// mint builds a collision-resistant placeholder for secret. The tag is the
// first tagLen hex chars of SHA-256(secret); on the astronomically rare event
// that two different secrets in one session share that prefix, we extend the
// tag from the same hash until it's unique, so the forward map never clobbers
// one secret's mapping with another's.
func (v *Vault) mint(secret string) string {
	sum := sha256.Sum256([]byte(secret))
	full := hex.EncodeToString(sum[:])
	n := tagLen
	for n <= len(full) {
		tag := full[:n]
		p := placeholderPrefix + tag + placeholderSuffix
		if existing, taken := v.forward[p]; !taken || existing == secret {
			return p
		}
		n++ // collision with a *different* secret: lengthen and retry
	}
	// Fallback (essentially unreachable): use the whole hash.
	return placeholderPrefix + full + placeholderSuffix
}

// Len reports how many distinct secrets the vault is holding.
func (v *Vault) Len() int { return len(v.forward) }

// Empty reports whether the vault holds no mappings.
func (v *Vault) Empty() bool { return len(v.forward) == 0 }

// Restore returns text with every known placeholder replaced by its original
// secret, and the count of substitutions made. Unknown placeholders (or an
// empty vault) leave the text untouched. Replacement is plain,
// non-overlapping string substitution; placeholders are opaque, fixed tokens
// that never nest, so a single pass per placeholder is safe.
//
// Longer placeholders are applied first so an extended-tag token can't be
// partially matched by a shorter one that happens to be its prefix.
func (v *Vault) Restore(text string) (string, int) {
	if len(v.forward) == 0 || text == "" {
		return text, 0
	}
	placeholders := make([]string, 0, len(v.forward))
	for p := range v.forward {
		placeholders = append(placeholders, p)
	}
	sort.Slice(placeholders, func(i, j int) bool {
		return len(placeholders[i]) > len(placeholders[j])
	})

	count := 0
	out := text
	for _, p := range placeholders {
		if n := strings.Count(out, p); n > 0 {
			out = strings.ReplaceAll(out, p, v.forward[p])
			count += n
		}
	}
	return out, count
}

// LooksLikePlaceholder reports whether s contains at least one token in
// leakpeek's reversible-placeholder shape. It's a cheap pre-check the CLI can
// use to warn "nothing to un-redact here" without consulting a vault.
func LooksLikePlaceholder(s string) bool {
	i := strings.Index(s, placeholderPrefix)
	if i < 0 {
		return false
	}
	return strings.Index(s[i+len(placeholderPrefix):], placeholderSuffix) >= 0
}

// session is the on-disk shape of a persisted vault. Kept separate from Vault
// so the wire format is explicit and versioned independently of the in-memory
// representation.
type session struct {
	Version int               `json:"version"`
	Created time.Time         `json:"created"`
	TTLSecs int               `json:"ttl_seconds"`
	Map     map[string]string `json:"map"` // placeholder → original
}

const sessionVersion = 1

// Save writes the vault to a private session file under dir (created 0700 if
// needed) so a later process can Load it for un-redaction. The file is written
// 0600. Saving an empty vault is a no-op that returns nil — there is nothing
// worth persisting, and we avoid leaving an empty secret-store on disk.
//
// This is the one place the map touches disk, and only when the caller
// explicitly asks (leakpeek gates it behind not passing --no-vault). The
// stored map holds real secrets, so callers must treat dir as sensitive and
// pair Save with an eventual Clear.
func (v *Vault) Save(dir string) error {
	if v.Empty() {
		return nil
	}
	if err := os.MkdirAll(dir, dirPerm); err != nil {
		return fmt.Errorf("creating vault dir: %w", err)
	}
	s := session{
		Version: sessionVersion,
		Created: v.created,
		TTLSecs: int(v.ttl / time.Second),
		Map:     v.forward,
	}
	data, err := json.Marshal(s)
	if err != nil {
		return fmt.Errorf("encoding vault: %w", err)
	}

	// Write to a temp file in the same dir, then rename, so a reader never
	// sees a half-written session. Create the temp file 0600 from the start.
	path := filepath.Join(dir, sessionFile)
	tmp, err := os.CreateTemp(dir, sessionFile+".tmp-*")
	if err != nil {
		return fmt.Errorf("creating vault temp file: %w", err)
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName) // harmless if the rename already consumed it

	if err := tmp.Chmod(filePerm); err != nil {
		tmp.Close()
		return fmt.Errorf("securing vault temp file: %w", err)
	}
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return fmt.Errorf("writing vault: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("closing vault temp file: %w", err)
	}
	if err := os.Rename(tmpName, path); err != nil {
		return fmt.Errorf("finalizing vault: %w", err)
	}
	return nil
}

// Load reads a persisted session from dir and returns the reconstructed
// Vault. It returns ErrNoSession if no session file exists (a normal,
// non-error "there's nothing to un-redact against" case the CLI reports
// gently) and ErrExpired if the session exists but has outlived its TTL — in
// which case the stale file is removed as a side effect so the secrets don't
// linger past their welcome.
func Load(dir string) (*Vault, error) {
	path := filepath.Join(dir, sessionFile)
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, ErrNoSession
		}
		return nil, fmt.Errorf("reading vault: %w", err)
	}

	var s session
	if err := json.Unmarshal(data, &s); err != nil {
		return nil, fmt.Errorf("decoding vault (corrupt session?): %w", err)
	}

	ttl := time.Duration(s.TTLSecs) * time.Second
	if ttl <= 0 {
		ttl = DefaultTTL
	}
	if time.Since(s.Created) > ttl {
		// Expired: wipe it so a stale secret map can't be read later, and tell
		// the caller it was too old.
		_ = os.Remove(path)
		return nil, ErrExpired
	}

	v := &Vault{
		forward: map[string]string{},
		reverse: map[string]string{},
		created: s.Created,
		ttl:     ttl,
	}
	for placeholder, original := range s.Map {
		v.forward[placeholder] = original
		v.reverse[original] = placeholder
	}
	return v, nil
}

// Clear removes any persisted session under dir. It returns (true, nil) when a
// session existed and was removed, (false, nil) when there was nothing to
// clear, and a non-nil error only on an actual filesystem failure. This is the
// user-facing "forget my secrets now" lever.
func Clear(dir string) (removed bool, err error) {
	path := filepath.Join(dir, sessionFile)
	if err := os.Remove(path); err != nil {
		if os.IsNotExist(err) {
			return false, nil
		}
		return false, fmt.Errorf("clearing vault: %w", err)
	}
	return true, nil
}

// DefaultDir returns the directory leakpeek uses for its (opt-in) session
// file: a private "leakpeek" folder under the OS temp dir. Temp is chosen
// deliberately over a config/home dir — a reversible session is meant to be
// short-lived and disposable, and temp is the natural home for that, often
// cleared on reboot as an extra backstop.
func DefaultDir() string {
	return filepath.Join(os.TempDir(), "leakpeek")
}
