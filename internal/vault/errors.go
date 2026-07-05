package vault

import "errors"

// Sentinel errors returned by Load so the CLI can distinguish the ordinary
// "no session yet" case from a genuinely stale one and word its message
// accordingly. Both are expected states in normal use, not bugs.
var (
	// ErrNoSession means no persisted session file was found. This is the
	// benign "you haven't redacted anything reversibly (or already cleared
	// it)" case — the CLI should explain, not treat it as a failure.
	ErrNoSession = errors.New("no reversible-redaction session found")

	// ErrExpired means a session existed but had outlived its TTL and was
	// removed on load. The CLI should tell the user their vault aged out so
	// they know why un-redaction found nothing to restore.
	ErrExpired = errors.New("reversible-redaction session has expired")
)
