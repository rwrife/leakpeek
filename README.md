# leakpeek 🕵️

**A paranoid bouncer for your clipboard.** It frisks your text for API keys, secrets, PII, and internal hostnames *right before* you paste it into an AI chat — then hands you a redacted copy. Local-only. No servers. No telemetry.

```
$ leakpeek
🚫 3 things you'd regret pasting:
   TYPE            COUNT  WHERE      PREVIEW
   aws-access-key      1  line 4:9   AKIA…MPLE
   openai-key          1  line 9:8   sk…wXyz
   email               1  line 12:3  j…@example.com
🚫 3 secrets across pii and secret. Don't paste that.
```

## Why

You paste stack traces, configs, and logs into ChatGPT all day. Sometimes they carry an API key, a customer email, or your `db-prod-01.corp.internal` hostname. Repo secret scanners never see that moment. leakpeek does — it scans the thing in your hand, one second before it leaves.

## Status

🚧 Early. See [`PLAN.md`](./PLAN.md) for the roadmap and milestones. v0.1 is regex + entropy, pure Go, single static binary.

**M1 (scaffold) is in:** `leakpeek` builds as a static binary, prints `--version`, and reads your clipboard (or `--stdin`) and echoes it back unchanged. CI builds + vets + tests on macOS, Linux, and Windows.

**M2 (detector engine) is in:** the `internal/detect` package provides the brains — a `Detector` interface (`Name`, `Kind`, `Find`), a Shannon-entropy helper, overlapping-span de-duplication, and the v0.1 core secret pack: AWS access keys, OpenAI `sk-` keys, GitHub PATs, Slack tokens, JWTs, private-key headers, emails, IPv4 addresses, named-entity PII (credit-card numbers via Luhn, IBANs via mod-97, US SSNs, and phone numbers), and a generic high-entropy catch-all. Specific detectors win over the catch-all during dedupe.

**Built-in detectors:**

| Detector | Kind | Validation | Example |
| --- | --- | --- | --- |
| `aws-access-key` | secret | prefix + length | `AKIAIOSFODNN7EXAMPLE` |
| `openai-key` | secret | prefix + length | `sk-proj-…` |
| `github-pat` | secret | prefix + length | `ghp_…`, `github_pat_…` |
| `slack-token` | secret | prefix + length | `xoxb-…` |
| `jwt` | secret | `eyJ` header shape | `eyJhbGci….….…` |
| `private-key` | private-key | PEM/OpenSSH header | `-----BEGIN … PRIVATE KEY-----` |
| `email` | pii | shape | `jane@corp.internal` |
| `credit-card` | payment | **Luhn** checksum | `4111 1111 1111 1111` |
| `iban` | pii | **mod-97** checksum | `GB82 WEST 1234 5698 7654 32` |
| `ssn` | pii | US area/group/serial filter | `078-05-1120` |
| `phone` | pii | E.164 / national digit-count | `+1 202-555-0100` |
| `ipv4` | network | octet range 0–255 | `10.0.12.34` |
| `high-entropy-token` | entropy | Shannon-entropy gate | long random blobs |

Credit-card findings are redacted receipt-style — all but the last four digits masked (`**** **** **** 1111`); the other PII detectors follow the standard shape/full/hash strategies.

**M3 (report + exit codes + `--json`) is in:** leakpeek no longer echoes — it now *scans and reports*. It runs the engine over your clipboard (or `--stdin`), prints a grouped findings table (type, count, line/column, masked preview) with a one-line personality verdict, and exits **3** when it finds something (**0** when clean). `--json` emits a versioned, machine-readable document; `--quiet` stays silent on a clean scan (handy for shell aliases). Previews are masked (`AKIA…MPLE`, `sk-proj…CDEF`, `j…@example.com`, `10.x.x.x`) so the report never re-leaks the secret it just caught.

**M4 (`--fix` redaction + clipboard write-back) is in:** leakpeek can now *fix* what it finds. `leakpeek --fix` redacts every finding and hands back a paste-safe copy — written straight back to the **clipboard**, or printed to **stdout** when the input came from a pipe (`cat secrets.env | leakpeek --fix > clean.env`). The report goes to stderr so it never contaminates piped output. Three strategies via `--strategy`:

- `shape` (default) — keeps a recognizable scheme hint so the AI still understands the token's *shape*: `sk-proj-REDACTED`, `AKIAREDACTED`, `ghp_REDACTED`, `REDACTED@corp.internal`, `x.x.x.x`.
- `full` — replaces the whole match with `[REDACTED-<KIND>]`, revealing nothing, not even the scheme.
- `hash` — replaces it with `[<KIND>:<8hex>]`, a stable, **non-reversible** fingerprint so you can see two redactions point at the *same* secret without exposing it.

The guarantee: for every strategy and every detector, the redacted output contains **no original secret material** (verified per-detector in the test suite). On a clean scan, `--fix` leaves the clipboard untouched and passes piped input through byte-for-byte.

**Reversible redaction vault is in:** the fourth strategy, `--strategy vault`, closes the loop with the AI. Instead of destroying each secret it swaps in an opaque, **reversible** placeholder — `[LEAKPEEK:1a5d44a2]` — and remembers the mapping in a short-lived, owner-only (`0600`) session file under your temp dir. When the AI's reply echoes those placeholders back at you, `leakpeek --unredact` reads it (clipboard or pipe) and splices your real values back in. Identical secrets collapse to one placeholder (so you can see two spots hold the same value) and the placeholder itself leaks nothing — it's derived from a hash, not the secret. Lifecycle is deliberately tight so nothing lingers: sessions carry a **15-minute TTL** (an expired one is refused *and wiped* on the next read), `--unredact` **clears the session by default** once it restores (pass `--keep-vault` to reuse it), `--vault-clear` wipes it on demand, and `--no-vault` redacts reversibly-shaped tokens while storing nothing at all. It never leaves your machine — the map touches disk only for this one local hop between redact and un-redact. This is the [Reversible redaction vault](./PLAN.md#8-backlog--future-features-v02) from the backlog.

**M6 (custom rules + release) is here:** you can now teach leakpeek your own secrets. `--rules <path>` loads extra detectors from a TOML rule file — or a whole directory of `*.toml` files — and runs them **alongside** the built-in pack. A rule is the same `{name, kind, regex}` triple a built-in is, so custom detectors report, group, and redact exactly like the core ones, and built-ins keep priority during de-duplication. This is the extensibility hook from PLAN.md §6. Release plumbing is wired too: [goreleaser](.goreleaser.yaml) cross-compiles static binaries for macOS/Linux/Windows (amd64 + arm64) and a [release workflow](.github/workflows/release.yml) publishes them — plus a Homebrew formula — on every `v*.*.*` tag. See [Install](#install).

**Format-aware redaction is in:** paste a `.env`, a JSON blob, or some YAML and you usually want the *shape* back — the keys, the nesting, the punctuation — with only the **values** scrubbed. `leakpeek --fix --format-aware` (alias `--format`) does exactly that: it sniffs the format, then redacts the values that carry a secret while leaving keys and structure byte-for-byte intact, so the AI still sees `"database_url": "[REDACTED-SECRET]"` instead of a hole where the structure used to be. It's **finding-driven**, not key-name-guessing: a value is only touched when a real detector fires inside it, so innocuous config (`"port": 5432`) is left exactly as written and a secret-shaped *key* (an email used as a JSON key) is never redacted — we redact values, not keys. JSON output stays valid JSON (quotes kept around the placeholder); quoted `.env` values keep their quotes and any trailing `# comment`; YAML keeps its indentation and list structure. Anything the format pass doesn't model — a secret sitting in a comment, or text that isn't structured at all — falls back to the ordinary span-based redaction, so nothing sensitive is ever left behind. Works with every strategy (`shape`/`full`/`hash`). This is the [Format-aware redaction](./PLAN.md#8-backlog--future-features-v02) item from the backlog.

**Redaction annotations (`--annotate`) are in:** when `--fix` hands back a redacted copy, `--annotate` appends a short, human-readable provenance footer that says what was scrubbed — grouped by kind and count, never by value — e.g. `[leakpeek: redacted 2 API keys, 1 email]`. It's off by default and opt-in. Why bother? A bare redacted paste can confuse the model on the other side (`what is [REDACTED]?`); a one-line summary tells the AI (and you) that redaction happened and roughly what came out, which sharpens downstream answers while staying **fully local** — the footer is derived only from detector *kinds* and *counts*, so it can never re-leak the secret it just removed. It works in every mode: the footer lands on its own trailing line for both **clipboard** write-back and **stdout/pipe** output (`cat secrets.env | leakpeek --fix --annotate > clean.env`), a **clean** scan adds nothing (byte-for-byte passthrough), and with `--strategy vault` the note flips to `[leakpeek: reversibly redacted … — run \`leakpeek --unredact\` to restore]` so the reader knows the placeholders can be reversed. `--json` mirrors the exact footer string in a top-level `annotation` field. This is the [Redaction summary annotations](./PLAN.md#8-backlog--future-features-v02) item from the backlog.

**M5 (cross-platform clipboard hardening) is in:** the clipboard layer now degrades gracefully everywhere a paste happens. Each OS has an ordered list of adapters, and leakpeek walks it — skipping tools that aren't installed **and falling through to the next tool when one is installed but fails at runtime**. So a Linux box with `wl-clipboard` installed but no Wayland compositor running still succeeds via `xclip`/`xsel`; an *empty* Wayland clipboard (where `wl-paste` exits non-zero) reads as empty text instead of an error. When nothing on the host can serve the request you get one clear, friendly message: if no tool is installed it wraps a recognizable sentinel and points you at `--stdin`; if tools were present but all failed it lists each tool and why it broke. See the [platform support matrix](#platform-support) below.

**Watch mode (`--watch`) is in:** leakpeek can now stand guard *continuously*. `leakpeek --watch` stays resident, taps the clipboard on a debounced interval (`--interval`, default `800ms`), and the instant a secret lands on it — before you ever reach the prompt box — it raises a **desktop notification** (`notify-send` / `osascript` / a PowerShell toast, best-effort per OS) and rings the **terminal bell**, plus a one-line stderr alert like `🚫 21:47:49  1 secret (secret) on your clipboard — don't paste that.` It's the doorman that never clocks out. True to the [out-of-scope rules](./PLAN.md#9-out-of-scope), it is **not** a clipboard manager: it stores nothing but an in-memory *hash* of the last value it saw (so it can tell "changed" from "polled again" without ever retaining your clipboard), never phones home, and forgets everything on exit. It's opt-in and stops on `Ctrl-C`; if the host has no clipboard tool at all it fails fast with one clear message instead of looping, and a *transient* read hiccup is logged once (not per tick) while it keeps trying. The polling loop itself is pure and fully unit-tested with a fake clock and clipboard.

**AI-CLI pre-paste hook is in:** the guard now reaches the prompts you fire straight from the terminal into a local model. [`scripts/leakpeek-guard`](./scripts/leakpeek-guard) is a dependency-free POSIX-sh wrapper that frisks a prompt on stdin *before* it reaches `llm`, `aichat`, `ollama run`, or any other stdin-reading AI CLI, and enforces a **block-or-redact policy**: `block` (default) refuses to run the tool and exits `3` when a secret is present, `redact` sends a scrubbed copy instead, `warn` forwards the original but flags it, and `off` is a pass-through escape hatch. Everything after `--` is the command it guards (`… | leakpeek-guard -- ollama run llama3`), so it drops into a shell function in one line. It adds no detection logic of its own — it rides leakpeek's existing `--stdin`/`--fix` contract and inherits `--rules`/`--strategy` — buffers the prompt only in a `umask 077` temp file that's shredded on exit, and never phones home. Ten scenarios are covered by an integration test that drives the real script against a freshly built binary. This is the [Git pre-paste hook for AI CLIs](./PLAN.md#8-backlog--future-features-v02) item from the backlog.

**Scan mode (`leakpeek scan <path>…`) is in:** where the clipboard path frisks the one thing in your hand, `scan` frisks the *folder you're about to zip up and hand to an AI or a vendor*. It walks files and directories (recursively), runs the same detector engine over every text file, and reports findings **grouped per file** with a one-line summary (`🚫 3 secrets across 2 files (17 files scanned)`). Binary files are skipped automatically (NUL-byte / invalid-UTF-8 heuristic), and noisy dependency/VCS dirs (`.git`, `node_modules`, `vendor`, `.venv`, …) are pruned from the walk. It honors your `.leakpeekignore` allowlist and `--ignore` files, the custom `--rules` pack, and the `--strict`/`--chill` sensitivity dials exactly like the clipboard path. `--json` emits a `files[]` array where each element carries the same per-file report schema you already parse; `--quiet` prints only the files that have hits. It exits **3** if any file has a finding, **0** when everything's clean. This is the [`scan <path>` diff/scan mode](./PLAN.md#8-backlog--future-features-v02) item from the backlog.

## Diff mode

`leakpeek --diff` compares the clipboard with the previous `--diff` input and
scans only added/changed lines. `leakpeek --stdin --diff --json < app.log` does
the same for stdin. Unchanged lines (including their accepted findings) are
not scanned; the verdict says **no new secrets**, not that the whole input is
paste-safe. Line/column and byte offsets always reference the full current
input, including Unicode and CRLF line endings.

The first run without a baseline scans everything and seeds the next comparison.
Only `--diff` runs save snapshots; ordinary scans and watch mode store no diff
content. Each successful diff scan replaces the snapshot with the full current
input, even if it is clean. `--no-snapshot` reads an existing baseline but does
not write or refresh it; with no baseline it performs a full, memory-only scan.
`leakpeek --diff-clear` removes the snapshot without reading the clipboard.
Diff mode cannot be combined with `--fix`, `--watch`, `--unredact`, or vault/stats
lifecycle commands. In particular, diff-only redaction could leave old secrets
in a supposedly safe copy; use an ordinary `--fix` scan instead.

Snapshots contain **raw input**, remain local, and are never transmitted.
They live in a per-user directory under the OS temp directory, with owner-only
permissions (directory `0700`, file `0600` on Unix; a protected owner-only ACL
on Windows). Symlinks and unsafe permissions are refused. Snapshots expire
after **15 minutes**; the next read deletes an expired snapshot, warns, and
performs a full scan. Expiry is lazy, not a background cleanup timer; clear the
snapshot explicitly when finished. Removal unlinks the file, not a guaranteed
physical secure erase.

JSON findings (including grouped items) have `newSince: true` in diff mode
(`false` in ordinary scans). Top-level `baselineAgeSeconds` is the baseline's
age at comparison, or `null` when there was no usable baseline (and for ordinary
scans). Clean diff runs exit `0`; new findings exit `3`, as with ordinary scans.
Adjacent changed lines are scanned together, so multiline custom rules can
match within a changed range, but never across an unchanged gap.

## Build & run (from source)

```bash
go build -o leakpeek ./cmd/leakpeek
./leakpeek --version
cat app.log | ./leakpeek --stdin           # scan a pipe, print a report
cat app.log | ./leakpeek --stdin --json    # machine-readable output
./leakpeek --stdin --quiet < app.log; echo "exit=$?"   # silent unless it finds something
cat secrets.env | ./leakpeek --fix > clean.env        # redact a pipe to stdout
./leakpeek --fix                            # redact the clipboard in place
./leakpeek --fix --strategy full           # or: --strategy hash
./leakpeek --fix --annotate                 # append [leakpeek: redacted 2 API keys, 1 email]
./leakpeek --watch                          # stand guard: alert the moment a secret is copied
./leakpeek --watch --interval 500ms        # poll faster (default 800ms, min 100ms)
./leakpeek scan .                            # frisk a whole folder before you share it
./leakpeek scan --json src/ config.env      # per-file findings as JSON
./leakpeek scan --quiet .; echo "exit=$?"  # print only files with hits
```

Example human report on a dirty input:

```
🚫 5 things you'd regret pasting:
   TYPE            COUNT  WHERE      PREVIEW
   aws-access-key      1  line 1:12  AKIA…MPLE
   openai-key          1  line 2:9   sk-proj…CDEF
   email               2  line 3:7   j…@example.com (+1 more)
   ipv4                1  line 4:9   10.x.x.x
🚫 5 secrets across network, pii and secret. Don't paste that.
```

And the same input redacted with `--fix` (shape-preserving), printed to stdout:

```
$ printf 'k=AKIAIOSFODNN7EXAMPLE\nm=jane.doe@corp.internal\nip=10.0.12.34\n' | leakpeek --fix --quiet
k=AKIAREDACTED
m=REDACTED@corp.internal
ip=x.x.x.x
```

### Exit codes

leakpeek's exit code is part of its contract, so CI jobs and shell aliases can branch on it:

- `0` — clean (no findings)
- `1` — an error occurred (couldn't read input, etc.)
- `2` — bad usage (unknown flag)
- `3` — scan completed and **found** something

Run the tests directly:

```bash
go test ./...                  # everything
go test ./internal/detect/...  # just the detector engine
go test ./internal/report/...  # just the reporter
```

Requires Go 1.23+. Clipboard reads use the native tool for your OS
(`pbpaste` on macOS; `wl-paste`/`xclip`/`xsel` on Linux; `Get-Clipboard` on
Windows) and fall back to `--stdin` when none is available.

## Install

### Homebrew (macOS / Linux)

```bash
brew install rwrife/tap/leakpeek
```

### Pre-built binaries

Grab a static binary for your OS/arch from the
[latest release](https://github.com/rwrife/leakpeek/releases/latest)
(macOS, Linux, and Windows; amd64 + arm64), unpack it, and drop `leakpeek`
on your `PATH`. Each release ships a `checksums.txt` so you can verify the
download:

```bash
sha256sum -c checksums.txt --ignore-missing
```

### From source

With Go 1.23+:

```bash
go install github.com/rwrife/leakpeek/cmd/leakpeek@latest
```

That drops a `leakpeek` binary in `$(go env GOPATH)/bin` (add it to your
`PATH`). Or clone and build:

```bash
git clone https://github.com/rwrife/leakpeek && cd leakpeek
go build -o leakpeek ./cmd/leakpeek
```

leakpeek shells out to your OS's native clipboard tool. The binary itself has
no runtime dependencies, but for clipboard read/write (as opposed to
`--stdin`) you'll want one of the platform tools below installed.

### Platform support

| OS | Read | Write | Install the tool |
| --- | --- | --- | --- |
| **macOS** | `pbpaste` | `pbcopy` | built in — nothing to install |
| **Linux (Wayland)** | `wl-paste` | `wl-copy` | `sudo apt install wl-clipboard` (or your distro's package) |
| **Linux (X11)** | `xclip` → `xsel` | `xclip` → `xsel` | `sudo apt install xclip` **or** `sudo apt install xsel` |
| **Windows** | PowerShell `Get-Clipboard` | `clip` | built in — nothing to install |
| **any / headless** | `--stdin` | `--fix` → stdout | no tool needed; pipe text in and out |

On Linux, leakpeek tries the Wayland tool first, then the X11 tools in order,
and uses the first that actually works — so a mixed or headless session
degrades cleanly. If none is installed, pipe instead:

```bash
pbpaste | leakpeek --stdin            # or wl-paste / xclip -o, etc.
cat secrets.env | leakpeek --fix > clean.env
```

## Trust but verify — run `leakpeek verify`

```bash
leakpeek verify
leakpeek verify --json                   # CI-friendly result
leakpeek verify --rules mine.toml        # built-ins plus your rules
```

Verification runs every detector independently against named positive and
negative fixtures, prints a matrix of positives caught/total, false positives,
and PASS/FAIL, then an overall verdict. It exits **0** only when everything
passes, **1** on a missed positive, a false positive, or an operational error,
and **2** on bad usage. The built-in corpus is embedded with `go:embed`: no
network, clipboard, stdin, or external corpus files are needed. Allowlists
and sensitivity overrides are deliberately not applied to this default-pack
self-test. JSON has `schema_version: 1`, `mode: "verify"`, `passed`, and a
`detectors` array with counts, verdicts (`passed`), and named failures; fixture
text is not emitted.

The [bundled corpus](internal/verify/corpus.json) covers all built-ins. Its
documented false-positive traps are: truncated AWS/GitHub/Slack tokens, short
`sk-` strings, ordinary dotted identifiers (not JWTs), public-key and non-PEM
private-looking headers, incomplete email addresses, out-of-range IPv4 octets,
invalid card/IBAN checksums, a Luhn-valid sequence too short to be a card,
unissued/zero SSN groups, unformatted numeric IDs and short phone numbers,
long English word runs, a short base64 English greeting, and low-entropy
mixed-character tokens. These are bounded regression checks, not a guarantee
that all Luhn-valid IDs or all base64-encoded prose will be ignored.
Long base64 tokens that decode to ordinary English prose are ignored when the
decoded text contains no detector finding and the token is not assigned to a
credential-like field. Other base64 blobs remain subject to the entropy check.

### Self-test custom rules

For `--rules mine.toml`, place fixtures in **`mine.toml.fixtures.json`**.
For `--rules ./rules`, place a single **`rules/fixtures.json`** beside the
TOML files, covering every rule loaded from that directory:

```json
[
  {
    "detector": "acme-employee-id",
    "positives": [{"name": "employee ID", "text": "EMP-123456"}],
    "negatives": [{"name": "too short", "text": "EMP-12"}]
  }
]
```

Each detector needs at least one positive and one negative; names must be
unique within that detector and fixture text must be nonempty. Missing
fixtures, unknown detector names/fields, and duplicate detector names
(including collisions with built-ins) are errors rather than untested
passes. A positive passes if that detector finds anything in its text; a
negative passes only if it finds nothing. Fixtures are tested only against
their named detector, so overlap with another detector cannot mask a miss.
Use synthetic examples, not real secrets, in fixture files.

## Custom rules

The built-in pack covers the usual suspects, but your secrets are yours: an
internal hostname scheme, an employee-ID format, a bespoke token prefix. Point
`--rules` at a TOML file (or a directory of `*.toml` files) and leakpeek runs
your detectors next to the built-ins:

```bash
leakpeek --rules ./rules                 # load every *.toml in a directory
cat app.log | leakpeek --stdin --rules acme.toml
leakpeek --fix --rules ./rules           # custom findings get redacted too
```

A rule file is an array of `[[rule]]` tables. Each rule needs a `name` and a
`regex`; `kind` is optional and defaults to `secret`:

```toml
# rules/acme.toml — flag Acme's internal stuff before it hits a chatbot.
[[rule]]
name  = "acme-internal-host"
kind  = "network"                 # secret | private-key | pii | payment | network | entropy
regex = '[a-z0-9-]+\.acme\.internal'   # single-quote literal strings keep backslashes

[[rule]]
name  = "acme-employee-id"        # no kind → defaults to "secret"
regex = 'EMP-[0-9]{6}'
```

Notes:

- `regex` is a Go/[RE2](https://github.com/google/re2/wiki/Syntax) pattern — the
  same engine the built-ins use. Prefer `'single quotes'` so backslashes stay
  literal.
- Custom detectors are appended after the built-ins, so a real AWS key still
  reports as `aws-access-key` rather than a broad custom catch-all; your rules
  claim spans nothing else did.
- A bad `regex`, an unknown `kind`, or a malformed file fails loudly with a
  `file:line` diagnostic (exit `1`) instead of silently skipping the rule.
- In a directory, files are loaded in filename order; `*.local.toml` is honored
  too and is already git-ignored, so you can keep private rules uncommitted.

A starter file lives at [`rules/example.toml`](./rules/example.toml).

## Org rule packs

Share a named, versioned directory with your team instead of passing rule-file
paths around. Packs are entirely **local and offline**: no registry, downloads,
or telemetry. Install them by copying a directory into a pack search root:

```text
<pack-root>/
  acme/
    leakpeek-pack.toml
    hosts.toml
    projects.toml
```

The manifest uses the same single-line quoted-string TOML subset as rule files:

```toml
name = "acme"
version = "1.0.0"
description = "Internal hostnames and project code names" # optional
```

`name` and a non-blank `version` are required (versions are labels, not version
constraints). The name must match the directory name and use only letters,
digits, `.`, `_`, or `-`, excluding `.` and `..`. Each pack must contain at
least one rule; every other `*.toml` file directly inside it is loaded in
filename order, with the usual `[[rule]]` format. Subdirectories are not loaded.

Search roots, **highest priority first**:

1. `$LEAKPEEK_PACKS`, if set: a single directory containing pack directories,
   not a path list or a pack directory itself. Relative paths resolve from cwd.
2. `~/.config/leakpeek/packs/` (also on Windows).
3. `./.leakpeek/packs/` in the current working directory.

The first matching pack directory wins, regardless of version; packs with the
same name are not merged. An invalid higher-priority pack fails explicitly
instead of silently falling back. Missing-pack errors print the searched paths.
`packs list` shows the effective version of each discovered pack, its rule
count and path; `packs show` lists its detector names and kinds.

```bash
# Try the shipped example without installing anything:
export LEAKPEEK_PACKS="$PWD/rules"
leakpeek packs list
leakpeek packs show acme
printf 'db.acme.internal ACME-PROJECT-0042\n' | leakpeek --stdin --rule-pack acme

# Or copy rules/acme to ~/.config/leakpeek/packs/acme.
leakpeek --fix --rule-pack acme --rule-pack infra --rules private.local.toml
leakpeek scan --rule-pack acme src/
```

In PowerShell, use `$env:LEAKPEEK_PACKS = Join-Path $PWD 'rules'`.
`--rule-pack` is repeatable (including `--rule-pack=acme`) and works with
clipboard, stdin, watch, redaction, and file scans. Built-ins keep the existing
equal-span dedupe priority, followed by `--rules`, then packs in flag order.
Repeated pack names are loaded once. Pack findings use the same reporting,
allowlisting, and redaction as all other custom rules. For names starting with
`-`, use the inline `--rule-pack=-name` form.

## Allowlist (`.leakpeekignore`)

leakpeek is a frisker, but some tokens are *known-safe* and firing on them every
paste is noise: public sandbox keys (`pk_test_…`), documented example IPs
(`192.0.2.0/24`), placeholder emails (`user@example.com`). An allowlist lets you
say "yes, I know, shut up about this one" without disabling a whole detector.

Drop a `.leakpeekignore` file in your project. leakpeek discovers it by walking
**up from the current directory** (like `.gitignore`, nearest wins) and also
merges a global file at `$XDG_CONFIG_HOME/leakpeek/ignore` (falling back to
`~/.config/leakpeek/ignore`). The upward walk stops at the repo root so it never
inherits a stranger's config.

```gitignore
# .leakpeekignore — one entry per line. '#' comments and blank lines are ignored.

user@example.com                 # literal: suppress this exact token
203.0.113.5                      # a documented example IP

/^pk_test_[A-Za-z0-9]+$/         # /regex/: suppress any Stripe test key
/^AKIA[0-9A-Z]{16}$/             # …or any AKIA-shaped key you know is a sample
```

Two entry forms:

- **Literal** — an exact token string. A finding whose match equals it verbatim
  is dropped.
- **Regex** — a line wrapped in `/…/` compiles as a Go/[RE2](https://github.com/google/re2/wiki/Syntax)
  pattern and is anchored to the **whole** match, so it can never suppress a mere
  substring of a longer secret (false negatives stay predictable).

Suppression is a pure post-filter: it happens **after** detection and **before**
the report or `--fix`, so an allowlisted token is never counted, never printed,
and never redacted (a `--fix` copy leaves it verbatim). If the *only* findings
were suppressed, leakpeek exits with the clean code, so it still composes in
shell aliases and CI.

```bash
cat .env | leakpeek --stdin                 # auto-discovers .leakpeekignore
leakpeek --ignore ./ci.leakpeekignore       # add an explicit file (repeatable)
leakpeek --no-ignore                        # ignore all discovery for this run
```

- `--ignore <path>` layers an extra ignore file on top of discovery, and is
  repeatable. It's honored even with `--no-ignore` (an explicit path is an
  explicit request).
- `--no-ignore` turns off `.leakpeekignore` / global discovery for the run.
- `--json` output gains a top-level `ignored` count; the human report prints a
  dim `(N suppressed by .leakpeekignore)` footer only when `N > 0`.
- A present-but-malformed ignore file (e.g. a broken regex) fails loudly with a
  `file:line` diagnostic (exit `1`) rather than silently letting a secret
  through.

## Sensitivity levels (`--strict` / `--chill`)

The specific detectors (AWS keys, GitHub PATs, JWTs, private keys, emails, IPs)
are precise and never change — a real `sk-` key is always a real key. But the
generic **high-entropy-token** catch-all is the classic double-edged sword:
crank it up and every base64 blob or git SHA lights up; relax it and you miss
real secrets. Instead of asking you to reason about Shannon bits, leakpeek gives
you two named dials over that one detector:

- **`--strict`** — paranoid. Lower entropy floor + shorter min length: flags
  more generic tokens, tolerates more false positives. Use it *before pasting
  into a public forum*.
- **default** (no flag) — the balanced production tuning. Unchanged behavior.
- **`--chill`** — relaxed. Higher entropy floor + longer min length, and it
  **drops bare internal-IP (IPv4) findings** by default since those are the most
  common low-value hit. Fewer interruptions. Use it for *trusted internal
  chats*.

`--strict` and `--chill` are mutually exclusive (passing both is a usage error,
exit `2`). Only the entropy detector's thresholds move — structured detectors
produce identical findings across all three levels. With `--json`, the active
`profile` (`strict`/`default`/`chill`) is included so scripted runs are
self-describing.

```console
$ printf 'internal box 10.0.4.7\n' | leakpeek --chill; echo exit=$?
✅ Clean. Paste away.
exit=0
$ printf 'internal box 10.0.4.7\n' | leakpeek; echo exit=$?
🚨 1 thing you'd regret. …
exit=3
```

## Local stats / streak (`--stats`)

leakpeek quietly saves your bacon, but you never *see* the score. Turn on the fully-local, **opt-in** counter and the bouncer can occasionally brag:

```console
$ leakpeek --stats
🛡️  leakpeek has stopped 47 leaks (across 210 runs).
📅 This month: 12 leaks stopped.
🔥 Streak: 5 days in a row.
🏷️  Top kinds: secret×31, pii×12, network×4
🗓️  Counting since 2026-07-08.
🔒 Local-only. These numbers live on this machine and are never transmitted.
```

- **Opt-in, always.** Recording is off by default (leakpeek "forgets" by design). Enable it per-run with `--stats-record`, or persistently with `LEAKPEEK_STATS=1` in your environment.
- **Where it lives.** `$XDG_STATE_HOME/leakpeek/stats.json` (falling back to `~/.local/state/leakpeek/stats.json`). Plain JSON: `totalLeaksStopped`, `totalRuns`, `byMonth`, `byKind`, `byDay`, `firstSeen`, `lastLeakAt`.
- **What counts.** A run that stops **≥1 leak** bumps `totalLeaksStopped`, the current month, and each finding *kind* present. A clean run bumps only `totalRuns`. The **streak** is consecutive calendar days with at least one recorded run.
- **Read it.** `leakpeek --stats` prints the human summary; `leakpeek --stats --json` prints the raw object. Both exit `0`.
- **Forget it.** `leakpeek --stats-reset` zeroes the counters (keeping the first-seen date); `leakpeek --stats-clear` deletes the file entirely.
- **Never breaks a scan.** Every write is best-effort: if the state dir is unwritable, recording is silently skipped — a vanity counter is never allowed to change a scan's exit code or block a redaction.
- **Local-only, no network.** No leaderboards, no sync, no telemetry. The numbers never leave your machine.

```bash
printf 'k=AKIAIOSFODNN7EXAMPLE\n' | leakpeek --stdin --stats-record   # count this run
LEAKPEEK_STATS=1 leakpeek --fix                                     # count every run
```

## Reversible redaction (un-redact an AI's reply)

Sometimes you don't just want to *hide* a secret — you want the AI's answer to still make sense when it hands your placeholder back. The `vault` strategy makes redaction reversible:

```bash
# 1) Redact reversibly. Secrets become opaque, restorable placeholders,
#    and the mapping is saved to a private, short-lived session.
leakpeek --fix --strategy vault
#   deploy with AKIAIOSFODNN7EXAMPLE  ->  deploy with [LEAKPEEK:1a5d44a2]

# 2) Paste the redacted text into your AI. It answers, echoing the
#    [LEAKPEEK:...] tokens. Copy its reply, then:
leakpeek --unredact
#   ...connect to [LEAKPEEK:1a5d44a2]  ->  ...connect to AKIAIOSFODNN7EXAMPLE
```

It composes in pipes too:

```bash
printf 'ssh key AKIAIOSFODNN7EXAMPLE\n' | leakpeek --fix --strategy vault --quiet | tee redacted.txt
cat ai_reply.txt | leakpeek --unredact > restored.txt
```

How it stays safe:

- **Local-only, single hop.** The placeholder→secret map is written *only* to an owner-only (`0600`) `session.json` in a private (`0700`) folder under your OS temp dir — the one place it needs to persist so a *later* `--unredact` process can find it. It never phones home.
- **Opaque placeholders.** `[LEAKPEEK:<hex>]` is derived from a hash of the secret, so it reveals nothing; identical secrets share one placeholder so you can still see two spots hold the same value.
- **Tight lifecycle.** Sessions expire after **15 minutes** (an expired one is refused *and deleted* on the next read). `--unredact` **clears the session by default** once it restores — pass `--keep-vault` to un-redact more than once. Wipe it anytime with `leakpeek --vault-clear`.
- **Opt out entirely.** `--fix --strategy vault --no-vault` emits the reversible-shaped placeholders but stores **nothing** on disk (so nothing to reverse later, and nothing to clean up).

## Format-aware redaction (keep the shape, scrub the values)

Structured config is the common case for "paste this into an AI and help me debug it" — and there you want the keys and shape preserved, not a blunt splice. Add `--format-aware` (or `--format`) to `--fix`:

```bash
# JSON: keys and structure preserved, only secret-bearing values redacted,
# and the output is still valid JSON.
$ printf '{"db_password":"AKIAIOSFODNN7EXAMPLE","port":5432}' \
    | leakpeek --fix --format-aware --quiet
{"db_password":"[REDACTED-SECRET]","port":5432}

# .env: KEY= and quotes and trailing comments survive; only the value goes.
$ printf 'export TOKEN="sk-proj-abcdef0123456789abcdef"  # prod\nDEBUG=true\n' \
    | leakpeek --fix --format-aware --quiet
export TOKEN="[REDACTED-SECRET]"  # prod
DEBUG=true

# YAML: indentation and list structure kept.
$ printf 'db:\n  password: AKIAIOSFODNN7EXAMPLE\n  port: 5432\n' \
    | leakpeek --fix --format-aware --quiet
db:
  password: [REDACTED-SECRET]
  port: 5432
```

It only redacts values a detector actually fires inside (so `port: 5432` is left alone), never touches keys (a secret-shaped key stays put), and falls back to normal span-based redaction for plain text or for a secret hiding somewhere the format pass doesn't model (like a comment). It composes with every strategy — `--format-aware --strategy hash` gives you `[SECRET:<8hex>]` inside the preserved structure.

## Guard your AI CLIs (pre-paste hook)

The most dangerous paste isn't into a chat *window* — it's the prompt you fire straight from your terminal into a local model with `llm`, `aichat`, or `ollama run`. `scripts/leakpeek-guard` is a tiny, dependency-free POSIX-sh wrapper that frisks that prompt on its way through and enforces a **block-or-redact policy** before a single byte reaches the model:

```bash
# Everything after `--` is the AI CLI to run; the prompt is piped to its stdin.
echo "why does this fail: $(cat error.log)" | scripts/leakpeek-guard -- llm
pbpaste | scripts/leakpeek-guard --policy redact -- aichat
cat prompt.txt | scripts/leakpeek-guard -- ollama run llama3
```

Pick a policy with `--policy` (or the `LEAKPEEK_POLICY` env var):

| Policy | What it does |
| --- | --- |
| `block` *(default)* | If a secret is found, print the findings and **refuse** to run the AI CLI (exit `3`). Nothing sensitive leaves the box. |
| `redact` | Scrub the secrets and send the AI CLI a **redacted** prompt instead of the original. |
| `warn` | Show what was found but send the **original** prompt through anyway. |
| `off` | Do nothing; pass the prompt straight through. An escape hatch (doesn't even need leakpeek installed). |

Wire it into your shell so guarding is the default, not a thing you remember to do. Drop this in your `.bashrc`/`.zshrc`:

```bash
# Guarded wrappers: block secrets by default, or set LEAKPEEK_POLICY=redact.
ask()  { printf '%s' "$*" | leakpeek-guard -- llm; }              # ask "..."
achat() { leakpeek-guard -- aichat; }                             # pipe or type
oll()  { printf '%s' "$*" | leakpeek-guard -- ollama run llama3; } # oll "..."
```

Under the hood it's just leakpeek's existing stdin contract — `leakpeek --stdin` to detect, `leakpeek --stdin --fix` to get a redacted copy on stdout — so the guard adds no new detection logic and inherits `--rules`, `--strategy`, and every detector you've configured. It buffers the prompt in a `umask 077` temp file that's shredded on exit, stores nothing else, and (like leakpeek) never phones home. Point it at a non-default binary with `--leakpeek /path` or `LEAKPEEK_BIN`; run `scripts/leakpeek-guard --help` for the full flag list.

## Quick idea of the interface (planned)

```bash
leakpeek            # scan clipboard, report findings, non-zero exit on a hit  (live)
cat app.log | leakpeek --stdin    # scan a pipe instead                       (live)
leakpeek --json     # machine-readable output for scripts                     (live)
leakpeek --quiet    # only print on a hit                                     (live)
leakpeek --fix      # put a redacted copy back on the clipboard               (live)
cat x | leakpeek --fix   # ...or print the redacted text to stdout for a pipe (live)
leakpeek --fix --strategy full|hash   # pick a redaction style                (live)
leakpeek --fix --strategy vault   # reversible: swap in restorable placeholders (live)
leakpeek --fix --format-aware   # JSON/YAML/.env: redact values, keep the shape  (live)
leakpeek --unredact   # restore secrets in an AI reply that echoed placeholders (live)
leakpeek --vault-clear   # forget the stored reversible-redaction session       (live)
leakpeek --rules ./rules   # load custom detectors from TOML                  (live)
leakpeek --ignore f.txt   # allowlist known-safe tokens (.leakpeekignore)     (live)
```

Guard a local AI CLI (block or redact secrets before they reach the model):

```bash
echo "$PROMPT" | leakpeek-guard -- llm                 # block on a secret (default)
cat prompt.txt | leakpeek-guard --policy redact -- aichat  # send a scrubbed copy
pbpaste | leakpeek-guard -- ollama run llama3          # works with any stdin-reading CLI
```

## Not a clipboard manager

leakpeek doesn't store your clipboard history. It frisks it once and forgets. One job, done fast.

## License

MIT (see `LICENSE` once added).
