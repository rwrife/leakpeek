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

**M2 (detector engine) is in:** the `internal/detect` package provides the brains — a `Detector` interface (`Name`, `Kind`, `Find`), a Shannon-entropy helper, overlapping-span de-duplication, and the v0.1 core secret pack: AWS access keys, OpenAI `sk-` keys, GitHub PATs, Slack tokens, JWTs, private-key headers, emails, IPv4 addresses, and a generic high-entropy catch-all. Specific detectors win over the catch-all during dedupe.

**M3 (report + exit codes + `--json`) is in:** leakpeek no longer echoes — it now *scans and reports*. It runs the engine over your clipboard (or `--stdin`), prints a grouped findings table (type, count, line/column, masked preview) with a one-line personality verdict, and exits **3** when it finds something (**0** when clean). `--json` emits a versioned, machine-readable document; `--quiet` stays silent on a clean scan (handy for shell aliases). Previews are masked (`AKIA…MPLE`, `sk-proj…CDEF`, `j…@example.com`, `10.x.x.x`) so the report never re-leaks the secret it just caught.

**M4 (`--fix` redaction + clipboard write-back) is in:** leakpeek can now *fix* what it finds. `leakpeek --fix` redacts every finding and hands back a paste-safe copy — written straight back to the **clipboard**, or printed to **stdout** when the input came from a pipe (`cat secrets.env | leakpeek --fix > clean.env`). The report goes to stderr so it never contaminates piped output. Three strategies via `--strategy`:

- `shape` (default) — keeps a recognizable scheme hint so the AI still understands the token's *shape*: `sk-proj-REDACTED`, `AKIAREDACTED`, `ghp_REDACTED`, `REDACTED@corp.internal`, `x.x.x.x`.
- `full` — replaces the whole match with `[REDACTED-<KIND>]`, revealing nothing, not even the scheme.
- `hash` — replaces it with `[<KIND>:<8hex>]`, a stable, **non-reversible** fingerprint so you can see two redactions point at the *same* secret without exposing it.

The guarantee: for every strategy and every detector, the redacted output contains **no original secret material** (verified per-detector in the test suite). On a clean scan, `--fix` leaves the clipboard untouched and passes piped input through byte-for-byte.

**Reversible redaction vault is in:** the fourth strategy, `--strategy vault`, closes the loop with the AI. Instead of destroying each secret it swaps in an opaque, **reversible** placeholder — `[LEAKPEEK:1a5d44a2]` — and remembers the mapping in a short-lived, owner-only (`0600`) session file under your temp dir. When the AI's reply echoes those placeholders back at you, `leakpeek --unredact` reads it (clipboard or pipe) and splices your real values back in. Identical secrets collapse to one placeholder (so you can see two spots hold the same value) and the placeholder itself leaks nothing — it's derived from a hash, not the secret. Lifecycle is deliberately tight so nothing lingers: sessions carry a **15-minute TTL** (an expired one is refused *and wiped* on the next read), `--unredact` **clears the session by default** once it restores (pass `--keep-vault` to reuse it), `--vault-clear` wipes it on demand, and `--no-vault` redacts reversibly-shaped tokens while storing nothing at all. It never leaves your machine — the map touches disk only for this one local hop between redact and un-redact. This is the [Reversible redaction vault](./PLAN.md#8-backlog--future-features-v02) from the backlog.

**M6 (custom rules + release) is here:** you can now teach leakpeek your own secrets. `--rules <path>` loads extra detectors from a TOML rule file — or a whole directory of `*.toml` files — and runs them **alongside** the built-in pack. A rule is the same `{name, kind, regex}` triple a built-in is, so custom detectors report, group, and redact exactly like the core ones, and built-ins keep priority during de-duplication. This is the extensibility hook from PLAN.md §6. Release plumbing is wired too: [goreleaser](.goreleaser.yaml) cross-compiles static binaries for macOS/Linux/Windows (amd64 + arm64) and a [release workflow](.github/workflows/release.yml) publishes them — plus a Homebrew formula — on every `v*.*.*` tag. See [Install](#install).

**Format-aware redaction is in:** paste a `.env`, a JSON blob, or some YAML and you usually want the *shape* back — the keys, the nesting, the punctuation — with only the **values** scrubbed. `leakpeek --fix --format-aware` (alias `--format`) does exactly that: it sniffs the format, then redacts the values that carry a secret while leaving keys and structure byte-for-byte intact, so the AI still sees `"database_url": "[REDACTED-SECRET]"` instead of a hole where the structure used to be. It's **finding-driven**, not key-name-guessing: a value is only touched when a real detector fires inside it, so innocuous config (`"port": 5432`) is left exactly as written and a secret-shaped *key* (an email used as a JSON key) is never redacted — we redact values, not keys. JSON output stays valid JSON (quotes kept around the placeholder); quoted `.env` values keep their quotes and any trailing `# comment`; YAML keeps its indentation and list structure. Anything the format pass doesn't model — a secret sitting in a comment, or text that isn't structured at all — falls back to the ordinary span-based redaction, so nothing sensitive is ever left behind. Works with every strategy (`shape`/`full`/`hash`). This is the [Format-aware redaction](./PLAN.md#8-backlog--future-features-v02) item from the backlog.

**M5 (cross-platform clipboard hardening) is in:** the clipboard layer now degrades gracefully everywhere a paste happens. Each OS has an ordered list of adapters, and leakpeek walks it — skipping tools that aren't installed **and falling through to the next tool when one is installed but fails at runtime**. So a Linux box with `wl-clipboard` installed but no Wayland compositor running still succeeds via `xclip`/`xsel`; an *empty* Wayland clipboard (where `wl-paste` exits non-zero) reads as empty text instead of an error. When nothing on the host can serve the request you get one clear, friendly message: if no tool is installed it wraps a recognizable sentinel and points you at `--stdin`; if tools were present but all failed it lists each tool and why it broke. See the [platform support matrix](#platform-support) below.

**Watch mode (`--watch`) is in:** leakpeek can now stand guard *continuously*. `leakpeek --watch` stays resident, taps the clipboard on a debounced interval (`--interval`, default `800ms`), and the instant a secret lands on it — before you ever reach the prompt box — it raises a **desktop notification** (`notify-send` / `osascript` / a PowerShell toast, best-effort per OS) and rings the **terminal bell**, plus a one-line stderr alert like `🚫 21:47:49  1 secret (secret) on your clipboard — don't paste that.` It's the doorman that never clocks out. True to the [out-of-scope rules](./PLAN.md#9-out-of-scope), it is **not** a clipboard manager: it stores nothing but an in-memory *hash* of the last value it saw (so it can tell "changed" from "polled again" without ever retaining your clipboard), never phones home, and forgets everything on exit. It's opt-in and stops on `Ctrl-C`; if the host has no clipboard tool at all it fails fast with one clear message instead of looping, and a *transient* read hiccup is logged once (not per tick) while it keeps trying. The polling loop itself is pure and fully unit-tested with a fake clock and clipboard.

**AI-CLI pre-paste hook is in:** the guard now reaches the prompts you fire straight from the terminal into a local model. [`scripts/leakpeek-guard`](./scripts/leakpeek-guard) is a dependency-free POSIX-sh wrapper that frisks a prompt on stdin *before* it reaches `llm`, `aichat`, `ollama run`, or any other stdin-reading AI CLI, and enforces a **block-or-redact policy**: `block` (default) refuses to run the tool and exits `3` when a secret is present, `redact` sends a scrubbed copy instead, `warn` forwards the original but flags it, and `off` is a pass-through escape hatch. Everything after `--` is the command it guards (`… | leakpeek-guard -- ollama run llama3`), so it drops into a shell function in one line. It adds no detection logic of its own — it rides leakpeek's existing `--stdin`/`--fix` contract and inherits `--rules`/`--strategy` — buffers the prompt only in a `umask 077` temp file that's shredded on exit, and never phones home. Ten scenarios are covered by an integration test that drives the real script against a freshly built binary. This is the [Git pre-paste hook for AI CLIs](./PLAN.md#8-backlog--future-features-v02) item from the backlog.

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
./leakpeek --watch                          # stand guard: alert the moment a secret is copied
./leakpeek --watch --interval 500ms        # poll faster (default 800ms, min 100ms)
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
kind  = "network"                 # secret | private-key | pii | network | entropy
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
