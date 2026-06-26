# leakpeek — PLAN.md

> A paranoid bouncer for your clipboard. It checks your ID before you paste it into an AI chat.

## 1. Pitch

You're about to paste a stack trace into ChatGPT. It has an API key in it. And your internal hostname. And a customer's email. **leakpeek** is a tiny, local-only CLI that reads your clipboard, sniffs out secrets / API keys / PII / internal infra, shows you exactly what it found, and hands you back a redacted version you can safely paste. No servers, no telemetry, no cloud — just a grumpy doorman standing between your clipboard and the prompt box.

## 2. Trend inspiration

What I saw on the web (June 2026) that pushed this:

- **"Show HN: Local personal data redaction for any AI tools"** — a desktop app that detects and redacts PII *locally* before any text hits a server, with rule-based + model-based filtering. The pain is real and current: people paste sensitive text into LLMs constantly. <https://news.ycombinator.com/item?id=48579589>
- **"Show HN: Desktop Agent Center — Local AI Automation via Hotkeys"** — bridging desktop clipboard/workflow into AI web UIs (ChatGPT/Gemini/Perplexity). Confirms the "clipboard → AI chat" path is where people live now. <https://news.ycombinator.com/item?id=48047444>
- **MacBar / ScreenSnagger / "screenshot to clipboard" menu-bar apps** — the whole 2026 macOS utility scene is clipboard-and-OCR obsessed, but all of it is *capture/manage*, none of it is *guard before paste*. <https://macbar.app/>
- **"Data Privacy in 2026: Why Local-First Software Is Gaining Momentum"** and SitePoint's *Definitive Guide to Local-First AI* — local-first / on-device inference is THE dominant privacy narrative this year. <https://locark.com/data-privacy-2026-local-first-software/>

The convergence: everyone is pasting into AI, everyone wants local-first privacy, and the existing redaction tools are heavyweight GUIs. There's room for a 5-second, terminal-native gut-check.

## 3. Why it's different

Explicit contrast with things that look similar:

- **vs. the Show HN PII-redaction desktop app** — that's a full GUI app with model-based redaction. leakpeek is a single binary you run from a terminal in under a second. No window, no model download required for v0.1 (pure regex/entropy). Friction is the whole point: low friction = people actually use it.
- **vs. clipboard managers (MacBar, Maccy, CopyQ)** — those *store and recall* clipboard history. leakpeek doesn't want to remember your clipboard; it wants to *frisk it once and let it go*. Opposite job.
- **vs. git secret scanners (gitleaks, trufflehog) and my own `canary-cage` / `skill-sniffer`** — those scan *files/repos at rest* or defend against injection. leakpeek scans the *thing in your hand right before it leaves*, targeting the human-pastes-into-chatbox gap that repo scanners never see.
- **vs. enterprise DLP** — DLP is server-side, policy-heavy, and hates you. leakpeek is a personal, opt-in, offline doorman with jokes.

The fresh angle: **the moment of paste**, not the repo, not the history, not the server. And it's small enough to live in your shell aliases.

## 4. MVP scope (v0.1)

The smallest useful thing:

- `leakpeek` (no args) → reads current clipboard, scans it, prints a findings report (type, count, line/offset, masked preview), exits non-zero if anything found.
- Built-in detector pack: AWS keys, generic high-entropy tokens, OpenAI/`sk-` keys, GitHub PATs, Slack tokens, private-key headers, JWTs, emails, IPv4, and a few "internal hostname" heuristics (`*.internal`, `*.corp`, `*.local`).
- `leakpeek --fix` → writes a redacted copy back to the clipboard (`sk-…REDACTED`), preserving structure so the AI still understands the shape.
- `leakpeek --stdin` / pipe support → `cat file | leakpeek` for non-clipboard use.
- `--json` output for scripting; `--quiet` to only print on a hit.
- Cross-platform clipboard read/write (macOS `pbcopy/pbpaste`, Linux `wl-clipboard`/`xclip`, Windows `clip`/PowerShell) with graceful fallback to stdin.
- Personality: a one-line verdict ("🚫 3 things you'd regret. Redacted copy is on your clipboard." / "✅ Clean. Paste away.").

## 5. Tech stack

Boring, fast, single-binary:

- **Go.** Compiles to a static binary per OS (no runtime to install — critical for a "just run it" utility), great regex stdlib, trivial clipboard shelling, fast cold start. The cold-start speed matters because this runs on every paste.
- **Standard library + a tiny clipboard helper** (shell out to native tools, or `atotto/clipboard` as the single dependency). Detectors are plain Go structs + `regexp` + a Shannon-entropy helper — no ML in v0.1.
- **Cobra** only if the flag surface grows; v0.1 can use stdlib `flag` to stay lean.
- **goreleaser** for cross-compiled release binaries + Homebrew tap later.

Why not Rust/Node? Rust is fine but Go's clipboard story and build simplicity win for a tiny tool; Node would need a runtime and starts slower — wrong tradeoff for a per-paste guard.

## 6. Architecture

```
cmd/leakpeek/main.go      → flag parsing, wiring, exit codes
internal/clipboard/       → read()/write(), per-OS adapters + stdin fallback
internal/detect/          → Detector interface, built-in detector pack, entropy helper
internal/redact/          → masking strategies (keep shape, full mask, hash-tag)
internal/report/          → human report + --json renderer + personality lines
rules/                    → optional user-supplied custom rules (TOML/regex), loaded at runtime
```

Key idea: a `Detector` is `{ Name, Kind, Find(text) []Finding }`. The engine runs all detectors, dedupes overlapping spans, and feeds findings to either the reporter or the redactor. Adding a new secret type = adding one detector. That's the extensibility hook.

## 7. Milestones

1. **M1 — scaffold + hello-world.** Go module, `cmd/leakpeek` that prints version and echoes clipboard contents (or stdin). CI build on 3 OSes. Nothing smart yet.
2. **M2 — detector engine + core pack.** `Detector` interface, entropy helper, and the v0.1 detector set (AWS, `sk-`, GitHub PAT, JWT, private key, email, IPv4). Unit tests with fixture strings.
3. **M3 — human report + exit codes + `--json`.** Pretty findings table, masked previews, personality verdicts, scriptable JSON, non-zero exit on hit.
4. **M4 — `--fix` redaction + clipboard write-back.** Shape-preserving masking, write redacted text to clipboard, `--stdin`/pipe redaction to stdout.
5. **M5 — cross-platform clipboard hardening.** Robust macOS/Linux(Wayland+X11)/Windows adapters with graceful fallback + clear errors; README install matrix.
6. **M6 — custom rules + release.** Load user rules from `rules/*.toml`, `--rules` flag, goreleaser cross-builds, tagged v0.1.0 with binaries + Homebrew formula.

## 8. Backlog / future features (v0.2+)

1. **Watch mode** (`leakpeek --watch`) — daemon that taps the clipboard and toasts/bells the instant a secret lands on it.
2. **Allowlist / ignore** — per-project `.leakpeekignore` for known-safe tokens (e.g., public sandbox keys).
3. **Entropy tuning profiles** — `--strict` / `--chill` presets for false-positive tolerance.
4. **Named-entity PII** (names, phones, addresses) via an optional local model plugin — keeps core regex-only.
5. **Git pre-paste hook for AI CLIs** — wrapper that pipes prompts through leakpeek before they reach `llm`, `aichat`, `ollama run`, etc.
6. **Reversible redaction vault** — map masked tokens to originals locally so you can un-redact an AI's reply.
7. **Format-aware redaction** — detect JSON/YAML/`.env` and redact values, not keys.
8. **Editor plugins** — VS Code / Neovim "scan selection before copy" command.
9. **Org rule packs** — shareable TOML rule bundles (e.g., "Acme internal hostnames").
10. **Stats / streak** — "leakpeek has stopped 47 leaks this month" (fully local).
11. **Screenshot/OCR mode** — scan an image on the clipboard for visible secrets before you share it.
12. **Shell hook** — auto-run on `pbcopy`/`wl-copy` via function override, opt-in.

## 9. Out of scope

Things we are deliberately NOT building:

- **A cloud service, account, or telemetry of any kind.** It never phones home. Period.
- **Enterprise DLP / policy enforcement / blocking the OS clipboard.** leakpeek advises; it doesn't police your machine.
- **A GUI / menu-bar app** in the core repo (a thin wrapper could come later, but the core is CLI).
- **Bundled large ML models** in v0.1 — regex/entropy first; models are an optional plugin, never a dependency.
- **Decrypting or validating found secrets** — we flag shapes, we don't test keys against live services.
- **Being a clipboard *manager*** — no history, no storage, no recall. One frisk, then it forgets.
