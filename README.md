# leakpeek 🕵️

**A paranoid bouncer for your clipboard.** It frisks your text for API keys, secrets, PII, and internal hostnames *right before* you paste it into an AI chat — then hands you a redacted copy. Local-only. No servers. No telemetry.

```
$ leakpeek
🚫 3 things you'd regret pasting:
   • aws-access-key   line 4   AKIA…REDACTED
   • openai-key       line 9   sk-…REDACTED
   • email            line 12  j…@example.com
A redacted copy is on your clipboard. You're welcome.
```

## Why

You paste stack traces, configs, and logs into ChatGPT all day. Sometimes they carry an API key, a customer email, or your `db-prod-01.corp.internal` hostname. Repo secret scanners never see that moment. leakpeek does — it scans the thing in your hand, one second before it leaves.

## Status

🚧 Early. See [`PLAN.md`](./PLAN.md) for the roadmap and milestones. v0.1 is regex + entropy, pure Go, single static binary.

**M1 (scaffold) is in:** `leakpeek` builds as a static binary, prints `--version`, and reads your clipboard (or `--stdin`) and echoes it back unchanged. CI builds + vets + tests on macOS, Linux, and Windows.

**M2 (detector engine) is in:** the `internal/detect` package now provides the brains — a `Detector` interface (`Name`, `Kind`, `Find`), a Shannon-entropy helper, overlapping-span de-duplication, and the v0.1 core secret pack: AWS access keys, OpenAI `sk-` keys, GitHub PATs, Slack tokens, JWTs, private-key headers, emails, IPv4 addresses, and a generic high-entropy catch-all. Specific detectors win over the catch-all during dedupe. Fixture-based unit tests cover positive and negative cases per detector. Wiring this into the CLI's output (a findings report + exit codes) is M3 — for now the binary still echoes its input.

## Build & run (from source)

```bash
go build -o leakpeek ./cmd/leakpeek
./leakpeek --version
cat app.log | ./leakpeek --stdin    # echoes input (M1); report wiring lands in M3
```

Run the detector engine's tests directly:

```bash
go test ./internal/detect/...
```

Requires Go 1.23+. Clipboard reads use the native tool for your OS
(`pbpaste` on macOS; `wl-paste`/`xclip`/`xsel` on Linux; `Get-Clipboard` on
Windows) and fall back to `--stdin` when none is available.

## Quick idea of the interface (planned)

```bash
leakpeek            # scan clipboard, report findings, non-zero exit on a hit
leakpeek --fix      # put a redacted copy back on the clipboard
cat app.log | leakpeek --stdin    # scan a pipe instead
leakpeek --json     # machine-readable output for scripts
```

## Not a clipboard manager

leakpeek doesn't store your clipboard history. It frisks it once and forgets. One job, done fast.

## License

MIT (see `LICENSE` once added).
