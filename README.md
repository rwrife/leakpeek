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

**M3 (report + exit codes + `--json`) is in:** leakpeek no longer echoes — it now *scans and reports*. It runs the engine over your clipboard (or `--stdin`), prints a grouped findings table (type, count, line/column, masked preview) with a one-line personality verdict, and exits **3** when it finds something (**0** when clean). `--json` emits a versioned, machine-readable document; `--quiet` stays silent on a clean scan (handy for shell aliases). Previews are masked (`AKIA…MPLE`, `sk-proj…CDEF`, `j…@example.com`, `10.x.x.x`) so the report never re-leaks the secret it just caught. Redaction + clipboard write-back (`--fix`) is M4.

## Build & run (from source)

```bash
go build -o leakpeek ./cmd/leakpeek
./leakpeek --version
cat app.log | ./leakpeek --stdin           # scan a pipe, print a report
cat app.log | ./leakpeek --stdin --json    # machine-readable output
./leakpeek --stdin --quiet < app.log; echo "exit=$?"   # silent unless it finds something
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

## Quick idea of the interface (planned)

```bash
leakpeek            # scan clipboard, report findings, non-zero exit on a hit  (live)
cat app.log | leakpeek --stdin    # scan a pipe instead                       (live)
leakpeek --json     # machine-readable output for scripts                     (live)
leakpeek --quiet    # only print on a hit                                     (live)
leakpeek --fix      # put a redacted copy back on the clipboard               (M4)
```

## Not a clipboard manager

leakpeek doesn't store your clipboard history. It frisks it once and forgets. One job, done fast.

## License

MIT (see `LICENSE` once added).
