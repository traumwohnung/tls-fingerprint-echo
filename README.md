# tls-fingerprint-echo

An HTTPS server that reads the TLS fingerprint from each incoming connection and returns it as JSON — along with a bot/spoof detection verdict and matching [httpcloak](https://github.com/sardanioss/httpcloak) presets.

## What it returns

```json
{
  "remote_addr": "[::1]:52924",
  "user_agent": "Mozilla/5.0 (Macintosh; ...) Chrome/146.0.0.0 Safari/537.36",
  "fingerprint": {
    "ja3_hash": "2b13deabd57ec8def529b9955a89a166",
    "ja3_raw": "771,4865-4866-4867-...",
    "ja4": "t13d1516h2_8daaf6152771_d8a2da3f94cd"
  },
  "verdict": {
    "level": "consistent",
    "score": 1.0,
    "reasons": ["exact match between UA and TLS fingerprint"],
    "ua_matches": ["Chrome 131"],
    "fingerprint_matches": ["Chrome 131"]
  },
  "httpcloak_preset_matches": [
    { "name": "chrome-latest", "user_agent": "Mozilla/5.0 ..." },
    { "name": "chrome-146-windows", "user_agent": "Mozilla/5.0 ..." }
  ]
}
```

### Fields

| Field | Description |
|---|---|
| `fingerprint.ja3_hash` | MD5 of the JA3 string |
| `fingerprint.ja3_raw` | Raw JA3 string (`version,ciphers,extensions,curves,point_formats`) |
| `fingerprint.ja4` | [JA4](https://github.com/FoxIO-LLC/ja4) fingerprint |
| `verdict.level` | `consistent` · `suspicious` · `mismatch` · `unknown` |
| `verdict.score` | 0.0 (definite mismatch) → 1.0 (perfect match) |
| `verdict.ua_matches` | DB entries matching the User-Agent |
| `verdict.fingerprint_matches` | DB entries matching the TLS fingerprint |
| `httpcloak_preset_matches` | httpcloak presets whose TLS family matches the fingerprint |

The verdict is computed by [helloprint](https://github.com/Easonliuliang/helloprint), which cross-references the JA3/JA4 fingerprint against its database of known clients and compares the result against the declared User-Agent.

## How it works

The server intercepts each raw TCP connection before the TLS handshake, reads the ClientHello to extract the JA3/JA4 fingerprints, then replays the bytes so the TLS handshake completes normally. Fingerprints are passed to HTTP handlers via the request context using [psanford/tlsfingerprint](https://github.com/psanford/tlsfingerprint).

## Running

```bash
go run ./cmd/tls-fingerprint-echo
# or
go build -o tls-fingerprint-echo ./cmd/tls-fingerprint-echo && ./tls-fingerprint-echo
```

A self-signed certificate is generated in memory at startup — no cert files needed.

### Configuration

| Variable | Default | Description |
|---|---|---|
| `PORT` | `8443` | Port to listen on |

## Testing

```bash
# quick check
curl -sk https://localhost:8443/ | jq .

# e2e tests (uses httpcloak presets as real TLS clients)
go test -v ./e2e/
```

## Project layout

```
cmd/tls-fingerprint-echo/   entry point
tls-fingerprint-echo/       core library (package echo)
  cert.go                   self-signed TLS certificate generation
  config.go                 environment variable loading
  fingerprint.go            JA3/JA4 extraction, verdict, HTTP handler
  presets.go                httpcloak preset matching
e2e/                        end-to-end tests
```

## Dependencies

| Library | Role |
|---|---|
| [psanford/tlsfingerprint](https://github.com/psanford/tlsfingerprint) | ClientHello interception, JA3/JA4 computation |
| [Easonliuliang/helloprint](https://github.com/Easonliuliang/helloprint) | UA vs fingerprint consistency verdict |
| [sardanioss/httpcloak](https://github.com/sardanioss/httpcloak) | Browser TLS presets for matching and e2e testing |
