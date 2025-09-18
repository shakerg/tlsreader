# TLS Inspector

TLS Inspector is a Node.js + OpenSSL diagnostic tool that enumerates a host's TLS protocol support and cipher suite behavior (TLS 1.0 → 1.3) with a web UI and JSON API. It performs deliberate per‑cipher handshakes (including a TLS 1.3 elimination scan) to distinguish between: genuinely unsupported ciphers, server preference ordering, and protocol disablement. Cipher strength and protocol security posture are visually classified.

## Key Features

* Protocol discovery (TLS 1.0–1.3) with strict legacy validation (prevents false positives for disabled TLS 1.0 / 1.1).
* Per‑cipher single‑suite negotiation attempts (TLS 1.2 & TLS 1.3) using `openssl s_client`.
* TLS 1.3 elimination scan: iterative multi‑suite offering to surface all supported TLS 1.3 ciphers even when the server always picks a preferred one.
* Negotiated cipher capture from both the initial Node TLS handshake and version‑constrained OpenSSL probes.
* Cipher strength heuristic (strong / moderate / weak / unknown) with UI coloring.
* Distinct statuses: `Supported`, `Not Supported`, `Not Tested`, `Not Negotiated`, `Timeout`.
* Accurate legacy protocol suppression (e.g. GitHub correctly flagged as not supporting TLS 1.0 / 1.1).
* Dockerized runtime (Debian + OpenSSL 3.x) ensuring TLS 1.3 suite availability.

## Project Structure

| Path | Purpose |
|------|---------|
| `server.js` | Express server & `/results` endpoint |
| `tlsreader.js` | Core scanning/orchestration logic (handshakes, elimination scan, parsing) |
| `public/` | Static UI (HTML/CSS/JS) rendering summary + per‑version cipher tables |
| `Dockerfile` | Container build (Node 22 bookworm, OpenSSL 3.x) |

## Prerequisites (Local, Non‑Docker)

* Node.js 18+ (project uses Node 22 in container).
* OpenSSL 1.1.1+ (OpenSSL 3.x recommended for full TLS 1.3 suite names).

## Quick Start (Local)

```bash
git clone https://github.com/yourusername/tls-inspector.git
cd tls-inspector
npm install
node server.js
# Open http://localhost:3000
```

## Quick Start (Docker)

```bash
docker build -t tlsinspector .
docker run --rm -p 3000:3000 tlsinspector
# Optional debug logging
docker run --rm -e DEBUG_TLS=1 -p 3000:3000 tlsinspector
```

## Using the Web UI
1. Enter a hostname (SNI is applied automatically).
2. Press Run. The UI displays:
   * Preferred protocol & negotiated cipher.
   * Protocol cards (status + security classification: Excellent / Good / Warning / Neutral / Poor).
   * Per‑version cipher tables (Status, Strength, Details).

## JSON API

Endpoint:
```
GET /results?hostname=<host>
```

Example (abridged):
```json
{
  "hostname": "github.com",
  "preferredProtocol": "TLS 1.3",
  "preferredCipher": { "name": "TLS_AES_128_GCM_SHA256", "standardName": "TLS_AES_128_GCM_SHA256" },
  "tlsVersions": {
    "TLS 1.2": {
      "supported": true,
      "ciphers": [
        { "cipher": "ECDHE-RSA-AES128-GCM-SHA256", "status": "Supported", "details": "Supported", "strength": "strong" },
        { "cipher": "AES128-SHA", "status": "Not Supported", "details": "Handshake failure (no cipher)", "strength": "weak" }
      ],
      "negotiatedCipher": "ECDHE-RSA-AES128-GCM-SHA256"
    },
    "TLS 1.3": {
      "supported": true,
      "ciphers": [
        { "cipher": "TLS_AES_128_GCM_SHA256", "status": "Supported", "details": "Negotiated (initial handshake)", "strength": "strong" },
        { "cipher": "TLS_AES_256_GCM_SHA384", "status": "Supported", "details": "Supported (elimination scan)", "strength": "strong" },
        { "cipher": "TLS_CHACHA20_POLY1305_SHA256", "status": "Supported", "details": "Supported (elimination scan)", "strength": "strong" }
      ],
      "negotiatedCipher": "TLS_AES_128_GCM_SHA256"
    },
    "TLS 1.0": { "supported": false, "ciphers": [ ... ], "negotiatedCipher": null }
  }
}
```

### Field Semantics
| Field | Meaning |
|-------|---------|
| `preferredProtocol` | Protocol version from initial unconstrained Node TLS handshake |
| `preferredCipher` | Cipher from that same handshake (Node’s `getCipher()`) |
| `tlsVersions[ver].supported` | True if at least one successful handshake for that exact version |
| `tlsVersions[ver].negotiatedCipher` | Cipher seen when probing the version directly (if known) |
| `ciphers[].status` | Result of forced single-cipher attempt (or elimination upgrade) |
| `ciphers[].details` | Context: negotiation path, failure reason, elimination note |
| `ciphers[].strength` | Heuristic (strong/moderate/weak/unknown) based on name patterns |

### Status Values
| Status | Description |
|--------|-------------|
| `Supported` | Cipher handshake succeeded (direct or inferred in TLS 1.3 elimination) |
| `Not Supported` | Handshake failed / rejected / wrong protocol / no shared cipher |
| `Not Negotiated` | Server always preferred another TLS 1.3 suite (rare if elimination disabled) |
| `Not Tested` | Skipped (e.g., client OpenSSL lacks suite) |
| `Timeout` | External process or network timeout |

## Strength Heuristic (Simplified)
* strong: ECDHE + (GCM / CHACHA20 / TLS_AES / POLY1305) or TLS 1.3 suites.
* weak: Legacy SHA1 HMAC suites (e.g. `AES128-SHA`, `AES256-SHA`), 3DES, RC4, NULL.
* moderate: Anything not matched as strong or weak.

## Design Notes
* Node’s built‑in TLS gives the real preferred protocol/cipher quickly.
* OpenSSL subprocesses provide precise per‑cipher negotiation control.
* TLS 1.3 elimination scan avoids false negatives when a server always picks its top suite.
* Legacy version validation rejects misleading OpenSSL output that can show a placeholder `Protocol: TLSv1.3` with `(NONE)` cipher when forcing older versions.

## Environment Variables
| Variable | Effect |
|----------|--------|
| `DEBUG_TLS=1` | Enables verbose command + parse logging in the container / process |

## Known Limitations / Future Enhancements
* Strength classification is heuristic; could be replaced with a curated registry.
* Does not currently perform certificate chain validation reporting beyond basic capture.
* No parallelization yet; scans are sequential to minimize side effects (session reuse).
* Elimination scan limited to standard three TLS 1.3 suites; custom deployments with GREASE or future suites would need list expansion.

## License
MIT (adjust if different in repository licensing).

## Contributing
PRs welcome: raise issues for feature requests (e.g., certificate transparency info, HTTP/2 ALPN display, JA3 fingerprinting).

