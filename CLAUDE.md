# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What this is

A server-rendered admin web app (Express + EJS) for issuing/revoking mTLS
client certificates. No database — all metadata is YAML under `data/`, all
key material under `pki/`. Runs as a single Docker container. Full
architectural rationale and the security model are documented in
`README.md`; this file focuses on things you need to know before editing
code that aren't obvious from any single file.

## Commands

```bash
npm install          # install deps (argon2 is a native addon, needs a C toolchain if no prebuilt binary)
npm start             # node src/server.js
node cli.js unlock-admin   # reset a locked-out admin account (locked=false, failedAttempts=0)

docker build -t mtls-certificate-manager .
docker compose up -d --build
```

There is no lint config and no automated test suite in this repo. Verify
changes by running the app locally against a scratch data/pki dir and
exercising routes with curl (or a browser), and cross-check any crypto
output with `openssl` (`openssl x509 -text`, `openssl crl -text`, `openssl
pkcs12 -info`) — that's how the current code was validated during
development, since node-forge's output can't be trusted to be correct
just because it doesn't throw.

Useful env vars for local runs (see README for the full table):
`DATA_DIR`, `PKI_DIR` (default to `./data`, `./pki`), `PORT`.

## Architecture

### Layers

- `src/routes/*.js` — thin Express handlers: auth checks, CSRF check, call a
  service, render/redirect.
- `src/services/*.js` — all actual logic. `pki.js` is pure crypto (no
  filesystem access); `pkiStore.js` is the only place that touches files
  under `pki/` and is what routes call; `*Store.js` (`adminStore`,
  `userStore`, `revokedStore`, `configStore`) each own one YAML file under
  `data/`.
- `src/views/*.ejs` — no client framework. Any new interactive behavior
  goes in `src/public/js/app.js` via `data-*` attributes, **not** inline
  `onclick`/`onsubmit`. Helmet's default CSP sets `script-src-attr 'none'`,
  which silently no-ops inline event handler attributes (this already bit
  the deactivate-confirmation dialog once — see git history).

### The password does double duty — this is the load-bearing fact of the whole app

There is one admin password. It is used for two independent things, and
both live in `data/admin.yml`:

1. An Argon2id hash (`admin.passwordHash`) for login verification —
   `adminStore.verifyLogin` / `verifyPasswordOnly`.
2. A separate Argon2id key derivation (fixed params in
   `crypto.js:KDF_PARAMS`, salt in `admin.kdfSalt`) that produces the
   AES-256-GCM key protecting `pki/ca.key.enc` and every issued
   `pki/certs/<user-id>/<serial>.key.enc`.

**`KDF_PARAMS` must never change** once any key file has been encrypted
under it — that would silently make every existing encrypted private key
undecryptable (there's no way to detect this except a `decryptBuffer` auth
failure at read time). If a KDF cost bump is ever needed, it has to be a
migration (decrypt-all-with-old-params, re-encrypt-with-new-params), not a
constant tweak.

The derived key is never cached anywhere (not in the session, not on
`req`). Every operation that needs it (`issueCertificateForUser`,
`readCertAndKey`, `exportCrl`, CA init) takes the plaintext password as a
parameter, derives the key inline, uses it, and calls `key.fill(0)` in a
`finally` block before returning. This is why every sensitive route in
`routes/{users,crl,share}.js` is a GET (render a password-prompt form) +
POST (verify password, do the crypto, discard the key) pair instead of a
single action — there is intentionally no "unlocked session" state.

### No CRL API in node-forge

`node-forge` can build X.509 certs, CSRs, and PKCS#12, but has **no CRL
support at all**. `pki.js:buildCrl` hand-assembles an RFC 5280
`CertificateList` from forge's low-level `asn1.create(...)` primitives
(the same primitives forge's own `x509.js` uses internally for
certificates — see the comment block above `buildCrl`). If you touch this
function, re-verify the output with
`openssl crl -in crl.pem -CAfile pki/ca.crt -noout -text` — a subtly wrong
ASN.1 structure will often still base64-encode and "work" without any JS
exception.

Key/cert type choice: CA is RSA-4096, issued leaf certs are RSA-2048 (not
ECDSA) — forge's cert/PKCS#12 code path is mature for RSA and thin for
ECDSA, so this isn't a security-driven choice, it's a "match the library"
choice. Don't switch to ECDSA without re-validating the whole forge
pipeline (cert issuance, PKCS#12 export, and the hand-rolled CRL signing)
against OpenSSL again.

### YAML storage pattern

`services/yamlStore.js` is the only thing that touches disk for `data/*`.
It maintains an in-process per-file-path async queue (`enqueue`) so
concurrent request handlers can't interleave a read-modify-write on the
same YAML file, and writes go through a temp-file + `rename` for atomicity.
This is single-process-safe only — there is no cross-process locking,
which is fine because the app is designed to run as exactly one container.
Every `*Store.js` module is a thin domain wrapper around
`readYaml`/`writeYaml`/`updateYaml`; add new persisted fields by extending
one of those, not by adding new ad-hoc file I/O.

### Revocation/status flow

`userStore.getDisplayStatus(user)` is the single source of truth for what
the dashboard shows (`active` / `expired` / `none`) — it's derived from
`currentSerial` + `certStatus` + `expiresAt` on read, not stored directly.
Reissuing or deactivating a cert both push an entry to `revoked.yml` via
`revokedStore.addRevoked` with a `reason` of `'reissued'` or
`'manually_deactivated'`; `pki.js` maps those app-level reasons to RFC 5280
CRL reason codes (`superseded` / `privilegeWithdrawn` respectively) —
extend `REASON_CODE_BY_APP_REASON` if a new revocation reason is ever
added. `revokedStore.listActiveForCrl()` filters to entries whose original
`expiresAt` is still in the future — CRL export only ever includes those.

### GoKapi integration

`services/gokapi.js` was written against the actual GoKapi source (not
just docs, which are incomplete on the response shape) —
`POST {GOKAPI_API_URL}/api/files/add`, header `apikey`, multipart fields
`file`/`allowedDownloads`/`expiryDays`/`password`, response
`{ Result, FileInfo: { UrlDownload, ... } }`. Notably the API only accepts
whole-day expiry (`expiryDays`), so `GOKAPI_SHARE_EXPIRY_HOURS` gets
rounded up to days in `gokapi.js:uploadFile`. Never let `GOKAPI_API_KEY`
reach a log line or an error message thrown back to the browser.

### Docker

`entrypoint.sh` runs as root, creates a user/group matching `PUID`/`PGID`,
chowns `/app/data` and `/app/pki`, then `exec su-exec`s down to that user
to actually start Node (linuxserver.io pattern) — this is what makes
bind-mounted volumes come out with host-matching ownership. The Dockerfile
is multi-stage specifically because `argon2` is a native addon; the
builder stage has a C toolchain, the runtime stage doesn't.
