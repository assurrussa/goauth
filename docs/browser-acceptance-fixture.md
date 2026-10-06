# Verified HTTPS browser acceptance fixture

`make browser-acceptance` uses real Chromium, HTTPS and disposable PostgreSQL.
It requires an explicit synthetic TLS fixture and a fresh dedicated Chromium
profile. It never installs a certificate, edits OS trust/DNS, uses a personal
profile, ignores a certificate error or disables the browser sandbox.

The fixture producer must establish a supported, separately authorized trust
route first. A certificate-error page is a failure, never permission to click
through a warning or use an ignore/SPKI exception. The previous permissive
httptest certificate path is not valid evidence for this stricter gate.

## Input contract

Set `GOAUTH_BROWSER_FIXTURE_DIR` to an absolute canonical directory with basename
`goauth-browser-*`, owned by the executing user and mode 0700. Use a newly created
temporary directory; do not rename or copy an ordinary browser profile into it.
No symlinks or group/other-accessible fixture inputs are accepted.

Required entries, using exactly these names:

- `ca.pem`, mode 0600: one synthetic CA certificate, with valid CA constraints
  and certificate-signing usage. This public certificate is the only fixture
  trust anchor to import. No private CA key is imported into Chromium.
- `server.pem`, mode 0600: a current server-authentication leaf (and any needed
  intermediate chain), signed by that CA. Its SANs must cover `localhost` and
  IP `127.0.0.1`; the latter serves the hostile-origin cookie/CSRF scenario.
- `server-key.pem`, mode 0600: the matching generated synthetic private key.
  Keep every key outside the repository, chat, screenshots and retained reports.
- `chromium-profile/`, mode 0700: a new dedicated user-data directory. Trust
  imports, if required, must have been explicitly approved and confined to this
  disposable profile/environment. It must not be running in another browser.
- `fixture.json`, mode 0600: the provenance record below. `createdAt` is the
  actual fixture creation time in UTC RFC3339. `expiresAt` is the explicit end
  of this test session, no later than the CA and leaf certificate expiry. `caHash`
  is the lowercase hex SHA-256 of the exact `ca.pem` file bytes.

```json
{
  "version": 1,
  "purpose": "goauth-browser-acceptance",
  "createdAt": "ACTUAL_UTC_RFC3339_CREATION_TIME",
  "expiresAt": "EXPLICIT_UTC_RFC3339_TEST_SESSION_END",
  "caHash": "ACTUAL_SHA256_OF_CA_PEM_BYTES"
}
```

The marker is an accidental-profile-reuse guard, not an attestation system.
The operator remains responsible for creating the new fixture, verifying its
ownership and CA fingerprint, and not refreshing timestamps on reused personal
profiles. Generate short-lived certificates solely for this test. Do not reuse
personal localhost keys, account credentials or host trust stores.

Before database creation, the Go gate verifies private/canonical input paths,
the explicit fixture validity window, CA fingerprint, certificate chain, current validity,
server-auth usage, both SANs and key-pair agreement. Node additionally verifies
the current user's ownership before launching the supplied profile.

## Browser and Node trust

The harness uses Playwright `launchPersistentContext` with `chromiumSandbox: true`
and `ignoreHTTPSErrors: false`. The installed browser must support its sandbox
under the current OS/container policy. Inspect the actual browser version and
launch arguments in the fixture report. Test sandbox capability against
`about:blank` before preparing/importing a CA if the environment is uncertain.

On supported Chromium builds, the certificate-manager UI can expose
profile-local custom server certificate trust. Verify the installed version and
scope; do not assume that an OS-managed certificate section is profile-local.
Any import is a separate authorized setup action. The test contains no internal
database edits, unsupported trust API, automated trust import or fallback.
On Linux, NSS trust may belong to HOME rather than only the browser profile;
isolate the entire HOME/XDG fixture before any separately approved import.

Docker's default security policy may block Chromium's sandbox namespaces. A
nonroot container by itself does not prove that sandboxing works. A blocked
sandbox is a blocker, not a reason to use `--no-sandbox`, privileged mode,
SYS_ADMIN or unconfined seccomp. Do not silently change host/container security.

Raw Node HTTPS requests pass the fixture CA explicitly and retain ordinary
chain/hostname verification. The Go launcher also sets child-only
`NODE_EXTRA_CA_CERTS` to this CA for Playwright's Node-side `route.fetch` path
and clears child `NODE_OPTIONS`. `NODE_TLS_REJECT_UNAUTHORIZED=0` is rejected.
Neither setting imports trust into Chromium or the host OS.

## Run and retain honest evidence

After fixture setup, from the clean candidate checkout with owned PostgreSQL:

```sh
export GOAUTH_BROWSER_FIXTURE_DIR="$OWNED_BROWSER_FIXTURE"
export GOAUTH_BROWSER_PLAYWRIGHT_MODULE="$PLAYWRIGHT_MODULE"
export GOAUTH_BROWSER_CHROMIUM_EXECUTABLE="$CHROMIUM_EXECUTABLE"
make browser-acceptance
```

Keep source SHA, browser/Playwright versions, public CA fingerprint, sandbox/TLS
settings and case outcomes in a credential-free report. The normal unit gate
tests configuration/source guards and rejects wrong-CA, wrong-hostname, expired
and mismatched-key inputs. Those unit checks are not actual browser acceptance.
Require the real browser lifecycle to pass separately, including recovery,
two-tab refresh, HttpOnly cookies, hostile-origin/CSRF denial and bearer isolation.
When establishing a new trust route, also verify that an untrusted CA and a
wrong-hostname certificate fail in the actual browser; never override either
error. Record any unperformed checks rather than inferring success.

Normal exit closes the browser context. After a failure, timeout or interruption,
the fixture owner must additionally confirm that all owned browser processes
have stopped before deleting the disposable profile, certificates and keys.
Preserve unrelated profiles, source, shared caches and nonsecret test reports.

References: [Playwright launch options](https://playwright.dev/docs/api/class-browsertype),
[Playwright Docker sandbox guidance](https://playwright.dev/docs/docker),
[Chromium certificate management](https://chromium.googlesource.com/chromium/src/+/main/docs/linux/cert_management.md).
