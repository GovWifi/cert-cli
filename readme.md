# cert-cli user manual

`cert-cli` generates, validates, and views GovWifi certificate authority (CA) material.

Use it to create a root CA with an intermediate and leaf certificates, check that a certificate was signed by a given issuer, or decode a PEM certificate into OpenSSL-style details. You can also use an embedded local web UI that shows generated PEMs on screen and only writes files when you choose to save them.

Generated keys are RSA 4096-bit. Certificates are PEM-encoded X.509 certificates with SHA-256 signatures.

| Certificate | Subject common name | Valid for (defaults) |
| --- | --- | --- |
| Root CA | GovWifi Root CA | 10 years |
| Intermediate CA | GovWifi Intermediate CA | 5 years |
| Leaf | GovWifi Leaf N | 1 year |

`generate` accepts separate `--*-start` and `--*-expiry` dates (`YYYY-MM-DD`). Empty dates use the defaults above. A past expiry date generates a certificate that is already expired. Leaf certificates are end-entity certificates (not CAs) with client authentication extended key usage. Each leaf is signed by the intermediate, not by the root.

## Install

You need Go 1.26 or later.

From the repository root:

```bash
go build -o cert-cli .
```

Then run `./cert-cli`. To install into your `GOPATH` or `GOBIN`:

```bash
go install .
```

Show all commands:

```bash
cert-cli --help
cert-cli generate --help
cert-cli validate --help
cert-cli view --help
cert-cli ui --help
```

## What gets written

`generate` writes files only when you pass `--save`. Each saved certificate has:

1. A private key (`*.key`)
2. A public key (`*.pub`) — the public key path is the private key path with the extension replaced by `.pub`
3. A certificate (`*.pem`)

Default filenames (under `--out`, default `test`):

| File | Default path |
| --- | --- |
| Root certificate | `rootcert.pem` |
| Root private key | `root.key` |
| Root public key | `root.pub` |
| Intermediate certificate | `intermediate.pem` |
| Intermediate private key | `intermediate.key` |
| Intermediate public key | `intermediate.pub` |
| Leaf N certificate | `leaf-N.pem` |
| Leaf N private key | `leaf-N.key` |
| Leaf N public key | `leaf-N.pub` |

Pass `--prefix` to prepend a string to every saved file name (for example `valid_` writes `valid_rootcert.pem`). Generate overwrites files at those paths if they already exist. Treat private keys as secrets and keep them out of version control.

## Local web UI

Start an embedded web UI on localhost:

```bash
cert-cli ui
```

This opens `http://127.0.0.1:30800` in your browser and keeps serving until you stop it with Ctrl+C.

### Flags

| Flag | Default | Purpose |
| --- | --- | --- |
| `--addr` | `127.0.0.1` | Listen address (localhost only) |
| `--port` | `30800` | Listen port |

Example:

```bash
cert-cli ui --addr 127.0.0.1 --port 9090
```

The UI is a single page with tabs for:

- Generate
- Validate
- View

**Generate** creates a root CA, intermediate, and leaf certificates with custom organization, subject names, and start/expiry dates. PEMs stay on screen until you save them. Tick **Save all certificates and keys to files** to write the root, intermediate, and every leaf under the output directory (default `test`). You can still copy or save each PEM on its own. Save paths are editable and writes are relative to the directory where you started `cert-cli ui` (existing files are overwritten silently).

For **Validate**, paste or upload both PEMs. The UI reports whether the signature checks out and shows OpenSSL-style certificate text for the certificate and issuer.

For **View**, paste or upload a single PEM certificate to decode it into OpenSSL-style details.

## Generate a certificate chain

Create a new root CA, an intermediate CA signed by that root, and leaf certificates signed by the intermediate:

```bash
cert-cli generate --leaves 3 --save
```

`gen` is an alias for `generate`. Without `--save`, the command prints each certificate and key as PEM text and does not write files. With `--save`, it writes them under `--out` (default: `test`).

Example output with `--save`:

```text
wrote test/root.key, test/root.pub, and test/rootcert.pem
wrote test/intermediate.key, test/intermediate.pub, and test/intermediate.pem
wrote test/leaf-1.key, test/leaf-1.pub, and test/leaf-1.pem
wrote test/leaf-2.key, test/leaf-2.pub, and test/leaf-2.pem
wrote test/leaf-3.key, test/leaf-3.pub, and test/leaf-3.pem
generated root, intermediate, and 3 leaf certificates
```

Leaf files are numbered from 1. The subject common name is `GovWifi Leaf N` unless you change the organization via `--organization`.

### Flags

| Flag | Default | Purpose |
| --- | --- | --- |
| `--leaves` | `1` | Number of leaf certificates to sign with the intermediate (1–100) |
| `--organization` | `GovWifi` | Organization name for every certificate subject |
| `--root-cn` | `GovWifi Root CA` | Root CA common name |
| `--intermediate-cn` | `GovWifi Intermediate CA` | Intermediate CA common name |
| `--root-start` | today | Root start date (`YYYY-MM-DD`) |
| `--root-expiry` | 10 years from today | Root expiry date (`YYYY-MM-DD`) |
| `--intermediate-start` | today | Intermediate start date (`YYYY-MM-DD`) |
| `--intermediate-expiry` | 5 years from today | Intermediate expiry date (`YYYY-MM-DD`) |
| `--leaf-start` | today | Leaf start date (`YYYY-MM-DD`) |
| `--leaf-expiry` | 1 year from today | Leaf expiry date (`YYYY-MM-DD`) |
| `--save` | off | Write every certificate, private key, and public key to files |
| `--out` | `test` | Directory for `--save` |
| `--prefix` | (empty) | Optional prefix prepended to every saved file name |

Example with custom names and a directory:

```bash
cert-cli generate \
  --leaves 3 \
  --organization Acme \
  --root-cn "Acme Root" \
  --intermediate-cn "Acme Intermediate" \
  --save \
  --out ./certs \
  --prefix valid_
```

That writes `certs/valid_rootcert.pem`, `certs/valid_intermediate.pem`, `certs/valid_leaf-1.pem`, and the matching `*.key` / `*.pub` files.

## Check a signature

Confirm that a certificate was signed by a given issuer:

```bash
cert-cli validate intermediate.pem --root rootcert.pem
```

On success:

```text
intermediate.pem is signed by rootcert.pem
```

On failure the command exits with an error, for example:

```text
certificate is not signed by rootcert.pem: crypto/rsa: verification error
```

`--root` is required. The first argument is the certificate to check (usually the intermediate). For a leaf, pass the intermediate as that issuer.

This checks the cryptographic signature only. It does not check expiry, hostname, or a full trust chain beyond “this cert was signed by that issuer”.

## View a certificate

Decode a PEM certificate into OpenSSL-style details:

```bash
cert-cli view rootcert.pem
```

## Typical workflows

### New environment from scratch

```bash
cert-cli generate --leaves 1 --save
cert-cli validate test/intermediate.pem --root test/rootcert.pem
cert-cli view test/rootcert.pem
```

Or with the UI:

```bash
cert-cli ui
```

Then use the **Generate** tab, review the PEMs, and save the files you need.

### Root, intermediate, and leaf certificates

```bash
cert-cli generate --leaves 5 --save --out ./certs
cert-cli validate certs/intermediate.pem --root certs/rootcert.pem
cert-cli validate certs/leaf-1.pem --root certs/intermediate.pem
```

Or with the UI, open the **Generate** tab, set the leaf count, and tick **Save all certificates and keys to files** before generating.

## Inspecting files

Certificates and keys are PEM text. You can inspect a certificate with `cert-cli view`, or with OpenSSL:

```bash
cert-cli view rootcert.pem
openssl x509 -in rootcert.pem -noout -text
openssl x509 -in intermediate.pem -noout -text
```

To confirm the intermediate issuer matches the root subject:

```bash
openssl x509 -in rootcert.pem -noout -subject
openssl x509 -in intermediate.pem -noout -issuer
```
