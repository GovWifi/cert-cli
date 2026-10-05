# cert-cli user manual

`cert-cli` generates and checks GovWifi certificate authority (CA) material.

Use it to create a root CA, create an intermediate CA signed by that root, create a chain of leaf certificates signed by a new intermediate, or check that a certificate was signed by a given root. You can also use an embedded local web UI that shows generated PEMs on screen and only writes files when you choose to save them.

Generated keys are RSA 4096-bit. Certificates are PEM-encoded X.509 CA certificates with SHA-256 signatures.

| Certificate | Subject common name | Valid for |
| --- | --- | --- |
| Root CA | GovWifi Root CA | 10 years (`gen all` and `gen chain`, and the default for `gen root`) |
| Intermediate CA | GovWifi Intermediate CA | 5 years with `gen all` and `gen chain`; 10 years by default with `gen inter` |
| Leaf | GovWifi Leaf N | 1 year (`gen chain`) |

`gen root` and `gen inter` take `--expiry YYYY-MM-DD`. The certificate is valid through the end of that local day. The default is 10 years from today. A past date generates a certificate that is already expired. `gen all` and `gen chain` do not take `--expiry` and keep the durations above. Leaf certificates are end-entity certificates (not CAs) with client authentication extended key usage. Each leaf is signed by the intermediate, not by the root.

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
cert-cli gen --help
cert-cli ui --help
```

## What gets written

`gen root`, `gen inter`, and `gen all` each write three files per certificate. `gen chain` writes files only when you pass `--save`. Each saved certificate has:

1. A private key (`*-key.pem`)
2. A public key (`*-key.pub`) — the public key path is the private key path with the extension replaced by `.pub`
3. A certificate (`*.pem`)

Default filenames:

| File | Default path |
| --- | --- |
| Root certificate | `rootcert.pem` |
| Root private key | `root-key.pem` |
| Root public key | `root-key.pub` |
| Intermediate certificate | `intermediate.pem` |
| Intermediate private key | `intermediate-key.pem` |
| Intermediate public key | `intermediate-key.pub` |

Generate commands overwrite files at those paths if they already exist. Treat private keys as secrets and keep them out of version control.

## Local web UI

Start an embedded web UI on localhost:

```bash
cert-cli ui
```

This opens `http://127.0.0.1:8080` in your browser and keeps serving until you stop it with Ctrl+C.

### Flags

| Flag | Default | Purpose |
| --- | --- | --- |
| `--addr` | `127.0.0.1` | Listen address (localhost only) |
| `--port` | `8080` | Listen port |

Example:

```bash
cert-cli ui --addr 127.0.0.1 --port 9090
```

The UI is a single page with tabs for:

- Generate all
- Chain
- Root
- Intermediate
- Validate

Generation shows certificate, private key, and public key PEMs on screen and does **not** write files until you click **Save** for each one. Save paths default to the CLI filenames and are editable. Saving writes to disk relative to the directory where you started `cert-cli ui` and overwrites existing files silently. Each PEM block also has a **Copy** button.

For **Chain**, choose how many leaf certificates to create. Tick **Save all certificates and keys to files** to write the root, intermediate, and every leaf — each with its certificate, private key, and public key — under the output directory (default `chain`). You can still copy or save each PEM on its own.

For **Intermediate**, paste or upload the existing root certificate and root private key (uploads stay in the request; they are not written to disk).

For **Validate**, paste or upload both PEMs. The UI reports whether the signature checks out and shows OpenSSL-style certificate text for the certificate and issuer.

## Generate a full CA hierarchy

Create a new root CA and an intermediate CA signed by it:

```bash
cert-cli gen all
```

Example output:

```text
wrote root-key.pem, root-key.pub, and rootcert.pem
wrote intermediate-key.pem, intermediate-key.pub, and intermediate.pem
generated root and intermediate CA
```

### Flags

| Flag | Default | Purpose |
| --- | --- | --- |
| `--root-cert` | `rootcert.pem` | Root certificate output path |
| `--root-key` | `root-key.pem` | Root private key output path |
| `--inter-cert` | `intermediate.pem` | Intermediate certificate output path |
| `--inter-key` | `intermediate-key.pem` | Intermediate private key output path |

Example with custom paths:

```bash
cert-cli gen all \
  --root-cert ca/root.pem \
  --root-key ca/root-key.pem \
  --inter-cert ca/intermediate.pem \
  --inter-key ca/intermediate-key.pem
```

## Generate a chain with leaf certificates

Create a new root CA, an intermediate CA signed by that root, and a chosen number of leaf certificates signed by the intermediate:

```bash
cert-cli gen chain --leaves 3 --save
```

Without `--save`, the command prints each certificate and key as PEM text and does not write files. With `--save`, it writes them under `--out` (default: the current directory).

Example output with `--save`:

```text
wrote root-key.pem, root-key.pub, and rootcert.pem
wrote intermediate-key.pem, intermediate-key.pub, and intermediate.pem
wrote leaf-1-key.pem, leaf-1-key.pub, and leaf-1.pem
wrote leaf-2-key.pem, leaf-2-key.pub, and leaf-2.pem
wrote leaf-3-key.pem, leaf-3-key.pub, and leaf-3.pem
generated root, intermediate, and 3 leaf certificates
```

Leaf files are numbered from 1. The subject common name is `GovWifi Leaf N`.

### Flags

| Flag | Default | Purpose |
| --- | --- | --- |
| `--leaves` | (required) | Number of leaf certificates to sign with the intermediate (1–100) |
| `--save` | off | Write every certificate, private key, and public key to files |
| `--out` | `.` | Directory for `--save` |

Example with a directory:

```bash
cert-cli gen chain --leaves 3 --save --out ./certs
```

That writes `certs/rootcert.pem`, `certs/intermediate.pem`, `certs/leaf-1.pem`, and the matching `*-key.pem` and `*-key.pub` files.

## Generate a root CA only

```bash
cert-cli gen root
```

This creates a key pair and a self-signed root certificate. It does not create an intermediate CA.

### Flags

| Flag | Default | Purpose |
| --- | --- | --- |
| `--cert` | `rootcert.pem` | Root certificate output path |
| `--key` | `root-key.pem` | Root private key output path |
| `--expiry` | 10 years from today | Expiry date (`YYYY-MM-DD`). A past date generates an expired certificate |

Example:

```bash
cert-cli gen root --cert rootcert.pem --key root-key.pem --expiry 2036-10-01
```

## Generate an intermediate CA

Sign a new intermediate certificate with an existing root CA:

```bash
cert-cli gen inter --root rootcert.pem
```

`--root` is required. The command also needs the matching root **private** key so it can sign the intermediate certificate. If that key is not `root-key.pem`, pass `--root-key`.

### Flags

| Flag | Default | Purpose |
| --- | --- | --- |
| `--root` | (required) | Path to the root CA certificate |
| `--root-key` | `root-key.pem` | Path to the root CA private key |
| `--cert` | `intermediate.pem` | Intermediate certificate output path |
| `--key` | `intermediate-key.pem` | Intermediate private key output path |
| `--expiry` | 10 years from today | Expiry date (`YYYY-MM-DD`). A past date generates an expired certificate |

Example:

```bash
cert-cli gen inter \
  --root rootcert.pem \
  --root-key root-key.pem \
  --cert intermediate.pem \
  --key intermediate-key.pem \
  --expiry 2036-10-01
```

## Check a signature

Confirm that a certificate was signed by a given root CA:

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

`--root` is required. The first argument is the certificate to check (usually the intermediate).

This checks the cryptographic signature only. It does not check expiry, hostname, or a full trust chain beyond “this cert was signed by that issuer”.

## Typical workflows

### New environment from scratch

```bash
cert-cli gen all
cert-cli validate intermediate.pem --root rootcert.pem
```

Or with the UI:

```bash
cert-cli ui
```

Then use the **Generate all** tab, review the PEMs, and save the files you need.

### Root, intermediate, and leaf certificates

```bash
cert-cli gen chain --leaves 5 --save --out ./certs
cert-cli validate certs/intermediate.pem --root certs/rootcert.pem
cert-cli validate certs/leaf-1.pem --root certs/intermediate.pem
```

`validate` checks that the first certificate was signed by the certificate passed to `--root`. For a leaf, pass the intermediate as that issuer.

Or with the UI, open the **Chain** tab, set the leaf count, and tick **Save all certificates and keys to files** before generating.

### Extra intermediate from an existing root

```bash
cert-cli gen inter \
  --root rootcert.pem \
  --root-key root-key.pem \
  --cert staging-intermediate.pem \
  --key staging-intermediate-key.pem

cert-cli validate staging-intermediate.pem --root rootcert.pem
```

## Inspecting files

Certificates and keys are PEM text. You can inspect a certificate with OpenSSL:

```bash
openssl x509 -in rootcert.pem -noout -text
openssl x509 -in intermediate.pem -noout -text
```

To confirm the intermediate issuer matches the root subject:

```bash
openssl x509 -in rootcert.pem -noout -subject
openssl x509 -in intermediate.pem -noout -issuer
```
