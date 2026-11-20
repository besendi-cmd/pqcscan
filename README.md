# pqcscan

**Find the cryptography that quantum computers will break, and get a migration plan.**

A large quantum computer running Shor's algorithm breaks RSA, elliptic-curve crypto (ECDSA, ECDH, Ed25519, X25519), DSA and Diffie-Hellman. Attackers can record encrypted traffic today and decrypt it later ("harvest now, decrypt later"). NIST published the replacement standards in 2024 (ML-KEM, ML-DSA, SLH-DSA) and plans to deprecate the vulnerable algorithms by 2030 and disallow them by 2035.

`pqcscan` scans a codebase, builds a cryptographic inventory, and tells you what to replace with what.

## What it finds

| Rule | Severity | Finds | Replace with |
|---|---|---|---|
| PQC001 | critical | RSA encryption / key transport | ML-KEM (FIPS 203) |
| PQC002 | high | RSA signatures, JWT `RS*`/`PS*` | ML-DSA (FIPS 204) |
| PQC003 | high | RSA key generation and usage | ML-KEM / ML-DSA |
| PQC004 | critical | ECDH, X25519, X448 key agreement | ML-KEM, hybrid X25519MLKEM768 |
| PQC005 | critical | Finite-field Diffie-Hellman | ML-KEM |
| PQC006 | high | ECDSA, JWT `ES*` | ML-DSA |
| PQC007 | high | Ed25519 / Ed448 | ML-DSA / SLH-DSA |
| PQC008 | high | DSA | ML-DSA |
| PQC009 | high | EC keys and curves (P-256, secp256k1, ...) | ML-KEM / ML-DSA |
| PQC010 | high | SSH keys (`ssh-rsa`, `ecdsa-sha2-*`, `ssh-ed25519`) | hybrid `mlkem768x25519-sha256` |
| PQC011 | low | AES-128 (Grover halves key strength) | AES-256 |
| PQC012 | medium | MD5, SHA-1 | SHA-256+ |
| PQC013 | medium | DES, 3DES, RC4 | AES-256-GCM, ChaCha20-Poly1305 |
| PQC014 | medium | Dependencies that only offer classical public-key crypto | PQ-capable libraries |
| PQC100 | critical | Committed private keys (parsed: algorithm and size) | remove, rotate, re-issue |
| PQC101 | high | X.509 certificates with RSA/EC/EdDSA keys | ML-DSA or hybrid certificates |
| PQC102 | high | PEM public keys with vulnerable algorithms | ML-KEM / ML-DSA |

Languages: Python, JavaScript/TypeScript, Go, Java/Kotlin/Scala, C/C++ (OpenSSL), C#, Rust, Ruby, PHP, Swift, plus config files, PEM keys/certificates and dependency manifests.

## Install

```bash
pip install git+https://github.com/besendi-cmd/pqcscan
```

## Usage

```bash
pqcscan scan .                                   # human-readable report
pqcscan scan . --format json -o report.json      # machine-readable inventory
pqcscan scan . --sarif pqcscan.sarif             # also write SARIF for GitHub Code Scanning
pqcscan scan . --format cbom -o cbom.json        # CycloneDX 1.6 cryptographic bill of materials
pqcscan scan . --fail-on high                    # exit 1 for CI if anything high or worse is found
pqcscan scan . --min-severity high --exclude "legacy/*"
pqcscan rules                                    # list rules
```

Example output:

```
CRITICAL  PQC001  auth.js:12:10  RSA encryption / key transport [RSA]
          return crypto.publicEncrypt(publicKey, Buffer.from(secret));
          fix: Replace RSA: use ML-KEM (FIPS 203) for encryption/key transport and ML-DSA (FIPS 204) for signatures.

Summary: critical 4 | high 12 | medium 4 | low 1
Cryptographic inventory:
  RSA                          9
  ECDSA                        3
  ...
```

Try it on the bundled sample: `pqcscan scan examples/vulnerable-app`.

### Cryptographic bill of materials (CBOM)

`--format cbom` (or `--cbom FILE` alongside another format) writes a [CycloneDX 1.6](https://cyclonedx.org/capabilities/cbom/) CBOM: one `cryptographic-asset` per algorithm (with primitive, functions, parameter set and `nistQuantumSecurityLevel`), keys and certificates as related crypto material, crypto-only dependencies as libraries, and every location as `evidence.occurrences`. Severity and recommended replacement are attached as `pqcscan:*` properties. Compliance teams can import it into tools that read CycloneDX, such as Dependency-Track.

### Baselines: fail CI only on new findings

Most codebases already use RSA or ECC, so failing every build is not useful on day one. Record what exists today and gate only on new findings:

```bash
pqcscan scan . --write-baseline .pqcscan-baseline.json   # commit this file
pqcscan scan . --baseline .pqcscan-baseline.json --fail-on high
# Baseline: 1 new, 21 already known, 3 fixed since the baseline
```

Fingerprints use the rule, file and normalised line content (not the line number), so unrelated edits don't resurface old findings. Re-run `--write-baseline` after migrating code to lock in progress. In the GitHub Action, set `baseline: .pqcscan-baseline.json`.

### Suppressing findings

- Add `pqcscan: ignore` in a comment on the line.
- List paths or globs in a `.pqcscanignore` file at the scan root, or pass `--exclude GLOB`.

## GitHub Action

```yaml
name: Post-quantum scan
on: [push, pull_request]
permissions:
  contents: read
  security-events: write
jobs:
  pqcscan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v5
      - uses: besendi-cmd/pqcscan@main
        with:
          fail-on: high
          # baseline: .pqcscan-baseline.json   # optional: only fail on new findings
```

Findings appear in the repository's **Security → Code scanning** tab.

## Development

```bash
python -m venv .venv && source .venv/bin/activate
pip install -e ".[dev]"
pytest
```

## Roadmap

- Live TLS / SSH endpoint scanning
- AST-based analysis to cut false positives
- Hosted dashboard tracking migration progress across an organisation's repositories

## Limitations

Detection is pattern-based, so expect some false positives (e.g. matching text in comments) and misses (crypto hidden behind wrappers). Treat results as an inventory to review, not a guarantee.
