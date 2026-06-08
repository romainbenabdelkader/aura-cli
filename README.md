# AURA CLI

Minimal reference demonstrator for verifiable origin, integrity and consent signals.

AURA CLI shows how a digital asset can be bound to a cryptographically verifiable manifest, without DRM, watermarking, monitoring, platform control or automated enforcement.

> AURA establishes technical facts. It does not enforce rights.

This repository is a non-normative reference testbed for the AURA model.

## Demo Video

Short demo video showing tamper detection and origin proof:

https://youtu.be/hyGM4gvHMXI

The video illustrates the conceptual workflow and an earlier version of the CLI. The current codebase refines the trust model with TPKR registry handling, key handling and metadata while preserving the same core principles.

## Position In The AURA Ecosystem

AURA is structured as three distinct layers:

- **AURA-STANDARD**: conceptual and specification layer
  https://github.com/romainbenabdelkader/AURA-STANDARD
- **aura-core**: reusable implementation primitives
  https://github.com/romainbenabdelkader/aura-core
- **aura-cli**: minimal command-line demonstrator
  this repository

## AURA Integrity Proof Demo

This repository includes a complete local proof demo showing that AURA can produce and verify a minimal technical artefact for origin declaration, file integrity, timestamping, rights reservation and manifest integrity.

The demo is intentionally readable for a non-technical audience:

- original file + original manifest = VALID
- identical copy of the file = VALID
- actually altered file = INVALID
- manifest altered after signature = INVALID

AURA provides a verifiable technical artefact. It does not decide legal ownership, infringement or liability. Law, audit, regulator or court decide.

### Create A Local AURA Manifest

```bash
python aura_cli.py create --asset assets/track.wav --out assets/track.aura.json
```

If your system exposes Python 3 as `python3`, use:

```bash
python3 aura_cli.py create --asset assets/track.wav --out assets/track.aura.json
```

The generated JSON manifest follows the local AURA v0.1 proof profile and includes:

- `aura_id`
- `issuer_id`
- `issued_at`
- `asset_type`
- `asset_hash`
- `rights_reservation`
- `tdm_opt_out`
- `proof_scope`
- `legal_note`
- `signature`

### Verify A Local AURA Manifest

```bash
python aura_cli.py verify --asset assets/track.wav --manifest assets/track.aura.json
```

Expected valid output:

```text
AURA manifest is VALID for this asset.
Verification result: VALID
Asset hash: OK
Manifest signature: OK
TDM opt-out: true
```

If the file bytes are modified, verification returns:

```text
AURA manifest is INVALID for this asset.
Verification result: INVALID
Reason: file hash mismatch
```

If the manifest is modified after signature, verification returns:

```text
AURA manifest is INVALID for this asset.
Verification result: INVALID
Reason: manifest signature mismatch
```

The verification output displays the probative elements:

- `aura_id`
- `issuer_id`
- `issued_at`
- `asset_type`
- `asset_hash`
- `manifest_hash`
- `signature_status`
- `timestamp`
- `rights_reservation`
- `tdm_opt_out`
- `verification_result`
- `legal_scope`

### Run The Full Demo

```bash
./demo_integrity.sh
```

The script automatically runs:

1. generation of the original manifest
2. verification of the original file
3. creation of an identical copy
4. verification of the identical copy
5. real modification of a copied file
6. verification of the modified file
7. modification of the manifest after signature
8. verification of the modified manifest

This demo does not present AURA as surveillance, automatic sanction, automated enforcement or absolute legal proof. It only demonstrates a verifiable technical artefact.

## Quick Start

### 1. Clone The Repository

```bash
git clone https://github.com/romainbenabdelkader/aura-cli
cd aura-cli
```

### 2. Install Dependencies

```bash
pip install -r requirements.txt
```

### 3. Initialize A Demo Issuer And Local TPKR Registry

```bash
python aura_cli.py init \
  --org "Demo Org" \
  --country FR \
  --contact "demo@example.org"
```

This generates:

- an Ed25519 key pair, with optional private key encryption via `AURA_KEY_PASSWORD`
- issuer metadata
- a local TPKR demo registry

### 4. Issue An AURA Manifest For A Local Asset

```bash
python aura_cli.py issue \
  --asset examples/example.wav \
  --asset-type audio \
  --tdm-opt-out
```

This produces a signed `.aura.json` manifest bound to the asset hash.

### 5. Verify The Asset Against Its Manifest

```bash
python aura_cli.py verify \
  --asset examples/example.wav \
  --manifest examples/example.wav.aura.json
```

Expected behaviour:

- original file: VALID
- identical copy: VALID
- modified file: INVALID

## What This Demonstrator Shows

This repository demonstrates, in the simplest possible form:

- cryptographic binding between an asset and a manifest
- deterministic canonicalisation of the manifest using a demo profile
- Ed25519 signatures
- issuer resolution via a local TPKR demo registry
- explicit separation between proof of origin, enforcement and monitoring

## What This Demonstrator Does Not Do

This is a reference demonstrator only.

It does not implement:

- DRM
- watermarking
- fingerprinting
- similarity detection
- content recognition
- usage monitoring
- platform-side enforcement

No rights are enforced. No platforms are controlled. No content is analysed beyond hashing.

## Example Use Case: AI Training Opt-Out

A publisher or issuer may attach a declaration to an asset indicating:

- origin
- issuer
- time of declaration
- an opt-out-related signal

AURA CLI demonstrates how this declaration can be made verifiable.

It does not demonstrate whether downstream systems respected the declaration.

## Files Generated By The Demonstrator

- `issuer_private.pem`: private key, optionally encrypted using `AURA_KEY_PASSWORD`
- `issuer_public.pem`: public key
- `issuer.json`: issuer metadata
- `tpk_registry.json`: local TPKR demo registry, non-governed
- `*.aura.json`: AURA manifests bound to assets

## Security And Trust Model

This is a demo trust model:

- the trust registry is local and not governed
- registry state can be modified locally

In a real deployment:

- the registry would be governed
- its state, or a hash of its state, would be published or anchored
- issuer onboarding would follow defined governance rules

This demonstrator intentionally keeps the trust model explicit and inspectable.

## GDPR And Personal Data

This CLI is designed to operate without personal data.

It processes only:

- local files
- cryptographic hashes
- signatures
- keys
- optional non-identifying issuer metadata

No personal data is required.

## Scope And Intent

AURA CLI is:

- a technical reference
- a testbed artefact
- a discussion support tool for regulators, institutions and engineers

It is not production software.

## Related Resources

AURA standard, public draft:

https://github.com/romainbenabdelkader/AURA-STANDARD

AURA v0.1, Public Draft DOI:

https://doi.org/10.5281/zenodo.19123074

Research paper:

**AURA: A Minimal Evidentiary Layer for Origin and Consent Signals in the AI Era**
https://doi.org/10.2139/ssrn.6135847

## Status

Reference demonstrator only. Non-normative. Not production software.

## License

MIT
