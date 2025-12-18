# AURA CLI — Reference implementation (demo)

This repository contains a minimal command-line tool demonstrating the core concepts
of the **AURA (European Origin Proof) Public Draft standard**.

Not related to the Neo4j “Aura CLI”.

It allows issuing and verifying a signed AURA manifest for a local digital asset
(audio, image, text, video), using cryptographic hashes and signatures.

> **Reference demo (non-production).**  
> This CLI is intended to illustrate the AURA draft with a minimal, local workflow.  
> It is **not** a production implementation and is **not** a trust registry (TPKR).  
> It does **not** perform DRM, fingerprinting, watermarking, or content recognition.

---

## What this demo illustrates

- Cryptographic hashing of an asset (SHA3‑256)

- Creation of a signed **AURA manifest** (JSON)

- Verification of asset integrity and manifest signature

- Expression of a simple rights signal (TDM opt‑out)

- Offline, portable proof of origin (no platform dependency)

---

## What this demo does NOT do

- No DRM

- No fingerprinting

- No watermarking

- No content recognition

- No platform, database, or registry

- No rights allocation or remuneration logic

---

## Identifiers

- AURA identifier (demo format; **not globally unique** in this prototype)

- Asset hash: `sha3‑256:<hex>`

- Issuer identifier: local/demo issuer (`LOCAL-ISSUER`)

---

## Third‑party verification (important)

This demo stores issuer keys locally.

In this prototype, verification uses the local issuer public key.

For **independent third‑party verification**, the issuer public key must be distributed
(e.g. embedded in the manifest or provided via a public key registry).

Key distribution and trust registries are **out of scope** of this minimal demo.

---

## Usage

### Initialise a local issuer

```bash
python aura_cli.py init

Issue an AURA manifest

python aura_cli.py issue --asset example.wav --asset-type audio --tdm-opt-out
This generates a .aura manifest file next to the asset
(example: example.wav.aura).

Verify an AURA manifest

python aura_cli.py verify --asset example.wav --manifest example.wav.aura


⸻

Security / Limitations

	•	Keys are generated and stored locally without passphrase (demo only).
	
	•	aura_id uses a local, non‑global format in this prototype (AURA-LOCAL-…-TEST).
	
	•	No trust registry (TPKR) or key rotation mechanism.
	
	•	Not intended for production use.

⸻

GDPR / personal data

This CLI is designed to operate without personal data.
It processes local assets and cryptographic material only
(hashes, signatures, and keys).

⸻

Related resources

	•	AURA standard (Public Draft): https://github.com/romainbenabdelkader/AURA-STANDARD
	
	•	Project overview: https://www.aura-standard.org