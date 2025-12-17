# AURA CLI – Minimal Origin Proof Demo

This repository contains a minimal command-line tool to issue and verify AURA origin manifests for local assets.

It is a **prototype** implementation of the AURA Origin Proof Standard (Draft v0.1):

- AURA-ID style identifier (local/demo format)
- JSON-LD manifest structure
- SHA3-256 hash of the raw asset
- Ed25519 signatures over canonical JSON
- TDM opt-out flag (`rights.tdm_opt_out`)

The goal of this CLI is to **demonstrate** how AURA manifests can be created and verified locally, not to provide a production-ready implementation.

## Usage

Install dependencies (Python 3.11+ recommended):

```bash
python3 -m venv .venv
source .venv/bin/activate
python3 -m pip install cryptography

Initialize local issuer (keys + metadata):

python3 aura_cli.py init

Issue a manifest for an asset:

python3 aura_cli.py issue \
  --asset myfile.wav \
  --asset-type audio \
  --tdm-opt-out
# → writes myfile.wav.aura

Verify a manifest:

python3 aura_cli.py verify \
  --asset myfile.wav \
  --manifest myfile.wav.aura

If the hash and signature are valid, the CLI prints a short summary of the manifest.

Security / Limitations

	•	Keys are generated and stored locally without passphrase (demo only).
	•	aura_id uses a local, non-global format (AURA-LOCAL-…-TEST).
	•	No TPKR / trust registry integration yet.
	•	Not intended for production use.

## Privacy / GDPR

This CLI does not process personal data.
It operates solely on local assets and cryptographic material (hashes, signatures, public keys).

Any use involving personal data (e.g., embedding identifiers linked to a natural person) is the sole responsibility of the implementer.

For the full AURA standard draft, see:
	•	https://github.com/romainbenabdelkader/AURA-STANDARD
	•	https://www.aura-standard.org