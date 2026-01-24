#!/usr/bin/env python3
"""
AURA – Minimal EU Testbed CLI 

Purpose:
- Demonstrate a neutral, non-commercial proof-of-origin mechanism
- Suitable for Digital Europe / EU innovation fund evaluation
- Explicit trust model: registry governance + future anchoring

Status:
- Draft / testbed implementation
- Canonicalization: demo profile (RFC 8785 JCS planned)
"""

import argparse
import base64
import hashlib
import json
import os
import uuid
from datetime import datetime, timezone
from getpass import getpass
from pathlib import Path
from typing import Dict, Any

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

ISSUER_PRIVATE_KEY_FILE = "issuer_private.pem"
ISSUER_PUBLIC_KEY_FILE = "issuer_public.pem"
ISSUER_META_FILE = "issuer.json"
TPKR_REGISTRY_FILE = "tpk_registry.json"


# ---------------------------------------------------------------------------
# Utilities
# ---------------------------------------------------------------------------

def canonical_json_demo_v0(data: Dict[str, Any]) -> bytes:
    """Deterministic JSON serialization (demo profile, not full RFC 8785)."""
    return json.dumps(
        data,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    ).encode("utf-8")


def now_utc_iso() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def b64url_encode(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def b64url_decode(s: str) -> bytes:
    pad = "=" * ((4 - len(s) % 4) % 4)
    return base64.urlsafe_b64decode((s + pad).encode("ascii"))


def sha256_bytes_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def sha256_file_hex(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(8192), b""):
            h.update(chunk)
    return h.hexdigest()


def safe_chmod_600(path: Path) -> None:
    """Best-effort permissions hardening for private key files."""
    try:
        os.chmod(path, 0o600)
    except Exception:
        pass


# ---------------------------------------------------------------------------
# Registry / Issuer
# ---------------------------------------------------------------------------

def pubkey_fingerprint_hex(public_key: Ed25519PublicKey) -> str:
    der = public_key.public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return sha256_bytes_hex(der)


def make_issuer_id(public_key: Ed25519PublicKey) -> str:
    return f"TPKR:ed25519:{pubkey_fingerprint_hex(public_key)}"


def load_registry(path: Path) -> Dict[str, Any]:
    if not path.exists():
        return {
            "version": "0.2-draft",
            "created_at": now_utc_iso(),
            "issuers": {},
        }
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception as e:
        raise SystemExit(
            f"TPKR registry is corrupted or unreadable: {path}\n"
            f"Error: {e}\n"
            f"Fix: restore the registry file or delete it and run `aura init` again."
        )


def save_registry(path: Path, reg: Dict[str, Any]) -> None:
    path.write_text(json.dumps(reg, indent=2, ensure_ascii=False), encoding="utf-8")


def registry_hash_hex(path: Path) -> str:
    return sha256_file_hex(path) if path.exists() else ""


def register_issuer_public_key(
    registry_path: Path,
    issuer_id: str,
    public_key: Ed25519PublicKey,
    meta: Dict[str, Any],
) -> None:
    reg = load_registry(registry_path)
    issuers = reg.setdefault("issuers", {})

    der = public_key.public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )

    issuers[issuer_id] = {
        "alg": "ed25519",
        "public_key_der_b64": base64.b64encode(der).decode("ascii"),
        "fingerprint_sha256": pubkey_fingerprint_hex(public_key),
        "updated_at": now_utc_iso(),
        "issuer_metadata": {
            "organization_name": meta.get("organization_name"),
            "country": meta.get("country"),
            "contact": meta.get("contact"),
            "issuer_role": meta.get("issuer_role"),
        },
    }

    reg["updated_at"] = now_utc_iso()
    save_registry(registry_path, reg)


def resolve_public_key_from_registry(registry_path: Path, issuer_id: str) -> Ed25519PublicKey:
    reg = load_registry(registry_path)
    entry = reg.get("issuers", {}).get(issuer_id)
    if not entry:
        raise SystemExit(
            "Unknown issuer_id (not registered in TPKR). "
            "Tip: run `aura init` to (re)register the local issuer."
        )

    if entry.get("alg") != "ed25519":
        raise SystemExit("Unsupported algorithm in registry entry.")

    der = base64.b64decode(entry["public_key_der_b64"])
    pub = serialization.load_der_public_key(der)
    if not isinstance(pub, Ed25519PublicKey):
        raise SystemExit("Invalid public key type in registry.")
    return pub


# ---------------------------------------------------------------------------
# Key management
# ---------------------------------------------------------------------------

def _load_private_key_pem(pem: bytes) -> Ed25519PrivateKey:
    try:
        k = serialization.load_pem_private_key(pem, password=None)
    except (TypeError, ValueError):
        pw = os.getenv("AURA_KEY_PASSWORD")
        if pw is None:
            pw = getpass("AURA issuer key password: ")
        try:
            k = serialization.load_pem_private_key(pem, password=pw.encode("utf-8"))
        except (TypeError, ValueError):
            raise SystemExit("Unable to load issuer_private.pem (wrong password or corrupted key).")

    if not isinstance(k, Ed25519PrivateKey):
        raise SystemExit("issuer_private.pem is not an Ed25519 private key.")
    return k


def _load_public_key_pem(pem: bytes) -> Ed25519PublicKey:
    k = serialization.load_pem_public_key(pem)
    if not isinstance(k, Ed25519PublicKey):
        raise SystemExit("issuer_public.pem is not an Ed25519 public key.")
    return k


def load_or_create_keys(registry_path: Path, meta_updates: Dict[str, Any]):
    priv_path = Path(ISSUER_PRIVATE_KEY_FILE)
    pub_path = Path(ISSUER_PUBLIC_KEY_FILE)
    meta_path = Path(ISSUER_META_FILE)

    if priv_path.exists() and pub_path.exists() and meta_path.exists():
        private_key = _load_private_key_pem(priv_path.read_bytes())
        derived_public_key = private_key.public_key()
        file_public_key = _load_public_key_pem(pub_path.read_bytes())

        if derived_public_key.public_bytes(
            serialization.Encoding.DER,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        ) != file_public_key.public_bytes(
            serialization.Encoding.DER,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        ):
            raise SystemExit("Public key mismatch: issuer_public.pem != issuer_private.pem")

        meta = json.loads(meta_path.read_text(encoding="utf-8"))

        for k, v in meta_updates.items():
            if v:
                meta[k] = v
        meta["updated_at"] = now_utc_iso()

        meta_path.write_text(json.dumps(meta, indent=2, ensure_ascii=False), encoding="utf-8")
        register_issuer_public_key(registry_path, meta["issuer_id"], file_public_key, meta)
        return private_key, file_public_key, meta

    # Create new keys
    private_key = Ed25519PrivateKey.generate()
    public_key = private_key.public_key()

    pw = os.getenv("AURA_KEY_PASSWORD")
    enc = serialization.BestAvailableEncryption(pw.encode("utf-8")) if pw else serialization.NoEncryption()

    priv_path.write_bytes(
        private_key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            enc,
        )
    )
    safe_chmod_600(priv_path)

    pub_path.write_bytes(
        public_key.public_bytes(
            serialization.Encoding.PEM,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        )
    )

    meta = {
        "issuer_id": make_issuer_id(public_key),
        "created_at": now_utc_iso(),
        **meta_updates,
    }

    meta_path.write_text(json.dumps(meta, indent=2, ensure_ascii=False), encoding="utf-8")
    register_issuer_public_key(registry_path, meta["issuer_id"], public_key, meta)
    return private_key, public_key, meta


# ---------------------------------------------------------------------------
# Commands
# ---------------------------------------------------------------------------

def cmd_init(args):
    reg = Path(args.registry)
    _, _, meta = load_or_create_keys(reg, {
        "organization_name": args.org,
        "country": args.country,
        "contact": args.contact,
        "issuer_role": args.role or "testbed participant",
    })

    print(json.dumps({
        "issuer": meta,
        "registry_hash_sha256": registry_hash_hex(reg),
        "note": "Registry hash to be published/anchored under EU testbed governance (planned).",
    }, indent=2, ensure_ascii=False))


def cmd_issue(args):
    reg = Path(args.registry)
    asset = Path(args.asset)
    if not asset.exists():
        raise SystemExit(f"Asset not found: {asset}")

    priv, pub, meta = load_or_create_keys(reg, {
        "organization_name": args.org,
        "country": args.country,
        "contact": args.contact,
        "issuer_role": args.role,
    })

    asset_hash = "sha256:" + sha256_file_hex(asset)

    manifest = {
        "@context": "https://aura-standard.org/context/v1.jsonld",
        "spec_version": "0.2-draft",
        "canonicalization": "demo_profile_v0 (RFC8785 planned)",
        "verification_model": "TPKR registry (governed); anchoring planned",
        "evidence_level": "self-declared (testbed)",
        "aura_id": f"AURA:{uuid.uuid4()}",
        "origin": {"type": args.origin_type, "declared_by": "issuer"},
        "asset": {"type": args.asset_type, "hash": asset_hash},
        "issuer_id": meta["issuer_id"],
        "issuer_key_fingerprint_sha256": pubkey_fingerprint_hex(pub),
        "issued_at": now_utc_iso(),
        "rights": {"tdm_opt_out": bool(args.tdm_opt_out)},
        "issuer_metadata": {
            "organization_name": meta.get("organization_name"),
            "country": meta.get("country"),
            "contact": meta.get("contact"),
            "issuer_role": meta.get("issuer_role"),
        },
    }

    payload = canonical_json_demo_v0(manifest)
    sig = priv.sign(payload)
    manifest["signature"] = {
        "alg": "ed25519",
        "encoding": "base64url",
        "value": b64url_encode(sig),
    }

    out = Path(args.manifest or f"{asset}.aura.json")
    out.write_text(json.dumps(manifest, indent=2, ensure_ascii=False), encoding="utf-8")

    print(json.dumps({
        "manifest_written_to": str(out),
        "signed_payload_hash_sha256": sha256_bytes_hex(payload),
        "registry_hash_sha256": registry_hash_hex(reg),
    }, indent=2, ensure_ascii=False))


def cmd_verify(args):
    reg = Path(args.registry)
    asset = Path(args.asset)
    manifest_path = Path(args.manifest)

    if not asset.exists():
        raise SystemExit(f"Asset not found: {asset}")
    if not manifest_path.exists():
        raise SystemExit(f"Manifest not found: {manifest_path}")

    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))

    issuer_id = manifest.get("issuer_id")
    if not issuer_id:
        raise SystemExit("Missing issuer_id in manifest.")

    pub = resolve_public_key_from_registry(reg, issuer_id)

    sig_block = manifest.get("signature") or {}
    sig = b64url_decode(sig_block["value"])

    unsigned = dict(manifest)
    unsigned.pop("signature", None)

    if unsigned["asset"]["hash"] != "sha256:" + sha256_file_hex(asset):
        raise SystemExit("Asset hash mismatch.")

    payload = canonical_json_demo_v0(unsigned)
    pub.verify(sig, payload)

    print(json.dumps({
        "status": "VALID",
        "aura_id": manifest.get("aura_id"),
        "issuer_id": issuer_id,
        "issued_at": manifest.get("issued_at"),
        "verified_payload_hash_sha256": sha256_bytes_hex(payload),
        "registry_hash_sha256": registry_hash_hex(reg),
    }, indent=2, ensure_ascii=False))


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def main():
    p = argparse.ArgumentParser("aura", description="AURA EU testbed CLI (final polished)")
    s = p.add_subparsers(dest="cmd", required=True)

    i = s.add_parser("init", help="Create/load issuer keys and (re)register in TPKR")
    i.add_argument("--registry", default=TPKR_REGISTRY_FILE)
    i.add_argument("--org")
    i.add_argument("--country")
    i.add_argument("--contact")
    i.add_argument("--role")
    i.set_defaults(func=cmd_init)

    is_ = s.add_parser("issue", help="Issue a signed AURA manifest for an asset")
    is_.add_argument("--registry", default=TPKR_REGISTRY_FILE)
    is_.add_argument("--asset", required=True)
    is_.add_argument("--asset-type", default="audio")
    is_.add_argument("--origin-type", default="human")
    is_.add_argument("--manifest")
    is_.add_argument("--tdm-opt-out", action="store_true")
    is_.add_argument("--org")
    is_.add_argument("--country")
    is_.add_argument("--contact")
    is_.add_argument("--role")
    is_.set_defaults(func=cmd_issue)

    v = s.add_parser("verify", help="Verify an AURA manifest against asset + TPKR")
    v.add_argument("--registry", default=TPKR_REGISTRY_FILE)
    v.add_argument("--asset", required=True)
    v.add_argument("--manifest", required=True)
    v.set_defaults(func=cmd_verify)

    args = p.parse_args()
    args.func(args)


if __name__ == "__main__":
    main()