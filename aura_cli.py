#!/usr/bin/env python3
import argparse
import base64
import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives import serialization

ISSUER_PRIVATE_KEY_FILE = "issuer_private.pem"
ISSUER_PUBLIC_KEY_FILE = "issuer_public.pem"
ISSUER_META_FILE = "issuer.json"


def canonical_json(data: dict) -> bytes:
    return json.dumps(
        data,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    ).encode("utf-8")


def load_or_create_keys():
    priv_path = Path(ISSUER_PRIVATE_KEY_FILE)
    pub_path = Path(ISSUER_PUBLIC_KEY_FILE)
    meta_path = Path(ISSUER_META_FILE)

    if priv_path.exists() and pub_path.exists() and meta_path.exists():
        private_key = serialization.load_pem_private_key(
            priv_path.read_bytes(),
            password=None,
        )
        public_key = private_key.public_key()
        meta = json.loads(meta_path.read_text(encoding="utf-8"))
        return private_key, public_key, meta

    private_key = Ed25519PrivateKey.generate()
    public_key = private_key.public_key()

    priv_bytes = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    pub_bytes = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )

    priv_path.write_bytes(priv_bytes)
    pub_path.write_bytes(pub_bytes)

    meta = {
        "issuer_id": "LOCAL-ISSUER",
        "created_at": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
    }
    meta_path.write_text(json.dumps(meta, indent=2), encoding="utf-8")

    return private_key, public_key, meta


def hash_file_sha3_256(path: Path) -> str:
    h = hashlib.sha3_256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(8192), b""):
            h.update(chunk)
    return "sha3-256:" + h.hexdigest()


def cmd_init(args):
    private_key, public_key, meta = load_or_create_keys()
    print("Issuer initialised:")
    print(json.dumps(meta, indent=2))


def cmd_issue(args):
    asset_path = Path(args.asset)
    if not asset_path.exists():
        raise SystemExit(f"Asset not found: {asset_path}")

    private_key, public_key, meta = load_or_create_keys()
    asset_hash = hash_file_sha3_256(asset_path)

    aura_id = f"AURA-LOCAL-{datetime.now().year}-000001-TEST"

    manifest = {
        "@context": "https://aura-standard.org/context/v1.jsonld",
        "origin_proof_version": "0.1",
        "aura_id": aura_id,
        "origin": {
            "type": "human",
            "declared_by": "issuer",
        },
        "asset": {
            "type": args.asset_type,
            "hash": asset_hash,
        },
        "issuer_id": meta["issuer_id"],
        "issued_at": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
        "rights": {
            "tdm_opt_out": bool(args.tdm_opt_out),
        },
    }

    to_sign = canonical_json(manifest)
    signature = private_key.sign(to_sign)
    manifest["signature"] = {
        "alg": "ed25519",
        "value": base64.b64encode(signature).decode("ascii"),
    }

    manifest_path = Path(args.manifest or (str(asset_path) + ".aura"))
    manifest_path.write_text(json.dumps(manifest, indent=2), encoding="utf-8")
    print(f"Manifest written to {manifest_path}")


def cmd_verify(args):
    asset_path = Path(args.asset)
    manifest_path = Path(args.manifest)

    if not asset_path.exists():
        raise SystemExit(f"Asset not found: {asset_path}")
    if not manifest_path.exists():
        raise SystemExit(f"Manifest not found: {manifest_path}")

    _, public_key, meta = load_or_create_keys()

    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    signature_block = manifest.get("signature") or {}
    sig_alg = signature_block.get("alg")
    sig_value_b64 = signature_block.get("value")

    if sig_alg != "ed25519" or not sig_value_b64:
        raise SystemExit("Invalid or missing signature block in manifest")

    sig_bytes = base64.b64decode(sig_value_b64)

    manifest_for_hash = dict(manifest)
    manifest_for_hash.pop("signature", None)
    expected_asset_hash = manifest_for_hash["asset"]["hash"]
    actual_asset_hash = hash_file_sha3_256(asset_path)

    if expected_asset_hash != actual_asset_hash:
        raise SystemExit("Asset hash mismatch – asset does not match manifest")

    to_verify = canonical_json(manifest_for_hash)
    try:
        public_key.verify(sig_bytes, to_verify)
    except Exception as e:
        raise SystemExit(f"Signature verification failed: {e}")

    print("AURA manifest is VALID for this asset.")
    print(
        json.dumps(
            {
                "aura_id": manifest["aura_id"],
                "issuer_id": manifest["issuer_id"],
                "issued_at": manifest["issued_at"],
                "tdm_opt_out": manifest["rights"]["tdm_opt_out"],
            },
            indent=2,
        )
    )


def main():
    parser = argparse.ArgumentParser(prog="aura", description="AURA minimal CLI demo")
    sub = parser.add_subparsers(dest="cmd", required=True)

    p_init = sub.add_parser("init", help="Initialise local issuer keys")
    p_init.set_defaults(func=cmd_init)

    p_issue = sub.add_parser("issue", help="Issue AURA manifest for an asset")
    p_issue.add_argument("--asset", required=True, help="Path to asset file")
    p_issue.add_argument("--asset-type", default="audio", help="Asset type")
    p_issue.add_argument("--manifest", help="Path to output manifest file (.aura)")
    p_issue.add_argument("--tdm-opt-out", action="store_true", help="Set TDM opt-out")
    p_issue.set_defaults(func=cmd_issue)

    p_verify = sub.add_parser("verify", help="Verify AURA manifest for an asset")
    p_verify.add_argument("--asset", required=True, help="Path to asset file")
    p_verify.add_argument("--manifest", required=True, help="Path to manifest file")
    p_verify.set_defaults(func=cmd_verify)

    args = parser.parse_args()
    args.func(args)


if __name__ == "__main__":
    main()
