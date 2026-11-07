#!/usr/bin/env python3
"""Sign and verify Sealvra provider packs (CONTRACT section 13.3).

Usage (run from the build root):

    # 1. Generate a signing keypair. The private key is printed as PEM
    #    ONLY with --print-private-key, or written 0600 to --out.
    #    NEVER commit the private key: see packs/SIGNING.md for the
    #    ceremony. For the v0.2 shipped packs the private half was
    #    generated ephemerally and destroyed after signing.
    python3 scripts/sign_pack.py gen-key --out /path/outside/the/repo/pack-signing.pem

    # 2. Finalise the pack hash first (finalise_pack), then sign it.
    #    Refuses a pack whose content_sha256 is stale.
    python3 scripts/sign_pack.py sign packs/github.json \
        --key /path/outside/the/repo/pack-signing.pem

    # 3. Verify a pack against its directory's trust files.
    python3 scripts/sign_pack.py verify packs/github.json
    #    exit 0 = signature + hash + trust + revocation all pass
    #    exit 1 = pack refused (reason printed, no partial trust)

    # 4. Show the public key / key ID for a private key, for building
    #    a trusted_keys.json entry (public key only, safe to commit).
    python3 scripts/sign_pack.py pubkey --key /path/outside/the/repo/pack-signing.pem

This script is a thin CLI over sealvra.packs: all signature logic
lives there, so the verifier and the signer can never drift apart.
It contacts no provider, reads no real keys, and writes only the
.sig file (and, for gen-key, the key file you name).
"""

from __future__ import annotations

import argparse
import base64
import json
import os
import stat
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from sealvra.packs import (  # noqa: E402
    PackRefusedError,
    generate_pack_keypair,
    load_pack,
    pack_key_id,
    private_key_from_pem,
    private_key_to_pem,
    public_key_bytes,
    sign_pack_dict,
)


def _read_private_key(key_path: Path):
    try:
        pem = key_path.read_bytes()
    except OSError as exc:
        raise PackRefusedError(f"cannot read private key {key_path}: {exc}") from exc
    return private_key_from_pem(pem)


def _cmd_gen_key(args: argparse.Namespace) -> int:
    private_key, public_bytes = generate_pack_keypair()
    pem = private_key_to_pem(private_key)
    key_id = pack_key_id(public_bytes)
    if args.out is not None:
        out = Path(args.out)
        if out.exists():
            print(f"refusing to overwrite existing file: {out}", file=sys.stderr)
            return 1
        out.write_bytes(pem)
        os.chmod(out, 0o600)
        print(f"private key written (0600) to {out}")
        print("DO NOT COMMIT THIS FILE. Store it offline; see packs/SIGNING.md.")
    elif args.print_private_key:
        sys.stdout.write(pem.decode("ascii"))
    else:
        print("refusing to print a private key without --print-private-key or --out",
              file=sys.stderr)
        return 1
    print(f"key_id: {key_id}")
    print("trusted_keys.json entry (public only, safe to commit):")
    print(json.dumps({
        "key_id": key_id,
        "algorithm": "Ed25519",
        "public_key": base64.b64encode(public_bytes).decode("ascii"),
    }, indent=2, sort_keys=True))
    return 0


def _cmd_pubkey(args: argparse.Namespace) -> int:
    private_key = _read_private_key(Path(args.key))
    public_bytes = public_key_bytes(private_key)
    print(json.dumps({
        "key_id": pack_key_id(public_bytes),
        "algorithm": "Ed25519",
        "public_key": base64.b64encode(public_bytes).decode("ascii"),
    }, indent=2, sort_keys=True))
    return 0


def _cmd_sign(args: argparse.Namespace) -> int:
    pack_path = Path(args.pack)
    try:
        pack_dict = json.loads(pack_path.read_text(encoding="utf-8"))
    except OSError as exc:
        print(f"cannot read pack {pack_path}: {exc}", file=sys.stderr)
        return 1
    except json.JSONDecodeError as exc:
        print(f"pack {pack_path} is not valid JSON: {exc}", file=sys.stderr)
        return 1
    private_key = _read_private_key(Path(args.key))
    try:
        envelope = sign_pack_dict(pack_dict, private_key)
    except PackRefusedError as exc:
        print(f"refusing to sign: {exc}", file=sys.stderr)
        return 1
    sig_path = pack_path.with_suffix(".sig")
    sig_path.write_text(json.dumps(envelope, indent=2, sort_keys=True) + "\n",
                        encoding="utf-8")
    print(f"signed {pack_path} -> {sig_path} (key_id {envelope['key_id']})")
    print("Verify with: python3 scripts/sign_pack.py verify " + str(pack_path))
    return 0


def _cmd_verify(args: argparse.Namespace) -> int:
    pack_path = Path(args.pack)
    trusted = Path(args.trusted_keys) if args.trusted_keys else None
    revoked = Path(args.revoked) if args.revoked else None
    try:
        pack = load_pack(pack_path, trusted_keys=trusted, revoked=revoked)
    except PackRefusedError as exc:
        print(f"REFUSED: {exc}", file=sys.stderr)
        return 1
    print(f"OK: pack {pack.name} version {pack.version} "
          f"signature + hash + trust + revocation all pass")
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Sign and verify Sealvra provider packs.")
    sub = parser.add_subparsers(dest="command", required=True)

    p_gen = sub.add_parser("gen-key", help="Generate a fresh Ed25519 pack-signing keypair.")
    p_gen.add_argument("--out", default=None, help="Write the private key PEM here (0600).")
    p_gen.add_argument("--print-private-key", action="store_true",
                       help="Print the private key PEM to stdout (pipe it somewhere safe).")
    p_gen.set_defaults(func=_cmd_gen_key)

    p_pub = sub.add_parser("pubkey", help="Print the trusted_keys.json entry for a key.")
    p_pub.add_argument("--key", required=True, help="Private key PEM file.")
    p_pub.set_defaults(func=_cmd_pubkey)

    p_sign = sub.add_parser("sign", help="Sign a finalised pack, writing <pack>.sig.")
    p_sign.add_argument("pack", help="Pack JSON file, e.g. packs/github.json.")
    p_sign.add_argument("--key", required=True, help="Private key PEM file.")
    p_sign.set_defaults(func=_cmd_sign)

    p_verify = sub.add_parser("verify", help="Verify a pack's signature, hash, trust, revocation.")
    p_verify.add_argument("pack", help="Pack JSON file, e.g. packs/github.json.")
    p_verify.add_argument("--trusted-keys", default=None,
                          help="trusted_keys.json path (default: sibling of the pack).")
    p_verify.add_argument("--revoked", default=None,
                          help="revoked.json path (default: sibling of the pack).")
    p_verify.set_defaults(func=_cmd_verify)

    args = parser.parse_args(argv)
    try:
        return args.func(args)
    except PackRefusedError as exc:
        print(f"REFUSED: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
