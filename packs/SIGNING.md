# Provider pack signing — format, ceremony, rotation

CONTRACT section 13.3. Read this before changing any file in `packs/`.

## Format

- Pack: `packs/<name>.json`, with `content_sha256` = SHA-256 of the
  canonical JSON (sorted keys, compact separators, UTF-8) of the pack
  with `content_sha256` removed.
- Signature: `packs/<name>.sig`, a JSON envelope (not a bare base64
  blob, deliberately — see below):

  ```json
  {"algorithm": "Ed25519", "key_id": "pk-<16 hex>", "signature": "<base64>"}
  ```

  The signature is Ed25519 over exactly the canonical bytes the hash
  covers (pack minus `content_sha256`). The envelope binds the
  signature to one key ID so revocation is checked explicitly before
  cryptography runs and the signer is auditable. Re-formatting the
  pack JSON does not break the signature (canonical bytes are
  recomputed from the parsed object); changing any content does.
- Trust: `packs/trusted_keys.json` lists key IDs and base64 raw
  32-byte Ed25519 public keys. A key ID is `pk-` + the first 16 hex
  of SHA-256 of the raw public key, and the loader refuses a trust
  file whose IDs do not match their keys.
- Revocation: `packs/revoked.json` lists revoked key IDs and revoked
  `(name, version)` pack pairs. Revocation beats trust: a revoked
  key's packs are refused even if hash and signature are valid.
  An empty revoked file is the explicit "nothing revoked" statement;
  a missing trust or revocation file refuses the load (unknown trust
  state is never treated as clean).

## Loading rule (the flip)

`sealvra.packs.load_pack` / `load_pack_directory` always verify
BOTH the content hash AND the signature against a trusted,
non-revoked key. A pack failing either is REFUSED, never loaded,
never silently fallen back to an unsigned or hash-only pack. There
is no flag to disable this for disk loads. `parse_pack` verifies
the hash of an in-memory dict only and is NOT a disk trust
boundary. `load_pack_directory` skips `trusted_keys.json` and
`revoked.json` (they are trust files, not packs).

## Signing ceremony

Use `scripts/sign_pack.py`. Never commit a private key, never paste
one into chat, never store one in the repo tree.

1. Generate a keypair OUTSIDE the repo
   (`sign_pack.py gen-key --out <path-outside-the-repo>`; the file
   is written 0600). Record only the `trusted_keys.json` entry it
   prints (public key — safe to commit).
2. Finalise the pack hash first, then sign:
   `sign_pack.py sign packs/<name>.json --key <private-key.pem>`.
   Signing refuses a pack whose `content_sha256` is stale.
3. Verify: `sign_pack.py verify packs/<name>.json` (exit 0 = hash +
   signature + trust + revocation all pass).
4. If the private key was generated for a single release, delete it
   after signing (shred, not just unlink, where the platform
   supports it) and record that fact in the release notes. If it is
   a custodian-held release key, store it offline under the release
   key custody rules and say which applies — never leave the
   custody ambiguous.

## What the v0.2 shipped signatures are — read honestly

The signatures on `github` / `gemini` v0.1.0 in this tree were made
2026-10-28 with a fresh keypair (`pk-a584d783bdcd5feb`) generated
ephemerally in one signing process: the private half existed only in
that process's memory, was never written to any file, and no longer
exists anywhere. Consequences, stated plainly:

- These signatures authenticate these exact pack bytes against the
  public key listed in `trusted_keys.json`. They do NOT prove the
  packs were authorised by any release process — a valid signature
  means "these bytes match a listed key", never "this pack was
  approved" (cf. f16-S7). The authorisation anchor is repo review
  of `packs/` + `trusted_keys.json` changes.
- Because the private half is destroyed, these exact signatures
  cannot be renewed. The next pack change MUST follow the rotation
  procedure below with a newly generated keypair; it must NOT reuse
  this key ID, and it must NOT be presented as "signed with the
  shipped key" unless a custodian-held key has genuinely replaced
  this ephemeral one via a reviewed commit.
- Anyone who can commit a change to `trusted_keys.json` can list
  their own key. Signing detects pack tampering by parties who
  cannot also rewrite the trust file; it does not survive a
  compromised commit. That limit is by design and must not be
  oversold in docs or release notes.

## Rotation (dual-key support)

The loader accepts a pack signed by ANY trusted, non-revoked key,
so rotation needs no loader change:

1. Generate the new keypair (step 1 above).
2. In ONE reviewed change: add the new public key to
   `trusted_keys.json`, re-sign every changed pack with the new
   key, and update `packs/*.json` content as needed. Old packs
   signed by the old key keep loading while the old key stays
   listed — that overlap is the rotation window.
3. When no shipped pack still depends on the old key, remove it
   from `trusted_keys.json` AND add its key ID to
   `revoked.json`'s `revoked_key_ids` (belt and braces: removal
   alone would already refuse it as untrusted; revocation also
   refuses it if it is ever re-listed by mistake).
4. If a key is ever suspected compromised, revoke first (add to
   `revoked_key_ids` in a reviewed commit), re-sign affected
   packs with a clean key, and only then remove the compromised
   key from the trust list. Never sign anything new with a
   compromised key "just to keep things loading".

## Revoking a pack version

Add `{"name": ..., "version": ...}` to `revoked_pack_versions`.
That (name, version) pair is refused whoever signed it, even with a
valid hash and signature. Use this when a published pack version
must never load again (e.g. it models an endpoint wrongly), not
merely when it is superseded — superseded versions are handled by
shipping a new version, not by revoking the old one.

## What NOT to do

- Do not put test packs in `packs/`; test packs use test-generated
  keys and live under `tests/` fixtures (CONTRACT section 13.3).
- Do not "fix" a signature failure by re-hashing the pack, deleting
  the `.sig`, or adding a key to `trusted_keys.json` without review.
  A signature failure is a refusal, and the response is to find out
  why the bytes or the trust file changed.
- Do not claim these signatures prove release authorisation, and do
  not describe the destroyed v0.2 ephemeral key as custodian-held.
