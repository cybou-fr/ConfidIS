// Protocol payload builders + canonical-JSON helpers.
//
// Each builder takes a "draft" object (everything except the signature), runs it
// through the exact same `serde_json::to_vec` byte layout the Rust server uses,
// and asks the Vault session to sign the resulting payload bytes. The session
// returns the hex signature, which is then attached to the draft to produce the
// final wire-format object.
//
// ## Canonical JSON contract
//
// `serde_json::to_vec(&value)` emits:
//   - struct fields in the order they are declared in Rust,
//   - `Option::None` as `null` (we do not set `skip_serializing_if`),
//   - dates in RFC 3339 with millisecond precision (chrono default),
//   - no whitespace,
//   - lowercase hex for byte fields (manually controlled).
//
// `JSON.stringify(obj)` emits keys in insertion order and uses no whitespace
// by default, so we control the byte layout by carefully building each draft
// object with the exact same field order as the Rust struct.

import { loadCrypto } from './cryptoBridge';

// ---------------------------------------------------------------------------
// Domain tags — must match confidis-protocol/src/lib.rs verbatim.
// ---------------------------------------------------------------------------

export const CELLULE_OWNER_CREATE_OPERATION = 'cellule.owner.create';
export const CELLULE_OWNER_RENEW_OPERATION = 'cellule.owner.renew';
export const CELLULE_OWNER_DELETE_OPERATION = 'cellule.owner.delete';

// ---------------------------------------------------------------------------
// Shared helpers
// ---------------------------------------------------------------------------

function uuid4() {
  // RFC 4122 v4 — uses crypto.getRandomValues for entropy.
  const bytes = new Uint8Array(16);
  crypto.getRandomValues(bytes);
  bytes[6] = (bytes[6] & 0x0f) | 0x40; // version 4
  bytes[8] = (bytes[8] & 0x3f) | 0x80; // variant 10
  const hex = Array.from(bytes, (b) => b.toString(16).padStart(2, '0'));
  return (
    hex.slice(0, 4).join('') +
    '-' +
    hex.slice(4, 6).join('') +
    '-' +
    hex.slice(6, 8).join('') +
    '-' +
    hex.slice(8, 10).join('') +
    '-' +
    hex.slice(10, 16).join('')
  );
}

export async function signCelluleCreate({
  session,
  label,
  retentionDays,
  reservedBytes = 0,
}) {
  const celluleId = uuid4();
  // Field order MUST match the Rust `CelluleOwnerCreate` struct: the node
  // verifies the signature over `serde_json` of the struct with the signature
  // field cleared, so `reserved_bytes` sits immediately after `retention_days`.
  // Legacy sizing input kept for compatibility with older nodes.
  const draft = {
    version: 1,
    operation: CELLULE_OWNER_CREATE_OPERATION,
    cellule_id: celluleId,
    label,
    owner_public_key: session.publicKeyHex,
    retention_days: retentionDays,
    reserved_bytes: Math.trunc(reservedBytes) || 0,
    storage_profile: null,
    funding_reference: null,
    issued_at: new Date().toISOString(),
    signature: '',
  };
  const payload = new TextEncoder().encode(JSON.stringify(draft));
  const signature = await session.sign(payload);
  return { ...draft, signature };
}

// ---------------------------------------------------------------------------
// CelluleOwnerRenew — re-sign owner claim to prove liveness
// ---------------------------------------------------------------------------

export async function signOwnerRenew({ session, celluleId }) {
  const draft = {
    version: 1,
    operation: CELLULE_OWNER_RENEW_OPERATION,
    cellule_id: celluleId,
    owner_public_key: session.publicKeyHex,
    claimed_at: new Date().toISOString(),
    signature: '',
  };
  const payload = new TextEncoder().encode(JSON.stringify(draft));
  const signature = await session.sign(payload);
  return { ...draft, signature };
}

// ---------------------------------------------------------------------------
// CelluleDeleteAuthorization — owner signs to delete their Cellule record
// ---------------------------------------------------------------------------

export async function signCelluleDelete({ session, celluleId }) {
  const draft = {
    version: 1,
    operation: CELLULE_OWNER_DELETE_OPERATION,
    cellule_id: celluleId,
    owner_public_key: session.publicKeyHex,
    issued_at: new Date().toISOString(),
    signature: '',
  };
  const payload2 = new TextEncoder().encode(JSON.stringify(draft));
  const signature = await session.sign(payload2);
  return { ...draft, signature };
}

export const CELLULE_RECIPIENT_PACKAGE_CREATE_OPERATION = 'cellule.recipient.package.create';
export const CELLULE_RECIPIENT_PACKAGE_REMOVE_OPERATION = 'cellule.recipient.package.remove';

// ---------------------------------------------------------------------------
// RecipientPackageRecord — owner creates a recipient package
// ---------------------------------------------------------------------------

export async function signRecipientPackageCreate({
  session,
  celluleId,
  recipientPublicKeyHex,
  recipientX25519PubkeyHex,
  fields,
  expiresAt,
}) {
  const crypto = await loadCrypto();
  const draft = {
    package_id: uuid4(),
    cellule_id: celluleId,
    owner_public_key: session.publicKeyHex,
    recipient_public_key: recipientPublicKeyHex,
    recipient_x25519_pubkey: recipientX25519PubkeyHex,
    fields,
    issued_at: new Date().toISOString(),
    expires_at: expiresAt ?? null,
    status: 'active',
    package_hash: '',
    owner_signature: '',
    delivery_receipts: [],
  };
  const hashPayload = new TextEncoder().encode(JSON.stringify(draft));
  const signedDraft = { ...draft, package_hash: crypto.blake3Hex(hashPayload) };
  const payload = new TextEncoder().encode(JSON.stringify(signedDraft));
  const signature = await session.sign(payload);
  return { ...signedDraft, owner_signature: signature };
}

// ---------------------------------------------------------------------------
// RecipientPackageRemove — owner removes a recipient package
// ---------------------------------------------------------------------------

export async function signRecipientPackageRemove({ session, packageId }) {
  const remove = {
    version: 1,
    operation: 'recipient.package.remove',
    package_id: packageId,
    owner_public_key: session.publicKeyHex,
    issued_at: new Date().toISOString(),
    signature: '',
  };
  const payload = new TextEncoder().encode(JSON.stringify(remove));
  const signature = await session.sign(payload);
  return { ...remove, signature };
}
