import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

import {
  CELLULE_OWNER_CREATE_OPERATION,
  CELLULE_OWNER_DELETE_OPERATION,
  CELLULE_OWNER_RENEW_OPERATION,
  signCelluleCreate,
  signCelluleDelete,
  signOwnerRenew,
  signRecipientPackageCreate,
  signRecipientPackageRemove,
} from './protocol';

vi.mock('./cryptoBridge', () => ({
  loadCrypto: vi.fn(async () => ({
    blake3Hex(payload) {
      return `hash:${new TextDecoder().decode(payload)}`;
    },
  })),
}));

const OWNER_PUBLIC_KEY = 'a'.repeat(64);

function makeSession() {
  const payloads = [];
  return {
    publicKeyHex: OWNER_PUBLIC_KEY,
    payloads,
    async sign(payload) {
      payloads.push(new TextDecoder().decode(payload));
      return `sig-${payloads.length}`;
    },
  };
}

beforeEach(() => {
  vi.useFakeTimers();
  vi.setSystemTime(new Date('2026-05-21T12:34:56.789Z'));
  vi.stubGlobal('crypto', {
    getRandomValues(bytes) {
      for (let i = 0; i < bytes.length; i += 1) bytes[i] = i;
      return bytes;
    },
  });
});

afterEach(() => {
  vi.useRealTimers();
  vi.unstubAllGlobals();
});

describe('wallet protocol payload builders', () => {
  it('signs Cellule create payload with Rust struct field order', async () => {
    const session = makeSession();

    const create = await signCelluleCreate({
      session,
      label: 'Dossier client',
      retentionDays: 90,
      reservedBytes: 42.9,
    });

    expect(create).toMatchObject({
      version: 1,
      operation: CELLULE_OWNER_CREATE_OPERATION,
      cellule_id: '00010203-0405-4607-8809-0a0b0c0d0e0f',
      label: 'Dossier client',
      owner_public_key: OWNER_PUBLIC_KEY,
      retention_days: 90,
      reserved_bytes: 42,
      storage_profile: null,
      funding_reference: null,
      issued_at: '2026-05-21T12:34:56.789Z',
      signature: 'sig-1',
    });
    expect(session.payloads[0]).toBe(JSON.stringify({ ...create, signature: '' }));
    expect(Object.keys(JSON.parse(session.payloads[0]))).toEqual([
      'version',
      'operation',
      'cellule_id',
      'label',
      'owner_public_key',
      'retention_days',
      'reserved_bytes',
      'storage_profile',
      'funding_reference',
      'issued_at',
      'signature',
    ]);
  });

  it('signs owner renew and delete payloads with operation tags', async () => {
    const renewSession = makeSession();
    const deleteSession = makeSession();

    const renew = await signOwnerRenew({ session: renewSession, celluleId: 'cellule-1' });
    const deletion = await signCelluleDelete({ session: deleteSession, celluleId: 'cellule-1' });

    expect(renew.operation).toBe(CELLULE_OWNER_RENEW_OPERATION);
    expect(deletion.operation).toBe(CELLULE_OWNER_DELETE_OPERATION);
    expect(JSON.parse(renewSession.payloads[0])).toEqual({ ...renew, signature: '' });
    expect(JSON.parse(deleteSession.payloads[0])).toEqual({ ...deletion, signature: '' });
  });

  it('signs recipient package removal with stable payload shape', async () => {
    const session = makeSession();

    const remove = await signRecipientPackageRemove({ session, packageId: 'pkg-123' });

    expect(remove).toEqual({
      version: 1,
      operation: 'recipient.package.remove',
      package_id: 'pkg-123',
      owner_public_key: OWNER_PUBLIC_KEY,
      issued_at: '2026-05-21T12:34:56.789Z',
      signature: 'sig-1',
    });
    expect(JSON.parse(session.payloads[0])).toEqual({ ...remove, signature: '' });
  });

  it('hashes and signs recipient package creation with stable payload shape', async () => {
    const session = makeSession();

    const pkg = await signRecipientPackageCreate({
      session,
      celluleId: 'cellule-1',
      recipientPublicKeyHex: 'b'.repeat(64),
      recipientX25519PubkeyHex: 'c'.repeat(64),
      fields: ['contact.email', 'kyc.status'],
      expiresAt: '2026-06-21T12:34:56.789Z',
    });

    const expectedDraft = {
      package_id: '00010203-0405-4607-8809-0a0b0c0d0e0f',
      cellule_id: 'cellule-1',
      owner_public_key: OWNER_PUBLIC_KEY,
      recipient_public_key: 'b'.repeat(64),
      recipient_x25519_pubkey: 'c'.repeat(64),
      fields: ['contact.email', 'kyc.status'],
      issued_at: '2026-05-21T12:34:56.789Z',
      expires_at: '2026-06-21T12:34:56.789Z',
      status: 'active',
      package_hash: '',
      owner_signature: '',
      delivery_receipts: [],
    };
    const expectedHash = `hash:${JSON.stringify(expectedDraft)}`;

    expect(pkg).toEqual({
      ...expectedDraft,
      package_hash: expectedHash,
      owner_signature: 'sig-1',
    });
    expect(session.payloads[0]).toBe(JSON.stringify({
      ...expectedDraft,
      package_hash: expectedHash,
    }));
    expect(Object.keys(JSON.parse(session.payloads[0]))).toEqual([
      'package_id',
      'cellule_id',
      'owner_public_key',
      'recipient_public_key',
      'recipient_x25519_pubkey',
      'fields',
      'issued_at',
      'expires_at',
      'status',
      'package_hash',
      'owner_signature',
      'delivery_receipts',
    ]);
  });
});
