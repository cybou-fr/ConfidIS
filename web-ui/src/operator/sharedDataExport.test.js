import { describe, expect, it } from 'vitest';

import {
  csvEscape,
  findSharedValue,
  flattenData,
  sharedItemsToCrmCsv,
  sharedItemsToCsv,
} from './sharedDataExport';

const sharedItem = {
  package_id: 'pkg-1',
  cellule_id: 'cellule-1',
  owner_public_key: 'owner',
  recipient_public_key: 'recipient',
  fields: ['contact.email', 'kyc.status', 'consent.status'],
  issued_at: '2026-05-21T10:00:00Z',
  expires_at: '2026-06-21T10:00:00Z',
  status: 'Active',
  package_hash: 'hash',
  data: {
    prénom: 'Anaïs',
    nom: 'Durand',
    contact: {
      email: 'anais@example.test',
      téléphone: '+33 1 02 03 04 05',
    },
    société: 'Atelier "Nord"; Poitiers',
    siret: '12345678900010',
    consent: { status: 'granted' },
    kyc: { status: 'verified' },
  },
};

describe('operator shared-data export helpers', () => {
  it('escapes CSV values with semicolons, quotes and line breaks', () => {
    expect(csvEscape('Atelier "Nord"; Poitiers')).toBe('"Atelier ""Nord""; Poitiers"');
    expect(csvEscape('line 1\nline 2')).toBe('"line 1\nline 2"');
    expect(csvEscape('simple')).toBe('simple');
    expect(csvEscape(null)).toBe('');
  });

  it('flattens nested objects and arrays into stable field paths', () => {
    expect(flattenData({ a: { b: 1 }, tags: ['x', 'y'], empty: null })).toEqual([
      { key: 'a.b', value: '1' },
      { key: 'tags[0]', value: 'x' },
      { key: 'tags[1]', value: 'y' },
      { key: 'empty', value: '' },
    ]);
  });

  it('finds CRM values across French accents and nested fields', () => {
    expect(findSharedValue(sharedItem, ['prenom'])).toBe('Anaïs');
    expect(findSharedValue(sharedItem, ['telephone'])).toBe('+33 1 02 03 04 05');
    expect(findSharedValue(sharedItem, ['organisation', 'societe'])).toBe('Atelier "Nord"; Poitiers');
    expect(findSharedValue(sharedItem, ['missing'])).toBe('');
  });

  it('exports raw shared data as semicolon CSV with traceability fields', () => {
    const csv = sharedItemsToCsv([sharedItem]);
    const lines = csv.split('\n');

    expect(lines[0]).toBe('package_id;cellule_id;owner_public_key;recipient_public_key;field;value;issued_at;expires_at;status;package_hash');
    expect(csv).toContain('pkg-1;cellule-1;owner;recipient;contact.email;anais@example.test;2026-05-21T10:00:00Z;2026-06-21T10:00:00Z;Active;hash');
    expect(csv).toContain('société;"Atelier ""Nord""; Poitiers"');
  });

  it('keeps metadata rows when a package has no predecrypted data', () => {
    const csv = sharedItemsToCsv([{ ...sharedItem, package_id: 'pkg-empty', data: null }]);

    expect(csv.split('\n')[1]).toBe('pkg-empty;cellule-1;owner;recipient;;;2026-05-21T10:00:00Z;2026-06-21T10:00:00Z;Active;hash');
  });

  it('exports CRM/contact CSV for PME import workflows', () => {
    const csv = sharedItemsToCrmCsv([sharedItem]);
    const lines = csv.split('\n');

    expect(lines[0]).toBe('first_name;last_name;email;phone;company;siret;consent_status;kyc_status;confidis_package_id;confidis_cellule_id;confidis_fields;confidis_expires_at');
    expect(lines[1]).toBe('Anaïs;Durand;anais@example.test;+33 1 02 03 04 05;"Atelier ""Nord""; Poitiers";12345678900010;granted;verified;pkg-1;cellule-1;"contact.email,kyc.status,consent.status";2026-06-21T10:00:00Z');
  });
});
