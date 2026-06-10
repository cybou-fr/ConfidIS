export function csvEscape(value) {
  const text = value == null ? '' : String(value);
  return /[",\n\r;]/.test(text) ? `"${text.replaceAll('"', '""')}"` : text;
}

export function flattenData(value, prefix = '') {
  if (!value || typeof value !== 'object') return [];
  if (Array.isArray(value)) {
    return value.flatMap((item, idx) => {
      const path = `${prefix}[${idx}]`;
      if (item && typeof item === 'object') return flattenData(item, path);
      return [{ key: path, value: item == null ? '' : String(item) }];
    });
  }
  return Object.entries(value).flatMap(([key, val]) => {
    const path = prefix ? `${prefix}.${key}` : key;
    if (val && typeof val === 'object') return flattenData(val, path);
    return [{ key: path, value: val == null ? '' : String(val) }];
  });
}

function normalizeKey(value) {
  return value.toLowerCase().normalize('NFD').replace(/[\u0300-\u036f]/g, '');
}

export function findSharedValue(item, candidates) {
  const rows = flattenData(item.data);
  const normalized = rows.map((row) => ({
    key: normalizeKey(row.key),
    value: row.value,
  }));
  for (const candidate of candidates) {
    const wanted = normalizeKey(candidate);
    const direct = normalized.find((row) => row.key === wanted || row.key.endsWith(`.${wanted}`));
    if (direct?.value) return direct.value;
  }
  return '';
}

export function sharedItemsToCsv(items) {
  const rows = [[
    'package_id',
    'cellule_id',
    'owner_public_key',
    'recipient_public_key',
    'field',
    'value',
    'issued_at',
    'expires_at',
    'status',
    'package_hash',
  ]];
  for (const item of items) {
    const flattened = flattenData(item.data);
    if (flattened.length === 0) {
      rows.push([
        item.package_id,
        item.cellule_id,
        item.owner_public_key,
        item.recipient_public_key,
        '',
        '',
        item.issued_at,
        item.expires_at || '',
        item.status,
        item.package_hash,
      ]);
      continue;
    }
    for (const row of flattened) {
      rows.push([
        item.package_id,
        item.cellule_id,
        item.owner_public_key,
        item.recipient_public_key,
        row.key,
        row.value,
        item.issued_at,
        item.expires_at || '',
        item.status,
        item.package_hash,
      ]);
    }
  }
  return rows.map((row) => row.map(csvEscape).join(';')).join('\n');
}

export function sharedItemsToCrmCsv(items) {
  const rows = [[
    'first_name',
    'last_name',
    'email',
    'phone',
    'company',
    'siret',
    'consent_status',
    'kyc_status',
    'confidis_package_id',
    'confidis_cellule_id',
    'confidis_fields',
    'confidis_expires_at',
  ]];
  for (const item of items) {
    rows.push([
      findSharedValue(item, ['first_name', 'firstname', 'given_name', 'prenom', 'prénom']),
      findSharedValue(item, ['last_name', 'lastname', 'family_name', 'nom']),
      findSharedValue(item, ['email', 'mail', 'contact.email']),
      findSharedValue(item, ['phone', 'telephone', 'téléphone', 'mobile']),
      findSharedValue(item, ['company', 'organisation', 'organization', 'societe', 'société']),
      findSharedValue(item, ['siret', 'siren']),
      findSharedValue(item, ['consent_status', 'consent.status', 'consentement']),
      findSharedValue(item, ['kyc_status', 'kyc.status', 'status']),
      item.package_id,
      item.cellule_id,
      (item.fields || []).join(','),
      item.expires_at || '',
    ]);
  }
  return rows.map((row) => row.map(csvEscape).join(';')).join('\n');
}
