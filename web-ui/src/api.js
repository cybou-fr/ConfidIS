// `??` (not `||`): an explicit empty VITE_NODE_URL means "same-origin
// relative" — the production bundle is served BY the node, so requests must
// be relative (CSP is `connect-src 'self'`; an absolute localhost URL would
// be cross-origin + mixed-content and get blocked). Only a truly unset env
// var (local dev) falls back to the localhost default.
const NODE_URL = import.meta.env.VITE_NODE_URL ?? 'http://127.0.0.1:4433';
const UI_TOKEN = import.meta.env.VITE_UI_TOKEN || '';

function authHeaders() {
  return UI_TOKEN ? { Authorization: `Bearer ${UI_TOKEN}` } : {};
}

export async function apiFetch(path, options = {}) {
  const { skipToken, ...fetchOptions } = options;
  const headers = {
    ...(skipToken ? {} : authHeaders()),
    ...(options.headers || {}),
  };
  const res = await fetch(`${NODE_URL}${path}`, { ...fetchOptions, headers });
  if (!res.ok) throw new Error(`Erreur API ${res.status} sur ${path}`);
  return res.json();
}

export async function apiPost(path, body, options = {}) {
  const { skipToken, ...fetchOptions } = options;
  const headers = {
    'Content-Type': 'application/json',
    ...(skipToken ? {} : authHeaders()),
    ...(options.headers || {}),
  };
  const res = await fetch(`${NODE_URL}${path}`, {
    ...fetchOptions,
    method: 'POST',
    headers,
    body: JSON.stringify(body),
  });
  if (!res.ok) throw new Error(`Erreur API ${res.status} sur ${path}`);
  return res.json();
}

export async function fetchHealth() {
  return apiFetch('/health');
}

export async function fetchCapacity() {
  return apiFetch('/capacity');
}

export async function fetchMaintenance() {
  try {
    return await apiFetch('/maintenance');
  } catch (e) {
    if (e.message.includes('404')) {
      return { jobs: [], unavailable_on_public_surface: true };
    }
    throw e;
  }
}

export async function fetchReadiness() {
  try {
    return await apiFetch('/readiness');
  } catch (e) {
    if (e.message.includes('404')) {
      return { unavailable_on_public_surface: true, checks: [] };
    }
    throw e;
  }
}

export async function fetchEvidencePack() {
  try {
    return await apiFetch('/evidence-pack');
  } catch (e) {
    if (e.message.includes('404')) {
      return { unavailable_on_public_surface: true };
    }
    throw e;
  }
}

export async function fetchEvidencePackZip() {
  const res = await fetch(`${NODE_URL}/evidence-pack.zip`, { headers: authHeaders() });
  if (!res.ok) {
    if (res.status === 404) return null;
    throw new Error(`Erreur API ${res.status} sur /evidence-pack.zip`);
  }
  return res.blob();
}

export async function fetchPeers() {
  return apiFetch('/peers');
}

export async function fetchMetrics() {
  const res = await fetch(`${NODE_URL}/metrics`, { headers: authHeaders() });
  if (!res.ok) throw new Error(`Erreur API ${res.status} sur /metrics`);
  return res.text();
}

export function nodeBaseUrl() {
  return NODE_URL;
}

export function uiTokenConfigured() {
  return Boolean(UI_TOKEN);
}

/**
 * Fetch the Cellule registry served by the node.
 * Returns [] when the node has no registry_path configured (404).
 */
export async function fetchCellules() {
  try {
    return await apiFetch('/cellules');
  } catch (e) {
    if (e.message.includes('404')) return [];
    throw e;
  }
}

export async function fetchOperatorSharedCellules(recipientPublicKey, query = '') {
  const params = new URLSearchParams({ recipient: recipientPublicKey });
  if (query.trim()) params.set('q', query.trim());
  try {
    return await apiFetch(`/operator/shared-cellules?${params.toString()}`);
  } catch (e) {
    if (e.message.includes('404')) {
      return { items: [], count: 0, warning: '' };
    }
    throw e;
  }
}

export async function fetchOperatorSharedCellule(packageId, recipientPublicKey) {
  const params = new URLSearchParams({ recipient: recipientPublicKey });
  return apiFetch(`/operator/shared-cellules/${encodeURIComponent(packageId)}?${params.toString()}`);
}

export async function requestOwnerReportChallenge(celluleId) {
  return apiPost('/owner/report/challenge', { cellule_id: celluleId });
}

export async function verifyOwnerReportProof(proof) {
  return apiPost('/owner/report/verify', { proof });
}

/**
 * Fetch all shard receipts from the node, newest-first.
 * Returns { receipts: ShardReceipt[], count: number }.
 */
export async function fetchReceipts(limit = 200) {
  try {
    return await apiFetch(`/receipts?limit=${limit}`);
  } catch (e) {
    if (e.message.includes('404')) return { receipts: [], count: 0 };
    throw e;
  }
}

/** Fetch node pricing rules (public endpoint — no auth token required). */
export async function fetchPricing() {
  return apiFetch('/pricing', { skipToken: true });
}

/**
 * Fetch the node's mode descriptor.
 * Returns `{ node_role: "company" | "authority", production_profile: boolean }`.
 * Public endpoint, no auth.
 */
export async function fetchNodeInfo() {
  return apiFetch('/node-info', { skipToken: true });
}

export async function creditCybFromAuthority(body) {
  return apiPost('/ledger/transfer', body);
}

export async function debitCybToAuthority(body) {
  return apiPost('/ledger/debit', body);
}

export async function setCybBalanceFromAuthority(body) {
  return apiPost('/ledger/set-balance', body);
}

/**
 * Formats bytes into a human-readable string (e.g., 14.2 GB).
 */
export function formatBytes(bytes) {
  if (bytes === 0) return '0 B';
  const k = 1024;
  const sizes = ['B', 'KB', 'MB', 'GB', 'TB'];
  const i = Math.floor(Math.log(bytes) / Math.log(k));
  return parseFloat((bytes / Math.pow(k, i)).toFixed(1)) + ' ' + sizes[i];
}

/**
 * Return days remaining until an ISO-8601 expiry string, or null if expired.
 */
export function daysUntil(expiresAt) {
  if (!expiresAt) return null;
  const ms = new Date(expiresAt) - Date.now();
  if (ms <= 0) return 0;
  return Math.ceil(ms / (1000 * 60 * 60 * 24));
}

// ---------------------------------------------------------------------------
// Owner wallet operations: route access uses the UI token when configured;
// lifecycle mutations are additionally authenticated by owner signatures in body.
// ---------------------------------------------------------------------------

// --------------------------------------------------------------------------
// New wallet APIs for owner operations.
// --------------------------------------------------------------------------

/**
 * Create a new Cellule via owner-signed request.
 * Body: { create: CelluleOwnerCreate }.
 * Returns { cellule_id: CelluleId, expires_at: ISO8601, ... }.
 */
export async function createWalletCellule(body) {
  const res = await fetch(`${NODE_URL}/wallet/cellules`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', ...authHeaders() },
    body: JSON.stringify(body),
  });
  if (!res.ok) {
    const text = await res.text();
    throw new Error(text || `HTTP ${res.status}`);
  }
  return res.json();
}

/**
 * Get wallet index for an owner public key.
 * Returns { cellules: WalletCelluleSummary[] }.
 */
export async function getWalletIndex(ownerPublicKey) {
  const params = new URLSearchParams({ owner: ownerPublicKey });
  const res = await fetch(`${NODE_URL}/wallet/index?${params.toString()}`, { headers: authHeaders() });
  if (!res.ok) {
    const text = await res.text();
    throw new Error(text || `HTTP ${res.status}`);
  }
  return res.json();
}

/**
 * Renew a Cellule via owner-signed request.
 * Body: { renew: CelluleOwnerRenew }.
 * Returns { cellule_id: CelluleId, new_expiry: ISO8601 }.
 */
export async function renewWalletCellule(celluleId, body) {
  const res = await fetch(`${NODE_URL}/wallet/cellules/${encodeURIComponent(celluleId)}/renew`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', ...authHeaders() },
    body: JSON.stringify(body),
  });
  if (!res.ok) {
    const text = await res.text();
    throw new Error(text || `HTTP ${res.status}`);
  }
  return res.json();
}

/**
 * Delete a Cellule via owner-signed request.
 * Body: { delete: CelluleOwnerDelete }.
 * Returns 204 No Content.
 */
export async function deleteWalletCellule(celluleId, body) {
  const res = await fetch(`${NODE_URL}/wallet/cellules/${encodeURIComponent(celluleId)}/delete`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', ...authHeaders() },
    body: JSON.stringify(body),
  });
  if (!res.ok) {
    const text = await res.text();
    throw new Error(text || `HTTP ${res.status}`);
  }
  return res.status === 204 ? { deleted: true } : res.json();
}

/**
 * Create a recipient package via owner-signed request.
 * Body: { package: RecipientPackageRecord }.
 * Returns { package_id: UUID, cellule_id: CelluleId, ... }.
 */
export async function createWalletPackage(body) {
  const res = await fetch(`${NODE_URL}/wallet/packages`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', ...authHeaders() },
    body: JSON.stringify(body),
  });
  if (!res.ok) {
    const text = await res.text();
    throw new Error(text || `HTTP ${res.status}`);
  }
  return res.json();
}

/**
 * Get wallet packages for an owner public key.
 * Returns { packages: WalletPackageSummary[] }.
 */
export async function getWalletPackages(ownerPublicKey) {
  const params = new URLSearchParams({ owner: ownerPublicKey });
  const res = await fetch(`${NODE_URL}/wallet/packages?${params.toString()}`, { headers: authHeaders() });
  if (!res.ok) {
    const text = await res.text();
    throw new Error(text || `HTTP ${res.status}`);
  }
  return res.json();
}

/**
 * Remove a recipient package.
 * Body: { remove: RecipientPackageRemove }.
 * Returns 204 No Content.
 */
export async function removeWalletPackage(packageId, body) {
  const res = await fetch(`${NODE_URL}/wallet/packages/${encodeURIComponent(packageId)}/remove`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', ...authHeaders() },
    body: JSON.stringify(body),
  });
  if (!res.ok) {
    const text = await res.text();
    throw new Error(text || `HTTP ${res.status}`);
  }
  return res.status === 204 ? { removed: true } : res.json();
}
