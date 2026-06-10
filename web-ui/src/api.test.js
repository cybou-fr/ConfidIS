import { afterEach, describe, expect, it, vi } from 'vitest';

import {
  apiFetch,
  fetchCellules,
  fetchOperatorSharedCellule,
  fetchOperatorSharedCellules,
  formatBytes,
} from './api';

afterEach(() => {
  vi.restoreAllMocks();
});

function jsonResponse(body, status = 200) {
  return {
    ok: status >= 200 && status < 300,
    status,
    json: vi.fn(async () => body),
    text: vi.fn(async () => JSON.stringify(body)),
  };
}

describe('api helpers', () => {
  it('fetches JSON from the configured node URL', async () => {
    const fetchMock = vi.spyOn(globalThis, 'fetch').mockResolvedValue(jsonResponse({ ok: true }));

    await expect(apiFetch('/health')).resolves.toEqual({ ok: true });

    expect(fetchMock).toHaveBeenCalledWith('http://127.0.0.1:4433/health', { headers: {} });
  });

  it('returns empty Cellules when the registry endpoint is absent', async () => {
    vi.spyOn(globalThis, 'fetch').mockResolvedValue(jsonResponse({ error: 'missing' }, 404));

    await expect(fetchCellules()).resolves.toEqual([]);
  });

  it('builds operator shared-data list query with recipient and trimmed search', async () => {
    const fetchMock = vi.spyOn(globalThis, 'fetch').mockResolvedValue(jsonResponse({ items: [], count: 0 }));

    await fetchOperatorSharedCellules('abc123', '  email@example.test  ');

    expect(fetchMock).toHaveBeenCalledWith(
      'http://127.0.0.1:4433/operator/shared-cellules?recipient=abc123&q=email%40example.test',
      { headers: {} },
    );
  });

  it('encodes operator shared-data detail package IDs safely', async () => {
    const fetchMock = vi.spyOn(globalThis, 'fetch').mockResolvedValue(jsonResponse({ item: { package_id: 'pkg/1' } }));

    await fetchOperatorSharedCellule('pkg/1', 'recipient-hex');

    expect(fetchMock).toHaveBeenCalledWith(
      'http://127.0.0.1:4433/operator/shared-cellules/pkg%2F1?recipient=recipient-hex',
      { headers: {} },
    );
  });

  it('formats byte counts for dashboard display', () => {
    expect(formatBytes(0)).toBe('0 B');
    expect(formatBytes(1536)).toBe('1.5 KB');
    expect(formatBytes(1024 * 1024 * 2)).toBe('2 MB');
  });
});
