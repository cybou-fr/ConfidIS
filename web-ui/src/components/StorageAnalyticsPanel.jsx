import { useState, useEffect } from 'react';
import { X, BarChart3, HardDrive, RefreshCw } from 'lucide-react';
import { fetchReceipts, fetchCellules, fetchCapacity } from '../api';

// ── Helpers ────────────────────────────────────────────────────────────────────

function fmtBytes(n) {
  if (!n || n === 0) return '0 B';
  if (n < 1024) return `${n} B`;
  if (n < 1024 * 1024) return `${(n / 1024).toFixed(1)} KB`;
  if (n < 1024 * 1024 * 1024) return `${(n / (1024 * 1024)).toFixed(2)} MB`;
  return `${(n / (1024 * 1024 * 1024)).toFixed(2)} GB`;
}

function fmtDate(iso) {
  if (!iso) return '—';
  try {
    return new Date(iso).toLocaleDateString(undefined, { month: 'short', day: 'numeric', year: 'numeric' });
  } catch { return iso; }
}

function daysUntil(iso) {
  if (!iso) return null;
  const diff = new Date(iso).getTime() - Date.now();
  return Math.ceil(diff / 86_400_000);
}

// ── Stat card ──────────────────────────────────────────────────────────────────

function StatCard({ label, value, sub, accent }) {
  return (
    <div style={{
      background: 'rgba(255,255,255,0.03)', borderRadius: '10px',
      border: `1px solid ${accent ? 'rgba(69,243,255,0.25)' : 'var(--border-color)'}`,
      padding: '1rem 1.25rem', flex: 1, minWidth: '140px',
    }}>
      <p style={{ fontSize: '0.72rem', color: 'var(--text-secondary)', textTransform: 'uppercase', letterSpacing: '0.08em', marginBottom: '0.3rem' }}>{label}</p>
      <p style={{ fontSize: '1.4rem', fontWeight: 700, color: accent ? 'var(--accent-primary)' : 'var(--text-primary)' }}>{value}</p>
      {sub && <p style={{ fontSize: '0.75rem', color: 'var(--text-secondary)', marginTop: '0.2rem' }}>{sub}</p>}
    </div>
  );
}

// ── Activity bar chart ─────────────────────────────────────────────────────────

function ActivityChart({ receipts }) {
  // bucket by day (last 14 days)
  const buckets = {};
  const now = Date.now();
  for (let i = 13; i >= 0; i--) {
    const d = new Date(now - i * 86_400_000);
    buckets[d.toISOString().slice(0, 10)] = 0;
  }
  receipts.forEach((r) => {
    const day = (r.timestamp || r.stored_at || '').slice(0, 10);
    if (day in buckets) buckets[day]++;
  });
  const days = Object.entries(buckets);
  const max = Math.max(...days.map(([, v]) => v), 1);

  return (
    <div>
      <p style={{ fontSize: '0.78rem', color: 'var(--text-secondary)', textTransform: 'uppercase', letterSpacing: '0.08em', marginBottom: '0.6rem' }}>
        Activité — 14 derniers jours
      </p>
      <div style={{ display: 'flex', alignItems: 'flex-end', gap: '4px', height: '60px' }}>
        {days.map(([day, count]) => (
          <div key={day} style={{ flex: 1, display: 'flex', flexDirection: 'column', alignItems: 'center', gap: '3px' }}>
            <div title={`${day}: ${count} ops`} style={{
              width: '100%', borderRadius: '3px 3px 0 0',
              height: `${Math.max(3, (count / max) * 54)}px`,
              background: count > 0 ? 'var(--accent-primary)' : 'rgba(255,255,255,0.06)',
              transition: 'height 0.3s',
            }} />
          </div>
        ))}
      </div>
      <div style={{ display: 'flex', justifyContent: 'space-between', marginTop: '3px' }}>
        <span style={{ fontSize: '0.65rem', color: 'var(--text-secondary)' }}>{days[0][0].slice(5)}</span>
        <span style={{ fontSize: '0.65rem', color: 'var(--text-secondary)' }}>{days[days.length - 1][0].slice(5)}</span>
      </div>
    </div>
  );
}

// ── Cellule inventory rows ─────────────────────────────────────────────────────

function CelluleInventoryTable({ cellules }) {
  if (!cellules?.length) return (
    <p style={{ color: 'var(--text-secondary)', fontSize: '0.82rem', textAlign: 'center', padding: '1rem 0' }}>
      Aucune Cellule trouvée.
    </p>
  );

  return (
    <div>
      <div style={{ display: 'grid', gridTemplateColumns: '2fr 1fr 1fr 1fr', gap: '0.5rem',
        padding: '0.4rem 0.6rem', borderBottom: '1px solid var(--border-color)',
        fontSize: '0.7rem', color: 'var(--text-secondary)', textTransform: 'uppercase', letterSpacing: '0.07em' }}>
        <span>Nom / ID</span><span>Taille</span><span>Expiration</span><span>Jours restants</span>
      </div>
      {cellules.slice(0, 20).map((c) => {
        const days = daysUntil(c.expires_at);
        const urgent = days !== null && days <= 7;
        const warn = days !== null && days <= 30 && days > 7;
        return (
          <div key={c.id} style={{
            display: 'grid', gridTemplateColumns: '2fr 1fr 1fr 1fr', gap: '0.5rem',
            padding: '0.55rem 0.6rem', borderBottom: '1px solid rgba(255,255,255,0.04)',
            fontSize: '0.8rem', alignItems: 'center',
          }}>
            <div>
              <p style={{ fontWeight: 600, marginBottom: '0.1rem', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                {c.name || c.id}
              </p>
              <p style={{ fontSize: '0.68rem', color: 'var(--text-secondary)', fontFamily: 'monospace' }}>{c.id?.slice(0, 12)}…</p>
            </div>
            <span>{fmtBytes(c.size_bytes)}</span>
            <span style={{ fontSize: '0.75rem' }}>{fmtDate(c.expires_at)}</span>
            <span style={{ color: urgent ? '#f87171' : warn ? '#fbbf24' : 'var(--text-primary)', fontWeight: urgent || warn ? 600 : 400 }}>
              {days !== null ? `${days} j` : '—'}
            </span>
          </div>
        );
      })}
    </div>
  );
}

// ── Main panel ─────────────────────────────────────────────────────────────────

export default function StorageAnalyticsPanel({ onClose }) {
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  const [receipts, setReceipts] = useState([]);
  const [cellules, setCellules] = useState([]);
  const [capacity, setCapacity] = useState(null);

  async function load() {
    setLoading(true);
    setError(null);
    try {
      const [rec, cel, cap] = await Promise.allSettled([
        fetchReceipts(500),
        fetchCellules(),
        fetchCapacity(),
      ]);
      if (rec.status === 'fulfilled') setReceipts(rec.value.receipts ?? []);
      if (cel.status === 'fulfilled') setCellules(cel.value.cellules ?? []);
      if (cap.status === 'fulfilled') setCapacity(cap.value);
    } catch (err) {
      setError(err.message);
    } finally {
      setLoading(false);
    }
  }

  useEffect(() => { load(); }, []);

  // Derived stats
  const stored = receipts.filter((r) => r.receipt_type === 'Stored' || r.receipt_type === 'stored').length;
  const deleted = receipts.filter((r) => r.receipt_type === 'Deleted' || r.receipt_type === 'deleted').length;
  const gets = receipts.filter((r) => r.receipt_type === 'Get' || r.receipt_type === 'get').length;
  const totalBytes = cellules.reduce((acc, c) => acc + (c.size_bytes || 0), 0);
  const expiringSoon = cellules.filter((c) => { const d = daysUntil(c.expires_at); return d !== null && d <= 30; });

  return (
    <div style={{
      position: 'fixed', inset: 0, background: 'rgba(0,0,0,0.75)', backdropFilter: 'blur(8px)',
      display: 'flex', alignItems: 'center', justifyContent: 'center', zIndex: 1000, padding: '1rem',
    }}>
      <div className="glass-panel" style={{ width: '100%', maxWidth: '780px', padding: '2rem', maxHeight: '90vh', overflowY: 'auto' }}>
        {/* Header */}
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', marginBottom: '1.5rem' }}>
          <div>
            <h2 style={{ fontSize: '1.2rem', fontWeight: 700, display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
              <BarChart3 size={20} color="var(--accent-primary)" /> Analytique du stockage
            </h2>
            <p style={{ color: 'var(--text-secondary)', fontSize: '0.8rem', marginTop: '0.2rem' }}>
              Reçus de shards locaux · inventaire des Cellules · capacité du noeud
            </p>
          </div>
          <div style={{ display: 'flex', gap: '0.5rem' }}>
            <button onClick={load} style={{ background: 'transparent', border: '1px solid var(--border-color)', color: 'var(--text-secondary)', cursor: 'pointer', borderRadius: '8px', padding: '0.4rem 0.7rem', display: 'flex', alignItems: 'center', gap: '0.4rem', fontSize: '0.8rem' }}>
              <RefreshCw size={13} /> Rafraîchir
            </button>
            <button onClick={onClose} style={{ background: 'transparent', border: 'none', color: 'var(--text-secondary)', cursor: 'pointer', padding: '0.25rem' }}>
              <X size={20} />
            </button>
          </div>
        </div>

        {loading && <p style={{ color: 'var(--text-secondary)', textAlign: 'center', padding: '2rem 0' }}>Chargement de l’analytique…</p>}
        {error && (
          <div style={{ background: 'rgba(248,113,113,0.1)', border: '1px solid rgba(248,113,113,0.3)', borderRadius: '8px', padding: '0.8rem 1rem', marginBottom: '1rem', color: '#f87171', fontSize: '0.85rem' }}>
            Échec du chargement des données : {error}
          </div>
        )}

        {!loading && (
          <>
            {/* Summary stats */}
            <div style={{ display: 'flex', gap: '0.75rem', flexWrap: 'wrap', marginBottom: '1.5rem' }}>
              <StatCard label="Total Cellules" value={cellules.length} sub={`${fmtBytes(totalBytes)} stockés`} accent />
              <StatCard label="Reçus" value={receipts.length} sub={`${stored} stockés · ${deleted} suppr. · ${gets} lectures`} />
              {capacity && <StatCard label="Capacité du noeud" value={fmtBytes(capacity.used_bytes)} sub={`sur ${fmtBytes(capacity.total_bytes)} au total`} />}
              {expiringSoon.length > 0 && (
                <StatCard label="Expirent bientôt" value={expiringSoon.length} sub="sous 30 jours — renouvelez maintenant" accent />
              )}
            </div>

            {/* Activity chart */}
            {receipts.length > 0 && (
              <div style={{ background: 'rgba(255,255,255,0.02)', borderRadius: '10px', border: '1px solid var(--border-color)', padding: '1rem 1.25rem', marginBottom: '1.5rem' }}>
                <ActivityChart receipts={receipts} />
              </div>
            )}

            {/* Cellule inventory table */}
            <div>
              <p style={{ fontSize: '0.78rem', color: 'var(--text-secondary)', textTransform: 'uppercase', letterSpacing: '0.08em', marginBottom: '0.75rem', display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
                <HardDrive size={14} /> Inventaire des Cellules
                <span>(taille, durée et pression sur les quotas locaux)</span>
              </p>
              <div style={{ background: 'rgba(255,255,255,0.02)', borderRadius: '10px', border: '1px solid var(--border-color)', overflow: 'hidden' }}>
                <CelluleInventoryTable cellules={cellules} />
              </div>
              {cellules.length > 20 && (
                <p style={{ fontSize: '0.75rem', color: 'var(--text-secondary)', marginTop: '0.5rem', textAlign: 'right' }}>
                  Affichage de 20 sur {cellules.length} Cellules
                </p>
              )}
            </div>

            {/* Usage config hint */}
          </>
        )}
      </div>
    </div>
  );
}
