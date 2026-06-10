import { useState, useEffect } from 'react';
import { ClipboardList, RefreshCw, X, ShieldCheck, Trash2, HardDrive, AlertTriangle, Download } from 'lucide-react';
import { fetchReceipts } from '../api';

// ── Helpers ───────────────────────────────────────────────────────────────────

const RECEIPT_TYPE_META = {
  Stored:  { label: 'Stocké',   icon: HardDrive,    color: '#4ade80', bg: 'rgba(74,222,128,0.08)'  },
  Deleted: { label: 'Supprimé', icon: Trash2,        color: '#f43f5e', bg: 'rgba(244,63,94,0.08)'   },
  Get:     { label: 'Lecture',  icon: Download,      color: 'var(--accent-primary)', bg: 'rgba(69,243,255,0.06)' },
};

function meta(type) {
  return RECEIPT_TYPE_META[type] ?? { label: type, icon: ShieldCheck, color: 'var(--text-secondary)', bg: 'rgba(255,255,255,0.04)' };
}

function fmtDate(iso) {
  if (!iso) return '—';
  return new Date(iso).toLocaleString(undefined, { year: 'numeric', month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit' });
}

function fmtBytes(n) {
  if (!n) return '—';
  if (n < 1024) return `${n} B`;
  if (n < 1024 * 1024) return `${(n / 1024).toFixed(1)} KB`;
  return `${(n / 1024 / 1024).toFixed(1)} MB`;
}

// ── Row ───────────────────────────────────────────────────────────────────────

function ReceiptRow({ receipt }) {
  const m = meta(receipt.receipt_type);
  const Icon = m.icon;

  return (
    <div style={{
      display: 'grid', gridTemplateColumns: '40px 1fr auto', alignItems: 'center',
      gap: '0.85rem', padding: '0.85rem 1rem', borderBottom: '1px solid var(--border-color)',
    }}>
      <div style={{ width: 36, height: 36, borderRadius: '50%', flexShrink: 0, display: 'flex', alignItems: 'center', justifyContent: 'center', background: m.bg }}>
        <Icon size={16} color={m.color} />
      </div>
      <div style={{ minWidth: 0 }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: '0.6rem', marginBottom: '0.2rem' }}>
          <span style={{ fontWeight: 600, fontSize: '0.82rem', color: m.color }}>{m.label}</span>
          <span style={{ fontFamily: 'monospace', fontSize: '0.7rem', color: 'var(--text-secondary)', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap', maxWidth: '240px' }}>
            {receipt.shard_id}
          </span>
        </div>
        <div style={{ fontSize: '0.72rem', color: 'var(--text-secondary)' }}>
          {fmtDate(receipt.issued_at)} · {fmtBytes(receipt.size_bytes)}
          {receipt.expires_at && ` · expire ${fmtDate(receipt.expires_at)}`}
        </div>
      </div>
      <div style={{ display: 'flex', alignItems: 'center', gap: '0.4rem', flexShrink: 0 }}>
        {receipt.signature ? (
          <span title="Reçu signé" style={{ display: 'flex', alignItems: 'center', gap: '0.25rem', fontSize: '0.72rem', color: '#4ade80' }}>
            <ShieldCheck size={12} /> Signé
          </span>
        ) : (
          <span title="Reçu non signé" style={{ fontSize: '0.72rem', color: 'var(--text-secondary)' }}>
            Non signé
          </span>
        )}
      </div>
    </div>
  );
}

// ── Main panel ────────────────────────────────────────────────────────────────

/**
 * AuditLogPanel — lists all shard receipts from the node, newest-first.
 *
 * Props:
 *   onClose   () => void
 */
export default function AuditLogPanel({ onClose }) {
  const [data, setData] = useState(null);
  const [error, setError] = useState(null);
  const [loading, setLoading] = useState(true);
  const [filter, setFilter] = useState('all');

  async function load() {
    setLoading(true);
    setError(null);
    try {
      const result = await fetchReceipts(500);
      setData(result);
    } catch (e) {
      const isOffline = e instanceof TypeError && /fetch|network/i.test(e.message);
      setError(isOffline ? 'Noeud injoignable — vérifiez VITE_NODE_URL' : e.message);
    } finally {
      setLoading(false);
    }
  }

  useEffect(() => { load(); }, []);

  const receipts = data?.receipts ?? [];
  const visible = filter === 'all' ? receipts : receipts.filter((r) => r.receipt_type === filter);

  const counts = receipts.reduce((acc, r) => {
    acc[r.receipt_type] = (acc[r.receipt_type] ?? 0) + 1;
    return acc;
  }, {});

  const filterBtn = (key, label) => (
    <button onClick={() => setFilter(key)}
      style={{
        padding: '0.35rem 0.75rem', borderRadius: '20px', fontSize: '0.78rem', fontWeight: 600, cursor: 'pointer',
        background: filter === key ? 'rgba(69,243,255,0.12)' : 'transparent',
        border: `1px solid ${filter === key ? 'var(--accent-primary)' : 'var(--border-color)'}`,
        color: filter === key ? 'var(--accent-primary)' : 'var(--text-secondary)',
      }}>
      {label}
    </button>
  );

  return (
    <div style={{
      position: 'fixed', inset: 0, background: 'rgba(0,0,0,0.75)', backdropFilter: 'blur(8px)',
      display: 'flex', alignItems: 'center', justifyContent: 'center', zIndex: 1000, padding: '1rem',
    }}>
      <div className="glass-panel" style={{ width: '100%', maxWidth: '680px', padding: '2rem', maxHeight: '90vh', display: 'flex', flexDirection: 'column' }}>
        {/* Header */}
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', marginBottom: '1.25rem', flexShrink: 0 }}>
          <div>
            <h2 style={{ fontSize: '1.2rem', fontWeight: 700, display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
              <ClipboardList size={20} color="var(--accent-primary)" /> Journal d’audit
            </h2>
            <p style={{ color: 'var(--text-secondary)', fontSize: '0.8rem', marginTop: '0.2rem' }}>
              Chronologie des reçus de shards de ce noeud — du plus récent au plus ancien.
            </p>
          </div>
          <div style={{ display: 'flex', gap: '0.6rem', alignItems: 'center' }}>
            <button onClick={load} title="Rafraîchir"
              style={{ background: 'transparent', border: '1px solid var(--border-color)', borderRadius: '8px', color: 'var(--text-secondary)', cursor: 'pointer', padding: '0.4rem', display: 'flex', alignItems: 'center' }}>
              <RefreshCw size={14} />
            </button>
            <button onClick={onClose}
              style={{ background: 'transparent', border: 'none', color: 'var(--text-secondary)', cursor: 'pointer', padding: '0.25rem' }}>
              <X size={20} />
            </button>
          </div>
        </div>

        {/* Stats row */}
        {data && (
          <div style={{ display: 'flex', gap: '1rem', marginBottom: '1rem', flexShrink: 0, flexWrap: 'wrap' }}>
            {[
              { key: 'Stored',  label: 'Stockés',   color: '#4ade80' },
              { key: 'Deleted', label: 'Supprimés', color: '#f43f5e' },
              { key: 'Get',     label: 'Lectures',  color: 'var(--accent-primary)' },
            ].map(({ key, label, color }) => (
              <div key={key} style={{ display: 'flex', gap: '0.4rem', alignItems: 'center', fontSize: '0.82rem' }}>
                <span style={{ fontWeight: 700, color }}>{counts[key] ?? 0}</span>
                <span style={{ color: 'var(--text-secondary)' }}>{label}</span>
              </div>
            ))}
            <span style={{ color: 'var(--text-secondary)', fontSize: '0.78rem', marginLeft: 'auto' }}>
              {receipts.length} au total
            </span>
          </div>
        )}

        {/* Filter chips */}
        <div style={{ display: 'flex', gap: '0.5rem', marginBottom: '1rem', flexShrink: 0, flexWrap: 'wrap' }}>
          {filterBtn('all', 'Tous')}
          {filterBtn('Stored', 'Stockés')}
          {filterBtn('Deleted', 'Supprimés')}
          {filterBtn('Get', 'Lectures')}
        </div>

        {/* Error */}
        {error && (
          <div style={{ display: 'flex', gap: '0.6rem', alignItems: 'center', padding: '0.75rem 1rem', background: 'rgba(255,42,122,0.06)', border: '1px solid rgba(255,42,122,0.2)', borderRadius: '10px', marginBottom: '1rem', flexShrink: 0 }}>
            <AlertTriangle size={14} color="#f9a8d4" />
            <span style={{ color: '#f9a8d4', fontSize: '0.82rem' }}>{error}</span>
          </div>
        )}

        {/* Receipt list */}
        <div style={{ overflowY: 'auto', flex: 1, borderRadius: '10px', border: '1px solid var(--border-color)', background: 'rgba(0,0,0,0.2)' }}>
          {loading && (
            <div style={{ textAlign: 'center', padding: '3rem', color: 'var(--text-secondary)', fontSize: '0.875rem' }}>
              Chargement des reçus…
            </div>
          )}
          {!loading && visible.length === 0 && !error && (
            <div style={{ textAlign: 'center', padding: '3rem', color: 'var(--text-secondary)', fontSize: '0.875rem' }}>
              {filter === 'all' ? 'Aucun reçu pour l’instant — les reçus sont créés lorsque des shards sont stockés ou supprimés.' : 'Aucun reçu pour ce filtre.'}
            </div>
          )}
          {!loading && visible.map((r) => <ReceiptRow key={r.receipt_id} receipt={r} />)}
        </div>

        <div style={{ marginTop: '1rem', flexShrink: 0, fontSize: '0.75rem', color: 'var(--text-secondary)' }}>
          Les reçus sont stockés sous forme de fichiers JSON dans <code style={{ background: 'rgba(255,255,255,0.07)', padding: '0 0.3rem', borderRadius: '3px', fontFamily: 'monospace' }}>{'{store_path}'}/receipts/</code> sur le noeud.
        </div>
      </div>
    </div>
  );
}
