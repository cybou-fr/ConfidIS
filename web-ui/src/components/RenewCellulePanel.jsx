import { useState } from 'react';
import { Clock, Copy, Check, ChevronRight, X, AlertTriangle, Terminal, RefreshCw } from 'lucide-react';
import KeyPolicyNotice from './KeyPolicyNotice';

// ── Helpers ───────────────────────────────────────────────────────────────────

function isoDatePlusDays(days) {
  const d = new Date();
  const boundedDays = Math.min(Math.max(Number(days) || 1, 1), 365);
  d.setDate(d.getDate() + boundedDays);
  return d.toISOString().replace(/\.\d{3}Z$/, 'Z');
}

function buildRenewCommand(data) {
  const parts = ['confidis cellule renew'];
  parts.push(`  --cellule-id "${data.celluleId}"`);
  parts.push(`  --registry "${data.registry}"`);
  parts.push(`  --blob-store "${data.blobStore}"`);
  parts.push(`  --private-key "${data.privateKey}"`);
  parts.push(`  --cellule-key "${data.celluleKey}"`);
  parts.push(`  --expires-at "${isoDatePlusDays(data.extendDays)}"`);
  parts.push(`  --output renewal-receipt.json`);
  return parts.join(' \\\n');
}

const fieldLabelStyle = {
  display: 'block', fontSize: '0.78rem', color: 'var(--text-secondary)',
  marginBottom: '0.4rem', textTransform: 'uppercase', letterSpacing: '0.08em', fontWeight: 600,
};

const inputStyle = {
  width: '100%', padding: '0.7rem 0.9rem', borderRadius: '9px', boxSizing: 'border-box',
  background: 'rgba(255,255,255,0.04)', border: '1px solid var(--border-color)',
  color: 'var(--text-primary)', fontFamily: 'monospace', fontSize: '0.8rem', outline: 'none',
};

const sectionStyle = {
  background: 'rgba(255,255,255,0.02)', borderRadius: '10px',
  border: '1px solid var(--border-color)', padding: '1rem 1.25rem', marginBottom: '1rem',
};

// ── Cellule selector card ─────────────────────────────────────────────────────

function CelluleCard({ cellule, selected, onSelect }) {
  const daysLeft = cellule.days_left ?? null;
  const urgent = daysLeft !== null && daysLeft <= 7;
  const warning = daysLeft !== null && daysLeft <= 30;

  return (
    <div
      onClick={onSelect}
      style={{
        display: 'flex', alignItems: 'center', justifyContent: 'space-between',
        padding: '0.9rem 1rem', borderRadius: '10px', cursor: 'pointer',
        border: `1px solid ${selected ? 'var(--accent-primary)' : urgent ? 'rgba(255,42,122,0.3)' : 'var(--border-color)'}`,
        background: selected ? 'rgba(69,243,255,0.06)' : urgent ? 'rgba(255,42,122,0.04)' : 'rgba(255,255,255,0.02)',
        marginBottom: '0.6rem', transition: 'all 0.15s',
      }}
    >
      <div>
        <p style={{ fontWeight: 600, fontSize: '0.9rem', marginBottom: '0.15rem' }}>{cellule.name || cellule.id}</p>
        <p style={{ fontFamily: 'monospace', fontSize: '0.72rem', color: 'var(--text-secondary)' }}>{cellule.id}</p>
      </div>
      {daysLeft !== null && (
        <div style={{ display: 'flex', alignItems: 'center', gap: '0.35rem', fontSize: '0.8rem', fontWeight: 600,
          color: urgent ? '#f43f5e' : warning ? '#fb923c' : 'var(--text-secondary)' }}>
          <Clock size={13} />
          {daysLeft <= 0 ? 'Expirée' : `${daysLeft} j restants`}
        </div>
      )}
    </div>
  );
}

// ── Main panel ────────────────────────────────────────────────────────────────

/**
 * RenewCellulePanel — guided command generator for `confidis cellule renew`.
 *
 * Props:
 *   expiringSoon  Array<{ id, name, days_left }> — pre-filtered list from CellulesManager
 *   onClose       () => void
 */
export default function RenewCellulePanel({ expiringSoon = [], onClose }) {
  const [step, setStep] = useState(0);
  const [data, setData] = useState({
    celluleId: expiringSoon[0]?.id ?? '',
    registry: '~/.confidis/registry.json',
    blobStore: '~/.confidis/blobs',
    privateKey: '',
    celluleKey: '~/.confidis/cellule.key',
    extendDays: 365,
  });
  const [copied, setCopied] = useState(false);

  function onChange(key, val) { setData((p) => ({ ...p, [key]: val })); }

  const command = buildRenewCommand(data);

  function copy() {
    navigator.clipboard.writeText(command);
    setCopied(true);
    setTimeout(() => setCopied(false), 2500);
  }

  const canGenerate = data.celluleId.trim() && data.registry.trim() && data.blobStore.trim() &&
    data.celluleKey.trim() && data.privateKey.trim();

  return (
    <div style={{
      position: 'fixed', inset: 0, background: 'rgba(0,0,0,0.75)', backdropFilter: 'blur(8px)',
      display: 'flex', alignItems: 'center', justifyContent: 'center', zIndex: 1000, padding: '1rem',
    }}>
      <div className="glass-panel" style={{ width: '100%', maxWidth: '600px', padding: '2rem', maxHeight: '90vh', overflowY: 'auto' }}>
        {/* Header */}
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', marginBottom: '1.25rem' }}>
          <div>
            <h2 style={{ fontSize: '1.2rem', fontWeight: 700, display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
              <RefreshCw size={20} color="var(--accent-primary)" /> Renouveler une Cellule
            </h2>
            <p style={{ color: 'var(--text-secondary)', fontSize: '0.8rem', marginTop: '0.2rem' }}>
              Prolongez une Cellule temporaire avant son expiration. Le renouvellement est borné à 365 jours et signé par le propriétaire.
            </p>
          </div>
          <button onClick={onClose}
            style={{ background: 'transparent', border: 'none', color: 'var(--text-secondary)', cursor: 'pointer', padding: '0.25rem' }}>
            <X size={20} />
          </button>
        </div>

        {/* Step 0: select + configure */}
        {step === 0 && (
          <>
            {expiringSoon.length > 0 && (
              <div style={{ marginBottom: '1.25rem' }}>
                <p style={{ ...fieldLabelStyle, marginBottom: '0.6rem' }}>Expirent bientôt</p>
                {expiringSoon.map((c) => (
                  <CelluleCard key={c.id} cellule={c}
                    selected={data.celluleId === c.id}
                    onSelect={() => onChange('celluleId', c.id)} />
                ))}
              </div>
            )}

            <div style={sectionStyle}>
              <label style={fieldLabelStyle}>Cellule ID *</label>
              <input style={inputStyle} placeholder="cellule-id hex..."
                value={data.celluleId} onChange={(e) => onChange('celluleId', e.target.value)} />
            </div>

            <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(210px, 1fr))', gap: '0.85rem', marginBottom: '1rem' }}>
              <div>
                <label style={fieldLabelStyle}>Registre *</label>
                <input style={inputStyle} placeholder="~/.confidis/registry.json"
                  value={data.registry} onChange={(e) => onChange('registry', e.target.value)} />
              </div>
              <div>
                <label style={fieldLabelStyle}>Blob store *</label>
                <input style={inputStyle} placeholder="~/.confidis/blobs"
                  value={data.blobStore} onChange={(e) => onChange('blobStore', e.target.value)} />
              </div>
              <div>
                <label style={fieldLabelStyle}>Fichier de clé de Cellule *</label>
                <input style={inputStyle} placeholder="~/.confidis/cellule.key"
                  value={data.celluleKey} onChange={(e) => onChange('celluleKey', e.target.value)} />
              </div>
              <div>
                <label style={fieldLabelStyle}>Prolonger de (jours) *</label>
                <input style={inputStyle} type="number" min="1" max="365"
                  value={data.extendDays}
                  onChange={(e) => onChange('extendDays', Math.min(Math.max(Number(e.target.value) || 1, 1), 365))} />
                <p style={{ marginTop: '0.3rem', fontSize: '0.72rem', color: 'var(--text-secondary)' }}>
                  Nouvelle expiration : {new Date(Date.now() + Math.min(Math.max(Number(data.extendDays) || 1, 1), 365) * 86400000).toLocaleDateString()}
                </p>
              </div>
            </div>

            <div style={sectionStyle}>
              <KeyPolicyNotice />
              <label style={fieldLabelStyle}>Clé privée (hex) *</label>
              <input style={inputStyle} type="password" placeholder="ed25519 private key hex..."
                value={data.privateKey} onChange={(e) => onChange('privateKey', e.target.value)} />
            </div>

            <button onClick={() => setStep(1)} disabled={!canGenerate} className="btn btn-primary"
              style={{ width: '100%', opacity: canGenerate ? 1 : 0.4, marginTop: '0.25rem' }}>
              Générer la commande <ChevronRight size={16} />
            </button>
          </>
        )}

        {/* Step 1: command */}
        {step === 1 && (
          <>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '0.4rem' }}>
              <span style={{ ...fieldLabelStyle, margin: 0 }}>Commande de terminal</span>
              <button onClick={copy}
                style={{ display: 'flex', alignItems: 'center', gap: '0.35rem', background: 'transparent', border: 'none',
                  color: copied ? '#4ade80' : 'var(--accent-primary)', cursor: 'pointer', fontSize: '0.8rem', fontWeight: 600, padding: 0 }}>
                {copied ? <Check size={14} /> : <Copy size={14} />}
                {copied ? 'Copié !' : 'Copier'}
              </button>
            </div>

            <pre style={{
              background: 'rgba(0,0,0,0.5)', borderRadius: '10px', padding: '1rem', fontSize: '0.75rem',
              fontFamily: 'monospace', whiteSpace: 'pre-wrap', wordBreak: 'break-all', lineHeight: 1.7,
              color: '#e2e8f0', border: '1px solid var(--border-color)', marginBottom: '1rem',
              overflowX: 'auto', maxHeight: '220px',
            }}>
              {command}
            </pre>

            <div style={{ ...sectionStyle, background: 'rgba(69,243,255,0.04)', borderColor: 'rgba(69,243,255,0.15)', marginBottom: '1.25rem' }}>
              <div style={{ display: 'flex', gap: '0.6rem', alignItems: 'flex-start', fontSize: '0.8rem', color: 'var(--text-secondary)' }}>
                <Terminal size={14} style={{ flexShrink: 0, marginTop: '0.1rem', color: 'var(--accent-primary)' }} />
                <span>
                  Exécutez cette commande dans votre terminal. La CLI met à jour l’horodatage d’expiration sur chaque shard
                  de tous les noeuds et publie un nouvel enregistrement de Cellule signé dans le registre.
                </span>
              </div>
            </div>

            <div style={{ ...sectionStyle, background: 'rgba(255,42,122,0.04)', borderColor: 'rgba(255,42,122,0.2)', marginBottom: '1.25rem' }}>
              <p style={{ display: 'flex', gap: '0.5rem', fontSize: '0.8rem', color: '#f9a8d4', alignItems: 'flex-start' }}>
                <AlertTriangle size={14} style={{ flexShrink: 0, marginTop: '0.1rem' }} />
                Renouvelez avant l’expiration de la Cellule — une Cellule expirée ne peut pas être renouvelée et doit être re-téléversée.
              </p>
            </div>

            <div style={{ display: 'flex', gap: '0.75rem' }}>
              <button onClick={() => setStep(0)} className="btn btn-secondary" style={{ flex: 1 }}>Retour</button>
              <button onClick={onClose} className="btn btn-primary" style={{ flex: 2 }}>Terminé</button>
            </div>
          </>
        )}
      </div>
    </div>
  );
}
