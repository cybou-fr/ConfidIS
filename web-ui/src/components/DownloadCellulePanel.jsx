import { useState } from 'react';
import { Download, Copy, Check, ChevronRight, X, Terminal, ShieldCheck, AlertTriangle } from 'lucide-react';
import KeyPolicyNotice from './KeyPolicyNotice';

// ── Helpers ───────────────────────────────────────────────────────────────────

function buildGetCommand(data) {
  const parts = ['confidis cellule get'];
  parts.push(`  --cellule-id "${data.celluleId}"`);
  parts.push(`  --registry "${data.registry}"`);
  parts.push(`  --blob-store "${data.blobStore}"`);
  parts.push(`  --cellule-key "${data.celluleKey}"`);
  parts.push(`  --private-key "${data.privateKey}"`);
  parts.push(`  --output "${data.outputDir}"`);
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

// ── Checklist step ────────────────────────────────────────────────────────────

function CheckItem({ label }) {
  return (
    <div style={{ display: 'flex', alignItems: 'center', gap: '0.6rem', fontSize: '0.85rem', padding: '0.5rem 0', borderBottom: '1px solid var(--border-color)' }}>
      <ShieldCheck size={15} color="#4ade80" style={{ flexShrink: 0 }} />
      <span>{label}</span>
    </div>
  );
}

// ── Main panel ────────────────────────────────────────────────────────────────

/**
 * DownloadCellulePanel — guided command generator for `confidis cellule get`.
 *
 * Props:
 *   initialCelluleId  string  (optional pre-filled cellule ID from action menu)
 *   onClose           () => void
 */
export default function DownloadCellulePanel({ initialCelluleId = '', onClose }) {
  const [step, setStep] = useState(0);
  const [data, setData] = useState({
    celluleId: initialCelluleId,
    registry: '~/.confidis/registry.json',
    blobStore: '~/.confidis/blobs',
    celluleKey: '~/.confidis/cellule.key',
    privateKey: '',
    outputDir: '~/Downloads',
  });
  const [copied, setCopied] = useState(false);

  function onChange(key, val) { setData((p) => ({ ...p, [key]: val })); }

  const command = buildGetCommand(data);

  function copy() {
    navigator.clipboard.writeText(command);
    setCopied(true);
    setTimeout(() => setCopied(false), 2500);
  }

  const canGenerate = data.celluleId.trim() && data.registry.trim() && data.blobStore.trim() &&
    data.celluleKey.trim() && data.privateKey.trim() && data.outputDir.trim();

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
              <Download size={20} color="var(--accent-primary)" /> Télécharger une Cellule
            </h2>
            <p style={{ color: 'var(--text-secondary)', fontSize: '0.8rem', marginTop: '0.2rem' }}>
              Reconstruisez et déchiffrez une Cellule vers votre système de fichiers local.
            </p>
          </div>
          <button onClick={onClose}
            style={{ background: 'transparent', border: 'none', color: 'var(--text-secondary)', cursor: 'pointer', padding: '0.25rem' }}>
            <X size={20} />
          </button>
        </div>

        {/* Step 0: configure */}
        {step === 0 && (
          <>
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
                <label style={fieldLabelStyle}>Répertoire de sortie *</label>
                <input style={inputStyle} placeholder="~/Downloads"
                  value={data.outputDir} onChange={(e) => onChange('outputDir', e.target.value)} />
              </div>
            </div>

            <div style={sectionStyle}>
              <KeyPolicyNotice />
              <label style={fieldLabelStyle}>Clé privée (hex) *</label>
              <input style={inputStyle} type="password" placeholder="ed25519 private key hex..."
                value={data.privateKey} onChange={(e) => onChange('privateKey', e.target.value)} />
              <div style={{ marginTop: '0.6rem', display: 'flex', gap: '0.5rem', alignItems: 'flex-start', fontSize: '0.75rem', color: 'var(--text-secondary)' }}>
                <ShieldCheck size={13} color="var(--accent-primary)" style={{ flexShrink: 0, marginTop: '0.1rem' }} />
                <span>Sert uniquement à générer la commande de terminal — jamais envoyée à un serveur ni stockée.</span>
              </div>
            </div>

            <button onClick={() => setStep(1)} disabled={!canGenerate} className="btn btn-primary"
              style={{ width: '100%', opacity: canGenerate ? 1 : 0.4, marginTop: '0.25rem' }}>
              Générer la commande <ChevronRight size={16} />
            </button>
          </>
        )}

        {/* Step 1: command + security notes */}
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

            <div style={{ ...sectionStyle, background: 'rgba(69,243,255,0.04)', borderColor: 'rgba(69,243,255,0.15)', marginBottom: '1rem' }}>
              <div style={{ display: 'flex', gap: '0.6rem', alignItems: 'flex-start', fontSize: '0.8rem', color: 'var(--text-secondary)' }}>
                <Terminal size={14} style={{ flexShrink: 0, marginTop: '0.1rem', color: 'var(--accent-primary)' }} />
                <span>
                  Exécutez cette commande dans votre terminal. La CLI récupère tous les shards du blob store,
                  reconstruit le fichier via Reed-Solomon et le déchiffre avec votre clé de Cellule.
                  Le fichier déchiffré est écrit dans <code style={{ fontFamily: 'monospace', background: 'rgba(255,255,255,0.07)', padding: '0 0.3rem', borderRadius: '3px' }}>{data.outputDir}</code>.
                </span>
              </div>
            </div>

            {/* Security checklist */}
            <div style={{ ...sectionStyle, marginBottom: '1.25rem' }}>
              <p style={{ fontWeight: 600, fontSize: '0.82rem', marginBottom: '0.5rem', color: 'var(--text-primary)' }}>
                Garanties zero-knowledge
              </p>
              <CheckItem label="Les shards sont récupérés chiffrés — les noeuds ne voient jamais le texte en clair" />
              <CheckItem label="La reconstruction Reed-Solomon s’exécute localement dans la CLI" />
              <CheckItem label="Le déchiffrement ChaCha20-Poly1305 a lieu sur votre machine" />
              <CheckItem label="Votre clé privée ne quitte jamais votre terminal" />
              <div style={{ display: 'flex', gap: '0.5rem', alignItems: 'flex-start', marginTop: '0.75rem', fontSize: '0.78rem', color: '#fb923c' }}>
                <AlertTriangle size={13} style={{ flexShrink: 0, marginTop: '0.1rem' }} />
                <span>Supprimez ou sécurisez le fichier déchiffré après usage.</span>
              </div>
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
