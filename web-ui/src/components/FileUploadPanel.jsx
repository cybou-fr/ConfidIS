import React, { useState, useRef } from 'react';
import { Upload, File, Copy, Check, CheckCircle2, ChevronRight, ChevronLeft, Terminal, AlertTriangle, X, FolderOpen } from 'lucide-react';
import KeyPolicyNotice from './KeyPolicyNotice';

// ── Helpers ──────────────────────────────────────────────────────────────────

function fmtBytes(n) {
  if (n < 1024) return `${n} B`;
  if (n < 1024 * 1024) return `${(n / 1024).toFixed(1)} KB`;
  return `${(n / (1024 * 1024)).toFixed(2)} MB`;
}

function isoDatePlusDays(days) {
  const d = new Date();
  const boundedDays = Math.min(Math.max(Number(days) || 1, 1), 365);
  d.setDate(d.getDate() + boundedDays);
  return d.toISOString().split('T')[0] + 'T00:00:00Z';
}

function buildPutCommand(data) {
  const parts = ['confidis cellule put'];
  data.nodes.forEach((n) => n.trim() && parts.push(`  --node ${n.trim()}`));
  parts.push(`  --input "${data.inputPath}"`);
  parts.push(`  --work-dir "${data.workDir}"`);
  parts.push(`  --registry "${data.registry}"`);
  parts.push(`  --blob-store "${data.blobStore}"`);
  parts.push(`  --public-key "${data.publicKey}"`);
  parts.push(`  --private-key "${data.privateKey}"`);
  parts.push(`  --cellule-key "${data.celluleKey}"`);
  parts.push(`  --expires-at "${isoDatePlusDays(data.expiryDays)}"`);
  parts.push(`  --sequence ${data.sequence}`);
  parts.push(`  --output upload-receipt.json`);
  return parts.join(' \\\n');
}

// ── Shared styles ─────────────────────────────────────────────────────────────

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

// ── Step 1: Configure ─────────────────────────────────────────────────────────

function StepConfigure({ data, onChange, onNext }) {
  const fileRef = useRef(null);
  function handleFileDrop(e) {
    e.preventDefault();
    const file = e.dataTransfer?.files?.[0] ?? e.target?.files?.[0];
    if (!file) return;
    onChange('fileName', file.name);
    onChange('fileSize', file.size);
    // Suggest a sensible input path from the file name
    if (!data.inputPath) onChange('inputPath', `~/${file.name}`);
  }

  const nodeInputs = data.nodes.length ? data.nodes : [''];

  function setNode(i, val) {
    const updated = [...data.nodes];
    updated[i] = val;
    onChange('nodes', updated);
  }

  function addNode() { onChange('nodes', [...data.nodes, '']); }
  function removeNode(i) { onChange('nodes', data.nodes.filter((_, idx) => idx !== i)); }

  const canProceed =
    data.inputPath.trim() &&
    data.nodes.some((n) => n.trim()) &&
    data.workDir.trim() &&
    data.registry.trim() &&
    data.blobStore.trim() &&
    data.publicKey.trim();

  return (
    <div>
      {/* File drop zone */}
      <div
        onDragOver={(e) => e.preventDefault()}
        onDrop={handleFileDrop}
        onClick={() => fileRef.current?.click()}
        style={{
          border: `2px dashed ${data.fileName ? 'var(--accent-primary)' : 'var(--border-color)'}`,
          borderRadius: '12px', padding: '1.75rem', textAlign: 'center',
          cursor: 'pointer', marginBottom: '1.25rem', transition: 'border-color 0.2s',
          background: data.fileName ? 'rgba(69,243,255,0.04)' : 'transparent',
        }}
      >
        <input ref={fileRef} type="file" style={{ display: 'none' }} onChange={handleFileDrop} />
        {data.fileName ? (
          <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'center', gap: '0.75rem' }}>
            <File size={22} color="var(--accent-primary)" />
            <div style={{ textAlign: 'left' }}>
              <p style={{ fontWeight: 600, fontSize: '0.95rem' }}>{data.fileName}</p>
              <p style={{ color: 'var(--text-secondary)', fontSize: '0.8rem' }}>{fmtBytes(data.fileSize)}</p>
            </div>
          </div>
        ) : (
          <>
            <Upload size={28} color="var(--text-secondary)" style={{ marginBottom: '0.5rem' }} />
            <p style={{ fontWeight: 600, marginBottom: '0.25rem' }}>Sélectionnez ou déposez un fichier</p>
            <p style={{ color: 'var(--text-secondary)', fontSize: '0.8rem' }}>
              Le contenu du fichier n’est pas téléversé vers cette page — seuls le nom et la taille sont lus localement
            </p>
          </>
        )}
      </div>

      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(210px, 1fr))', gap: '0.85rem', marginBottom: '0.85rem' }}>
        <div>
          <label style={fieldLabelStyle}>Chemin du fichier sur le disque *</label>
          <input style={inputStyle} placeholder="/home/user/document.pdf"
            value={data.inputPath} onChange={(e) => onChange('inputPath', e.target.value)} />
        </div>
        <div>
          <label style={fieldLabelStyle}>Expiration (jours) *</label>
          <input style={inputStyle} type="number" min="1" max="365"
            value={data.expiryDays}
            onChange={(e) => onChange('expiryDays', Math.min(Math.max(Number(e.target.value) || 1, 1), 365))} />
          <p style={{ marginTop: '0.3rem', fontSize: '0.72rem', color: 'var(--text-secondary)' }}>
            Durée active de la copie réseau chiffrée : 1 à 365 jours. Gardez l’original hors réseau.
          </p>
        </div>
      </div>

      <div style={sectionStyle}>
        <label style={fieldLabelStyle}>Endpoints de noeuds * (au moins un)</label>
        {nodeInputs.map((n, i) => (
          <div key={i} style={{ display: 'flex', gap: '0.5rem', marginBottom: '0.5rem' }}>
            <input style={{ ...inputStyle, flex: 1 }} placeholder="http://127.0.0.1:4433"
              value={n} onChange={(e) => setNode(i, e.target.value)} />
            {nodeInputs.length > 1 && (
              <button onClick={() => removeNode(i)}
                style={{ background: 'transparent', border: 'none', color: 'var(--text-secondary)', cursor: 'pointer', padding: '0 0.5rem' }}>
                <X size={15} />
              </button>
            )}
          </div>
        ))}
        <button onClick={addNode}
          style={{ fontSize: '0.8rem', color: 'var(--accent-primary)', background: 'transparent', border: 'none', cursor: 'pointer', padding: 0 }}>
          + Ajouter un noeud
        </button>
      </div>

      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(170px, 1fr))', gap: '0.85rem', marginBottom: '0.85rem' }}>
        <div>
          <label style={fieldLabelStyle}>Répertoire de travail *</label>
          <input style={inputStyle} placeholder="~/.confidis/work"
            value={data.workDir} onChange={(e) => onChange('workDir', e.target.value)} />
        </div>
        <div>
          <label style={fieldLabelStyle}>Registre *</label>
          <input style={inputStyle} placeholder="~/.confidis/registry.json"
            value={data.registry} onChange={(e) => onChange('registry', e.target.value)} />
        </div>
        <div>
          <label style={fieldLabelStyle}>Blob store *</label>{/* terme technique */}
          <input style={inputStyle} placeholder="~/.confidis/blobs"
            value={data.blobStore} onChange={(e) => onChange('blobStore', e.target.value)} />
        </div>
      </div>

      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(210px, 1fr))', gap: '0.85rem', marginBottom: '0.85rem' }}>
        <div>
          <label style={fieldLabelStyle}>Votre clé publique (hex) *</label>
          <input style={inputStyle} placeholder="ed25519 public key hex (64 chars)"
            value={data.publicKey} onChange={(e) => onChange('publicKey', e.target.value)} />
        </div>
        <div>
          <label style={fieldLabelStyle}>Fichier de clé de Cellule *</label>
          <input style={inputStyle} placeholder="~/.confidis/cellule.key"
            value={data.celluleKey} onChange={(e) => onChange('celluleKey', e.target.value)} />
        </div>
      </div>

      <div style={{ ...sectionStyle, background: 'rgba(255,42,122,0.04)', borderColor: 'rgba(255,42,122,0.2)', marginBottom: '1.25rem' }}>
        <p style={{ display: 'flex', gap: '0.5rem', fontSize: '0.8rem', color: '#f9a8d4', alignItems: 'flex-start' }}>
          <AlertTriangle size={14} style={{ flexShrink: 0, marginTop: '0.1rem' }} />
          Votre clé privée sera ajoutée à l’étape 2. Elle n’apparaît que dans la commande de terminal — elle ne
          quitte jamais votre appareil et n’est jamais envoyée à cette page web.
        </p>
      </div>

      <button onClick={onNext} disabled={!canProceed} className="btn btn-primary"
        style={{ width: '100%', opacity: canProceed ? 1 : 0.4 }}>
        Continuer — Vérifier la commande <ChevronRight size={16} />
      </button>
    </div>
  );
}

// ── Step 2: Keys + CLI command ────────────────────────────────────────────────

function StepCommand({ data, onChange, onBack, onNext }) {
  const [copied, setCopied] = useState(false);
  const command = buildPutCommand(data);

  function copy() {
    navigator.clipboard.writeText(command);
    setCopied(true);
    setTimeout(() => setCopied(false), 2500);
  }

  const canProceed = data.privateKey.trim().length > 0;

  return (
    <div>
      <KeyPolicyNotice />
      <div style={{ ...sectionStyle, marginBottom: '1rem' }}>
        <label style={fieldLabelStyle}>Votre clé privée (hex) *</label>
        <input style={{ ...inputStyle, fontFamily: 'monospace' }} type="password"
          placeholder="clé privée ed25519 hex — sert uniquement à construire la commande de terminal"
          value={data.privateKey} onChange={(e) => onChange('privateKey', e.target.value)} />
        <p style={{ marginTop: '0.5rem', fontSize: '0.75rem', color: 'var(--text-secondary)' }}>
          La clé apparaîtra dans la commande de terminal ci-dessous mais n’est jamais envoyée à un serveur depuis cette page.
        </p>
      </div>

      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(210px, 1fr))', gap: '0.85rem', marginBottom: '1rem' }}>
        <div>
          <label style={fieldLabelStyle}>Numéro de séquence</label>
          <input style={inputStyle} type="number" min="1"
            value={data.sequence} onChange={(e) => onChange('sequence', Number(e.target.value))} />
          <p style={{ marginTop: '0.3rem', fontSize: '0.72rem', color: 'var(--text-secondary)' }}>
            À incrémenter pour chaque nouvelle Cellule créée avec la même paire de clés.
          </p>
        </div>
      </div>

      <div style={{ position: 'relative', marginBottom: '1.25rem' }}>
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '0.4rem' }}>
          <span style={{ ...fieldLabelStyle, margin: 0 }}>Commande de terminal</span>
          <button onClick={copy}
            style={{ display: 'flex', alignItems: 'center', gap: '0.35rem', background: 'transparent', border: 'none', color: copied ? '#4ade80' : 'var(--accent-primary)', cursor: 'pointer', fontSize: '0.8rem', fontWeight: 600, padding: 0 }}>
            {copied ? <Check size={14} /> : <Copy size={14} />}
            {copied ? 'Copié !' : 'Copier'}
          </button>
        </div>
        <pre style={{
          background: 'rgba(0,0,0,0.5)', borderRadius: '10px', padding: '1rem', fontSize: '0.75rem',
          fontFamily: 'monospace', whiteSpace: 'pre-wrap', wordBreak: 'break-all', lineHeight: 1.7,
          color: '#e2e8f0', border: '1px solid var(--border-color)', margin: 0,
          overflowX: 'auto', maxHeight: '260px',
        }}>
          {command}
        </pre>
      </div>

      <div style={{ ...sectionStyle, background: 'rgba(69,243,255,0.04)', borderColor: 'rgba(69,243,255,0.15)', marginBottom: '1.25rem' }}>
        <div style={{ display: 'flex', gap: '0.6rem', alignItems: 'flex-start', fontSize: '0.8rem', color: 'var(--text-secondary)' }}>
          <Terminal size={14} style={{ flexShrink: 0, marginTop: '0.1rem', color: 'var(--accent-primary)' }} />
          <span>
            Copiez la commande ci-dessus et exécutez-la dans votre terminal. La CLI chiffre le fichier, l’encode en
            Reed-Solomon, téléverse les shards vers chaque noeud et écrit un reçu JSON dans <code>upload-receipt.json</code>.
          </span>
        </div>
      </div>

      <div style={{ display: 'flex', gap: '0.75rem' }}>
        <button onClick={onBack} className="btn btn-secondary" style={{ flex: 1 }}>
          <ChevronLeft size={16} /> Retour
        </button>
        <button onClick={onNext} disabled={!canProceed} className="btn btn-primary" style={{ flex: 2, opacity: canProceed ? 1 : 0.4 }}>
          J’ai exécuté la commande <ChevronRight size={16} />
        </button>
      </div>
    </div>
  );
}

// ── Step 3: Done ──────────────────────────────────────────────────────────────

function StepDone({ data, onClose }) {
  const checks = [
    'Chiffrement des shards terminé (ChaCha20-Poly1305)',
    'Shards Reed-Solomon 20+10 téléversés vers les noeuds',
    'Manifeste signé écrit dans le blob store',
    'Enregistrement de Cellule écrit dans le registre',
    'Reçu de téléversement enregistré dans upload-receipt.json',
    'Admission vérifiée par quotas locaux et politique du noeud',
  ].filter(Boolean);

  return (
    <div style={{ textAlign: 'center' }}>
      <CheckCircle2 size={52} color="#4ade80" style={{ marginBottom: '0.75rem' }} />
      <h3 style={{ fontSize: '1.2rem', fontWeight: 700, marginBottom: '0.4rem' }}>Téléversement terminé</h3>
      <p style={{ color: 'var(--text-secondary)', fontSize: '0.875rem', marginBottom: '1.75rem' }}>
        {data.fileName ? `« ${data.fileName} » est désormais` : 'Votre fichier est désormais'} chiffré et distribué sur le réseau CONFIDIS.
      </p>

      <div style={{ ...sectionStyle, textAlign: 'left', marginBottom: '1.5rem' }}>
        {checks.map((c, i) => (
          <div key={i} style={{ display: 'flex', gap: '0.6rem', alignItems: 'center', padding: '0.4rem 0', fontSize: '0.85rem', borderBottom: i < checks.length - 1 ? '1px solid var(--border-color)' : 'none' }}>
            <Check size={14} color="#4ade80" style={{ flexShrink: 0 }} />
            {c}
          </div>
        ))}
      </div>

      <div style={{ ...sectionStyle, background: 'rgba(255,42,122,0.04)', borderColor: 'rgba(255,42,122,0.2)', textAlign: 'left', marginBottom: '1.5rem', fontSize: '0.8rem', color: '#f9a8d4' }}>
        <p style={{ display: 'flex', gap: '0.5rem' }}>
          <AlertTriangle size={14} style={{ flexShrink: 0, marginTop: '0.1rem' }} />
          Sauvegardez votre fichier de clé de Cellule et votre mnémonique. La perte de la clé entraîne une perte d’accès définitive — CONFIDIS n’a aucune récupération de clé, par conception.
        </p>
      </div>

      <button onClick={onClose} className="btn btn-primary" style={{ width: '100%' }}>
        Retour aux Cellules
      </button>
    </div>
  );
}

// ── Step indicator ────────────────────────────────────────────────────────────

function StepIndicator({ step }) {
  const steps = ['Configurer', 'Commande', 'Terminé'];
  return (
    <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', marginBottom: '1.75rem' }}>
      {steps.map((label, i) => {
        const active = i === step;
        const done = i < step;
        return (
          <React.Fragment key={i}>
            <div style={{ display: 'flex', alignItems: 'center', gap: '0.4rem' }}>
              <div style={{
                width: '22px', height: '22px', borderRadius: '50%', display: 'flex', alignItems: 'center',
                justifyContent: 'center', fontSize: '0.7rem', fontWeight: 700, flexShrink: 0,
                background: active ? 'var(--accent-primary)' : done ? 'rgba(69,243,255,0.2)' : 'rgba(255,255,255,0.06)',
                color: active ? '#0a0a0f' : done ? 'var(--accent-primary)' : 'var(--text-secondary)',
                border: done ? '1px solid var(--accent-primary)' : 'none',
              }}>
                {done ? '✓' : i + 1}
              </div>
              <span style={{ fontSize: '0.8rem', fontWeight: active ? 600 : 400, color: active ? 'var(--text-primary)' : 'var(--text-secondary)' }}>
                {label}
              </span>
            </div>
            {i < steps.length - 1 && (
              <div style={{ flex: 1, height: '1px', background: 'var(--border-color)' }} />
            )}
          </React.Fragment>
        );
      })}
    </div>
  );
}

// ── Main panel ────────────────────────────────────────────────────────────────

export default function FileUploadPanel({ onClose }) {
  const [step, setStep] = useState(0);
  const [data, setData] = useState({
    fileName: '',
    fileSize: 0,
    inputPath: '',
    nodes: [''],
    workDir: '~/.confidis/work',
    registry: '~/.confidis/registry.json',
    blobStore: '~/.confidis/blobs',
    publicKey: '',
    privateKey: '',
    celluleKey: '~/.confidis/cellule.key',
    expiryDays: 365,
    sequence: 1,
  });

  function onChange(key, val) {
    setData((prev) => ({ ...prev, [key]: val }));
  }

  return (
    <div style={{
      position: 'fixed', inset: 0, background: 'rgba(0,0,0,0.75)', backdropFilter: 'blur(8px)',
      display: 'flex', alignItems: 'center', justifyContent: 'center', zIndex: 1000, padding: '1rem',
    }}>
      <div className="glass-panel" style={{ width: '100%', maxWidth: '680px', padding: '2rem', maxHeight: '90vh', overflowY: 'auto' }}>
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', marginBottom: '1rem' }}>
          <div>
            <h2 style={{ fontSize: '1.2rem', fontWeight: 700, display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
              <FolderOpen size={20} color="var(--accent-primary)" /> Téléverser un fichier vers une Cellule
            </h2>
            <p style={{ color: 'var(--text-secondary)', fontSize: '0.8rem', marginTop: '0.2rem' }}>
              Le chiffrement et la distribution créent une copie réseau temporaire ; votre original reste hors réseau.
            </p>
          </div>
          <button onClick={onClose}
            style={{ background: 'transparent', border: 'none', color: 'var(--text-secondary)', cursor: 'pointer', padding: '0.25rem' }}>
            <X size={20} />
          </button>
        </div>

        <StepIndicator step={step} />

        {step === 0 && <StepConfigure data={data} onChange={onChange} onNext={() => setStep(1)} />}
        {step === 1 && <StepCommand data={data} onChange={onChange} onBack={() => setStep(0)} onNext={() => setStep(2)} />}
        {step === 2 && <StepDone data={data} onClose={onClose} />}
      </div>
    </div>
  );
}
