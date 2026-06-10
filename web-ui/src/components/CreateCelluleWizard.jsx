import React, { useState } from 'react';
import {
  X,
  ChevronRight,
  ChevronLeft,
  Terminal,
  Copy,
  Check,
  ShieldCheck,
  Key,
  CheckCircle,
  AlertTriangle,
} from 'lucide-react';

const STEPS = ['Configurer', 'Clés', 'Commande CLI', 'Terminé'];

const inputStyle = {
  width: '100%',
  padding: '0.75rem 1rem',
  borderRadius: '10px',
  background: 'rgba(255,255,255,0.04)',
  border: '1px solid var(--border-color)',
  color: 'var(--text-primary)',
  fontSize: '0.875rem',
  outline: 'none',
  boxSizing: 'border-box',
};

const labelStyle = {
  display: 'block',
  fontSize: '0.75rem',
  color: 'var(--text-secondary)',
  marginBottom: '0.4rem',
  textTransform: 'uppercase',
  letterSpacing: '0.08em',
  fontWeight: 600,
};

function isoDatePlusDays(days) {
  const d = new Date();
  const boundedDays = Math.min(Math.max(Number(days) || 1, 1), 365);
  d.setDate(d.getDate() + boundedDays);
  return d.toISOString().split('T')[0] + 'T00:00:00Z';
}

function StepIndicator({ current }) {
  return (
    <div style={{ display: 'flex', alignItems: 'center', gap: '0', marginBottom: '2rem' }}>
      {STEPS.map((label, i) => {
        const done = i < current;
        const active = i === current;
        return (
          <React.Fragment key={i}>
            <div style={{ display: 'flex', flexDirection: 'column', alignItems: 'center', gap: '0.35rem' }}>
              <div
                style={{
                  width: '28px',
                  height: '28px',
                  borderRadius: '50%',
                  display: 'flex',
                  alignItems: 'center',
                  justifyContent: 'center',
                  fontSize: '0.75rem',
                  fontWeight: 700,
                  background: done
                    ? 'rgba(74,222,128,0.15)'
                    : active
                    ? 'rgba(69,243,255,0.15)'
                    : 'rgba(255,255,255,0.05)',
                  border: `2px solid ${
                    done ? '#4ade80' : active ? 'var(--accent-primary)' : 'var(--border-color)'
                  }`,
                  color: done ? '#4ade80' : active ? 'var(--accent-primary)' : 'var(--text-secondary)',
                }}
              >
                {done ? <Check size={14} /> : i + 1}
              </div>
              <span
                style={{
                  fontSize: '0.7rem',
                  color: active ? 'var(--text-primary)' : 'var(--text-secondary)',
                  fontWeight: active ? 600 : 400,
                  whiteSpace: 'nowrap',
                }}
              >
                {label}
              </span>
            </div>
            {i < STEPS.length - 1 && (
              <div
                style={{
                  flex: 1,
                  height: '2px',
                  background: done ? 'rgba(74,222,128,0.4)' : 'var(--border-color)',
                  margin: '0 6px',
                  marginBottom: '1.1rem',
                }}
              />
            )}
          </React.Fragment>
        );
      })}
    </div>
  );
}

// ── Step 1: Configure ─────────────────────────────────────────────────────────

function StepConfigure({ data, onChange }) {
  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: '1.25rem' }}>
      <div>
        <label style={labelStyle}>Nom d’affichage de la Cellule</label>
        <input
          style={inputStyle}
          type="text"
          placeholder="ex. Mes fichiers de projet"
          value={data.name}
          onChange={(e) => onChange('name', e.target.value)}
        />
        <p style={{ fontSize: '0.72rem', color: 'var(--text-secondary)', marginTop: '0.3rem' }}>
          Libellé lisible — stocké localement dans votre registre uniquement.
        </p>
      </div>
      <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '1rem' }}>
        <div>
          <label style={labelStyle}>Expiration (jours)</label>
          <input
            style={inputStyle}
            type="number"
            min="1"
            max="365"
            placeholder="365"
            value={data.expiryDays}
            onChange={(e) => onChange('expiryDays', String(Math.min(Math.max(Number(e.target.value) || 1, 1), 365)))}
          />
          <p style={{ fontSize: '0.72rem', color: 'var(--text-secondary)', marginTop: '0.3rem' }}>
            Durée active de la Cellule réseau : 1 à 365 jours.
          </p>
        </div>
        <div>
          <label style={labelStyle}>Nature de la Cellule</label>
          <div style={{ ...inputStyle, fontFamily: 'inherit', color: 'var(--text-secondary)' }}>
            Copie réseau temporaire chiffrée ; l’original reste chez vous, hors réseau CONFIDIS.
          </div>
        </div>
      </div>
      <div>
        <label style={labelStyle}>Endpoint du noeud</label>
        <input
          style={{ ...inputStyle, fontFamily: 'monospace', fontSize: '0.8rem' }}
          type="text"
          placeholder="http://127.0.0.1:4433"
          value={data.nodeEndpoint}
          onChange={(e) => onChange('nodeEndpoint', e.target.value)}
        />
      </div>
      <div>
        <label style={labelStyle}>Chemin du fichier de registre</label>
        <input
          style={{ ...inputStyle, fontFamily: 'monospace', fontSize: '0.8rem' }}
          type="text"
          placeholder="/home/user/.confidis/registry.json"
          value={data.registryPath}
          onChange={(e) => onChange('registryPath', e.target.value)}
        />
      </div>
    </div>
  );
}

// ── Step 2: Key Setup ─────────────────────────────────────────────────────────

function StepKeySetup({ data, onChange }) {
  const [keygenCopied, setKeygenCopied] = useState(false);
  const keygenCmd = 'confidis cellule keygen';

  function copyKeygen() {
    navigator.clipboard.writeText(keygenCmd);
    setKeygenCopied(true);
    setTimeout(() => setKeygenCopied(false), 2000);
  }

  const isValidHex = /^[0-9a-fA-F]{64}$/.test(data.publicKeyHex.trim());

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: '1.25rem' }}>
      <div
        style={{
          padding: '1rem',
          background: 'rgba(69,243,255,0.06)',
          border: '1px solid rgba(69,243,255,0.2)',
          borderRadius: '10px',
          fontSize: '0.825rem',
          lineHeight: 1.6,
          color: 'var(--text-secondary)',
        }}
      >
        <p style={{ color: 'var(--text-primary)', fontWeight: 600, marginBottom: '0.4rem' }}>
          <Key size={14} style={{ verticalAlign: 'middle', marginRight: '0.4rem' }} />
          Génération de clé sécurisée
        </p>
        Le matériel de clé est généré par la CLI — pas dans le navigateur. Cela garde votre clé
        privée hors de la mémoire JavaScript et du stockage du navigateur.
      </div>

      <div>
        <label style={labelStyle}>Étape 1 — Générer une nouvelle clé de Cellule</label>
        <div
          style={{
            display: 'flex',
            alignItems: 'center',
            gap: '0.75rem',
            background: 'rgba(0,0,0,0.4)',
            border: '1px solid var(--border-color)',
            borderRadius: '10px',
            padding: '0.75rem 1rem',
            fontFamily: 'monospace',
            fontSize: '0.875rem',
          }}
        >
          <Terminal size={16} color="var(--accent-primary)" style={{ flexShrink: 0 }} />
          <span style={{ flex: 1, color: '#a5f3fc' }}>{keygenCmd}</span>
          <button
            onClick={copyKeygen}
            style={{
              background: 'transparent',
              border: 'none',
              color: keygenCopied ? '#4ade80' : 'var(--text-secondary)',
              cursor: 'pointer',
              padding: '2px',
            }}
          >
            {keygenCopied ? <Check size={15} /> : <Copy size={15} />}
          </button>
        </div>
        <p style={{ fontSize: '0.72rem', color: 'var(--text-secondary)', marginTop: '0.4rem' }}>
          Exécutez cette commande dans votre terminal. Elle affiche une phrase mnémonique et une
          clé publique en hex. Conservez la mnémonique hors ligne en lieu sûr — elle est irrécupérable.
        </p>
      </div>

      <div>
        <label style={labelStyle}>Étape 2 — Collez la clé publique Ed25519 (hex)</label>
        <input
          style={{
            ...inputStyle,
            fontFamily: 'monospace',
            fontSize: '0.8rem',
            borderColor: data.publicKeyHex
              ? isValidHex
                ? 'rgba(74,222,128,0.5)'
                : 'rgba(255,42,122,0.5)'
              : 'var(--border-color)',
          }}
          type="text"
          placeholder="hex de 64 caractères issu de `confidis cellule keygen`"
          value={data.publicKeyHex}
          onChange={(e) => onChange('publicKeyHex', e.target.value.trim())}
          spellCheck={false}
        />
        {data.publicKeyHex && !isValidHex && (
          <p style={{ fontSize: '0.72rem', color: 'var(--accent-secondary)', marginTop: '0.3rem', display: 'flex', alignItems: 'center', gap: '0.3rem' }}>
            <AlertTriangle size={12} /> Doit faire exactement 64 caractères hex (32 octets).
          </p>
        )}
        {data.publicKeyHex && isValidHex && (
          <p style={{ fontSize: '0.72rem', color: '#4ade80', marginTop: '0.3rem', display: 'flex', alignItems: 'center', gap: '0.3rem' }}>
            <Check size={12} /> Clé publique Ed25519 valide.
          </p>
        )}
      </div>
    </div>
  );
}

// ── Step 3: CLI Command ───────────────────────────────────────────────────────

function buildCliCommand(data) {
  const parts = [
    'confidis cellule put',
    `--node ${data.nodeEndpoint || 'http://127.0.0.1:4433'}`,
    '--input "/chemin/vers/votre-fichier"',
    '--work-dir "~/.confidis/work"',
    `--registry "${data.registryPath || '~/.confidis/registry.json'}"`,
    '--blob-store "~/.confidis/blobs"',
    `--public-key "${data.publicKeyHex}"`,
    '--private-key "<votre-cle-privee-hex>"',
    '--cellule-key "~/.confidis/cellule.key"',
    `--expires-at "${isoDatePlusDays(data.expiryDays)}"`,
    '--output upload-receipt.json',
  ]
    .join(' \\\n  ');
  return parts;
}

function StepCliCommand({ data }) {
  const [copied, setCopied] = useState(false);
  const cmd = buildCliCommand(data);

  function copy() {
    navigator.clipboard.writeText(cmd);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  }

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: '1.25rem' }}>
      <p style={{ fontSize: '0.875rem', color: 'var(--text-secondary)', lineHeight: 1.6 }}>
        CONFIDIS ne crée pas une Cellule vide permanente. La Cellule temporaire est créée lors du premier
        <code> cellule put </code> propriétaire-signé, avec une expiration bornée à 365 jours.
      </p>

      <div>
        <div
          style={{
            display: 'flex',
            justifyContent: 'space-between',
            alignItems: 'center',
            marginBottom: '0.5rem',
          }}
        >
          <label style={labelStyle}>Commande réelle de création + téléversement</label>
          <button
            onClick={copy}
            style={{
              display: 'flex',
              alignItems: 'center',
              gap: '0.4rem',
              background: 'rgba(69,243,255,0.1)',
              border: '1px solid rgba(69,243,255,0.3)',
              color: copied ? '#4ade80' : 'var(--accent-primary)',
              borderRadius: '6px',
              padding: '0.3rem 0.75rem',
              fontSize: '0.75rem',
              fontWeight: 600,
              cursor: 'pointer',
            }}
          >
            {copied ? <Check size={13} /> : <Copy size={13} />}
            {copied ? 'Copié !' : 'Copier'}
          </button>
        </div>
        <pre
          style={{
            background: 'rgba(0,0,0,0.5)',
            border: '1px solid var(--border-color)',
            borderRadius: '10px',
            padding: '1rem 1.25rem',
            fontFamily: 'monospace',
            fontSize: '0.8rem',
            color: '#a5f3fc',
            overflowX: 'auto',
            whiteSpace: 'pre-wrap',
            wordBreak: 'break-all',
            margin: 0,
            lineHeight: 1.6,
          }}
        >
          {cmd}
        </pre>
      </div>

      <div
        style={{
          padding: '0.875rem 1rem',
          background: 'rgba(251,191,36,0.08)',
          border: '1px solid rgba(251,191,36,0.25)',
          borderRadius: '10px',
          fontSize: '0.8rem',
          color: '#fde68a',
          lineHeight: 1.6,
        }}
      >
        <AlertTriangle size={13} style={{ verticalAlign: 'middle', marginRight: '0.4rem' }} />
        Remplacez le chemin de fichier et la clé privée dans votre terminal. La perte de clé entraîne
        une perte d’accès à cette Cellule réseau, pas une perte de vos originaux hors réseau.
      </div>
    </div>
  );
}

// ── Step 4: Done ──────────────────────────────────────────────────────────────

function StepDone({ data, onClose }) {
  return (
    <div style={{ display: 'flex', flexDirection: 'column', alignItems: 'center', gap: '1.25rem', padding: '1rem 0', textAlign: 'center' }}>
      <CheckCircle size={56} color="#4ade80" />
      <div>
        <h3 style={{ fontSize: '1.4rem', fontWeight: 700, marginBottom: '0.4rem' }}>
          Prêt pour le premier téléversement
        </h3>
        <p style={{ color: 'var(--text-secondary)', fontSize: '0.875rem', lineHeight: 1.6 }}>
          <strong style={{ color: 'var(--text-primary)' }}>{data.name || 'Votre Cellule'}</strong> sera créée
          au premier téléversement signé.
        </p>
      </div>
      <div
        style={{
          background: 'rgba(255,255,255,0.03)',
          border: '1px solid var(--border-color)',
          borderRadius: '12px',
          padding: '1rem 1.5rem',
          width: '100%',
          textAlign: 'left',
        }}
      >
        <p style={{ fontSize: '0.75rem', color: 'var(--text-secondary)', fontWeight: 600, textTransform: 'uppercase', letterSpacing: '0.08em', marginBottom: '0.75rem' }}>
          Prochaines étapes
        </p>
        {[
          'Sauvegardez votre phrase mnémonique dans un gestionnaire de mots de passe chiffré ou un stockage hors ligne.',
          'Gardez l’original du fichier hors réseau CONFIDIS.',
          'Utilisez `confidis cellule put` ou le panneau de téléversement pour créer la copie réseau temporaire.',
        ].map((s, i) => (
          <div key={i} style={{ display: 'flex', gap: '0.75rem', marginBottom: '0.625rem', fontSize: '0.825rem', color: 'var(--text-secondary)', lineHeight: 1.5 }}>
            <span style={{ color: 'var(--accent-primary)', fontWeight: 700, flexShrink: 0 }}>{i + 1}.</span>
            <span>{s}</span>
          </div>
        ))}
      </div>
      <button className="btn btn-primary" style={{ width: '100%' }} onClick={onClose}>
        <ShieldCheck size={16} /> Terminé
      </button>
    </div>
  );
}

// ── Wizard Shell ──────────────────────────────────────────────────────────────

export default function CreateCelluleWizard({ onClose }) {
  const [step, setStep] = useState(0);
  const [data, setData] = useState({
    name: '',
    expiryDays: '365',
    nodeEndpoint: 'http://127.0.0.1:4433',
    registryPath: '',
    publicKeyHex: '',
  });

  function update(field, value) {
    setData((prev) => ({ ...prev, [field]: value }));
  }

  function canAdvance() {
    if (step === 0) return data.nodeEndpoint.trim().length > 0;
    if (step === 1) return /^[0-9a-fA-F]{64}$/.test(data.publicKeyHex.trim());
    return true;
  }

  return (
    <div
      style={{
        position: 'fixed',
        inset: 0,
        zIndex: 200,
        display: 'flex',
        alignItems: 'center',
        justifyContent: 'center',
        background: 'rgba(0,0,0,0.75)',
        backdropFilter: 'blur(6px)',
        padding: '1rem',
      }}
    >
      <div
        className="glass-panel"
        style={{ width: '100%', maxWidth: '560px', padding: '2rem', position: 'relative' }}
      >
        {/* Close */}
        <button
          onClick={onClose}
          style={{
            position: 'absolute',
            top: '1rem',
            right: '1rem',
            background: 'transparent',
            border: 'none',
            color: 'var(--text-secondary)',
            cursor: 'pointer',
          }}
        >
          <X size={20} />
        </button>

        {/* Header */}
        <div style={{ marginBottom: '1.5rem' }}>
          <h2 style={{ fontSize: '1.4rem', fontWeight: 700, display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
            <ShieldCheck size={22} color="var(--accent-primary)" />
            {step < STEPS.length - 1 ? 'Créer une Cellule' : 'Cellule créée'}
          </h2>
          <p style={{ color: 'var(--text-secondary)', fontSize: '0.825rem', marginTop: '0.25rem' }}>
            {step === 0 && 'Configurez votre nouvel espace de données chiffré zero-knowledge.'}
            {step === 1 && 'Générez votre clé de Cellule via la CLI, puis collez la clé publique.'}
            {step === 2 && 'Exécutez la commande ci-dessous dans votre terminal pour enregistrer la Cellule.'}
            {step === 3 && 'Enregistrement terminé.'}
          </p>
        </div>

        <StepIndicator current={step} />

        {/* Step content */}
        <div style={{ minHeight: '260px' }}>
          {step === 0 && <StepConfigure data={data} onChange={update} />}
          {step === 1 && <StepKeySetup data={data} onChange={update} />}
          {step === 2 && <StepCliCommand data={data} />}
          {step === 3 && <StepDone data={data} onClose={onClose} />}
        </div>

        {/* Navigation */}
        {step < 3 && (
          <div style={{ display: 'flex', justifyContent: 'space-between', marginTop: '2rem', gap: '1rem' }}>
            <button
              className="btn btn-secondary"
              style={{ flex: 1, visibility: step === 0 ? 'hidden' : 'visible' }}
              onClick={() => setStep((s) => s - 1)}
            >
              <ChevronLeft size={16} /> Retour
            </button>
            <button
              className="btn btn-primary"
              style={{ flex: 1 }}
              disabled={!canAdvance()}
              onClick={() => setStep((s) => s + 1)}
            >
              {step === 2 ? (
                <>Marquer comme terminé <CheckCircle size={16} /></>
              ) : (
                <>Suivant <ChevronRight size={16} /></>
              )}
            </button>
          </div>
        )}
      </div>
    </div>
  );
}
