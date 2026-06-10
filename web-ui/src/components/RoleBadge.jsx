import { useNodeMode } from './NodeModeContextValue';

// Phase 1c — small inline badge that says where the user currently is
// (which node role) and who operates it. Shown in headers/banners. Subtle by
// default — meant to be a constant, low-distraction context indicator.
//
// Variants:
//   - authority (node_role=authority):
//       "Noeud d'autorité isolé"
//   - company-node (node_role=company):
//       "Noeud d'entreprise · quotas locaux"
//   - unknown:
//       "Mode de noeud inconnu — contactez votre administrateur"

const baseStyle = {
  display: 'inline-flex',
  alignItems: 'center',
  gap: 8,
  padding: '4px 10px',
  borderRadius: 999,
  fontSize: 12,
  fontWeight: 500,
  border: '1px solid var(--border-subtle, rgba(255,255,255,0.12))',
  background: 'var(--bg-elevated, rgba(255,255,255,0.04))',
  color: 'var(--text-primary, #e6e6e6)',
};

function pickVariant(mode) {
  if (!mode) {
    return {
      tone: 'unknown',
      label: 'Mode de noeud inconnu — contactez votre administrateur',
      hint: '',
    };
  }
  if (mode.node_role === 'authority') {
    return {
      tone: 'authority',
      label: "Noeud d'autorité isolé",
      hint: 'Surface limitée; les opérations opérateur restent locales.',
    };
  }
  if (mode.node_role === 'company') {
    return {
      tone: 'operator',
      label: "Noeud d'entreprise",
      hint: "L'organisation hébergeante applique les quotas locaux.",
    };
  }
  return {
    tone: 'unknown',
    label: 'Mode de noeud inconnu — contactez votre administrateur',
    hint: '',
  };
}

const toneAccent = {
  authority: '#45f3ff',
  operator: '#9ad7ff',
  unknown: '#ff8b8b',
};

export default function RoleBadge({ compact = false, style = {} }) {
  const { mode, loading } = useNodeMode();
  if (loading) {
    return (
      <span style={{ ...baseStyle, opacity: 0.6, ...style }}>
        <span>Détection du noeud…</span>
      </span>
    );
  }
  const v = pickVariant(mode);
  return (
    <span
      style={{
        ...baseStyle,
        borderColor: `${toneAccent[v.tone]}33`,
        ...style,
      }}
      title={v.hint}
    >
      <span
        aria-hidden="true"
        style={{
          display: 'inline-block',
          width: 6,
          height: 6,
          borderRadius: '50%',
          background: toneAccent[v.tone],
        }}
      />
      <span>{v.label}</span>
      {!compact && v.hint ? (
        <span style={{ opacity: 0.7, fontWeight: 400 }}>· {v.hint}</span>
      ) : null}
    </span>
  );
}
