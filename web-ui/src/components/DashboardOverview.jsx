import { useState, useEffect } from 'react';
import { useLocation } from 'react-router-dom';
import { AlertTriangle, HardDrive, Server, ShieldCheck, Activity } from 'lucide-react';
import { fetchCapacity, fetchHealth, fetchPeers, fetchReadiness, formatBytes } from '../api';
import ReadinessPanel from './ReadinessPanel';

const POLL_INTERVAL_MS = 5000;

function useNodeData() {
  const [capacity, setCapacity] = useState(null);
  const [health, setHealth] = useState(null);
  const [peers, setPeers] = useState(null);
  const [readiness, setReadiness] = useState(null);
  const [error, setError] = useState(null);

  useEffect(() => {
    let cancelled = false;
    async function refresh() {
      try {
        const [cap, nodeHealth, peerList, readinessReport] = await Promise.all([
          fetchCapacity(),
          fetchHealth(),
          fetchPeers(),
          fetchReadiness(),
        ]);
        if (!cancelled) {
          setCapacity(cap);
          setHealth(nodeHealth);
          setPeers(peerList);
          setReadiness(readinessReport);
          setError(null);
        }
      } catch {
        if (!cancelled) setError('Noeud hors ligne — confidis-node est-il démarré sur http://127.0.0.1:4433 ?');
      }
    }
    refresh();
    const id = setInterval(refresh, POLL_INTERVAL_MS);
    return () => { cancelled = true; clearInterval(id); };
  }, []);

  return { capacity, health, peers, readiness, error };
}

export default function DashboardOverview() {
  const { capacity, health, peers, readiness, error } = useNodeData();
  const location = useLocation();
  const isOperator = location.pathname.startsWith('/operator');

  const peerCount = peers?.peers?.length ?? '—';
  const usedBytes = capacity?.used_bytes ?? 0;
  const maxBytes  = capacity?.max_bytes  ?? 0;
  const freeBytes = capacity?.free_bytes ?? 0;
  const healthScore = capacity ? Math.round(capacity.health_score * 100) : '—';
  const region = capacity?.region ?? '—';
  const securityWarning = health?.node_banned
    ? 'Ce noeud est bloqué par la liste de quarantaine configurée.'
    : health?.public_ui_only
      ? null
    : health && !health.ui_auth_required
      ? 'Le jeton d’API local n’est pas configuré. Gardez ce noeud privé et lié à localhost.'
      : health && !health.ui_cors_restricted
        ? 'Le jeton d’API local est actif, mais le CORS n’est pas restreint à une seule origine de navigateur.'
        : health && !health.ban_verification_enabled
          ? 'La vérification de la liste de quarantaine est désactivée car aucune racine optionnelle n’est configurée.'
          : null;
  const securityTone = health?.node_banned || health && !health.public_ui_only && !health.ui_auth_required ? 'risk' : 'warn';

  const stats = [
    {
      label: 'Stockage utilisé',
      value: capacity ? `${formatBytes(usedBytes)} / ${formatBytes(maxBytes)}` : '—',
      icon: <HardDrive size={24} color="var(--accent-tertiary)" />,
    },
    {
      label: 'Capacité libre',
      value: capacity ? formatBytes(freeBytes) : '—',
      icon: <ShieldCheck size={24} color="var(--accent-primary)" />,
    },
    {
      label: 'Pairs réseau',
      value: peers ? `${peerCount} noeuds` : '—',
      icon: <Server size={24} color="#4ade80" />,
    },
    {
      label: 'Score de santé',
      value: capacity ? `${healthScore}%` : '—',
      icon: <Activity size={24} color="var(--accent-secondary)" />,
    },
  ];

  return (
    <div style={{ padding: '2rem' }}>
      <header style={{ marginBottom: '2.5rem', display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start' }}>
        <div>
          <h1 style={{ fontSize: '2rem', fontWeight: 700, marginBottom: '0.5rem' }}>Tableau de bord</h1>
          <p style={{ color: 'var(--text-secondary)' }}>
            {capacity
              ? <>Noeud <code style={{ fontFamily: 'monospace', color: 'var(--accent-primary)', fontSize: '0.875rem' }}>{capacity.node_id?.['0'] ?? capacity.node_id}</code> · Région : <strong>{region}</strong></>
              : 'Connexion à votre noeud de stockage souverain…'
            }
          </p>
        </div>
        <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', padding: '0.375rem 0.875rem', borderRadius: '20px', background: error ? 'rgba(255,42,122,0.08)' : 'rgba(74,222,128,0.08)', border: `1px solid ${error ? 'rgba(255,42,122,0.25)' : 'rgba(74,222,128,0.25)'}`, fontSize: '0.8rem', fontWeight: 600, color: error ? 'var(--accent-secondary)' : '#4ade80' }}>
          <span style={{ width: 8, height: 8, borderRadius: '50%', background: error ? 'var(--accent-secondary)' : '#4ade80', display: 'inline-block', boxShadow: error ? 'none' : '0 0 6px #4ade80' }} />
          {error ? 'Hors ligne' : 'En ligne'}
        </div>
      </header>

      {error && (
        <div style={{ marginBottom: '2rem' }}>
          <div style={{ display: 'flex', gap: '0.6rem', alignItems: 'center', padding: '1rem 1.5rem', borderRadius: '12px', background: 'rgba(255,42,122,0.06)', border: '1px solid rgba(255,42,122,0.2)', color: 'var(--accent-secondary)', marginBottom: '1.5rem', fontSize: '0.875rem' }}>
            <AlertTriangle size={17} /> {error}
          </div>
          <div className="glass-panel" style={{ padding: '2rem' }}>
            <h3 style={{ fontSize: '1.15rem', fontWeight: 700, marginBottom: '1.25rem', display: 'flex', alignItems: 'center', gap: '0.6rem' }}>
              Démarrer CONFIDIS en local
            </h3>
            <ol style={{ margin: 0, paddingLeft: '1.4rem', display: 'flex', flexDirection: 'column', gap: '0.9rem', color: 'var(--text-secondary)', fontSize: '0.875rem', lineHeight: 1.6 }}>
              <li>
                <strong style={{ color: 'var(--text-primary)' }}>Compiler la CLI</strong>{' '}
                <code style={{ background: 'rgba(255,255,255,0.07)', padding: '0.1rem 0.4rem', borderRadius: '4px', fontFamily: 'monospace', fontSize: '0.8rem' }}>cargo build --release -p confidis</code>
              </li>
              <li>
                <strong style={{ color: 'var(--text-primary)' }}>Créer la configuration du noeud</strong>{' '}
                <code style={{ background: 'rgba(255,255,255,0.07)', padding: '0.1rem 0.4rem', borderRadius: '4px', fontFamily: 'monospace', fontSize: '0.8rem' }}>cargo run -p confidis -- node init-config --output ./node.json</code>
              </li>
              <li>
                <strong style={{ color: 'var(--text-primary)' }}>Démarrer le noeud</strong>{' '}
                <code style={{ background: 'rgba(255,255,255,0.07)', padding: '0.1rem 0.4rem', borderRadius: '4px', fontFamily: 'monospace', fontSize: '0.8rem' }}>cargo run -p confidis -- node serve ./node.json</code>
              </li>
              <li>
                <strong style={{ color: 'var(--text-primary)' }}>Protéger l’accès navigateur</strong>{' '}
                définissez <code style={{ background: 'rgba(255,255,255,0.07)', padding: '0.1rem 0.4rem', borderRadius: '4px', fontFamily: 'monospace', fontSize: '0.8rem' }}>ui_token</code> et <code style={{ background: 'rgba(255,255,255,0.07)', padding: '0.1rem 0.4rem', borderRadius: '4px', fontFamily: 'monospace', fontSize: '0.8rem' }}>ui_allowed_origin</code> avant d’exposer l’interface au-delà de localhost.
              </li>
            </ol>
          </div>
        </div>
      )}

      {!error && isOperator && <ReadinessPanel health={health} readiness={readiness} />}

      {!error && !isOperator && securityWarning && (
        <div style={{ display: 'flex', gap: '0.65rem', alignItems: 'flex-start', padding: '1rem 1.25rem', borderRadius: '12px', background: securityTone === 'risk' ? 'rgba(255,42,122,0.06)' : 'rgba(251,146,60,0.07)', border: `1px solid ${securityTone === 'risk' ? 'rgba(255,42,122,0.22)' : 'rgba(251,146,60,0.24)'}`, color: securityTone === 'risk' ? 'var(--accent-secondary)' : '#fb923c', marginBottom: '1.5rem', fontSize: '0.875rem', lineHeight: 1.55 }}>
          <AlertTriangle size={17} style={{ marginTop: 2, flexShrink: 0 }} />
          <span>{securityWarning}</span>
        </div>
      )}

      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(240px, 1fr))', gap: '1.5rem', marginBottom: '2.5rem' }}>
        {stats.map((stat, i) => (
          <div key={i} className="glass-panel" style={{ padding: '1.5rem', display: 'flex', alignItems: 'center', gap: '1rem' }}>
            <div style={{ width: '48px', height: '48px', borderRadius: '12px', background: 'rgba(255,255,255,0.05)', display: 'flex', alignItems: 'center', justifyContent: 'center', flexShrink: 0 }}>
              {stat.icon}
            </div>
            <div>
              <p style={{ color: 'var(--text-secondary)', fontSize: '0.875rem', marginBottom: '0.25rem' }}>{stat.label}</p>
              <h3 style={{ fontSize: '1.35rem', fontWeight: 600, opacity: capacity || peers ? 1 : 0.4 }}>{stat.value}</h3>
            </div>
          </div>
        ))}
      </div>

      <div style={{ display: 'grid', gridTemplateColumns: '2fr 1fr', gap: '1.5rem' }}>
        <div className="glass-panel" style={{ padding: '1.5rem' }}>
          <h3 style={{ fontSize: '1.25rem', marginBottom: '1.5rem', display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
            <Activity size={20} color="var(--accent-primary)" /> Répartition du stockage
          </h3>
          {capacity ? (
            <div>
              <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: '0.75rem', fontSize: '0.875rem', color: 'var(--text-secondary)' }}>
                <span>Utilisé : {formatBytes(usedBytes)}</span>
                <span>Total : {formatBytes(maxBytes)}</span>
              </div>
              <div style={{ width: '100%', height: '10px', borderRadius: '99px', background: 'rgba(255,255,255,0.05)', overflow: 'hidden' }}>
                <div style={{ height: '100%', width: maxBytes > 0 ? `${Math.min(100, (usedBytes / maxBytes) * 100).toFixed(1)}%` : '0%', background: 'linear-gradient(90deg, var(--accent-primary), var(--accent-tertiary))', borderRadius: '99px', transition: 'width 0.6s ease' }} />
              </div>
              <div style={{ marginTop: '1.5rem', display: 'grid', gridTemplateColumns: '1fr 1fr 1fr', gap: '1rem' }}>
                {[
                  { label: 'Utilisé', value: formatBytes(usedBytes), color: 'var(--accent-primary)' },
                  { label: 'Libre', value: formatBytes(freeBytes), color: '#4ade80' },
                  { label: 'Shards', value: capacity.current_shard_count ?? '—', color: 'var(--accent-tertiary)' },
                ].map((item, i) => (
                  <div key={i} style={{ padding: '1rem', borderRadius: '10px', background: 'rgba(255,255,255,0.03)', border: '1px solid var(--border-color)', textAlign: 'center' }}>
                    <p style={{ color: item.color, fontWeight: 700, fontSize: '1.1rem' }}>{item.value}</p>
                    <p style={{ color: 'var(--text-secondary)', fontSize: '0.75rem', marginTop: '0.25rem' }}>{item.label}</p>
                  </div>
                ))}
              </div>
            </div>
          ) : (
            <div style={{ height: '160px', display: 'flex', alignItems: 'center', justifyContent: 'center', border: '1px dashed var(--border-color)', borderRadius: '12px' }}>
              <p style={{ color: 'var(--text-secondary)', fontSize: '0.875rem' }}>En attente de connexion au noeud…</p>
            </div>
          )}
        </div>

        <div className="glass-panel" style={{ padding: '1.5rem' }}>
          <h3 style={{ fontSize: '1.25rem', marginBottom: '1.5rem' }}>Aperçu des pairs</h3>
          {peers ? (
            <div style={{ display: 'flex', flexDirection: 'column', gap: '0.75rem' }}>
              {peers.peers.length === 0 && (
                <p style={{ color: 'var(--text-secondary)', fontSize: '0.875rem' }}>Aucun pair découvert pour l’instant.</p>
              )}
              {peers.peers.slice(0, 4).map((peer, i) => (
                <div key={i} style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', paddingBottom: '0.75rem', borderBottom: i < Math.min(peers.peers.length, 4) - 1 ? '1px solid var(--border-color)' : 'none' }}>
                  <div>
                    <p style={{ fontWeight: 500, fontSize: '0.8rem', maxWidth: '160px', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                      {peer.node_id?.['0'] ?? peer.endpoint}
                    </p>
                    <p style={{ color: 'var(--text-secondary)', fontSize: '0.7rem', fontFamily: 'monospace' }}>{peer.region ?? 'inconnu'}</p>
                  </div>
                  <span style={{ width: 8, height: 8, borderRadius: '50%', background: '#4ade80', display: 'inline-block', boxShadow: '0 0 6px #4ade80', flexShrink: 0 }} />
                </div>
              ))}
              {peers.peers.length > 4 && (
                <p style={{ color: 'var(--text-secondary)', fontSize: '0.75rem', textAlign: 'center' }}>+{peers.peers.length - 4} autres pairs</p>
              )}
            </div>
          ) : (
            <div style={{ height: '160px', display: 'flex', alignItems: 'center', justifyContent: 'center' }}>
              <p style={{ color: 'var(--text-secondary)', fontSize: '0.875rem' }}>En attente des données de pairs…</p>
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
