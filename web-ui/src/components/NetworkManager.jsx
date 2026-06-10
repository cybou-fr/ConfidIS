import { useState, useEffect } from 'react';
import { Activity, AlertTriangle, Server, Globe, Signal, Shield, RefreshCw } from 'lucide-react';
import { fetchCapacity, fetchHealth, fetchPeers, formatBytes } from '../api';

const POLL_INTERVAL_MS = 5000;

export default function NetworkManager() {
  const [capacity, setCapacity] = useState(null);
  const [health, setHealth] = useState(null);
  const [peerList, setPeerList] = useState(null);
  const [error, setError] = useState(null);
  const [lastUpdated, setLastUpdated] = useState(null);

  async function refresh() {
    try {
      const [cap, nodeHealth, peers] = await Promise.all([fetchCapacity(), fetchHealth(), fetchPeers()]);
      setCapacity(cap);
      setHealth(nodeHealth);
      setPeerList(peers);
      setLastUpdated(new Date());
      setError(null);
    } catch {
      setError('Impossible de joindre l’API du noeud local.');
    }
  }

  useEffect(() => {
    refresh();
    const id = setInterval(refresh, POLL_INTERVAL_MS);
    return () => clearInterval(id);
  }, []);

  const peers = peerList?.peers ?? [];
  const totalFreeBytes = capacity?.free_bytes ?? 0;
  const peerCount = peers.length;
  const securityNote = health?.node_banned
    ? 'Cette clé de noeud est bloquée par la liste de quarantaine configurée.'
    : health && !health.ui_auth_required
      ? 'Les API UI locales sont actuellement non authentifiées. Gardez ce noeud privé tant que ui_token n’est pas configuré.'
      : health && !health.ban_verification_enabled
        ? 'La vérification de la liste de quarantaine est désactivée car aucune racine optionnelle n’est configurée.'
        : health && !health.ui_cors_restricted
          ? 'Le jeton UI est actif, mais le CORS n’est pas restreint à une seule origine de navigateur.'
          : null;

  return (
    <div style={{ padding: '2rem' }}>
      <header style={{ marginBottom: '2.5rem', display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start' }}>
        <div>
          <h1 style={{ fontSize: '2rem', fontWeight: 700, marginBottom: '0.5rem', display: 'flex', alignItems: 'center', gap: '0.75rem' }}>
            <Activity color="#4ade80" /> État du réseau
          </h1>
          <p style={{ color: 'var(--text-secondary)' }}>
            Table de routage P2P en direct · rafraîchissement auto toutes les 5 s
            {lastUpdated && <> <span style={{ marginLeft: '1rem', opacity: 0.5, fontSize: '0.8rem' }}>Dernier : {lastUpdated.toLocaleTimeString()}</span></>}
          </p>
        </div>
        <button
          onClick={refresh}
          style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', padding: '0.5rem 1rem', borderRadius: '8px', background: 'rgba(255,255,255,0.05)', border: '1px solid var(--border-color)', color: 'var(--text-primary)', cursor: 'pointer', fontSize: '0.875rem' }}
        >
          <RefreshCw size={14} /> Rafraîchir
        </button>
      </header>

      {error && (
        <div style={{ display: 'flex', gap: '0.6rem', alignItems: 'center', padding: '1rem 1.5rem', borderRadius: '12px', background: 'rgba(255,42,122,0.06)', border: '1px solid rgba(255,42,122,0.2)', color: 'var(--accent-secondary)', marginBottom: '2rem', fontSize: '0.875rem' }}>
          <AlertTriangle size={17} /> {error}
        </div>
      )}

      {!error && securityNote && (
        <div style={{ display: 'flex', gap: '0.65rem', alignItems: 'flex-start', padding: '1rem 1.25rem', borderRadius: '12px', background: 'rgba(251,146,60,0.07)', border: '1px solid rgba(251,146,60,0.24)', color: '#fb923c', marginBottom: '1.5rem', fontSize: '0.875rem', lineHeight: 1.55 }}>
          <AlertTriangle size={17} style={{ marginTop: 2, flexShrink: 0 }} />
          <span>{securityNote}</span>
        </div>
      )}

      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(220px, 1fr))', gap: '1.5rem', marginBottom: '2.5rem' }}>
        <div className="glass-panel" style={{ padding: '1.5rem', display: 'flex', alignItems: 'center', gap: '1rem' }}>
          <div style={{ width: '48px', height: '48px', borderRadius: '12px', background: 'rgba(74, 222, 128, 0.1)', display: 'flex', alignItems: 'center', justifyContent: 'center' }}>
            <Server size={24} color="#4ade80" />
          </div>
          <div>
            <p style={{ color: 'var(--text-secondary)', fontSize: '0.875rem', marginBottom: '0.25rem' }}>Pairs actifs</p>
            <h3 style={{ fontSize: '1.5rem', fontWeight: 600 }}>{peerList ? `${peerCount} noeuds` : '—'}</h3>
          </div>
        </div>

        <div className="glass-panel" style={{ padding: '1.5rem', display: 'flex', alignItems: 'center', gap: '1rem' }}>
          <div style={{ width: '48px', height: '48px', borderRadius: '12px', background: 'rgba(69, 243, 255, 0.1)', display: 'flex', alignItems: 'center', justifyContent: 'center' }}>
            <Globe size={24} color="var(--accent-primary)" />
          </div>
          <div>
            <p style={{ color: 'var(--text-secondary)', fontSize: '0.875rem', marginBottom: '0.25rem' }}>Capacité libre locale</p>
            <h3 style={{ fontSize: '1.5rem', fontWeight: 600 }}>{capacity ? formatBytes(totalFreeBytes) : '—'}</h3>
          </div>
        </div>

        <div className="glass-panel" style={{ padding: '1.5rem', display: 'flex', alignItems: 'center', gap: '1rem' }}>
          <div style={{ width: '48px', height: '48px', borderRadius: '12px', background: 'rgba(168, 85, 247, 0.1)', display: 'flex', alignItems: 'center', justifyContent: 'center' }}>
            <Shield size={24} color="var(--accent-tertiary)" />
          </div>
          <div>
            <p style={{ color: 'var(--text-secondary)', fontSize: '0.875rem', marginBottom: '0.25rem' }}>Score de santé</p>
            <h3 style={{ fontSize: '1.5rem', fontWeight: 600 }}>{capacity ? `${Math.round(capacity.health_score * 100)}%` : '—'}</h3>
          </div>
        </div>
      </div>

        <div className="glass-panel" style={{ padding: '1.5rem' }}>
        <h3 style={{ fontSize: '1.25rem', marginBottom: '1.5rem' }}>
          Table de routage
          {peerList && <> <span style={{ marginLeft: '0.75rem', fontSize: '0.75rem', color: 'var(--text-secondary)', fontWeight: 400 }}>({peers.length} pairs)</span></>}
        </h3>

        <div style={{ display: 'flex', flexDirection: 'column', gap: '0.5rem', overflowX: 'auto' }}>
          <div style={{ display: 'grid', gridTemplateColumns: 'minmax(240px, 2fr) minmax(110px, 1fr) minmax(140px, 1fr) minmax(110px, 1fr)', minWidth: 680, padding: '0.75rem 1.25rem', color: 'var(--text-secondary)', fontSize: '0.75rem', textTransform: 'uppercase', letterSpacing: '1px' }}>
            <div>Endpoint / ID de noeud</div>
            <div>Région</div>
            <div>Domaine de panne</div>
            <div>Statut</div>
          </div>

          {!peerList && (
            <div style={{ padding: '2rem', textAlign: 'center', color: 'var(--text-secondary)', fontSize: '0.875rem' }}>
              Connexion au noeud…
            </div>
          )}

          {peerList && peers.length === 0 && (
            <div style={{ padding: '2rem', textAlign: 'center', color: 'var(--text-secondary)', fontSize: '0.875rem' }}>
              Aucun pair dans la table de routage pour l’instant. Ajoutez des pairs de fédération de confiance dans Paramètres.
            </div>
          )}

          {peers.map((peer, i) => {
            const isExpired = peer.expires_at && new Date(peer.expires_at) < new Date();
            const hasFullInfo = !!peer.node_id;
            const nodeLabel = peer.node_id?.['0'] ?? peer.node_id ?? peer.endpoint;
            const region = peer.region ?? '—';
            const fd = peer.failure_domain ?? '—';
            const status = isExpired ? 'Périmé' : hasFullInfo ? 'Joignable' : 'Pair initial';
            const statusColor = isExpired ? 'rgba(255,42,122,0.1)' : hasFullInfo ? 'rgba(74,222,128,0.1)' : 'rgba(69,243,255,0.1)';
            const statusTextColor = isExpired ? 'var(--accent-secondary)' : hasFullInfo ? '#4ade80' : 'var(--accent-primary)';

            return (
              <div
                key={i}
                style={{ display: 'grid', gridTemplateColumns: 'minmax(240px, 2fr) minmax(110px, 1fr) minmax(140px, 1fr) minmax(110px, 1fr)', minWidth: 680, padding: '1.25rem', background: 'rgba(255,255,255,0.02)', borderRadius: '12px', border: '1px solid var(--border-color)', alignItems: 'center', transition: 'var(--transition)' }}
                onMouseOver={(e) => e.currentTarget.style.background = 'rgba(255,255,255,0.05)'}
                onMouseOut={(e) => e.currentTarget.style.background = 'rgba(255,255,255,0.02)'}
              >
                <div style={{ display: 'flex', alignItems: 'center', gap: '0.75rem' }}>
                  <div style={{ width: '32px', height: '32px', borderRadius: '8px', background: 'rgba(255,255,255,0.05)', display: 'flex', alignItems: 'center', justifyContent: 'center', flexShrink: 0 }}>
                    <Server size={16} color="var(--text-primary)" />
                  </div>
                  <div style={{ minWidth: 0 }}>
                    <p style={{ fontWeight: 500, fontSize: '0.875rem', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{nodeLabel}</p>
                    <p style={{ color: 'var(--text-secondary)', fontSize: '0.7rem', fontFamily: 'monospace', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{peer.endpoint}</p>
                  </div>
                </div>

                <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', fontSize: '0.875rem', color: 'var(--text-secondary)' }}>
                  <Signal size={14} color={hasFullInfo ? '#4ade80' : 'var(--text-secondary)'} />
                  {region}
                </div>

                <div style={{ fontSize: '0.875rem', fontFamily: 'monospace', color: 'var(--text-secondary)' }}>
                  {fd}
                </div>

                <div>
                  <span style={{ display: 'inline-block', padding: '0.25rem 0.75rem', borderRadius: '20px', fontSize: '0.75rem', fontWeight: 600, background: statusColor, color: statusTextColor, border: `1px solid ${statusColor.replace('0.1', '0.25')}` }}>
                    {status}
                  </span>
                </div>
              </div>
            );
          })}
        </div>
      </div>
    </div>
  );
}
