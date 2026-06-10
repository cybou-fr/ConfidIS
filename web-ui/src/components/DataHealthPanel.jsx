import { useEffect, useMemo, useState } from 'react';
import {
  Activity,
  AlertTriangle,
  CheckCircle2,
  Clock,
  Database,
  HardDrive,
  MapPin,
  RefreshCw,
  Server,
  Shield,
  ShieldCheck,
  Wrench,
  X,
} from 'lucide-react';
import { fetchCapacity, fetchCellules, fetchHealth, fetchMaintenance, fetchPeers, fetchReceipts, formatBytes, daysUntil } from '../api';

const RECOMMENDED_MIN_RAM_GB = 4;
const RECOMMENDED_MIN_SSD_GB = 100;
const RECOMMENDED_FREE_SPACE_RATIO = 0.15;

function fmtDate(iso) {
  if (!iso) return '-';
  try {
    return new Date(iso).toLocaleString();
  } catch {
    return iso;
  }
}

function receiptShardId(receipt) {
  return receipt.shard_id?.['0'] || receipt.shard_id || '-';
}

function groupReceiptsByShard(receipts) {
  const byShard = new Map();
  receipts.forEach((receipt) => {
    const id = receiptShardId(receipt);
    if (!byShard.has(id)) byShard.set(id, []);
    byShard.get(id).push(receipt);
  });
  return [...byShard.entries()].map(([shardId, shardReceipts]) => {
    const latest = shardReceipts[0];
    return {
      shardId,
      latest,
      count: shardReceipts.length,
      nodeId: latest.node_id?.['0'] || latest.node_id || '-',
      type: latest.receipt_type || '-',
      sizeBytes: latest.size_bytes || 0,
      issuedAt: latest.issued_at || latest.timestamp,
      signed: Boolean(latest.signature),
    };
  });
}

function jobTone(job) {
  if (job?.attention || job?.status === 'attention') return 'warn';
  if (job?.status === 'running') return 'warn';
  if (job?.status === 'ok') return 'ok';
  return 'warn';
}

function HealthBadge({ tone, children }) {
  const colors = {
    ok: ['rgba(74,222,128,0.1)', '#4ade80', 'rgba(74,222,128,0.25)'],
    warn: ['rgba(251,146,60,0.1)', '#fb923c', 'rgba(251,146,60,0.25)'],
    risk: ['rgba(255,42,122,0.1)', 'var(--accent-secondary)', 'rgba(255,42,122,0.25)'],
  };
  const [bg, fg, border] = colors[tone] || colors.warn;
  return (
    <span style={{ display: 'inline-flex', alignItems: 'center', gap: '0.35rem', padding: '0.25rem 0.65rem', borderRadius: 999, background: bg, color: fg, border: `1px solid ${border}`, fontSize: '0.75rem', fontWeight: 700 }}>
      {children}
    </span>
  );
}

function Stat({ icon: Icon, label, value, detail, tone = 'ok' }) {
  const color = tone === 'risk' ? 'var(--accent-secondary)' : tone === 'warn' ? '#fb923c' : 'var(--accent-primary)';
  return (
    <div style={{ padding: '1rem', border: '1px solid var(--border-color)', borderRadius: 8, background: 'rgba(255,255,255,0.025)' }}>
      <p style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', color: 'var(--text-secondary)', fontSize: '0.75rem', marginBottom: '0.4rem' }}>
        <Icon size={15} color={color} />
        {label}
      </p>
      <p style={{ fontSize: '1.15rem', fontWeight: 800 }}>{value}</p>
      {detail && <p style={{ color: 'var(--text-secondary)', fontSize: '0.75rem', marginTop: '0.25rem', lineHeight: 1.45 }}>{detail}</p>}
    </div>
  );
}

export default function DataHealthPanel({ onClose }) {
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  const [capacity, setCapacity] = useState(null);
  const [health, setHealth] = useState(null);
  const [cellules, setCellules] = useState([]);
  const [peers, setPeers] = useState([]);
  const [receipts, setReceipts] = useState([]);
  const [maintenance, setMaintenance] = useState(null);

  async function load() {
    setLoading(true);
    setError(null);
    try {
      const [cap, nodeHealth, cel, peerList, rec, maint] = await Promise.allSettled([
        fetchCapacity(),
        fetchHealth(),
        fetchCellules(),
        fetchPeers(),
        fetchReceipts(1000),
        fetchMaintenance(),
      ]);
      if (cap.status === 'fulfilled') setCapacity(cap.value);
      if (nodeHealth.status === 'fulfilled') setHealth(nodeHealth.value);
      if (cel.status === 'fulfilled') setCellules(Array.isArray(cel.value) ? cel.value : cel.value?.cellules || []);
      if (peerList.status === 'fulfilled') setPeers(peerList.value?.peers || []);
      if (rec.status === 'fulfilled') setReceipts(rec.value?.receipts || []);
      if (maint.status === 'fulfilled') setMaintenance(maint.value);
      const failed = [cap, nodeHealth, cel, peerList, rec, maint].filter((r) => r.status === 'rejected');
      if (failed.length) setError(`${failed.length} source(s) de données indisponible(s)`);
    } finally {
      setLoading(false);
    }
  }

  useEffect(() => { load(); }, []);

  const shardRows = useMemo(() => groupReceiptsByShard(receipts).slice(0, 40), [receipts]);
  const maxBytes = capacity?.max_bytes || 0;
  const freeBytes = capacity?.free_bytes ?? Math.max(0, maxBytes - (capacity?.used_bytes || 0));
  const freeRatio = maxBytes > 0 ? freeBytes / maxBytes : 0;
  const diskGb = maxBytes / (1024 ** 3);
  const diskTone = diskGb < RECOMMENDED_MIN_SSD_GB || freeRatio < RECOMMENDED_FREE_SPACE_RATIO ? 'warn' : 'ok';
  const expiring = cellules.filter((cellule) => {
    const days = daysUntil(cellule.expires_at);
    return days !== null && days <= 30;
  });
  const unsignedReceipts = receipts.filter((receipt) => !receipt.signature).length;
  const maintenanceJobs = Array.isArray(maintenance?.jobs) ? maintenance.jobs : [];
  const maintenanceAttention = maintenanceJobs.filter((job) => job.attention || job.status === 'attention');
  const dataHealthTone = expiring.length || unsignedReceipts || maintenanceAttention.length ? 'warn' : 'ok';
  const governanceTone = health?.node_banned
    ? 'risk'
    : health?.ban_verification_enabled && health?.node_ban_list_present
      ? 'ok'
      : 'warn';
  const governanceText = health?.node_banned
    ? 'Bloqué'
    : health?.ban_verification_enabled
      ? (health?.node_ban_list_present ? 'Vérifié' : 'Racine seule')
      : 'Mode dev';
  const governanceDetail = health?.node_banned
    ? 'Cette clé de noeud est bloquée par la liste de quarantaine de l’autorité.'
    : health?.ban_verification_enabled
      ? (health?.node_ban_list_present
        ? `Liste de quarantaine signée chargée · ${health.trust_root_source || 'racine de confiance configurée'}`
        : 'Racine de confiance configurée ; aucune liste de quarantaine valide chargée pour l’instant.')
      : 'Aucune racine de quarantaine configurée ; la vérification de la liste de quarantaine est désactivée.';
  const uiTone = !health ? 'risk' : health.public_ui_only ? 'ok' : !health.ui_auth_required ? 'risk' : health.ui_cors_restricted ? 'ok' : 'warn';
  const uiText = !health ? '-' : health.public_ui_only ? 'Publique isolée' : !health.ui_auth_required ? 'Non protégée' : health.ui_cors_restricted ? 'Protégée' : 'Jeton seul';
  const uiDetail = !health
    ? 'En attente des données de santé.'
    : health.public_ui_only
      ? 'Les routes opérateur et authority ne sont pas exposées dans cette interface publique.'
    : !health.ui_auth_required
      ? 'ui_token est absent. Gardez ce noeud lié à localhost.'
      : health.ui_cors_restricted
        ? 'ui_token et une origine de navigateur restreinte sont actifs.'
        : 'ui_token est actif. Définissez ui_allowed_origin avant d’exposer cette interface.';

  return (
    <div style={{ position: 'fixed', inset: 0, background: 'rgba(0,0,0,0.74)', backdropFilter: 'blur(8px)', display: 'flex', justifyContent: 'center', alignItems: 'center', zIndex: 1000, padding: '1rem' }}>
      <div className="glass-panel" style={{ width: '100%', maxWidth: 1120, maxHeight: '90vh', overflow: 'auto', padding: '1.75rem' }}>
        <header style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', gap: '1rem', marginBottom: '1.25rem' }}>
          <div>
            <h2 style={{ display: 'flex', alignItems: 'center', gap: '0.6rem', fontSize: '1.2rem', fontWeight: 800, marginBottom: '0.4rem' }}>
              <Activity size={21} color="var(--accent-primary)" />
              Santé des données
            </h2>
            <p style={{ color: 'var(--text-secondary)', fontSize: '0.86rem', lineHeight: 1.6, maxWidth: 760 }}>
              Le noeud fonctionne avec des valeurs par défaut sûres. Cette vue montre si les ressources sont suffisantes, quelles Cellules sont enregistrées,
              et quels reçus de shards ce noeud peut prouver localement.
            </p>
          </div>
          <div style={{ display: 'flex', gap: '0.5rem' }}>
            <button onClick={load} className="btn btn-secondary" style={{ padding: '0.55rem 0.8rem' }}>
              <RefreshCw size={15} /> Rafraîchir
            </button>
            <button onClick={onClose} style={{ background: 'transparent', border: 'none', color: 'var(--text-secondary)', cursor: 'pointer' }} aria-label="Fermer la santé des données">
              <X size={22} />
            </button>
          </div>
        </header>

        {loading && <p style={{ color: 'var(--text-secondary)', textAlign: 'center', padding: '2rem' }}>Chargement de la santé des données…</p>}

        {!loading && (
          <>
            {error && (
              <div style={{ display: 'flex', gap: '0.6rem', alignItems: 'center', padding: '0.75rem 1rem', border: '1px solid rgba(251,146,60,0.25)', borderRadius: 8, background: 'rgba(251,146,60,0.06)', color: '#fb923c', marginBottom: '1rem', fontSize: '0.82rem' }}>
                <AlertTriangle size={16} /> {error} ; santé partielle affichée.
              </div>
            )}

            <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(210px, 1fr))', gap: '0.85rem', marginBottom: '1.35rem' }}>
              <Stat icon={Shield} label="Gouvernance de l’autorité" value={governanceText} detail={governanceDetail} tone={governanceTone} />
              <Stat icon={ShieldCheck} label="Santé des données" value={dataHealthTone === 'ok' ? 'OK' : 'Attention'} detail={`${cellules.length} Cellules · ${receipts.length} reçus locaux`} tone={dataHealthTone} />
              <Stat icon={HardDrive} label="Allocation SSD" value={capacity ? formatBytes(maxBytes) : '-'} detail={`Minimum recommandé : ${RECOMMENDED_MIN_SSD_GB} Go SSD · libre ${formatBytes(freeBytes)}`} tone={diskTone} />
              <Stat icon={Database} label="Shards locaux" value={capacity?.current_shard_count ?? shardRows.length} detail="Shards visibles sur ce noeud d’après la capacité/les reçus" />
            </div>

            <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(240px, 1fr))', gap: '0.85rem', marginBottom: '1.35rem' }}>
              <Stat icon={Server} label="Pairs réseau" value={peers.length} detail={`RAM minimum recommandée : ${RECOMMENDED_MIN_RAM_GB} Go pour les petits sites`} />
              <Stat icon={ShieldCheck} label="Périmètre de l’API locale" value={uiText} detail={uiDetail} tone={uiTone} />
            </div>

            <section style={{ border: '1px solid var(--border-color)', borderRadius: 8, overflow: 'hidden', marginBottom: '1.25rem' }}>
              <div style={{ padding: '0.9rem 1rem', borderBottom: '1px solid var(--border-color)', display: 'flex', justifyContent: 'space-between', alignItems: 'center', gap: '0.8rem' }}>
                <h3 style={{ display: 'flex', alignItems: 'center', gap: '0.45rem', fontSize: '0.95rem' }}>
                  <Wrench size={15} color="var(--accent-primary)" />
                  Maintenance autonome
                </h3>
                {maintenanceAttention.length ? <HealthBadge tone="warn">{maintenanceAttention.length} à surveiller</HealthBadge> : <HealthBadge tone="ok"><CheckCircle2 size={13} /> fonctionne correctement</HealthBadge>}
              </div>
              <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(220px, 1fr))', gap: '0.7rem', padding: '0.9rem' }}>
                {maintenanceJobs.length === 0 && <p style={{ color: 'var(--text-secondary)', fontSize: '0.85rem', gridColumn: '1 / -1' }}>Aucun état de maintenance signalé pour l’instant. Les workers publient leur état après leur premier cycle.</p>}
                {maintenanceJobs.map((job) => (
                  <div key={job.job_id} style={{ padding: '0.85rem', border: '1px solid rgba(255,255,255,0.08)', borderRadius: 8, background: 'rgba(255,255,255,0.025)', minHeight: 130 }}>
                    <div style={{ display: 'flex', justifyContent: 'space-between', gap: '0.6rem', alignItems: 'flex-start', marginBottom: '0.45rem' }}>
                      <p style={{ fontSize: '0.84rem', fontWeight: 800 }}>{job.label || job.job_id}</p>
                      <HealthBadge tone={jobTone(job)}>{job.status || 'idle'}</HealthBadge>
                    </div>
                    <p style={{ color: 'var(--text-secondary)', fontSize: '0.74rem', lineHeight: 1.45 }}>{job.detail || 'En attente du prochain cycle autonome.'}</p>
                    {job.last_error && <p style={{ color: '#fb923c', fontSize: '0.74rem', lineHeight: 1.45, marginTop: '0.35rem' }}>{job.last_error}</p>}
                    <p style={{ color: 'var(--text-secondary)', fontSize: '0.72rem', marginTop: '0.5rem' }}>dernier passage : {fmtDate(job.last_finished_at || job.last_started_at)} · cycles : {job.runs ?? 0}</p>
                  </div>
                ))}
              </div>
              <p style={{ padding: '0 0.9rem 0.9rem', color: 'var(--text-secondary)', fontSize: '0.75rem', lineHeight: 1.5 }}>
                Persisté localement dans {maintenance?.persisted_path || 'store/maintenance/status.json du noeud'} pour les audits et collecteurs SIEM.
              </p>
            </section>

            <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '1rem', marginBottom: '1.25rem' }}>
              <section style={{ border: '1px solid var(--border-color)', borderRadius: 8, overflow: 'hidden' }}>
                <div style={{ padding: '0.9rem 1rem', borderBottom: '1px solid var(--border-color)', display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                  <h3 style={{ fontSize: '0.95rem' }}>Cellules</h3>
                  {expiring.length ? <HealthBadge tone="warn">{expiring.length} expirent bientôt</HealthBadge> : <HealthBadge tone="ok"><CheckCircle2 size={13} /> conservation ok</HealthBadge>}
                </div>
                <div style={{ maxHeight: 320, overflow: 'auto' }}>
                  {cellules.length === 0 && <p style={{ padding: '1rem', color: 'var(--text-secondary)', fontSize: '0.85rem' }}>Aucune Cellule enregistrée sur ce noeud.</p>}
                  {cellules.map((cellule) => {
                    const days = daysUntil(cellule.expires_at);
                    const statusTone = days !== null && days <= 30 ? 'warn' : 'ok';
                    return (
                      <div key={cellule.cellule_id} style={{ padding: '0.85rem 1rem', borderBottom: '1px solid rgba(255,255,255,0.05)' }}>
                        <div style={{ display: 'flex', justifyContent: 'space-between', gap: '1rem', marginBottom: '0.35rem' }}>
                          <p style={{ fontFamily: 'monospace', fontSize: '0.76rem', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{cellule.cellule_id}</p>
                          <HealthBadge tone={statusTone}>{days === 0 ? 'expirée' : `${days ?? '-'} jours`}</HealthBadge>
                        </div>
                        <p style={{ color: 'var(--text-secondary)', fontSize: '0.74rem', fontFamily: 'monospace' }}>manifest: {cellule.manifest_cid || '-'}</p>
                        <p style={{ color: 'var(--text-secondary)', fontSize: '0.74rem', marginTop: '0.2rem' }}><Clock size={12} style={{ verticalAlign: 'middle' }} /> expire {fmtDate(cellule.expires_at)}</p>
                      </div>
                    );
                  })}
                </div>
              </section>

              <section style={{ border: '1px solid var(--border-color)', borderRadius: 8, overflow: 'hidden' }}>
                <div style={{ padding: '0.9rem 1rem', borderBottom: '1px solid var(--border-color)', display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                  <h3 style={{ fontSize: '0.95rem' }}>Où les données sont stockées</h3>
                  <HealthBadge tone="ok"><MapPin size={13} /> preuve locale</HealthBadge>
                </div>
                <div style={{ maxHeight: 320, overflow: 'auto' }}>
                  {shardRows.length === 0 && <p style={{ padding: '1rem', color: 'var(--text-secondary)', fontSize: '0.85rem' }}>Aucun reçu de shard local pour l’instant.</p>}
                  {shardRows.map((row) => (
                    <div key={row.shardId} style={{ padding: '0.8rem 1rem', borderBottom: '1px solid rgba(255,255,255,0.05)' }}>
                      <div style={{ display: 'flex', justifyContent: 'space-between', gap: '0.8rem', marginBottom: '0.3rem' }}>
                        <p style={{ fontFamily: 'monospace', fontSize: '0.74rem', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{row.shardId}</p>
                        <HealthBadge tone={row.signed ? 'ok' : 'warn'}>{row.signed ? 'signé' : 'non signé'}</HealthBadge>
                      </div>
                      <p style={{ color: 'var(--text-secondary)', fontSize: '0.74rem' }}>noeud : {row.nodeId} · type : {row.type} · taille : {formatBytes(row.sizeBytes)}</p>
                      <p style={{ color: 'var(--text-secondary)', fontSize: '0.74rem', marginTop: '0.2rem' }}>dernière preuve : {fmtDate(row.issuedAt)} · reçus : {row.count}</p>
                    </div>
                  ))}
                </div>
              </section>
            </div>

            <div style={{ padding: '0.85rem 1rem', border: '1px solid rgba(69,243,255,0.2)', background: 'rgba(69,243,255,0.045)', borderRadius: 8, color: 'var(--text-secondary)', fontSize: '0.8rem', lineHeight: 1.55 }}>
              Ce noeud local montre sa propre santé et les shards qu’il peut prouver localement. Un rapport de placement complet par Cellule ne doit être affiché qu’après authentification du propriétaire par signature ; la requête signée peut débloquer le contexte de manifeste du propriétaire sans révéler de métadonnées en clair au noeud de stockage ni donner de clés privées au navigateur.
            </div>
          </>
        )}
      </div>
    </div>
  );
}
