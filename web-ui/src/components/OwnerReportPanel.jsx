import { useEffect, useMemo, useState } from 'react';
import { AlertTriangle, Check, ClipboardSignature, Copy, RefreshCw, ShieldCheck, X } from 'lucide-react';
import { fetchCellules, requestOwnerReportChallenge, verifyOwnerReportProof } from '../api';

function celluleId(value) {
  if (Array.isArray(value)) return value[0] || '';
  return value || '';
}

function short(value, head = 12, tail = 8) {
  if (!value) return '—';
  if (value.length <= head + tail + 1) return value;
  return `${value.slice(0, head)}…${value.slice(-tail)}`;
}

function CodeBlock({ text }) {
  const [copied, setCopied] = useState(false);
  const copy = async () => {
    await navigator.clipboard.writeText(text);
    setCopied(true);
    setTimeout(() => setCopied(false), 1600);
  };
  return (
    <div style={{ display: 'grid', gap: '0.55rem' }}>
      <pre style={{ margin: 0, padding: '0.8rem', background: 'rgba(0,0,0,0.3)', border: '1px solid var(--border-color)', borderRadius: '8px', overflowX: 'auto', color: '#a5f3fc', fontSize: '0.72rem', lineHeight: 1.5 }}>{text}</pre>
      <button onClick={copy} className="btn btn-secondary" style={{ justifySelf: 'start', padding: '0.45rem 0.75rem', fontSize: '0.78rem' }}>
        {copied ? <><Check size={14} /> Copié</> : <><Copy size={14} /> Copier la commande</>}
      </button>
    </div>
  );
}

export default function OwnerReportPanel({ initialCelluleId = '', onClose }) {
  const [cellules, setCellules] = useState([]);
  const [celluleIdValue, setCelluleIdValue] = useState(initialCelluleId);
  const [challenge, setChallenge] = useState(null);
  const [proofText, setProofText] = useState('');
  const [verified, setVerified] = useState(null);
  const [reportText, setReportText] = useState('');
  const [report, setReport] = useState(null);
  const [error, setError] = useState(null);
  const [loading, setLoading] = useState(false);

  useEffect(() => {
    fetchCellules().then((records) => {
      setCellules(records);
      if (!initialCelluleId && records.length > 0) setCelluleIdValue(celluleId(records[0].cellule_id));
    }).catch(() => setCellules([]));
  }, [initialCelluleId]);

  const command = useMemo(() => {
    if (!challenge) return '';
    return `confidis cellule report-proof \\
  --cellule-id ${challenge.cellule_id?.[0] || challenge.cellule_id || celluleIdValue} \\
  --registry ./registry.json \\
  --owner-private-key <hex> \\
  --challenge ${challenge.challenge} \\
  --scope cellule.report \\
  --output ./owner-report-proof.json`;
  }, [challenge, celluleIdValue]);

  const reportCommand = useMemo(() => {
    if (!verified) return '';
    return `confidis cellule report-export \\
  --cellule-id ${celluleId(verified.cellule_id)} \\
  --registry ./registry.json \\
  --blob-store ./blobs \\
  --owner-private-key <hex> \\
  --cellule-key ./cellule.key \\
  --proof ./owner-report-proof.json \\
  --output ./owner-report.json`;
  }, [verified]);

  const requestChallenge = async () => {
    setLoading(true);
    setError(null);
    setVerified(null);
    try {
      const result = await requestOwnerReportChallenge(celluleIdValue.trim());
      setChallenge(result);
    } catch (e) {
      const isOffline = e instanceof TypeError && /fetch|network/i.test(e.message);
      setError(isOffline ? 'Noeud injoignable — vérifiez VITE_NODE_URL' : 'Impossible de demander le challenge de rapport propriétaire');
    } finally {
      setLoading(false);
    }
  };

  const verifyProof = async () => {
    setLoading(true);
    setError(null);
    try {
      const parsed = JSON.parse(proofText);
      const proof = parsed.proof || parsed;
      const result = await verifyOwnerReportProof(proof);
      setVerified(result);
      setReport(null);
      setReportText('');
    } catch (e) {
      setVerified(null);
      setError(e instanceof SyntaxError ? 'Le JSON de preuve est invalide' : 'Échec de la vérification de la preuve propriétaire');
    } finally {
      setLoading(false);
    }
  };

  const importReport = () => {
    setError(null);
    try {
      const parsed = JSON.parse(reportText);
      setReport(parsed);
    } catch {
      setReport(null);
      setError('Le JSON du rapport propriétaire est invalide');
    }
  };

  return (
    <div style={{ position: 'fixed', inset: 0, background: 'rgba(0,0,0,0.7)', backdropFilter: 'blur(8px)', zIndex: 1000, padding: '1rem', overflowY: 'auto' }}>
      <div className="glass-panel" style={{ width: 'min(860px, 100%)', margin: '2rem auto', padding: '1.5rem' }}>
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', gap: '1rem', marginBottom: '1.25rem' }}>
          <div>
            <h2 style={{ fontSize: '1.15rem', fontWeight: 700, display: 'flex', alignItems: 'center', gap: '0.55rem', marginBottom: '0.35rem' }}>
              <ClipboardSignature size={18} color="var(--accent-primary)" /> Authentification du rapport propriétaire
            </h2>
            <p style={{ color: 'var(--text-secondary)', fontSize: '0.84rem', margin: 0 }}>Signez un challenge à durée de vie courte avant tout flux de rapport complet de Cellule.</p>
          </div>
          <button onClick={onClose} style={{ background: 'transparent', border: 'none', color: 'var(--text-secondary)', cursor: 'pointer' }}><X size={20} /></button>
        </div>

        <div style={{ background: 'rgba(251,146,60,0.07)', border: '1px solid rgba(251,146,60,0.22)', borderRadius: '8px', padding: '0.75rem 0.9rem', marginBottom: '1rem', display: 'flex', gap: '0.65rem', color: '#fed7aa', fontSize: '0.8rem', lineHeight: 1.5 }}>
          <AlertTriangle size={16} style={{ flexShrink: 0, marginTop: '0.1rem' }} />
          <span>Le navigateur ne reçoit jamais votre clé privée. Exécutez la commande générée localement, puis collez uniquement le JSON de preuve signé.</span>
        </div>

        <div style={{ display: 'grid', gap: '0.75rem', marginBottom: '1rem' }}>
          <label style={{ color: 'var(--text-secondary)', fontSize: '0.78rem' }}>Cellule</label>
          <input list="owner-report-cellules" value={celluleIdValue} onChange={(e) => setCelluleIdValue(e.target.value)} placeholder="identifiant de cellule"
            style={{ width: '100%', boxSizing: 'border-box', background: 'rgba(0,0,0,0.24)', border: '1px solid var(--border-color)', borderRadius: '8px', color: 'var(--text-primary)', padding: '0.7rem 0.85rem', outline: 'none', fontSize: '0.84rem', fontFamily: 'monospace' }} />
          <datalist id="owner-report-cellules">
            {cellules.map((record) => <option key={celluleId(record.cellule_id)} value={celluleId(record.cellule_id)} />)}
          </datalist>
          <button onClick={requestChallenge} disabled={!celluleIdValue.trim() || loading} className="btn btn-primary" style={{ justifySelf: 'start' }}>
            <RefreshCw size={15} /> Demander un challenge
          </button>
        </div>

        {error && <div style={{ padding: '0.85rem', border: '1px solid rgba(255,42,122,0.25)', borderRadius: '8px', color: '#f9a8d4', marginBottom: '1rem' }}>{error}</div>}

        {challenge && (
          <div style={{ display: 'grid', gap: '1rem' }}>
            <div style={{ border: '1px solid var(--border-color)', borderRadius: '8px', padding: '1rem', background: 'rgba(255,255,255,0.025)' }}>
              <p style={{ color: 'var(--text-secondary)', fontSize: '0.78rem', margin: '0 0 0.35rem' }}>Challenge</p>{/* terme technique */}
              <p style={{ fontFamily: 'monospace', fontSize: '0.78rem', margin: 0, color: 'var(--text-primary)', wordBreak: 'break-all' }}>{challenge.challenge}</p>
              <p style={{ color: 'var(--text-secondary)', fontSize: '0.75rem', margin: '0.6rem 0 0' }}>Clé propriétaire {short(challenge.owner_public_key)}</p>
            </div>

            <CodeBlock text={command} />

            <div style={{ display: 'grid', gap: '0.6rem' }}>
              <label style={{ color: 'var(--text-secondary)', fontSize: '0.78rem' }}>JSON de preuve signé</label>
              <textarea value={proofText} onChange={(e) => setProofText(e.target.value)} rows={7} placeholder='Collez la sortie de owner-report-proof.json'
                style={{ width: '100%', boxSizing: 'border-box', background: 'rgba(0,0,0,0.28)', border: '1px solid var(--border-color)', borderRadius: '8px', color: 'var(--text-primary)', padding: '0.75rem', outline: 'none', fontSize: '0.76rem', fontFamily: 'monospace', resize: 'vertical' }} />
              <button onClick={verifyProof} disabled={!proofText.trim() || loading} className="btn btn-secondary" style={{ justifySelf: 'start' }}>
                <ShieldCheck size={15} /> Vérifier la preuve propriétaire
              </button>
            </div>
          </div>
        )}

        {verified && (
          <div style={{ marginTop: '1rem', border: '1px solid rgba(74,222,128,0.24)', background: 'rgba(74,222,128,0.07)', borderRadius: '8px', padding: '1rem', color: '#bbf7d0' }}>
            <p style={{ margin: '0 0 0.4rem', fontWeight: 700 }}>Signature propriétaire vérifiée</p>
            <p style={{ margin: 0, fontSize: '0.8rem' }}>Cellule {short(celluleId(verified.cellule_id), 14, 10)} · manifeste {short(verified.record?.manifest_cid, 14, 10)}</p>
            <p style={{ margin: '0.6rem 0 0', fontSize: '0.78rem', color: '#d9f99d' }}>{verified.warning}</p>
          </div>
        )}

        {verified && (
          <div style={{ marginTop: '1rem', display: 'grid', gap: '1rem' }}>
            <div>
              <p style={{ color: 'var(--text-secondary)', fontSize: '0.82rem', margin: '0 0 0.55rem' }}>Générez le rapport complet en local</p>
              <CodeBlock text={reportCommand} />
            </div>
            <div style={{ display: 'grid', gap: '0.6rem' }}>
              <label style={{ color: 'var(--text-secondary)', fontSize: '0.78rem' }}>JSON du rapport propriétaire</label>
              <textarea value={reportText} onChange={(e) => setReportText(e.target.value)} rows={7} placeholder="Collez owner-report.json"
                style={{ width: '100%', boxSizing: 'border-box', background: 'rgba(0,0,0,0.28)', border: '1px solid var(--border-color)', borderRadius: '8px', color: 'var(--text-primary)', padding: '0.75rem', outline: 'none', fontSize: '0.76rem', fontFamily: 'monospace', resize: 'vertical' }} />
              <button onClick={importReport} disabled={!reportText.trim()} className="btn btn-secondary" style={{ justifySelf: 'start' }}>
                <ShieldCheck size={15} /> Afficher le rapport
              </button>
            </div>
          </div>
        )}

        {report && (
          <div style={{ marginTop: '1rem', display: 'grid', gap: '1rem' }}>
            <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(130px, 1fr))', gap: '0.75rem' }}>
              {[
                ['Disponibles', `${report.availability?.available_shards ?? '—'} / ${report.availability ? report.availability.available_shards + report.availability.missing_shards : '—'}`],
                ['Restauration', report.availability?.restore_possible ? 'possible' : 'à risque'],
                ['Réparation', report.availability?.repair_needed ? 'nécessaire' : 'non nécessaire'],
                ['Fournisseurs', report.providers?.length ?? 0],
                ['Régions', report.regions?.length ?? 0],
                ['Domaines de panne', report.failure_domains?.length ?? 0],
              ].map(([label, value]) => (
                <div key={label} style={{ border: '1px solid var(--border-color)', borderRadius: '8px', padding: '0.75rem', background: 'rgba(255,255,255,0.025)' }}>
                  <p style={{ margin: '0 0 0.25rem', color: 'var(--text-secondary)', fontSize: '0.72rem' }}>{label}</p>
                  <p style={{ margin: 0, fontWeight: 700, fontSize: '1rem' }}>{value}</p>
                </div>
              ))}
            </div>

            <div style={{ border: '1px solid var(--border-color)', borderRadius: '8px', overflow: 'hidden' }}>
              <div style={{ display: 'grid', gridTemplateColumns: '80px 1fr 120px 120px', gap: '0.75rem', padding: '0.7rem 0.85rem', background: 'rgba(255,255,255,0.05)', color: 'var(--text-secondary)', fontSize: '0.72rem' }}>
                <span>Index</span><span>Shard</span><span>Statut</span><span>Fournisseurs</span>
              </div>
              {(report.shards || []).slice(0, 60).map((shard) => (
                <div key={`${shard.shard_index}-${shard.shard_id?.[0] || shard.shard_id}`} style={{ display: 'grid', gridTemplateColumns: '80px 1fr 120px 120px', gap: '0.75rem', padding: '0.7rem 0.85rem', borderTop: '1px solid var(--border-color)', fontSize: '0.76rem', alignItems: 'center' }}>
                  <span>{shard.shard_index}</span>
                  <span style={{ fontFamily: 'monospace', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{short(shard.shard_id?.[0] || shard.shard_id, 14, 8)}</span>
                  <span style={{ color: shard.available ? '#4ade80' : '#f9a8d4' }}>{shard.available ? 'présent' : 'manquant'}</span>
                  <span>{shard.providers?.length ?? 0}</span>
                </div>
              ))}
            </div>
            {report.warning && <p style={{ color: 'var(--text-secondary)', fontSize: '0.78rem', margin: 0 }}>{report.warning}</p>}
          </div>
        )}
      </div>
    </div>
  );
}
