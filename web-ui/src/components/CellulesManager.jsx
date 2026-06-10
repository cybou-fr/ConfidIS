import { useState, useEffect, useCallback } from 'react';
import { Database, Plus, Search, MoreVertical, ShieldCheck, Clock, Share2, X, Copy, Check, QrCode, RefreshCw, AlertTriangle, Upload, Download, ClipboardList, BarChart3, Activity, ClipboardSignature, FolderOpen } from 'lucide-react';
import { QRCodeSVG } from 'qrcode.react';
import { fetchCellules, daysUntil } from '../api';
import { useToast } from './Toast';
import CreateCelluleWizard from './CreateCelluleWizard';
import FileUploadPanel from './FileUploadPanel';
import RenewCellulePanel from './RenewCellulePanel';
import DownloadCellulePanel from './DownloadCellulePanel';
import AuditLogPanel from './AuditLogPanel';
import StorageAnalyticsPanel from './StorageAnalyticsPanel';
import DataHealthPanel from './DataHealthPanel';
import OwnerReportPanel from './OwnerReportPanel';

function useCellules(toast) {
  const [cellules, setCellules] = useState(null);
  const [error, setError] = useState(null);
  const [loading, setLoading] = useState(true);

  const load = useCallback(async (isManual = false) => {
    setLoading(true);
    try {
      const data = await fetchCellules();
      setCellules(data);
      setError(null);
      if (isManual) toast.success(`${data.length} cellule(s) chargée(s)`);
      // Warn about cellules expiring within 7 days (only on initial load to avoid spam).
      const expiring = data.filter((c) => {
        const d = daysUntil(c.expires_at);
        return d !== null && d <= 7;
      });
      if (expiring.length > 0) {
        toast.warning(
          `${expiring.length} cellule(s) expirant sous 7 jours — pensez à renouveler`,
          6000,
        );
      }
    } catch (e) {
      const isOffline = e instanceof TypeError && /fetch|network/i.test(e.message);
      setError(
        isOffline
          ? 'Noeud injoignable — vérifiez VITE_NODE_URL et que le noeud est démarré'
          : 'Impossible de charger les Cellules depuis le noeud. registry_path est-il configuré ?',
      );
      if (isManual) toast.error('Échec du rafraîchissement des cellules');
    } finally {
      setLoading(false);
    }
  }, [toast]);

  useEffect(() => { load(false); }, [load]);
  return { cellules, error, loading, reload: () => load(true) };
}

function ShareModal({ cellule, onClose }) {
  const [tab, setTab] = useState('url');
  const [input, setInput] = useState('');
  const [copied, setCopied] = useState(null);

  const copy = (text, key) => {
    navigator.clipboard.writeText(text);
    setCopied(key);
    setTimeout(() => setCopied(null), 2000);
  };

  const tabStyle = (t) => ({
    padding: '0.5rem 1rem', borderRadius: '8px', border: 'none', cursor: 'pointer',
    fontSize: '0.825rem', fontWeight: 600, transition: 'all 0.15s',
    background: tab === t ? 'rgba(69,243,255,0.12)' : 'transparent',
    color: tab === t ? 'var(--accent-primary)' : 'var(--text-secondary)',
  });

  return (
    <div style={{ position: 'fixed', inset: 0, background: 'rgba(0,0,0,0.7)', backdropFilter: 'blur(8px)', display: 'flex', alignItems: 'center', justifyContent: 'center', zIndex: 1000, padding: '1rem' }}>
      <div className="glass-panel" style={{ width: '100%', maxWidth: '540px', padding: '1.75rem' }}>
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '1.25rem' }}>
          <h2 style={{ fontSize: '1.1rem', fontWeight: 700, display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
            <Share2 size={18} color="var(--accent-primary)" /> Partager l’accès à la Cellule
          </h2>
          <button onClick={onClose} style={{ background: 'transparent', border: 'none', color: 'var(--text-secondary)', cursor: 'pointer' }}>
            <X size={20} />
          </button>
        </div>

        <div style={{ marginBottom: '1.25rem', padding: '0.75rem 1rem', background: 'rgba(255,255,255,0.03)', borderRadius: '10px', border: '1px solid var(--border-color)' }}>
          <p style={{ fontSize: '0.75rem', color: 'var(--text-secondary)', marginBottom: '0.2rem' }}>Partage de l’accès à</p>
          <p style={{ fontWeight: 600, fontSize: '0.9rem' }}>{cellule.name}</p>
          <p style={{ fontFamily: 'monospace', fontSize: '0.75rem', color: 'var(--text-secondary)' }}>{cellule.id}</p>
        </div>

        <div style={{ display: 'flex', alignItems: 'flex-start', gap: '0.6rem', background: 'rgba(255,42,122,0.06)', border: '1px solid rgba(255,42,122,0.2)', borderRadius: '8px', padding: '0.75rem 1rem', marginBottom: '1.25rem', fontSize: '0.8rem', color: '#f9a8d4' }}>
          <AlertTriangle size={16} style={{ flexShrink: 0, marginTop: 2 }} />
          <div>
            <strong>Générez d’abord les artefacts de partage avec la CLI.</strong>
            <code style={{ display: 'block', marginTop: '0.4rem', fontFamily: 'monospace', wordBreak: 'break-all', color: '#a5f3fc', fontSize: '0.7rem', lineHeight: 1.45 }}>
              confidis cellule share --cellule-id {cellule.id} --registry ./registry.json --private-key &lt;hex&gt; --cellule-key ./cellule.key --node https://node.example.com
            </code>
          </div>
        </div>

        <div style={{ display: 'flex', gap: '0.25rem', marginBottom: '1.25rem', padding: '0.25rem', background: 'rgba(255,255,255,0.04)', borderRadius: '10px' }}>
          <button style={tabStyle('url')} onClick={() => setTab('url')}>URL d’accès</button>
          <button style={tabStyle('mnemonic')} onClick={() => setTab('mnemonic')}>Phrase mnémonique</button>
          <button style={tabStyle('qr')} onClick={() => setTab('qr')}>QR Code</button>
        </div>

        {tab === 'url' && (
          <div>
            <p style={{ fontSize: '0.825rem', color: 'var(--text-secondary)', marginBottom: '0.75rem', lineHeight: 1.6 }}>
              Collez l’<code style={{ fontFamily: 'monospace', color: 'var(--accent-primary)', fontSize: '0.8em' }}>access_url</code> issu de la sortie CLI. La clé de Cellule réside dans le fragment d’URL — jamais envoyée à un serveur.
            </p>
            <textarea onChange={(e) => setInput(e.target.value)} placeholder="https://confidis.fr/access#eyJ2IjoxLCJjaWQiOi..." rows={4}
              style={{ width: '100%', background: 'rgba(0,0,0,0.3)', border: '1px solid var(--border-color)', borderRadius: '8px', color: 'var(--text-primary)', padding: '0.75rem', fontFamily: 'monospace', fontSize: '0.75rem', resize: 'vertical', outline: 'none', boxSizing: 'border-box' }} />
            {input && <button className="btn btn-secondary" style={{ marginTop: '0.75rem', width: '100%' }} onClick={() => copy(input, 'url')}>
              {copied === 'url' ? <><Check size={16} /> Copié !</> : <><Copy size={16} /> Copier l’URL</>}
            </button>}
          </div>
        )}

        {tab === 'mnemonic' && (
          <div>
            <p style={{ fontSize: '0.825rem', color: 'var(--text-secondary)', marginBottom: '0.75rem', lineHeight: 1.6 }}>
              Collez la phrase mnémonique BIP39 de 24 mots issue de la sortie CLI. Elle encode votre clé de Cellule de 32 octets.
            </p>
            <textarea onChange={(e) => setInput(e.target.value)} placeholder="acoustic absorb above ability able absent access ..." rows={4}
              style={{ width: '100%', background: 'rgba(0,0,0,0.3)', border: '1px solid var(--border-color)', borderRadius: '8px', color: 'var(--text-primary)', padding: '0.75rem', fontFamily: 'monospace', fontSize: '0.825rem', resize: 'vertical', outline: 'none', boxSizing: 'border-box' }} />
            <div style={{ background: 'rgba(168,85,247,0.06)', border: '1px solid rgba(168,85,247,0.2)', borderRadius: '8px', padding: '0.75rem 1rem', marginTop: '0.75rem', fontSize: '0.8rem', color: 'var(--text-secondary)' }}>
              Toute personne disposant de cette phrase peut lire toutes les données de cette Cellule. Conservez-la hors ligne, chiffrée.
            </div>
            {input && <button className="btn btn-secondary" style={{ marginTop: '0.75rem', width: '100%' }} onClick={() => copy(input, 'mnemonic')}>
              {copied === 'mnemonic' ? <><Check size={16} /> Copié !</> : <><Copy size={16} /> Copier la phrase</>}
            </button>}
          </div>
        )}

        {tab === 'qr' && (
          <div style={{ display: 'flex', flexDirection: 'column', alignItems: 'center', gap: '1rem' }}>
            <p style={{ fontSize: '0.825rem', color: 'var(--text-secondary)', textAlign: 'center', lineHeight: 1.6 }}>
              Collez <code style={{ fontFamily: 'monospace', color: 'var(--accent-primary)', fontSize: '0.8em' }}>access_url</code> ou <code style={{ fontFamily: 'monospace', color: 'var(--accent-primary)', fontSize: '0.8em' }}>qr_data</code> pour générer un QR code imprimable.
            </p>
            <input type="text" placeholder="Collez access_url ou qr_data ici…" value={input} onChange={(e) => setInput(e.target.value)}
              style={{ width: '100%', background: 'rgba(0,0,0,0.3)', border: '1px solid var(--border-color)', borderRadius: '8px', color: 'var(--text-primary)', padding: '0.6rem 0.9rem', fontFamily: 'monospace', fontSize: '0.75rem', outline: 'none', boxSizing: 'border-box' }} />
            {input ? (
              <div style={{ padding: '1rem', background: '#fff', borderRadius: '12px' }}>
                <QRCodeSVG value={input} size={200} bgColor="#ffffff" fgColor="#050608" level="M" />
              </div>
            ) : (
              <div style={{ width: '232px', height: '232px', border: '2px dashed var(--border-color)', borderRadius: '12px', display: 'flex', alignItems: 'center', justifyContent: 'center', flexDirection: 'column', gap: '0.5rem' }}>
                <QrCode size={40} color="var(--text-secondary)" />
                <p style={{ color: 'var(--text-secondary)', fontSize: '0.75rem' }}>Le QR code apparaît ici</p>
              </div>
            )}
            {input && <p style={{ fontSize: '0.75rem', color: 'var(--text-secondary)', textAlign: 'center' }}>Imprimez ou capturez l’écran — le destinataire le scanne pour charger le bundle d’accès.</p>}
          </div>
        )}
      </div>
    </div>
  );
}

function ActionMenu({ cellule, onShare, onRenew, onDownload, onClose }) {
  const menuBtnStyle = { display: 'flex', alignItems: 'center', gap: '0.6rem', width: '100%', background: 'transparent', border: 'none', color: 'var(--text-primary)', cursor: 'pointer', padding: '0.6rem 0.75rem', borderRadius: '7px', fontSize: '0.825rem', textAlign: 'left' };
  return (
    <div style={{ position: 'absolute', right: '2.5rem', top: 0, background: 'rgba(20,22,28,0.98)', border: '1px solid var(--border-color)', borderRadius: '10px', padding: '0.4rem', zIndex: 100, minWidth: '160px', boxShadow: '0 8px 32px rgba(0,0,0,0.5)' }}>
      <button onClick={() => { onShare(); onClose(); }} style={menuBtnStyle}
        onMouseOver={(e) => e.currentTarget.style.background = 'rgba(255,255,255,0.06)'}
        onMouseOut={(e) => e.currentTarget.style.background = 'transparent'}>
        <Share2 size={14} /> Partager l’accès
      </button>
      <button onClick={() => { onDownload(); onClose(); }} style={menuBtnStyle}
        onMouseOver={(e) => e.currentTarget.style.background = 'rgba(255,255,255,0.06)'}
        onMouseOut={(e) => e.currentTarget.style.background = 'transparent'}>
        <Download size={14} /> Télécharger
      </button>
      {(cellule.daysLeft === null || cellule.daysLeft <= 30) && (
        <button onClick={() => { onRenew(); }} style={{ ...menuBtnStyle, color: '#fb923c' }}
          onMouseOver={(e) => e.currentTarget.style.background = 'rgba(251,146,60,0.08)'}
          onMouseOut={(e) => e.currentTarget.style.background = 'transparent'}>
          <RefreshCw size={14} /> Renouveler
        </button>
      )}
    </div>
  );
}

export default function CellulesManager() {
  const toast = useToast();
  const [search, setSearch] = useState('');
  const [shareTarget, setShareTarget] = useState(null);
  const [menuOpen, setMenuOpen] = useState(null);
  const [showCreateWizard, setShowCreateWizard] = useState(false);
  const [showUploadPanel, setShowUploadPanel] = useState(false);
  const [showRenewPanel, setShowRenewPanel] = useState(false);
  const [downloadTarget, setDownloadTarget] = useState(null); // cellule id or ''
  const [showAuditLog, setShowAuditLog] = useState(false);
  const [showAnalytics, setShowAnalytics] = useState(false);
  const [showDataHealth, setShowDataHealth] = useState(false);
  const [showOwnerReport, setShowOwnerReport] = useState(false);
  const { cellules, error, loading, reload } = useCellules(toast);

  // Derive UI fields from CellulePublicRecord
  const toRow = (c) => {
    const days = daysUntil(c.expires_at);
    const status = days === null ? 'Inconnu' : days <= 30 ? 'Bientôt expirée' : 'Active';
    const label = days === null ? '—' : days === 0 ? 'Expirée' : `${days} jours`;
    return { id: c.cellule_id, name: c.manifest_cid ? `${c.cellule_id.slice(0, 8)}…` : c.cellule_id, cid: c.manifest_cid || '—', expires: label, status, daysLeft: days };
  };

  const rows = (cellules || []).map(toRow).filter(c =>
    c.id.includes(search) || c.name.toLowerCase().includes(search.toLowerCase()) || c.cid.includes(search)
  );

  // Cellules expiring within 30 days — passed to RenewCellulePanel as pre-selection.
  const expiringSoon = rows
    .filter((c) => c.daysLeft !== null && c.daysLeft <= 30)
    .map((c) => ({ id: c.id, name: c.name, days_left: c.daysLeft }));

  return (
    <div style={{ padding: '2rem' }} onClick={() => setMenuOpen(null)}>
      <header style={{ marginBottom: '2.5rem', display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', gap: '1rem', flexWrap: 'wrap' }}>
        <div>
          <h1 style={{ fontSize: '2rem', fontWeight: 700, marginBottom: '0.5rem', display: 'flex', alignItems: 'center', gap: '0.75rem' }}>
            <Database color="var(--accent-primary)" /> Cellules
          </h1>
          <p style={{ color: 'var(--text-secondary)' }}>Gérez vos espaces de données chiffrés zero-knowledge.</p>
        </div>
        <div style={{ display: 'flex', gap: '0.75rem', alignItems: 'center', flexWrap: 'wrap', justifyContent: 'flex-end' }}>
          <button onClick={reload} style={{ background: 'transparent', border: '1px solid var(--border-color)', color: 'var(--text-secondary)', cursor: 'pointer', padding: '0.5rem', borderRadius: '8px', display: 'flex', alignItems: 'center' }} title="Rafraîchir">
            <RefreshCw size={16} />
          </button>
          <button onClick={() => setShowCreateWizard(true)} className="btn btn-primary"><Plus size={18} /> Créer une Cellule</button>
          <button onClick={() => setShowUploadPanel(true)} className="btn btn-secondary"><Upload size={18} /> Téléverser un fichier</button>
          <button onClick={() => setShowRenewPanel(true)} className="btn btn-secondary"><RefreshCw size={18} /> Renouveler</button>
          <button onClick={() => setShowDataHealth(true)} className="btn btn-secondary"><Activity size={18} /> Santé des données</button>
          <button onClick={() => setShowOwnerReport(true)} className="btn btn-secondary"><ClipboardSignature size={18} /> Rapport propriétaire</button>
          <button onClick={() => setShowAuditLog(true)} className="btn btn-secondary"><ClipboardList size={18} /> Journal d’audit</button>
          <button onClick={() => setShowAnalytics(true)} className="btn btn-secondary"><BarChart3 size={18} /> Analytique</button>
        </div>
      </header>

      <div className="glass-panel" style={{ padding: '1.5rem', marginBottom: '2rem' }}>
        <div style={{ marginBottom: '1.5rem' }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', background: 'rgba(255,255,255,0.05)', padding: '0.5rem 1rem', borderRadius: '8px', width: 'min(100%, 340px)', border: '1px solid var(--border-color)' }}>
            <Search size={16} color="var(--text-secondary)" />
            <input type="text" placeholder="Rechercher des cellules…" value={search} onChange={(e) => setSearch(e.target.value)}
              style={{ background: 'transparent', border: 'none', color: 'var(--text-primary)', outline: 'none', width: '100%', fontSize: '0.875rem' }} />
          </div>
        </div>

        {error && (
          <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', gap: '0.75rem', padding: '1rem 1.25rem', background: 'rgba(255,42,122,0.06)', border: '1px solid rgba(255,42,122,0.2)', borderRadius: '10px', marginBottom: '1rem' }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: '0.75rem', color: '#f9a8d4', fontSize: '0.875rem' }}>
              <AlertTriangle size={16} style={{ flexShrink: 0 }} />
              <span>{error}</span>
            </div>
            <button onClick={() => reload()} style={{ display: 'flex', alignItems: 'center', gap: '0.4rem', padding: '0.4rem 0.85rem', background: 'rgba(255,42,122,0.12)', border: '1px solid rgba(255,42,122,0.3)', borderRadius: '7px', color: '#f9a8d4', cursor: 'pointer', fontSize: '0.8rem', fontWeight: 600, whiteSpace: 'nowrap' }}>
              <RefreshCw size={13} /> Réessayer
            </button>
          </div>
        )}

        {loading && (
          <div style={{ textAlign: 'center', padding: '3rem', color: 'var(--text-secondary)', fontSize: '0.9rem' }}>Chargement des Cellules…</div>
        )}

        {!loading && (
        <div style={{ display: 'grid', gap: '1rem' }}>
          {rows.map((cell) => (
            <div key={cell.id}
              style={{ display: 'grid', gridTemplateColumns: 'minmax(240px, 1.4fr) minmax(120px, 0.7fr) minmax(120px, 0.7fr) minmax(110px, 0.55fr) auto', gap: '1rem', alignItems: 'center', padding: '1.25rem', background: 'rgba(255,255,255,0.02)', borderRadius: '12px', border: '1px solid var(--border-color)', position: 'relative', transition: 'var(--transition)', overflowX: 'auto' }}
              onMouseOver={(e) => e.currentTarget.style.background = 'rgba(255,255,255,0.05)'}
              onMouseOut={(e) => e.currentTarget.style.background = 'rgba(255,255,255,0.02)'}
            >
              <div style={{ display: 'flex', alignItems: 'center', gap: '1rem', minWidth: 0 }}>
                <div style={{ width: '40px', height: '40px', borderRadius: '10px', background: 'rgba(69,243,255,0.1)', display: 'flex', alignItems: 'center', justifyContent: 'center', color: 'var(--accent-primary)', flexShrink: 0 }}>
                  <ShieldCheck size={20} />
                </div>
                <div style={{ minWidth: 0 }}>
                  <h4 style={{ fontWeight: 600, fontSize: '1rem', marginBottom: '0.25rem' }}>{cell.name}</h4>
                  <p style={{ color: 'var(--text-secondary)', fontSize: '0.75rem', fontFamily: 'monospace', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{cell.id}</p>
                </div>
              </div>

              <div>
                <p style={{ color: 'var(--text-secondary)', fontSize: '0.75rem', marginBottom: '0.25rem' }}>CID du manifeste</p>
                <p style={{ fontWeight: 500, fontSize: '0.75rem', fontFamily: 'monospace', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap', maxWidth: '120px' }}>{cell.cid}</p>
              </div>

              <div>
                <p style={{ color: 'var(--text-secondary)', fontSize: '0.75rem', marginBottom: '0.25rem' }}>Expire dans</p>
                <p style={{ fontWeight: 500, fontSize: '0.875rem', display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
                  <Clock size={14} color={cell.status === 'Bientôt expirée' ? 'var(--accent-secondary)' : 'var(--text-secondary)'} />
                  <span style={{ color: cell.status === 'Bientôt expirée' ? 'var(--accent-secondary)' : 'inherit' }}>{cell.expires}</span>
                </p>
              </div>

              <div>
                <span style={{ display: 'inline-block', padding: '0.25rem 0.75rem', borderRadius: '20px', fontSize: '0.75rem', fontWeight: 600, background: cell.status === 'Active' ? 'rgba(74,222,128,0.1)' : 'rgba(255,42,122,0.1)', color: cell.status === 'Active' ? '#4ade80' : 'var(--accent-secondary)', border: `1px solid ${cell.status === 'Active' ? 'rgba(74,222,128,0.2)' : 'rgba(255,42,122,0.2)'}` }}>
                  {cell.status}
                </span>
              </div>

              <div style={{ position: 'relative' }} onClick={(e) => e.stopPropagation()}>
                <button onClick={() => setMenuOpen(menuOpen === cell.id ? null : cell.id)}
                  style={{ background: 'transparent', border: 'none', color: 'var(--text-secondary)', cursor: 'pointer', padding: '0.5rem', borderRadius: '6px' }}>
                  <MoreVertical size={18} />
                </button>
                {menuOpen === cell.id && (
                  <ActionMenu cellule={cell} onShare={() => setShareTarget(cell)}
                    onDownload={() => { setMenuOpen(null); setDownloadTarget(cell.id); }}
                    onRenew={() => { setMenuOpen(null); setShowRenewPanel(true); }}
                    onClose={() => setMenuOpen(null)} />
                )}
              </div>
            </div>
          ))}

          {rows.length === 0 && !error && (
            search ? (
              <div style={{ textAlign: 'center', padding: '3rem', color: 'var(--text-secondary)', fontSize: '0.9rem' }}>
                Aucune Cellule ne correspond à votre recherche.
              </div>
            ) : cellules !== null && cellules.length === 0 ? (
              /* Empty state — no cellules yet */
              <div style={{ textAlign: 'center', padding: '3.5rem 2rem' }}>
                <div style={{ width: 64, height: 64, margin: '0 auto 1rem', borderRadius: 16, display: 'flex', alignItems: 'center', justifyContent: 'center', background: 'rgba(69,243,255,0.08)', border: '1px solid rgba(69,243,255,0.22)', color: 'var(--accent-primary)' }}>
                  <FolderOpen size={34} />
                </div>
                <h3 style={{ fontWeight: 700, fontSize: '1.1rem', marginBottom: '0.5rem' }}>Aucune Cellule pour l’instant</h3>
                <p style={{ color: 'var(--text-secondary)', fontSize: '0.875rem', maxWidth: '380px', margin: '0 auto 1.5rem' }}>
                  Une Cellule est une copie réseau temporaire chiffrée. Votre original reste hors réseau ; créez la Cellule au premier téléversement signé.
                </p>
                <div style={{ display: 'flex', gap: '0.75rem', justifyContent: 'center', flexWrap: 'wrap' }}>
                  <button onClick={() => setShowCreateWizard(true)} className="btn btn-primary">
                    <Plus size={16} /> Préparer une Cellule
                  </button>
                  <button onClick={() => setShowUploadPanel(true)} className="btn btn-secondary">
                    <Upload size={16} /> Téléverser un fichier
                  </button>
                </div>
                <p style={{ marginTop: '2rem', color: 'var(--text-secondary)', fontSize: '0.8rem' }}>
                  Ou utilisez la CLI : <code style={{ background: 'rgba(255,255,255,0.07)', padding: '0.15rem 0.45rem', borderRadius: '4px', fontFamily: 'monospace', fontSize: '0.78rem' }}>confidis cellule put --expires-at &lt;RFC3339 ≤ 365 jours&gt;</code>
                </p>
              </div>
            ) : null
          )}
        </div>
        )}
      </div>

      {shareTarget && <ShareModal cellule={shareTarget} onClose={() => setShareTarget(null)} />}
      {showCreateWizard && (
        <CreateCelluleWizard onClose={() => { setShowCreateWizard(false); reload(); }} />
      )}
      {showUploadPanel && (
        <FileUploadPanel onClose={() => setShowUploadPanel(false)} />
      )}
      {showRenewPanel && (
        <RenewCellulePanel expiringSoon={expiringSoon} onClose={() => setShowRenewPanel(false)} />
      )}
      {downloadTarget !== null && (
        <DownloadCellulePanel initialCelluleId={downloadTarget} onClose={() => setDownloadTarget(null)} />
      )}
      {showAuditLog && (
        <AuditLogPanel onClose={() => setShowAuditLog(false)} />
      )}
      {showAnalytics && (
        <StorageAnalyticsPanel onClose={() => setShowAnalytics(false)} />
      )}
      {showDataHealth && (
        <DataHealthPanel onClose={() => setShowDataHealth(false)} />
      )}
      {showOwnerReport && (
        <OwnerReportPanel onClose={() => setShowOwnerReport(false)} />
      )}
    </div>
  );
}
