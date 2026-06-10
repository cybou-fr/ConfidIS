// OperatorPanel — operator-side wallet for node administration.
//
// Flow:
//   1. Detect or create an operator-role vault on this browser.
//   2. Unlock with password → session.
//   3. Use the operator identity for signed node administration.

import { useCallback, useEffect, useState } from 'react';
import {
  Building2,
  Unlock,
  Lock,
  AlertTriangle,
  ShieldCheck,
  Search,
  RefreshCw,
  Database,
  Terminal,
  Server,
  Copy,
  FileJson,
  FileSpreadsheet,
  Plug,
  Play,
  Code2,
} from 'lucide-react';

import {
  fetchHealth,
  fetchOperatorSharedCellule,
  fetchOperatorSharedCellules,
  nodeBaseUrl,
  uiTokenConfigured,
} from '../api';
import { ensureCryptoLoaded, loadCrypto } from '../wallet/cryptoBridge';
import {
  listVaults,
  createVault,
  unlockVault,
  SESSION_IDLE_MS,
} from '../wallet/vault';
import {
  flattenData,
  sharedItemsToCsv,
  sharedItemsToCrmCsv,
} from '../operator/sharedDataExport';

const OPERATOR_VAULT_ID = 'operator-default';

const cardStyle = {
  background: 'var(--bg-secondary)',
  border: '1px solid var(--border)',
  borderRadius: '12px',
  padding: '1.5rem',
};

const codeStyle = {
  fontFamily: 'ui-monospace, SFMono-Regular, Menlo, monospace',
  background: 'var(--bg-tertiary, rgba(255,255,255,0.04))',
  padding: '0.75rem 1rem',
  borderRadius: '8px',
  fontSize: '0.85rem',
  wordBreak: 'break-all',
  lineHeight: 1.5,
};

const buttonPrimary = {
  display: 'inline-flex',
  alignItems: 'center',
  gap: '0.5rem',
  padding: '0.65rem 1.25rem',
  background: 'var(--accent-primary)',
  color: 'var(--bg-primary)',
  border: 'none',
  borderRadius: '8px',
  cursor: 'pointer',
  fontWeight: 600,
  fontSize: '0.95rem',
};

const buttonSecondary = {
  ...buttonPrimary,
  background: 'transparent',
  color: 'var(--text-primary)',
  border: '1px solid var(--border)',
};

const inputStyle = {
  width: '100%',
  padding: '0.55rem 0.85rem',
  background: 'var(--bg-tertiary, rgba(255,255,255,0.04))',
  border: '1px solid var(--border)',
  borderRadius: '8px',
  color: 'var(--text-primary)',
  fontSize: '0.95rem',
  fontFamily: 'inherit',
  boxSizing: 'border-box',
};

const smallButton = {
  ...buttonSecondary,
  padding: '0.45rem 0.65rem',
  fontSize: '0.82rem',
};

function shortHex(value, start = 16, end = 8) {
  if (!value) return 'unknown';
  if (value.length <= start + end + 1) return value;
  return `${value.slice(0, start)}…${value.slice(-end)}`;
}

function formatDate(value) {
  if (!value) return 'Pas d’expiration';
  return new Date(value).toLocaleString();
}

function valuePreview(value) {
  if (value == null) return 'Contenu non livré par l’inventaire. Utilisez /access/read/* avec preuve destinataire.';
  if (typeof value === 'string') return value;
  return JSON.stringify(value, null, 2);
}

async function copyText(value) {
  try {
    await navigator.clipboard.writeText(value);
  } catch {
    // Clipboard is a convenience only; command text remains visible.
  }
}

function downloadText(filename, content, type) {
  const blob = new Blob([content], { type });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = filename;
  document.body.appendChild(a);
  a.click();
  a.remove();
  URL.revokeObjectURL(url);
}

function exportSharedJson(items, filename = 'confidis-shared-data.json') {
  downloadText(filename, JSON.stringify({ exported_at: new Date().toISOString(), items }, null, 2), 'application/json');
}

function exportSharedCsv(items, filename = 'confidis-shared-data.csv') {
  downloadText(filename, sharedItemsToCsv(items), 'text/csv;charset=utf-8');
}

function exportSharedCrmCsv(items, filename = 'confidis-crm-contacts.csv') {
  downloadText(filename, sharedItemsToCrmCsv(items), 'text/csv;charset=utf-8');
}

function CommandBlock({ title, command }) {
  return (
    <div style={{ display: 'grid', gap: '0.35rem' }}>
      <div style={{ fontSize: '0.75rem', color: 'var(--text-secondary)', display: 'flex', alignItems: 'center', gap: '0.35rem' }}>
        <Terminal size={13} /> {title}
      </div>
      <div style={{ display: 'flex', gap: '0.5rem', alignItems: 'stretch' }}>
        <pre style={{ ...codeStyle, margin: 0, flex: 1, whiteSpace: 'pre-wrap', fontSize: '0.76rem' }}>{command}</pre>
        <button type="button" onClick={() => copyText(command)} style={{ ...smallButton, alignSelf: 'stretch' }} title="Copier la commande">
          <Copy size={14} />
        </button>
      </div>
    </div>
  );
}

function Notice({ tone = 'info', children }) {
  const colors = {
    info: ['rgba(69, 243, 255, 0.08)', 'rgba(69, 243, 255, 0.25)', 'var(--accent-primary)'],
    warn: ['rgba(244, 196, 0, 0.08)', 'rgba(244, 196, 0, 0.32)', '#f4c400'],
    danger: ['rgba(255, 118, 118, 0.08)', 'rgba(255, 118, 118, 0.32)', '#ff7676'],
  }[tone];
  return (
    <div
      style={{
        display: 'flex',
        gap: '0.75rem',
        alignItems: 'flex-start',
        padding: '0.85rem 1rem',
        background: colors[0],
        border: `1px solid ${colors[1]}`,
        borderRadius: '8px',
        fontSize: '0.85rem',
        lineHeight: 1.55,
        color: 'var(--text-secondary)',
      }}
    >
      <AlertTriangle size={18} color={colors[2]} style={{ flexShrink: 0, marginTop: '2px' }} />
      <div>{children}</div>
    </div>
  );
}

function OperatorSecurityNotice() {
  const [health, setHealth] = useState(null);
  const [error, setError] = useState(null);

  const load = useCallback(async () => {
    try {
      setError(null);
      setHealth(await fetchHealth());
    } catch (err) {
      setError(err.message || String(err));
    }
  }, []);

  useEffect(() => {
    load();
  }, [load]);

  if (error) {
    return (
      <Notice tone="warn">
        Impossible de lire l’état de sécurité du noeud. Vérifiez que le noeud local est joignable avant d’utiliser les flux opérateur.
      </Notice>
    );
  }
  if (!health) return null;

  if (!health.ui_auth_required) {
    return (
      <Notice tone="danger">
        <strong style={{ color: 'var(--text-primary)' }}>Mode développement local :</strong>{' '}
        ce noeud n’a pas de <span style={{ fontFamily: 'monospace' }}>ui_token</span>, donc les API destinées à l’UI ne sont pas protégées.
        Gardez-le lié à localhost et n’utilisez pas de vraies données personnelles partagées tant que <span style={{ fontFamily: 'monospace' }}>ui_token</span>{' '}
        et <span style={{ fontFamily: 'monospace' }}>authorized_operator_pubkeys</span> ne sont pas configurés.
      </Notice>
    );
  }

  if (!uiTokenConfigured()) {
    return (
      <Notice tone="warn">
        Le noeud exige un jeton UI, mais ce build d’interface web n’a pas de jeton correspondant configuré. Les lectures opérateur peuvent échouer tant que l’UI n’est pas servie avec le bon environnement de jeton.
      </Notice>
    );
  }

  if (!health.ui_cors_restricted) {
    return (
      <Notice tone="warn">
        La protection par jeton UI est active, mais le CORS n’est pas restreint. Définissez <span style={{ fontFamily: 'monospace' }}>ui_allowed_origin</span> avant d’exposer ce noeud hors d’un environnement local de confiance.
      </Notice>
    );
  }

  return (
    <Notice>
      La protection par jeton UI est active pour les API opérateur. Les données partagées affichées ici se limitent aux packages actifs adressés à cette clé opérateur.
    </Notice>
  );
}

// ---------------------------------------------------------------------------
// Operator vault setup: create or unlock the operator wallet
// ---------------------------------------------------------------------------

function CreateOperatorVault({ onCreated }) {
  const [mnemonic, setMnemonic] = useState('');
  const [confirmed, setConfirmed] = useState(false);
  const [password, setPassword] = useState('');
  const [passwordConfirm, setPasswordConfirm] = useState('');
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState(null);

  useEffect(() => {
    let cancelled = false;
    (async () => {
      const c = await loadCrypto();
      if (!cancelled) setMnemonic(c.generateMnemonic24());
    })();
    return () => { cancelled = true; };
  }, []);

  async function handleCreate(e) {
    e.preventDefault();
    if (password.length < 8 || password !== passwordConfirm) return;
    setBusy(true);
    setError(null);
    try {
      await createVault({
        role: 'operator',
        vaultId: OPERATOR_VAULT_ID,
        mnemonic,
        password,
      });
      onCreated();
    } catch (err) {
      setError(err.message || String(err));
    } finally {
      setBusy(false);
    }
  }

  return (
    <form onSubmit={handleCreate} style={{ ...cardStyle, display: 'grid', gap: '1rem' }}>
      <h2 style={{ margin: 0, display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
        <Building2 size={20} /> Configurer le wallet opérateur sur ce navigateur
      </h2>
      <div
        style={{
          display: 'flex',
          gap: '0.75rem',
          alignItems: 'flex-start',
          padding: '0.85rem 1rem',
          background: 'rgba(244, 196, 0, 0.08)',
          border: '1px solid rgba(244, 196, 0, 0.3)',
          borderRadius: '8px',
          fontSize: '0.85rem',
        }}
      >
        <AlertTriangle size={18} color="#f4c400" style={{ flexShrink: 0, marginTop: '2px' }} />
        <div>
          Ce wallet autorise les actions opérateur sur ce noeud. Notez la phrase de
          24 mots sur papier. La perdre = perdre l’identité opérateur de ce noeud.
        </div>
      </div>
      <div>
        <div style={{ fontSize: '0.8rem', color: 'var(--text-secondary)', marginBottom: '0.35rem' }}>
          Phrase de récupération
        </div>
        <div style={codeStyle}>{mnemonic || 'Génération…'}</div>
      </div>
      <label style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', fontSize: '0.9rem' }}>
        <input type="checkbox" checked={confirmed} onChange={(e) => setConfirmed(e.target.checked)} />
        J’ai noté la phrase hors ligne. CONFIDIS ne peut pas la récupérer.
      </label>
      <div>
        <label style={{ display: 'block', marginBottom: '0.35rem', fontSize: '0.85rem' }}>
          Mot de passe du coffre opérateur (≥ 8 caractères)
        </label>
        <input
          type="password"
          value={password}
          onChange={(e) => setPassword(e.target.value)}
          autoComplete="new-password"
          style={inputStyle}
        />
      </div>
      <div>
        <label style={{ display: 'block', marginBottom: '0.35rem', fontSize: '0.85rem' }}>
          Confirmez le mot de passe
        </label>
        <input
          type="password"
          value={passwordConfirm}
          onChange={(e) => setPasswordConfirm(e.target.value)}
          autoComplete="new-password"
          style={inputStyle}
        />
      </div>
      {error && <div style={{ color: '#ff7676', fontSize: '0.9rem' }}>{error}</div>}
      <div style={{ display: 'flex', justifyContent: 'flex-end' }}>
        <button
          type="submit"
          disabled={busy || !confirmed || password.length < 8 || password !== passwordConfirm}
          style={buttonPrimary}
        >
          {busy ? 'Scellement…' : 'Créer le wallet opérateur'}
        </button>
      </div>
    </form>
  );
}

function UnlockOperatorVault({ vault, onUnlocked }) {
  const [password, setPassword] = useState('');
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState(null);

  async function handle(e) {
    e.preventDefault();
    setBusy(true);
    setError(null);
    try {
      const session = await unlockVault({ vaultId: vault.vaultId, password });
      onUnlocked(session);
    } catch (err) {
      setError(err.message || String(err));
    } finally {
      setBusy(false);
    }
  }

  return (
    <form onSubmit={handle} style={{ ...cardStyle, display: 'grid', gap: '1rem' }}>
      <h2 style={{ margin: 0, display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
        <Unlock size={20} /> Déverrouiller le wallet opérateur
      </h2>
      <div>
        <div style={{ fontSize: '0.8rem', color: 'var(--text-secondary)', marginBottom: '0.35rem' }}>
          Clé publique opérateur
        </div>
        <div style={codeStyle}>{vault.publicKeyHex}</div>
      </div>
      <input
        type="password"
        value={password}
        onChange={(e) => setPassword(e.target.value)}
        placeholder="Mot de passe du coffre"
        autoFocus
        style={inputStyle}
      />
      {error && <div style={{ color: '#ff7676', fontSize: '0.9rem' }}>{error}</div>}
      <div style={{ display: 'flex', justifyContent: 'flex-end' }}>
        <button type="submit" disabled={busy || !password} style={buttonPrimary}>
          {busy ? 'Déverrouillage…' : 'Déverrouiller'}
        </button>
      </div>
    </form>
  );
}

function OperatorStatus({ session }) {
  return (
    <div style={{ ...cardStyle, display: 'grid', gap: '1rem' }}>
      <h2 style={{ margin: 0, display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
        <ShieldCheck size={20} /> Identité opérateur prête
      </h2>
      <p style={{ margin: 0, color: 'var(--text-secondary)', lineHeight: 1.6 }}>
        Les nouveaux utilisateurs créent leur wallet et leur première Cellule directement dans
        l’interface web hébergée par le noeud ; ce wallet opérateur est réservé aux opérations
        du noeud et aux lectures locales des packages explicitement partagés avec cette identité opérateur.
      </p>
      <div>
        <div style={{ fontSize: '0.8rem', color: 'var(--text-secondary)', marginBottom: '0.35rem' }}>
          Clé publique opérateur
        </div>
        <div style={codeStyle}>{session.publicKeyHex}</div>
      </div>
    </div>
  );
}

function SharedCelluleCard({ item, operatorPublicKey }) {
  const dataRows = flattenData(item.data);
  const hasData = item.data && item.data !== null;
  const apiUrl = `${nodeBaseUrl()}/operator/shared-cellules/${item.package_id}?recipient=${operatorPublicKey}`;
  const cliCommand = `confidis cellule fields-recipient-open \\
  --package ./shared/${item.package_id}.package.json \\
  --recipient-x25519-secret "$CONFIDIS_OPERATOR_X25519_SECRET" \\
  --output ./shared/${item.package_id}.data.json`;
  const apiCommand = `curl -H "Authorization: Bearer $CONFIDIS_UI_TOKEN" \\
  "${apiUrl}"`;

  return (
    <article style={{ border: '1px solid var(--border)', borderRadius: '8px', padding: '1rem', display: 'grid', gap: '0.85rem' }}>
      <div style={{ display: 'flex', justifyContent: 'space-between', gap: '1rem', flexWrap: 'wrap' }}>
        <div style={{ minWidth: 0 }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: '0.45rem', fontWeight: 700 }}>
            <Database size={16} color="var(--accent-primary)" />
            Cellule {shortHex(item.cellule_id, 18, 8)}
          </div>
          <div style={{ fontSize: '0.78rem', color: 'var(--text-secondary)', marginTop: '0.25rem' }}>
            Partagé par {shortHex(item.owner_public_key)} · package {shortHex(item.package_id, 8, 8)}
          </div>
        </div>
        <div style={{ fontSize: '0.78rem', color: '#5ee08a', fontWeight: 700, textTransform: 'uppercase' }}>
          {item.status}
        </div>
      </div>

      <div style={{ display: 'flex', gap: '0.5rem', flexWrap: 'wrap' }}>
        {(item.fields || []).map((field) => (
          <span
            key={field}
            style={{
              border: '1px solid var(--border)',
              borderRadius: '999px',
              padding: '0.22rem 0.55rem',
              fontSize: '0.75rem',
              color: 'var(--text-secondary)',
            }}
          >
            {field}
          </span>
        ))}
        {(!item.fields || item.fields.length === 0) && (
          <span style={{ fontSize: '0.78rem', color: 'var(--text-secondary)' }}>Package métadonnées seules</span>
        )}
      </div>

      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(180px, 1fr))', gap: '0.65rem' }}>
        <div style={{ fontSize: '0.78rem', color: 'var(--text-secondary)' }}>
          Émis<br /><strong style={{ color: 'var(--text-primary)', fontWeight: 600 }}>{formatDate(item.issued_at)}</strong>
        </div>
        <div style={{ fontSize: '0.78rem', color: 'var(--text-secondary)' }}>
          Expire<br /><strong style={{ color: 'var(--text-primary)', fontWeight: 600 }}>{formatDate(item.expires_at)}</strong>
        </div>
        <div style={{ fontSize: '0.78rem', color: 'var(--text-secondary)' }}>
          Hash du package<br /><strong style={{ color: 'var(--text-primary)', fontWeight: 600, fontFamily: 'monospace' }}>{shortHex(item.package_hash, 12, 8)}</strong>
        </div>
      </div>

      {hasData && dataRows.length > 0 && (
        <div style={{ border: '1px solid var(--border)', borderRadius: '8px', overflow: 'hidden' }}>
          {dataRows.map((row) => (
            <div
              key={row.key}
              style={{
                display: 'grid',
                gridTemplateColumns: 'minmax(130px, 0.35fr) minmax(0, 1fr)',
                gap: '0.75rem',
                padding: '0.55rem 0.7rem',
                borderBottom: '1px solid var(--border)',
                fontSize: '0.82rem',
              }}
            >
              <div style={{ color: 'var(--text-secondary)', fontFamily: 'monospace', overflowWrap: 'anywhere' }}>{row.key}</div>
              <div style={{ overflowWrap: 'anywhere' }}>{row.value}</div>
            </div>
          ))}
        </div>
      )}

      <details>
        <summary style={{ cursor: 'pointer', color: 'var(--text-secondary)', fontSize: '0.85rem' }}>
          Métadonnées et commande d’ouverture chiffrée
        </summary>
        <div style={{ display: 'grid', gap: '0.75rem', marginTop: '0.75rem' }}>
          <div style={{ display: 'flex', gap: '0.5rem', flexWrap: 'wrap' }}>
            <button type="button" onClick={() => exportSharedJson([item], `confidis-shared-${item.package_id}.json`)} style={smallButton}>
              <FileJson size={14} /> Export métadonnées JSON
            </button>
            <button type="button" onClick={() => exportSharedCsv([item], `confidis-shared-${item.package_id}.csv`)} style={smallButton}>
              <FileSpreadsheet size={14} /> Export métadonnées CSV
            </button>
            <button type="button" onClick={() => exportSharedCrmCsv([item], `confidis-crm-${item.package_id}.csv`)} style={smallButton}>
              <FileSpreadsheet size={14} /> CSV inventaire
            </button>
            <button type="button" onClick={() => copyText(JSON.stringify(item, null, 2))} style={smallButton}>
              <Copy size={14} /> Copier JSON
            </button>
          </div>
          <pre style={{ ...codeStyle, margin: 0, whiteSpace: 'pre-wrap', maxHeight: '280px', overflow: 'auto' }}>
            {valuePreview(item.data)}
          </pre>
          <CommandBlock title="Ouvrir un package chiffré avec la CLI" command={cliCommand} />
          <CommandBlock title="Consulter les métadonnées de ce package via l’API du noeud" command={apiCommand} />
        </div>
      </details>
    </article>
  );
}

function OperatorSharedData({ session }) {
  const [query, setQuery] = useState('');
  const [items, setItems] = useState(null);
  const [warning, setWarning] = useState('');
  const [error, setError] = useState(null);
  const [busy, setBusy] = useState(false);

  const loadSharedData = useCallback(async (nextQuery = '') => {
    setBusy(true);
    setError(null);
    try {
      const response = await fetchOperatorSharedCellules(session.publicKeyHex, nextQuery);
      setItems(response.items || []);
      setWarning(response.warning || '');
    } catch (err) {
      setError(err.message || String(err));
      setItems([]);
    } finally {
      setBusy(false);
    }
  }, [session.publicKeyHex]);

  useEffect(() => {
    loadSharedData('');
  }, [loadSharedData]);

  function handleSearch(e) {
    e.preventDefault();
    loadSharedData(query);
  }

  const count = items ? items.length : 0;
  const exportDisabled = !items || items.length === 0;

  return (
    <section style={{ ...cardStyle, display: 'grid', gap: '1rem' }}>
      <div style={{ display: 'flex', justifyContent: 'space-between', gap: '1rem', alignItems: 'flex-start', flexWrap: 'wrap' }}>
        <div>
          <h2 style={{ margin: 0, display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
            <Server size={20} /> Cellules de données partagées
          </h2>
          <p style={{ margin: '0.35rem 0 0', color: 'var(--text-secondary)', lineHeight: 1.5, maxWidth: '760px' }}>
            Packages actifs adressés à cette identité opérateur. Cet inventaire expose uniquement les métadonnées ; le contenu reste chiffré et requiert une preuve destinataire.
          </p>
        </div>
        <button type="button" onClick={() => loadSharedData(query)} disabled={busy} style={smallButton}>
          <RefreshCw size={14} /> {busy ? 'Rafraîchissement…' : 'Rafraîchir'}
        </button>
      </div>

      <form onSubmit={handleSearch} style={{ display: 'flex', gap: '0.6rem', flexWrap: 'wrap' }}>
        <div style={{ flex: '1 1 260px', position: 'relative' }}>
          <Search size={16} style={{ position: 'absolute', left: '0.75rem', top: '50%', transform: 'translateY(-50%)', color: 'var(--text-secondary)' }} />
          <input
            value={query}
            onChange={(e) => setQuery(e.target.value)}
            placeholder="Rechercher champs, propriétaires ou IDs de package"
            style={{ ...inputStyle, paddingLeft: '2.2rem' }}
          />
        </div>
        <button type="submit" disabled={busy} style={buttonPrimary}>
          <Search size={16} /> Rechercher
        </button>
      </form>

      {warning && (
        <div style={{ fontSize: '0.82rem', color: 'var(--text-secondary)', border: '1px solid var(--border)', borderRadius: '8px', padding: '0.7rem 0.85rem' }}>
          {warning}
        </div>
      )}

      {error && <div style={{ color: '#ff7676', fontSize: '0.9rem' }}>Impossible de charger les données partagées : {error}</div>}
      {!items && !error && <div style={{ color: 'var(--text-secondary)', fontSize: '0.9rem' }}>Chargement des données partagées…</div>}

      {items && (
        <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', gap: '0.75rem', flexWrap: 'wrap' }}>
          <div style={{ color: 'var(--text-secondary)', fontSize: '0.85rem' }}>
            {count} {count === 1 ? 'Cellule partagée active' : 'Cellules partagées actives'} pour {shortHex(session.publicKeyHex)}.
          </div>
          <div style={{ display: 'flex', gap: '0.5rem', flexWrap: 'wrap' }}>
            <button type="button" disabled={exportDisabled} onClick={() => exportSharedJson(items)} style={{ ...smallButton, opacity: exportDisabled ? 0.5 : 1 }}>
              <FileJson size={14} /> Métadonnées JSON
            </button>
            <button type="button" disabled={exportDisabled} onClick={() => exportSharedCsv(items)} style={{ ...smallButton, opacity: exportDisabled ? 0.5 : 1 }}>
              <FileSpreadsheet size={14} /> Métadonnées CSV
            </button>
            <button type="button" disabled={exportDisabled} onClick={() => exportSharedCrmCsv(items)} style={{ ...smallButton, opacity: exportDisabled ? 0.5 : 1 }}>
              <FileSpreadsheet size={14} /> CSV inventaire
            </button>
          </div>
        </div>
      )}

      {items && items.length === 0 && (
        <div style={{ border: '1px dashed var(--border)', borderRadius: '8px', padding: '1.25rem', color: 'var(--text-secondary)', lineHeight: 1.5 }}>
          Aucun package actif n’est encore adressé à cette clé opérateur. Lorsqu’un propriétaire crée un package chiffré pour cette clé publique, ses métadonnées apparaîtront ici.
        </div>
      )}

      {items && items.length > 0 && (
        <div style={{ display: 'grid', gap: '0.85rem' }}>
          {items.map((item) => (
            <SharedCelluleCard key={item.package_id} item={item} operatorPublicKey={session.publicKeyHex} />
          ))}
        </div>
      )}
    </section>
  );
}

function EndpointCard({ method, path, description, queryParams, responseFields, command, children }) {
  const methodColor = method === 'GET' ? 'var(--accent-primary)' : '#f4c400';
  return (
    <div style={{ border: '1px solid var(--border)', borderRadius: '10px', overflow: 'hidden' }}>
      <div style={{ display: 'grid', gridTemplateColumns: '80px minmax(0, 1fr)', borderBottom: '1px solid var(--border)' }}>
        <div style={{ padding: '0.8rem 0.9rem', background: 'rgba(69, 243, 255, 0.08)', color: methodColor, fontWeight: 800, fontSize: '0.85rem' }}>
          {method}
        </div>
        <div style={{ padding: '0.8rem 0.9rem', fontFamily: 'ui-monospace, SFMono-Regular, Menlo, monospace', fontSize: '0.9rem', overflowWrap: 'anywhere' }}>
          {path}
        </div>
      </div>
      <div style={{ display: 'grid', gap: '0.85rem', padding: '1rem' }}>
        <p style={{ margin: 0, color: 'var(--text-secondary)', lineHeight: 1.55, fontSize: '0.88rem' }}>{description}</p>
        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(220px, 1fr))', gap: '0.85rem' }}>
          <div>
            <div style={{ color: 'var(--text-secondary)', fontSize: '0.76rem', textTransform: 'uppercase', letterSpacing: '0.08em', marginBottom: '0.4rem' }}>
              Paramètres
            </div>
            <div style={{ display: 'grid', gap: '0.35rem' }}>
              {queryParams.map((param) => (
                <div key={param.name} style={{ fontSize: '0.82rem', display: 'grid', gridTemplateColumns: '110px minmax(0, 1fr)', gap: '0.5rem' }}>
                  <span style={{ fontFamily: 'monospace', color: 'var(--accent-primary)' }}>{param.name}</span>
                  <span style={{ color: 'var(--text-secondary)' }}>{param.description}</span>
                </div>
              ))}
            </div>
          </div>
          <div>
            <div style={{ color: 'var(--text-secondary)', fontSize: '0.76rem', textTransform: 'uppercase', letterSpacing: '0.08em', marginBottom: '0.4rem' }}>
              Réponse utile
            </div>
            <div style={{ display: 'flex', gap: '0.35rem', flexWrap: 'wrap' }}>
              {responseFields.map((field) => (
                <span key={field} style={{ fontFamily: 'monospace', fontSize: '0.74rem', color: 'var(--text-secondary)', border: '1px solid var(--border)', borderRadius: '999px', padding: '0.18rem 0.5rem' }}>
                  {field}
                </span>
              ))}
            </div>
          </div>
        </div>
        <CommandBlock title="Commande curl" command={command} />
        {children}
      </div>
    </div>
  );
}

const integrationTargets = [
  {
    name: 'Sellsy / Axonaut',
    fit: 'CRM, devis, facturation pour PME françaises',
    pilot: 'Inventaire CSV des packages adressés',
    later: 'Ouverture chiffrée auditée puis connecteur minimal',
  },
  {
    name: 'Odoo / Dolibarr',
    fit: 'ERP modulaire, gestion commerciale, associations, ateliers',
    pilot: 'Inventaire JSON/CSV sans contenu personnel',
    later: 'Module CONFIDIS avec ouverture prouvée',
  },
  {
    name: 'Pennylane / Sage / Cegid / EBP',
    fit: 'Compta, gestion et back-office',
    pilot: 'Métadonnées de package uniquement',
    later: 'Flux contrôlé avec preuve et validation métier',
  },
  {
    name: 'HubSpot / Pipedrive / Zoho',
    fit: 'CRM cloud déjà en place dans les équipes commerciales',
    pilot: 'Inventaire des accès partagés',
    later: 'Connecteur de lecture avec scopes minimaux',
  },
  {
    name: 'Brevo / Mailchimp',
    fit: 'Marketing, newsletter, relation client B2C',
    pilot: 'Inventaire des packages de consentement',
    later: 'Synchronisation avec ouverture explicitement autorisée',
  },
];

function OperatorIntegrationTargets() {
  return (
    <div style={{ border: '1px solid var(--border)', borderRadius: '10px', padding: '1rem', display: 'grid', gap: '0.85rem' }}>
      <div>
        <h3 style={{ margin: 0, fontSize: '1rem' }}>Connecteurs PME/PMI prioritaires</h3>
        <p style={{ margin: '0.25rem 0 0', color: 'var(--text-secondary)', fontSize: '0.86rem', lineHeight: 1.5 }}>
          Commencer par l’inventaire des packages. Un connecteur de données ne peut ouvrir du contenu qu’avec le flux destinataire prouvé et audité.
        </p>
      </div>
      <div style={{ display: 'grid', gap: '0.65rem' }}>
        {integrationTargets.map((target) => (
          <div
            key={target.name}
            style={{
              display: 'grid',
              gridTemplateColumns: 'repeat(auto-fit, minmax(180px, 1fr))',
              gap: '0.75rem',
              border: '1px solid var(--border)',
              borderRadius: '8px',
              padding: '0.75rem',
              fontSize: '0.82rem',
            }}
          >
            <strong>{target.name}</strong>
            <span style={{ color: 'var(--text-secondary)' }}>{target.fit}</span>
            <span>{target.pilot}</span>
            <span style={{ color: 'var(--text-secondary)' }}>{target.later}</span>
          </div>
        ))}
      </div>
    </div>
  );
}

function OperatorApiExplorer({ session }) {
  const [query, setQuery] = useState('');
  const [packageId, setPackageId] = useState('');
  const [result, setResult] = useState(null);
  const [detailResult, setDetailResult] = useState(null);
  const [error, setError] = useState(null);
  const [busy, setBusy] = useState(false);
  const listUrl = `${nodeBaseUrl()}/operator/shared-cellules?recipient=${session.publicKeyHex}${query.trim() ? `&q=${encodeURIComponent(query.trim())}` : ''}`;
  const detailUrl = `${nodeBaseUrl()}/operator/shared-cellules/${packageId || '<package_id>'}?recipient=${session.publicKeyHex}`;
  const listCommand = `curl -H "Authorization: Bearer $CONFIDIS_UI_TOKEN" \\
  "${listUrl}"`;
  const detailCommand = `curl -H "Authorization: Bearer $CONFIDIS_UI_TOKEN" \\
  "${detailUrl}"`;

  async function tryList(e) {
    e.preventDefault();
    setBusy(true);
    setError(null);
    try {
      const response = await fetchOperatorSharedCellules(session.publicKeyHex, query);
      setResult(response);
      const firstId = response.items?.[0]?.package_id;
      if (firstId && !packageId) setPackageId(firstId);
    } catch (err) {
      setError(err.message || String(err));
    } finally {
      setBusy(false);
    }
  }

  async function tryDetail(e) {
    e.preventDefault();
    if (!packageId.trim()) return;
    setBusy(true);
    setError(null);
    try {
      setDetailResult(await fetchOperatorSharedCellule(packageId.trim(), session.publicKeyHex));
    } catch (err) {
      setError(err.message || String(err));
    } finally {
      setBusy(false);
    }
  }

  return (
    <section style={{ ...cardStyle, display: 'grid', gap: '1rem' }}>
      <div>
        <h2 style={{ margin: 0, display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
          <Plug size={20} /> API d’intégration opérateur
        </h2>
        <p style={{ margin: '0.35rem 0 0', color: 'var(--text-secondary)', lineHeight: 1.55, maxWidth: '840px' }}>
          Surface locale protégée par jeton UI pour inventorier les packages destinataire actifs adressés à cette clé opérateur. Elle ne constitue pas une lecture du contenu.
        </p>
      </div>

      <Notice tone="warn">
        Les exports ci-dessous ne contiennent que les métadonnées d’inventaire. Pour obtenir le contenu, utilisez le flux chiffré `/access/read/*`, qui exige la preuve de possession de la clé destinataire et conserve une piste d’audit.
      </Notice>

      <OperatorIntegrationTargets />

      <EndpointCard
        method="GET"
        path="/operator/shared-cellules"
        description="Liste les packages destinataire actifs adressés à la clé opérateur. Le paramètre q recherche uniquement dans leurs métadonnées et périmètres."
        queryParams={[
          { name: 'recipient', description: 'clé publique opérateur Ed25519, hex 32 octets' },
          { name: 'q', description: 'recherche texte optionnelle' },
        ]}
        responseFields={['recipient_public_key', 'count', 'items[]', 'items[].data=null', 'warning']}
        command={listCommand}
      >
        <form onSubmit={tryList} style={{ display: 'flex', gap: '0.55rem', flexWrap: 'wrap' }}>
          <input
            value={query}
            onChange={(e) => setQuery(e.target.value)}
            placeholder="Recherche q optionnelle"
            style={{ ...inputStyle, flex: '1 1 260px' }}
          />
          <button type="submit" disabled={busy} style={buttonPrimary}>
            <Play size={15} /> Essayer
          </button>
        </form>
        {result && (
          <pre style={{ ...codeStyle, margin: 0, whiteSpace: 'pre-wrap', maxHeight: '260px', overflow: 'auto' }}>
            {JSON.stringify(result, null, 2)}
          </pre>
        )}
      </EndpointCard>

      <EndpointCard
        method="GET"
        path="/operator/shared-cellules/{package_id}"
        description="Retourne un package partagé précis, si ce package est actif, non expiré et adressé à la clé opérateur."
        queryParams={[
          { name: 'package_id', description: 'UUID du package dans le chemin' },
          { name: 'recipient', description: 'clé publique opérateur Ed25519, hex 32 octets' },
        ]}
        responseFields={['item.package_id', 'item.cellule_id', 'item.fields', 'item.data=null', 'warning']}
        command={detailCommand}
      >
        <form onSubmit={tryDetail} style={{ display: 'flex', gap: '0.55rem', flexWrap: 'wrap' }}>
          <input
            value={packageId}
            onChange={(e) => setPackageId(e.target.value)}
            placeholder="UUID du package"
            style={{ ...inputStyle, flex: '1 1 300px', fontFamily: 'ui-monospace, SFMono-Regular, Menlo, monospace' }}
          />
          <button type="submit" disabled={busy || !packageId.trim()} style={buttonPrimary}>
            <Play size={15} /> Essayer
          </button>
        </form>
        {detailResult && (
          <pre style={{ ...codeStyle, margin: 0, whiteSpace: 'pre-wrap', maxHeight: '260px', overflow: 'auto' }}>
            {JSON.stringify(detailResult, null, 2)}
          </pre>
        )}
      </EndpointCard>

      {error && <div style={{ color: '#ff7676', fontSize: '0.9rem' }}>Erreur API : {error}</div>}

      <details>
        <summary style={{ cursor: 'pointer', color: 'var(--text-secondary)', fontSize: '0.9rem', display: 'flex', alignItems: 'center', gap: '0.35rem' }}>
          <Code2 size={15} /> Schéma simplifié d’un item
        </summary>
        <pre style={{ ...codeStyle, marginTop: '0.75rem', whiteSpace: 'pre-wrap' }}>
{`{
  "package_id": "uuid",
  "cellule_id": "cellule id",
  "owner_public_key": "hex",
  "recipient_public_key": "hex",
  "recipient_x25519_pubkey": "hex",
  "fields": ["kyc.status", "patient.name"],
  "issued_at": "ISO-8601",
  "expires_at": "ISO-8601 | null",
  "status": "Active",
  "package_hash": "hex",
  "data": null
}`}
        </pre>
      </details>
    </section>
  );
}

// ---------------------------------------------------------------------------
// Top-level component
// ---------------------------------------------------------------------------

export default function OperatorPanel() {
  const [vault, setVault] = useState(null);
  const [mode, setMode] = useState('loading'); // loading | create | unlock | active
  const [session, setSession] = useState(null);
  const [error, setError] = useState(null);
  const [remainingMs, setRemainingMs] = useState(SESSION_IDLE_MS);

  const refresh = useCallback(async () => {
    try {
      await ensureCryptoLoaded();
      const list = await listVaults();
      const found = list.find((v) => v.vaultId === OPERATOR_VAULT_ID);
      if (found) {
        setVault(found);
        setMode('unlock');
      } else {
        setMode('create');
      }
    } catch (err) {
      setError(err.message || String(err));
    }
  }, []);

  useEffect(() => {
    refresh();
  }, [refresh]);

  useEffect(() => {
    if (!session) return;
    const id = setInterval(() => {
      const ms = Math.max(0, session.expiresAt.getTime() - Date.now());
      setRemainingMs(ms);
      if (ms === 0) {
        session.lock();
        setSession(null);
        setMode('unlock');
      }
    }, 1000);
    return () => clearInterval(id);
  }, [session]);

  if (error) {
    return (
      <div style={{ display: 'grid', gap: '1rem' }}>
        <OperatorSecurityNotice />
        <div style={cardStyle}>
          <h2 style={{ marginTop: 0 }}>Wallet opérateur indisponible</h2>
          <p>{error}</p>
        </div>
      </div>
    );
  }

  if (mode === 'loading') {
    return (
      <div style={{ display: 'grid', gap: '1rem' }}>
        <OperatorSecurityNotice />
        <div style={cardStyle}>Chargement…</div>
      </div>
    );
  }

  if (mode === 'create') {
    return (
      <div style={{ display: 'grid', gap: '1rem' }}>
        <OperatorSecurityNotice />
        <CreateOperatorVault
          onCreated={async () => {
            await refresh();
          }}
        />
      </div>
    );
  }

  if (mode === 'unlock' && vault) {
    return (
      <div style={{ display: 'grid', gap: '1rem' }}>
        <OperatorSecurityNotice />
        <UnlockOperatorVault
          vault={vault}
          onUnlocked={(s) => {
            setSession(s);
            setMode('active');
          }}
        />
      </div>
    );
  }

  if (mode === 'active' && session) {
    const mins = Math.floor(remainingMs / 60000);
    const secs = Math.floor((remainingMs % 60000) / 1000).toString().padStart(2, '0');
    return (
      <div style={{ display: 'grid', gap: '1rem' }}>
        <OperatorSecurityNotice />
        <div style={{ ...cardStyle, display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: '0.75rem' }}>
            <ShieldCheck size={20} color="var(--accent-primary)" />
            <div>
              <div style={{ fontWeight: 600 }}>Opérateur déverrouillé</div>
              <div style={{ fontSize: '0.8rem', color: 'var(--text-secondary)' }}>
                {session.publicKeyHex.slice(0, 16)}…{session.publicKeyHex.slice(-8)} · verrouillage auto {mins}:{secs}
              </div>
            </div>
          </div>
          <button
            onClick={() => {
              session.lock();
              setSession(null);
              setMode('unlock');
            }}
            style={buttonSecondary}
          >
            <Lock size={16} /> Verrouiller
          </button>
        </div>
        <OperatorStatus session={session} />
        <OperatorSharedData session={session} />
        <OperatorApiExplorer session={session} />
      </div>
    );
  }

  return null;
}
