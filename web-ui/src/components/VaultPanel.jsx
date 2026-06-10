// VaultPanel — in-browser wallet with live Cellule operations.
//
// After unlock the panel fetches Cellules and recipient packages for the vault's
// public key and lets the owner sign renew / delete / remove operations, which
// are verified by the node against the registered owner_public_key.

import { useCallback, useEffect, useState } from 'react';
import {
  KeyRound,
  Lock,
  Unlock,
  Plus,
  Trash2,
  Copy,
  Check,
  AlertTriangle,
  PencilLine,
  ShieldCheck,
  RefreshCw,
} from 'lucide-react';

import { ensureCryptoLoaded, loadCrypto } from '../wallet/cryptoBridge';
import {
  listVaults,
  createVault,
  unlockVault,
  wipeVault,
  SESSION_IDLE_MS,
} from '../wallet/vault';
import {
  signOwnerRenew,
  signCelluleDelete,
  signCelluleCreate,
  signRecipientPackageRemove,
} from '../wallet/protocol';
import {
  createWalletCellule,
  getWalletIndex,
  getWalletPackages,
  renewWalletCellule,
  deleteWalletCellule,
  removeWalletPackage,
} from '../api';
import { useToast } from './Toast';

const DEFAULT_VAULT_ID = 'end-user-default';

/**
 * Multi-tenant vault id allocator. Kept for future federation flows where an
 * end-user surface may host many independent owner identities side by side.
 * We keep the legacy default vault id for backward compatibility and allocate
 * `end-user-<random>` for new tenants. Operator vaults are NOT multi-tenant:
 * there's one operator identity per node.
 */
function newTenantVaultId() {
  // 8 random hex chars — short enough to display, low collision risk.
  const rand = Math.floor(Math.random() * 0xffffffff)
    .toString(16)
    .padStart(8, '0');
  return `end-user-${rand}`;
}

// --------------------------------------------------------------------------
// Reusable styles — mirror the rest of web-ui.
// --------------------------------------------------------------------------

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

const buttonDanger = {
  ...buttonSecondary,
  color: '#ff7676',
  borderColor: 'rgba(255, 118, 118, 0.4)',
};

const inputStyle = {
  width: '100%',
  padding: '0.65rem 0.85rem',
  background: 'var(--bg-tertiary, rgba(255,255,255,0.04))',
  border: '1px solid var(--border)',
  borderRadius: '8px',
  color: 'var(--text-primary)',
  fontSize: '0.95rem',
  fontFamily: 'inherit',
};

// --------------------------------------------------------------------------
// Sub-components
// --------------------------------------------------------------------------

function ZeroKnowledgeNotice() {
  return (
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
        lineHeight: 1.5,
      }}
    >
      <AlertTriangle size={18} color="#f4c400" style={{ flexShrink: 0, marginTop: '2px' }} />
      <div>
        <strong>CONFIDIS n’a jamais votre clé.</strong> Votre mnémonique est l’unique
        voie de récupération de vos Cellules réseau. La perdre = perdre l’accès à chaque Cellule signée avec ce wallet, pas aux originaux hors réseau que vous conservez.
      </div>
    </div>
  );
}

function CopyButton({ value }) {
  const [copied, setCopied] = useState(false);
  function handle() {
    navigator.clipboard?.writeText(value);
    setCopied(true);
    setTimeout(() => setCopied(false), 1500);
  }
  return (
    <button onClick={handle} style={{ ...buttonSecondary, padding: '0.4rem 0.75rem', fontSize: '0.8rem' }}>
      {copied ? <Check size={14} /> : <Copy size={14} />}
      {copied ? 'Copié' : 'Copier'}
    </button>
  );
}

// --------------------------------------------------------------------------
// Flows
// --------------------------------------------------------------------------

function CreateFlow({ onCreated, onCancel, role = 'end-user', vaultId = DEFAULT_VAULT_ID }) {
  const [step, setStep] = useState('mnemonic'); // 'mnemonic' | 'password' | 'working'
  const [mode, setMode] = useState('generate'); // 'generate' | 'import'
  const [mnemonic, setMnemonic] = useState('');
  const [confirmed, setConfirmed] = useState(false);
  const [password, setPassword] = useState('');
  const [passwordConfirm, setPasswordConfirm] = useState('');
  const [error, setError] = useState(null);
  const toast = useToast();

  // Auto-generate a fresh phrase only in 'generate' mode. In 'import' mode the
  // user supplies their own existing phrase; createVault() validates it.
  useEffect(() => {
    if (mode !== 'generate') return;
    let cancelled = false;
    (async () => {
      try {
        const crypto = await loadCrypto();
        const m = crypto.generateMnemonic24();
        if (!cancelled) setMnemonic(m);
      } catch (err) {
        if (!cancelled) setError(err.message || String(err));
      }
    })();
    return () => {
      cancelled = true;
    };
  }, [mode]);

  function switchMode(next) {
    if (next === mode) return;
    setError(null);
    setConfirmed(false);
    setMnemonic('');
    setMode(next);
  }

  // Normalised word count for the import textarea (basic UX hint only — the
  // authoritative BIP39 check happens in createVault()).
  const wordCount = mnemonic.trim().split(/\s+/).filter(Boolean).length;

  async function finalize() {
    setStep('working');
    setError(null);
    try {
      const { publicKeyHex } = await createVault({
        role,
        vaultId,
        mnemonic,
        password,
      });
      toast?.success('Coffre créé. Votre wallet est prêt à être déverrouillé.');
      onCreated({ publicKeyHex });
    } catch (err) {
      setError(err.message || String(err));
      setStep('password');
    }
  }

  if (step === 'mnemonic') {
    const importReady = mode === 'import' && wordCount === 24;
    const generateReady = mode === 'generate' && !!mnemonic && confirmed;
    const tab = (id, label) => (
      <button
        key={id}
        onClick={() => switchMode(id)}
        style={{
          ...buttonSecondary,
          flex: 1,
          opacity: mode === id ? 1 : 0.6,
          borderColor: mode === id ? 'var(--accent, #0071e3)' : undefined,
        }}
      >
        {label}
      </button>
    );
    return (
      <div style={{ ...cardStyle, display: 'grid', gap: '1rem' }}>
        <ZeroKnowledgeNotice />
        <div style={{ display: 'flex', gap: '0.5rem' }}>
          {tab('generate', 'Créer un nouveau wallet')}
          {tab('import', 'Importer une phrase existante')}
        </div>

        {mode === 'generate' ? (
          <>
            <h2 style={{ margin: 0, display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
              <PencilLine size={20} /> Notez votre phrase de récupération de 24 mots
            </h2>
            <p style={{ margin: 0, color: 'var(--text-secondary)', fontSize: '0.9rem' }}>
              Cette phrase n’est affichée qu’une seule fois. Recopiez-la sur papier ou un autre
              support hors ligne — NE faites PAS de capture d’écran, NE vous l’envoyez PAS par e-mail,
              NE la collez PAS dans un gestionnaire de mots de passe synchronisé vers le cloud.
            </p>
            <div style={codeStyle} data-smoke-redact="recovery-phrase">
              {mnemonic || 'Génération…'}
            </div>
            {mnemonic && (
              <div style={{ display: 'flex', justifyContent: 'flex-end' }}>
                <CopyButton value={mnemonic} />
              </div>
            )}
            <label style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', fontSize: '0.9rem' }}>
              <input type="checkbox" checked={confirmed} onChange={(e) => setConfirmed(e.target.checked)} />
              J’ai noté ma phrase de récupération. Je comprends que CONFIDIS ne peut pas la
              récupérer à ma place.
            </label>
          </>
        ) : (
          <>
            <h2 style={{ margin: 0, display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
              <KeyRound size={20} /> Importez votre phrase de récupération de 24 mots
            </h2>
            <p style={{ margin: 0, color: 'var(--text-secondary)', fontSize: '0.9rem' }}>
              Restaurez un wallet que vous possédez déjà sur ce navigateur. Saisissez les 24 mots
              séparés par des espaces. La phrase ne quitte jamais cet appareil ; elle est scellée
              localement avec le mot de passe de votre coffre.
            </p>
            <textarea
              value={mnemonic}
              onChange={(e) =>
                setMnemonic(e.target.value.replace(/\s+/g, ' ').replace(/^\s+/, '').toLowerCase())
              }
              placeholder="word1 word2 word3 … word24"
              spellCheck={false}
              autoComplete="off"
              rows={3}
              style={{ ...inputStyle, fontFamily: 'monospace', resize: 'vertical' }}
            />
            <div style={{ fontSize: '0.8rem', color: wordCount === 24 ? 'var(--text-secondary)' : '#ff9f43' }}>
              {wordCount} / 24 mots{wordCount === 24 ? ' — phrase exacte vérifiée à l’étape Continuer' : ''}
            </div>
          </>
        )}

        <div style={{ display: 'flex', gap: '0.75rem', justifyContent: 'flex-end' }}>
          <button onClick={onCancel} style={buttonSecondary}>
            Annuler
          </button>
          <button
            onClick={() => setStep('password')}
            disabled={!(importReady || generateReady)}
            style={{ ...buttonPrimary, opacity: importReady || generateReady ? 1 : 0.5 }}
          >
            Continuer
          </button>
        </div>
      </div>
    );
  }

  if (step === 'password' || step === 'working') {
    const passwordOk = password.length >= 8 && password === passwordConfirm;
    return (
      <div style={{ ...cardStyle, display: 'grid', gap: '1rem' }}>
        <h2 style={{ margin: 0, display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
          <KeyRound size={20} /> Choisissez un mot de passe de coffre
        </h2>
        <p style={{ margin: 0, color: 'var(--text-secondary)', fontSize: '0.9rem' }}>
          Ce mot de passe déverrouille votre wallet sur ce navigateur. Il est combiné à la
          mnémonique via Argon2id — un mauvais mot de passe (ou un coffre volé sur ce
          navigateur) ne peut pas être cassé rapidement par force brute.
        </p>
        <div>
          <label style={{ display: 'block', marginBottom: '0.35rem', fontSize: '0.85rem' }}>
            Mot de passe (≥ 8 caractères)
          </label>
          <input
            type="password"
            value={password}
            onChange={(e) => setPassword(e.target.value)}
            autoComplete="new-password"
            style={inputStyle}
            disabled={step === 'working'}
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
            disabled={step === 'working'}
          />
        </div>
        {error && (
          <div style={{ color: '#ff7676', fontSize: '0.9rem' }}>{error}</div>
        )}
        <div style={{ display: 'flex', gap: '0.75rem', justifyContent: 'flex-end' }}>
          <button onClick={() => setStep('mnemonic')} style={buttonSecondary} disabled={step === 'working'}>
            Retour
          </button>
          <button
            onClick={finalize}
            disabled={!passwordOk || step === 'working'}
            style={{ ...buttonPrimary, opacity: passwordOk && step !== 'working' ? 1 : 0.5 }}
          >
            {step === 'working' ? 'Scellement du coffre…' : 'Créer le coffre'}
          </button>
        </div>
        <p style={{ fontSize: '0.8rem', color: 'var(--text-secondary)', margin: 0 }}>
          Le scellement prend ~250 ms sur un ordinateur portable récent (Argon2id 64 Mio, 3 itérations).
        </p>
      </div>
    );
  }

  return null;
}

function UnlockedPanel({ session, onLock, onWipe }) {
  const [remainingMs, setRemainingMs] = useState(SESSION_IDLE_MS);
  const [cellules, setCellules] = useState(null);
  const [packages, setPackages] = useState(null);
  const [dataError, setDataError] = useState(null);
  const [busy, setBusy] = useState({});
  const toast = useToast();

  // ---- session countdown ----
  useEffect(() => {
    const id = setInterval(() => {
      const ms = Math.max(0, session.expiresAt.getTime() - Date.now());
      setRemainingMs(ms);
      if (ms === 0) onLock();
    }, 1000);
    return () => clearInterval(id);
  }, [session, onLock]);

  // ---- load owner data ----
  const loadData = useCallback(async () => {
    setDataError(null);
    try {
      const [index, packageIndex] = await Promise.all([
        getWalletIndex(session.publicKeyHex),
        getWalletPackages(session.publicKeyHex),
      ]);
      setCellules(index.cellules ?? []);
      setPackages(packageIndex.packages ?? []);
    } catch (e) {
      setDataError(e.message || String(e));
    }
  }, [session.publicKeyHex]);

  useEffect(() => { loadData(); }, [loadData]);

  // ---- helpers ----
  function setBusyFor(key, val) {
    setBusy((prev) => ({ ...prev, [key]: val }));
  }

  async function handleRenew(celluleId) {
    setBusyFor(celluleId, 'renewing');
    try {
      const renew = await signOwnerRenew({ session, celluleId });
      await renewWalletCellule(celluleId, { renew });
      toast?.success('Cellule renouvelée — vivacité confirmée sur le noeud.');
      await loadData();
    } catch (e) {
      toast?.error(`Échec du renouvellement : ${e.message || e}`);
    } finally {
      setBusyFor(celluleId, null);
    }
  }

  async function handleDelete(celluleId) {
    if (!confirm(`Supprimer la Cellule ${celluleId.slice(0, 12)}… ?\n\nCela supprime définitivement l’enregistrement de propriété. Les shards expirent selon leur TTL.`)) return;
    setBusyFor(celluleId, 'deleting');
    try {
      const delete_op = await signCelluleDelete({ session, celluleId });
      await deleteWalletCellule(celluleId, { delete: delete_op });
      toast?.success('Enregistrement de propriété de la Cellule supprimé.');
      await loadData();
    } catch (e) {
      toast?.error(`Échec de la suppression : ${e.message || e}`);
    } finally {
      setBusyFor(celluleId, null);
    }
  }

  async function handleRemovePackage(pkg) {
    if (!confirm(`Retirer la copie partagée pour ${pkg.recipient_public_key.slice(0, 16)}… ?`)) return;
    setBusyFor(pkg.package_id, 'removing');
    try {
      const remove = await signRecipientPackageRemove({ session, packageId: pkg.package_id });
      await removeWalletPackage(pkg.package_id, { remove });
      toast?.success('Copie partagée retirée.');
      await loadData();
    } catch (e) {
      toast?.error(`Échec du retrait : ${e.message || e}`);
    } finally {
      setBusyFor(pkg.package_id, null);
    }
  }

  async function handleCreate() {
    const label = prompt('Saisissez un libellé pour la nouvelle Cellule :');
    if (!label) return;
    const retentionDays = parseInt(prompt('Saisissez la durée active de la Cellule en jours (1-365) :', '30'));
    if (!retentionDays || retentionDays < 1 || retentionDays > 365) return;
    const reservedMiB = parseInt(
      prompt('Réserver une disponibilité réseau temporaire pour cette Cellule (Mio, 0 = frais de base minimum uniquement) :', '0'),
      10,
    );
    if (Number.isNaN(reservedMiB) || reservedMiB < 0) return;
    const reservedBytes = reservedMiB * 1024 * 1024;

    setBusyFor('create', 'creating');
    try {
      const create = await signCelluleCreate({
        session,
        label,
        retentionDays,
        reservedBytes,
      });
      await createWalletCellule({ create });
      toast?.success('Cellule créée avec succès !');
      await loadData();
    } catch (e) {
      toast?.error(`Échec de la création : ${e.message || e}`);
    } finally {
      setBusyFor('create', null);
    }
  }

  const mins = Math.floor(remainingMs / 60000);
  const secs = Math.floor((remainingMs % 60000) / 1000).toString().padStart(2, '0');

  return (
    <div style={{ display: 'grid', gap: '1rem' }}>
      {/* ---- session header ---- */}
      <div style={{ ...cardStyle, display: 'grid', gap: '0.75rem' }}>
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
          <h2 style={{ margin: 0, display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
            <ShieldCheck size={20} color="var(--accent-primary)" /> Coffre déverrouillé
          </h2>
          <div style={{ fontSize: '0.85rem', color: 'var(--text-secondary)' }}>
            Verrouillage auto dans {mins}:{secs}
          </div>
        </div>
        <div>
          <div style={{ fontSize: '0.8rem', color: 'var(--text-secondary)', marginBottom: '0.35rem' }}>
            Clé publique ({session.role})
          </div>
          <div style={{ display: 'flex', gap: '0.5rem', alignItems: 'center' }}>
            <div style={{ ...codeStyle, flex: 1, fontSize: '0.78rem' }}>{session.publicKeyHex}</div>
            <CopyButton value={session.publicKeyHex} />
          </div>
        </div>
        <div style={{ display: 'flex', gap: '0.75rem', flexWrap: 'wrap' }}>
          <button onClick={onLock} style={buttonSecondary}>
            <Lock size={16} /> Verrouiller
          </button>
          <button onClick={onWipe} style={buttonDanger}>
            <Trash2 size={16} /> Effacer le coffre
          </button>
        </div>
      </div>

      {/* ---- My Cellules ---- */}
      <div style={{ ...cardStyle, display: 'grid', gap: '0.75rem' }}>
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
          <h3 style={{ margin: 0 }}>Mes Cellules</h3>
          <div style={{ display: 'flex', gap: '0.5rem' }}>
            <button
              disabled={!!busy['create']}
              onClick={handleCreate}
              style={{ ...buttonPrimary, padding: '0.35rem 0.65rem', fontSize: '0.82rem' }}
            >
              <Plus size={14} />
              {busy['create'] === 'creating' ? 'Création…' : 'Créer'}
            </button>
            <button onClick={loadData} style={{ ...buttonSecondary, padding: '0.35rem 0.65rem' }}>
              <RefreshCw size={14} />
            </button>
          </div>
        </div>

        {dataError && (
          <div style={{ color: '#ff7676', fontSize: '0.85rem' }}>
            Impossible de charger les données du noeud : {dataError}
          </div>
        )}

        {!cellules && !dataError && (
          <div style={{ color: 'var(--text-secondary)', fontSize: '0.9rem' }}>Chargement…</div>
        )}

        {cellules && cellules.length === 0 && (
          <div style={{ color: 'var(--text-secondary)', fontSize: '0.9rem' }}>
            Aucune Cellule trouvée pour cette clé. Créez votre première Cellule depuis le parcours wallet.
          </div>
        )}

        {cellules && cellules.map((c) => {
          const b = busy[c.cellule_id];
          const claimed = c.status === 'claimed';
          return (
            <div
              key={c.cellule_id}
              style={{
                padding: '0.85rem',
                border: '1px solid var(--border)',
                borderRadius: '8px',
                display: 'grid',
                gap: '0.5rem',
              }}
            >
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', flexWrap: 'wrap', gap: '0.5rem' }}>
                <div>
                  <div style={{ fontWeight: 600, fontFamily: 'monospace', fontSize: '0.88rem' }}>
                    {c.cellule_id.slice(0, 20)}…
                  </div>
                  {c.company_label && (
                    <div style={{ fontSize: '0.8rem', color: 'var(--text-secondary)' }}>{c.company_label}</div>
                  )}
                  <div style={{ fontSize: '0.78rem', color: 'var(--text-secondary)', marginTop: '0.2rem' }}>
                    Statut : <strong>{c.status}</strong>
                    {c.last_renewed_at && (
                      <> · Renouvelée {new Date(c.last_renewed_at).toLocaleString()}</>
                    )}
                    {!c.last_renewed_at && c.finalized_at && (
                      <> · Revendiquée {new Date(c.finalized_at).toLocaleString()}</>
                    )}
                  </div>
                </div>
                {claimed && (
                  <div style={{ display: 'flex', gap: '0.5rem', flexShrink: 0 }}>
                    <button
                      disabled={!!b}
                      onClick={() => handleRenew(c.cellule_id)}
                      style={{ ...buttonSecondary, padding: '0.4rem 0.75rem', fontSize: '0.82rem' }}
                    >
                      <RefreshCw size={13} />
                      {b === 'renewing' ? 'Renouvellement…' : 'Renouveler'}
                    </button>
                    <button
                      disabled={!!b}
                      onClick={() => handleDelete(c.cellule_id)}
                      style={{ ...buttonDanger, padding: '0.4rem 0.75rem', fontSize: '0.82rem' }}
                    >
                      <Trash2 size={13} />
                      {b === 'deleting' ? 'Suppression…' : 'Supprimer'}
                    </button>
                  </div>
                )}
              </div>
            </div>
          );
        })}
      </div>

      {/* ---- Shared copies ---- */}
      <div style={{ ...cardStyle, display: 'grid', gap: '0.75rem' }}>
        <h3 style={{ margin: 0 }}>Copies partagées</h3>

        {packages && packages.length === 0 && (
          <div style={{ color: 'var(--text-secondary)', fontSize: '0.9rem' }}>
            Aucun package destinataire créé depuis cette clé.
          </div>
        )}

        {packages && packages.map((pkg) => {
          const b = busy[pkg.package_id];
          const active = String(pkg.status || '').toLowerCase() === 'active';
          return (
            <div
              key={pkg.package_id}
              style={{
                padding: '0.85rem',
                border: `1px solid ${active ? 'var(--border)' : 'rgba(255,118,118,0.25)'}`,
                borderRadius: '8px',
                display: 'grid',
                gap: '0.4rem',
                opacity: active ? 1 : 0.6,
              }}
            >
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', flexWrap: 'wrap', gap: '0.5rem' }}>
                <div>
                  <div style={{ fontSize: '0.78rem', fontFamily: 'monospace', color: 'var(--text-secondary)' }}>
                    Destinataire : {pkg.recipient_public_key.slice(0, 20)}…
                  </div>
                  <div style={{ fontSize: '0.8rem', marginTop: '0.2rem' }}>
                    Champs : <strong>{(pkg.fields || []).join(', ') || 'métadonnées du package uniquement'}</strong>
                  </div>
                  <div style={{ fontSize: '0.78rem', color: 'var(--text-secondary)', marginTop: '0.15rem' }}>
                    Cellule: {pkg.cellule_id.slice(0, 16)}…
                    {' · '}
                    <span style={{ color: active ? '#5ee08a' : '#ff7676' }}>
                      {pkg.status || 'unknown'}
                    </span>
                    {pkg.expires_at && <> · expire le {new Date(pkg.expires_at).toLocaleDateString()}</>}
                  </div>
                </div>
                {active && (
                  <button
                    disabled={!!b}
                    onClick={() => handleRemovePackage(pkg)}
                    style={{ ...buttonDanger, padding: '0.4rem 0.75rem', fontSize: '0.82rem', flexShrink: 0 }}
                  >
                    <Trash2 size={13} />
                    {b === 'removing' ? 'Retrait…' : 'Retirer'}
                  </button>
                )}
              </div>
            </div>
          );
        })}
      </div>
    </div>
  );
}

function UnlockForm({ vault, onUnlocked }) {
  const [password, setPassword] = useState('');
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState(null);
  const toast = useToast();

  async function handleUnlock(e) {
    e?.preventDefault();
    setBusy(true);
    setError(null);
    try {
      const session = await unlockVault({ vaultId: vault.vaultId, password });
      toast?.success('Coffre déverrouillé.');
      onUnlocked(session);
    } catch (err) {
      setError(err.message || String(err));
    } finally {
      setBusy(false);
    }
  }

  return (
    <form onSubmit={handleUnlock} style={{ ...cardStyle, display: 'grid', gap: '1rem' }}>
      <h2 style={{ margin: 0, display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
        <Unlock size={20} /> Déverrouillez votre wallet
      </h2>
      <div>
        <div style={{ fontSize: '0.8rem', color: 'var(--text-secondary)', marginBottom: '0.35rem' }}>
          Clé publique
        </div>
        <div style={codeStyle}>{vault.publicKeyHex}</div>
      </div>
      <div>
        <label style={{ display: 'block', marginBottom: '0.35rem', fontSize: '0.85rem' }}>
          Mot de passe du coffre
        </label>
        <input
          type="password"
          value={password}
          onChange={(e) => setPassword(e.target.value)}
          autoComplete="current-password"
          style={inputStyle}
          autoFocus
        />
      </div>
      {error && <div style={{ color: '#ff7676', fontSize: '0.9rem' }}>{error}</div>}
      <div style={{ display: 'flex', justifyContent: 'flex-end' }}>
        <button type="submit" disabled={busy || !password} style={buttonPrimary}>
          {busy ? 'Déverrouillage…' : 'Déverrouiller'}
        </button>
      </div>
    </form>
  );
}

// --------------------------------------------------------------------------
// Top-level component
// --------------------------------------------------------------------------

export default function VaultPanel({ role = 'end-user' }) {
  // Multi-tenant end-user vaults are currently disabled for public builds.
  // Company-node end-user space and the operator space keep their
  // single-vault behaviour.
  const isMultiTenantEndUser = false;
  const defaultVaultId =
    role === 'operator' ? 'operator-default' : DEFAULT_VAULT_ID;

  const [vaults, setVaults] = useState(null);
  const [mode, setMode] = useState('loading'); // 'loading' | 'list' | 'create' | 'unlock' | 'unlocked'
  const [activeVault, setActiveVault] = useState(null);
  // `createVaultId` is the vaultId currently being created; in multi-tenant
  // mode it differs per "+ Ajouter un wallet" click.
  const [createVaultId, setCreateVaultId] = useState(defaultVaultId);
  const [session, setSession] = useState(null);
  const [loadError, setLoadError] = useState(null);
  const toast = useToast();

  const refresh = useCallback(async () => {
    try {
      await ensureCryptoLoaded();
      const all = await listVaults();
      // Operator space: only the canonical operator vault.
      // Multi-tenant end-user space: ALL end-user vaults.
      // Company-node end-user space: only the canonical default vault.
      const v = all.filter((x) => {
        if (role === 'operator') return x.vaultId === 'operator-default';
        if (isMultiTenantEndUser) return x.role === 'end-user';
        return x.vaultId === defaultVaultId;
      });
      setVaults(v);
      setMode(v.length > 0 ? 'list' : 'create');
      if (v.length === 0) {
        setCreateVaultId(
          isMultiTenantEndUser ? newTenantVaultId() : defaultVaultId,
        );
      }
    } catch (err) {
      setLoadError(err.message || String(err));
    }
  }, [defaultVaultId, isMultiTenantEndUser, role]);

  useEffect(() => {
    refresh();
  }, [refresh]);

  async function handleWipe() {
    if (!session) return;
    if (!confirm('Effacer ce coffre ? Vous perdrez l’accès sauf si vous disposez de votre mnémonique de 24 mots.')) {
      return;
    }
    try {
      session.lock();
      await wipeVault(session.vaultId);
      setSession(null);
      setActiveVault(null);
      toast?.success('Coffre effacé.');
      await refresh();
    } catch (err) {
      alert(`Échec de l’effacement : ${err.message || err}`);
    }
  }

  if (loadError) {
    return (
      <div style={cardStyle}>
        <h2 style={{ marginTop: 0 }}>Wallet indisponible</h2>
        <p>{loadError}</p>
      </div>
    );
  }

  if (mode === 'loading' || vaults === null) {
    return (
      <div style={cardStyle}>
        <p style={{ margin: 0 }}>Chargement du module cryptographique CONFIDIS…</p>
      </div>
    );
  }

  if (mode === 'list') {
    return (
      <div style={{ display: 'grid', gap: '1rem' }}>
        <ZeroKnowledgeNotice />
        <div style={{ ...cardStyle, display: 'grid', gap: '1rem' }}>
          <h2 style={{ margin: 0 }}>
            {isMultiTenantEndUser ? 'Vos wallets' : 'Votre wallet'}
          </h2>
          {isMultiTenantEndUser ? (
            <p
              style={{
                margin: 0,
                color: 'var(--text-secondary)',
                fontSize: '0.85rem',
              }}
            >
              Vous pouvez maintenir plusieurs identités propriétaires
              indépendantes sur ce navigateur; chacune contrôle ses propres
              Cellules et packages destinataire.
            </p>
          ) : null}
          {vaults.map((v) => (
            <div
              key={v.vaultId}
              style={{
                display: 'flex',
                justifyContent: 'space-between',
                alignItems: 'center',
                padding: '0.75rem',
                border: '1px solid var(--border)',
                borderRadius: '8px',
              }}
            >
              <div>
                <div style={{ fontWeight: 600 }}>{v.vaultId}</div>
                <div
                  style={{
                    fontSize: '0.8rem',
                    color: 'var(--text-secondary)',
                  }}
                >
                  Créé le {new Date(v.createdAt).toLocaleString()} · rôle {v.role}
                </div>
                {isMultiTenantEndUser ? (
                  <div
                    style={{
                      fontSize: '0.72rem',
                      color: 'var(--text-secondary)',
                      fontFamily:
                        'ui-monospace, SFMono-Regular, Menlo, monospace',
                      marginTop: 2,
                    }}
                    title="Clé publique propriétaire — identifiant réseau"
                  >
                    {v.publicKeyHex?.slice(0, 16)}…{v.publicKeyHex?.slice(-8)}
                  </div>
                ) : null}
              </div>
              <button
                onClick={() => {
                  setActiveVault(v);
                  setMode('unlock');
                }}
                style={buttonPrimary}
              >
                <Unlock size={16} /> Déverrouiller
              </button>
            </div>
          ))}
          {isMultiTenantEndUser ? (
            <button
              onClick={() => {
                setCreateVaultId(newTenantVaultId());
                setMode('create');
              }}
              style={buttonSecondary}
            >
              <Plus size={16} /> Ajouter un wallet
            </button>
          ) : null}
        </div>
      </div>
    );
  }

  if (mode === 'create') {
    return (
      <div style={{ display: 'grid', gap: '1rem' }}>
        <CreateFlow
          role={role}
          vaultId={createVaultId}
          onCreated={async () => {
            await refresh();
            // Land on the unlock screen for the just-created vault.
            const list = await listVaults();
            const v = list.find((x) => x.vaultId === createVaultId);
            setActiveVault(v);
            setMode('unlock');
          }}
          onCancel={() => setMode(vaults.length > 0 ? 'list' : 'create')}
        />
        {vaults.length > 0 && (
          <button onClick={() => setMode('list')} style={buttonSecondary}>
            Retour à la liste des coffres
          </button>
        )}
      </div>
    );
  }

  if (mode === 'unlock' && activeVault) {
    return (
      <div style={{ display: 'grid', gap: '1rem' }}>
        <UnlockForm
          vault={activeVault}
          onUnlocked={(s) => {
            setSession(s);
            setMode('unlocked');
          }}
        />
        <button
          onClick={() => {
            setActiveVault(null);
            setMode('list');
          }}
          style={buttonSecondary}
        >
          Retour
        </button>
      </div>
    );
  }

  if (mode === 'unlocked' && session) {
    return (
      <UnlockedPanel
        session={session}
        onLock={() => {
          session.lock();
          setSession(null);
          setMode('list');
          toast?.info('Coffre verrouillé.');
        }}
        onWipe={handleWipe}
      />
    );
  }

  return null;
}

// Empty-state CTA when no vault is found — shown by parent containers that
// want to embed the create flow inline. Currently unused but kept exported
// so the future operator route can call it directly.
export function CreateVaultCard() {
  return (
    <div style={{ ...cardStyle, textAlign: 'center', display: 'grid', gap: '0.75rem' }}>
      <Plus size={24} style={{ margin: '0 auto' }} />
      <h3 style={{ margin: 0 }}>Créer un wallet CONFIDIS</h3>
      <p style={{ margin: 0, color: 'var(--text-secondary)', fontSize: '0.9rem' }}>
        Générez une phrase de récupération de 24 mots et un coffre local scellé par mot de passe.
        Rien ne quitte votre navigateur.
      </p>
    </div>
  );
}
