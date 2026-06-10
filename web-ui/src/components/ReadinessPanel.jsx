import { AlertTriangle, Download, ShieldCheck } from 'lucide-react';
import { fetchEvidencePackZip } from '../api';

// Production-readiness checklist derived ENTIRELY from GET /health — no
// private keys, no new endpoints, read-only. Each row turns a posture flag
// into a concrete remediation an operator can act on without reading the
// admin docs. Shown only in the operator space (see DashboardOverview).
//
// Severity:
//   ok   — satisfied
//   warn — safe locally, must be fixed before public exposure
//   fail — blocking / actively wrong

const TONE = {
  pass: { color: '#4ade80', bg: 'rgba(74,222,128,0.07)',  bd: 'rgba(74,222,128,0.22)',  label: 'OK' },
  warning: { color: '#fb923c', bg: 'rgba(251,146,60,0.07)',  bd: 'rgba(251,146,60,0.24)',  label: 'ACTION' },
  fail: { color: 'var(--accent-secondary)', bg: 'rgba(255,42,122,0.06)', bd: 'rgba(255,42,122,0.22)', label: 'BLOQUANT' },
};

function buildChecks(h) {
  const trustRoot = h.trust_root_source && !['missing', 'unknown'].includes(h.trust_root_source);
  return [
    {
      key: 'banned',
      title: 'Statut de quarantaine',
      status: h.node_banned ? 'fail' : 'pass',
      detail: h.node_banned
        ? 'Cette clé de noeud est bannie ou mise en quarantaine par la liste de suspension configurée. Le trafic de shards sera refusé. Analysez la sanction avant de continuer.'
        : 'Non banni par la politique de quarantaine.',
    },
    {
      key: 'ui_token',
      title: 'Authentification API (ui_token)',
      status: h.ui_auth_required ? 'pass' : 'fail',
      detail: h.ui_auth_required
        ? 'Les endpoints destinés à l’UI exigent un jeton Bearer.'
        : 'Aucun ui_token — les API locales de console ne sont pas authentifiées. Exécutez `confidis node gen-token`, définissez ui_token dans node.json, reconstruisez l’UI avec ce VITE_UI_TOKEN, puis redémarrez. Gardez le noeud lié à localhost jusque-là.',
    },
    {
      key: 'cors',
      title: 'Verrouillage d’origine navigateur (ui_allowed_origin)',
      status: h.ui_cors_restricted ? 'pass' : 'warning',
      detail: h.ui_cors_restricted
        ? 'Le CORS est limité à une seule origine navigateur.'
        : 'Le CORS n’est pas verrouillé sur une origine. Définissez ui_allowed_origin sur l’origine exacte de l’UI (ex. https://votre-domaine) avant d’exposer le noeud au-delà de localhost.',
    },
    {
      key: 'trust_root',
      title: 'Racine de quarantaine optionnelle',
      status: h.ban_verification_enabled && trustRoot ? 'pass' : 'warning',
      detail: h.ban_verification_enabled && trustRoot
        ? `Vérification de liste de quarantaine activée (racine : ${h.trust_root_source}).`
        : 'Aucune racine de quarantaine vérifiée. Définissez confidis_root_pubkey seulement si vous utilisez une liste de suspension signée.',
    },
    {
      key: 'ban_list',
      title: 'Liste de quarantaine réactive chargée',
      status: h.node_ban_list_present ? 'pass' : 'warning',
      detail: h.node_ban_list_present
        ? 'Une liste de quarantaine de noeuds signée est chargée.'
        : 'Aucune liste de quarantaine chargée. Configurez node_ban_list_path (et éventuellement node_ban_list_url) pour appliquer les bans et quarantaines réactifs.',
    },
    {
      key: 'webui',
      title: 'Interface web embarquée servie',
      status: h.webui_enabled ? 'pass' : 'warning',
      detail: h.webui_enabled
        ? 'Le noeud sert l’interface web embarquée.'
        : 'webui_path n’est pas défini — l’API fonctionne, mais aucune UI n’est servie. Pointez webui_path vers le bundle UI compilé.',
    },
  ];
}

function checksFromReadiness(readiness) {
  if (!readiness || readiness.unavailable_on_public_surface || !Array.isArray(readiness.checks) || readiness.checks.length === 0) {
    return null;
  }
  return readiness.checks.map(check => ({
    key: check.id,
    title: check.title,
    status: check.status,
    detail: check.remediation
      ? `${check.detail} ${check.remediation}`
      : check.detail,
  }));
}

function downloadReadiness(readiness) {
  if (!readiness || readiness.unavailable_on_public_surface) return;
  const blob = new Blob([JSON.stringify(readiness, null, 2)], { type: 'application/json' });
  const url = URL.createObjectURL(blob);
  const node = document.createElement('a');
  const stamp = new Date().toISOString().replace(/[:.]/g, '-');
  node.href = url;
  node.download = `confidis-readiness-${stamp}.json`;
  document.body.appendChild(node);
  node.click();
  node.remove();
  URL.revokeObjectURL(url);
}

async function downloadEvidencePack() {
  const blob = await fetchEvidencePackZip();
  if (!blob) return;
  const url = URL.createObjectURL(blob);
  const node = document.createElement('a');
  const stamp = new Date().toISOString().replace(/[:.]/g, '-');
  node.href = url;
  node.download = `confidis-evidence-pack-${stamp}.zip`;
  document.body.appendChild(node);
  node.click();
  node.remove();
  URL.revokeObjectURL(url);
}

export default function ReadinessPanel({ health, readiness }) {
  if (!health && !readiness) return null;
  const canExport = readiness && !readiness.unavailable_on_public_surface && Array.isArray(readiness.checks) && readiness.checks.length > 0;
  const checks = checksFromReadiness(readiness) || buildChecks(health);
  const fails = checks.filter(c => c.status === 'fail').length;
  const warns = checks.filter(c => c.status === 'warning').length;

  const summary = fails > 0
    ? { tone: 'fail', text: `Pas prêt pour la production — ${fails} point${fails > 1 ? 's' : ''} bloquant${fails > 1 ? 's' : ''}${warns ? `, ${warns} à traiter` : ''}.` }
    : warns > 0
      ? { tone: 'warning', text: readiness?.summary || `Sûr en local — ${warns} point${warns > 1 ? 's' : ''} à traiter avant exposition publique.` }
      : { tone: 'pass', text: readiness?.summary || 'Prêt pour la production — tous les contrôles sont validés.' };

  const st = TONE[summary.tone];

  return (
    <div className="glass-panel" style={{ padding: '1.5rem', marginBottom: '1.5rem' }}>
      <div style={{ display: 'flex', alignItems: 'center', gap: '0.75rem', marginBottom: '1.25rem', justifyContent: 'space-between', flexWrap: 'wrap' }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: '0.6rem' }}>
          <ShieldCheck size={20} color="var(--accent-primary)" />
          <h3 style={{ fontSize: '1.25rem', fontWeight: 700, margin: 0 }}>Préparation production</h3>
        </div>
        {canExport && (
          <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
            <button
              type="button"
              onClick={() => downloadReadiness(readiness)}
              title="Exporter le rapport readiness JSON"
              aria-label="Exporter le rapport readiness JSON"
              style={{
                display: 'inline-flex', alignItems: 'center', justifyContent: 'center',
                width: 38, height: 38, borderRadius: '8px',
                background: 'rgba(255,255,255,0.04)', border: '1px solid var(--border-color)',
                color: 'var(--text-primary)', cursor: 'pointer',
              }}
            >
              <Download size={17} />
            </button>
            <button
              type="button"
              onClick={() => downloadEvidencePack()}
              title="Exporter l’evidence pack ZIP"
              aria-label="Exporter l’evidence pack ZIP"
              style={{
                display: 'inline-flex', alignItems: 'center', justifyContent: 'center',
                width: 38, height: 38, borderRadius: '8px',
                background: 'rgba(69,243,255,0.08)', border: '1px solid rgba(69,243,255,0.22)',
                color: 'var(--accent-primary)', cursor: 'pointer',
              }}
            >
              <ShieldCheck size={17} />
            </button>
          </div>
        )}
      </div>

      <div style={{
        display: 'flex', alignItems: 'center', gap: '0.6rem',
        padding: '0.75rem 1rem', borderRadius: '10px',
        background: st.bg, border: `1px solid ${st.bd}`, color: st.color,
        fontSize: '0.9rem', fontWeight: 600, marginBottom: '1.25rem',
      }}>
        {summary.tone === 'pass' ? <ShieldCheck size={17} /> : <AlertTriangle size={17} />}
        <span>{summary.text}</span>
      </div>

      <div style={{ display: 'flex', flexDirection: 'column', gap: '0.6rem' }}>
        {checks.map(c => {
          const t = TONE[c.status];
          return (
            <div key={c.key} style={{
              display: 'flex', gap: '0.85rem', alignItems: 'flex-start',
              padding: '0.85rem 1rem', borderRadius: '10px',
              background: 'rgba(255,255,255,0.03)', border: '1px solid var(--border-color)',
            }}>
              <span style={{
                width: 9, height: 9, borderRadius: '50%', marginTop: 6,
                background: t.color, flexShrink: 0,
                boxShadow: c.status === 'pass' ? `0 0 6px ${t.color}` : 'none',
              }} />
              <div style={{ flex: 1, minWidth: 0 }}>
                <div style={{ display: 'flex', alignItems: 'center', gap: '0.6rem', marginBottom: '0.2rem', flexWrap: 'wrap' }}>
                  <span style={{ fontWeight: 600, fontSize: '0.9rem', color: 'var(--text-primary)' }}>{c.title}</span>
                  <span style={{
                    fontSize: '0.65rem', fontWeight: 700, letterSpacing: '0.05em',
                    color: t.color, border: `1px solid ${t.bd}`, background: t.bg,
                    padding: '0.05rem 0.4rem', borderRadius: '4px',
                  }}>{t.label}</span>
                </div>
                <p style={{ color: 'var(--text-secondary)', fontSize: '0.825rem', lineHeight: 1.55, margin: 0 }}>{c.detail}</p>
              </div>
            </div>
          );
        })}
      </div>
    </div>
  );
}
