import { useState } from 'react';
import { Link } from 'react-router-dom';
import { ShieldCheck, Globe, FileCheck, ChevronDown, ChevronRight, ArrowRight } from 'lucide-react';
import ParticlesBackground from './ParticlesBackground';
import RoleBadge from './RoleBadge';
import { useNodeMode } from './NodeModeContextValue';

// Canonical project links — keep these the single source of truth so the
// GitHub repo and the signed .deb release point are consistent everywhere.
const GITHUB_URL = 'https://github.com/confidis-project/confidis';
const RELEASES_URL = 'https://github.com/confidis-project/confidis/releases/latest';

const FEATURES = [
  {
    icon: <ShieldCheck size={28} color="#45f3ff" />,
    title: 'Cellules contrôlées par l’utilisateur',
    body: 'L’utilisateur crée ses clés dans le navigateur. L’organisation fournit l’appliance, les quotas et l’accompagnement sans recevoir la clé privée.',
  },
  {
    icon: <Globe size={28} color="#45f3ff" />,
    title: 'Fédération de noeuds de confiance',
    body: 'Les shards chiffrés peuvent être répliqués entre noeuds explicitement autorisés, avec limites réciproques, reçus signés et état de santé local.',
  },
  {
    icon: <FileCheck size={28} color="#45f3ff" />,
    title: 'Preuves de cycle de vie',
    body: 'Expiration, demandes de suppression, reçus signés et journaux d’audit rendent les décisions de conservation visibles.',
  },
];

const STEPS = [
  {
    num: '01',
    title: 'Créer une identité propriétaire',
    body: 'L’utilisateur crée sa clé propriétaire et sa phrase de récupération dans l’interface web servie par le noeud. La clé privée reste côté client.',
  },
  {
    num: '02',
    title: 'Contrôler une Cellule',
    body: 'Le noeud applique les quotas locaux et la durée maximale. L’utilisateur contrôle renouvellement, suppression et copies chiffrées.',
  },
  {
    num: '03',
    title: 'Envoyer des copies chiffrées',
    body: 'L’utilisateur crée des packages destinataire pour l’organisation ou un tiers, avec périmètre, expiration, retrait et preuves.',
  },
];

const FAQS = [
  {
    q: 'Qu’est-ce que CONFIDIS OS ?',
    a: 'CONFIDIS OS est une appliance open-source basée sur Debian pour déployer un noeud auto-hébergé de Cellules personnelles temporaires chiffrées.',
  },
  {
    q: 'Qu’est-ce qu’une Cellule ?',
    a: 'Une Cellule est un espace de données chiffré contrôlé par une clé utilisateur. Elle possède une durée active maximale et ne peut être renouvelée qu’avec le consentement explicite du propriétaire.',
  },
  {
    q: 'Est-ce un réseau à jetons ?',
    a: 'Non. CONFIDIS OS v1 fonctionne sans jeton, sans crédit interne et sans place de marché. L’usage est limité par quotas locaux et accords de fédération.',
  },
  {
    q: 'Comment fonctionne le chiffrement ?',
    a: 'Les données sont chiffrées côté client avant l’envoi. Les packages destinataire sont chiffrés pour une clé publique précise, sans accès en clair pour les noeuds de stockage.',
  },
  {
    q: 'Que se passe-t-il à l’expiration ?',
    a: 'Sans renouvellement, le réseau planifie la suppression et collecte les reçus signés des noeuds ayant exécuté l’action. CONFIDIS produit des preuves techniques, pas une garantie juridique automatique.',
  },
];

function FaqItem({ q, a }) {
  const [open, setOpen] = useState(false);
  return (
    <div
      style={{
        borderBottom: '1px solid rgba(255,255,255,0.08)',
        cursor: 'pointer',
      }}
      onClick={() => setOpen(o => !o)}
    >
      <div style={{
        display: 'flex', justifyContent: 'space-between', alignItems: 'center',
        padding: '18px 0', fontWeight: 500, fontSize: 15,
      }}>
        {q}
        {open ? <ChevronDown size={18} color="#45f3ff" /> : <ChevronRight size={18} color="#888" />}
      </div>
      {open && (
        <p style={{ margin: '0 0 18px', color: '#9aa0a6', fontSize: 14, lineHeight: 1.7 }}>{a}</p>
      )}
    </div>
  );
}

export default function MarketingPage() {
  const [step, setStep] = useState(0);

  // Phase 1b — on an authority node, the operator space is CLI-only and the
  // public landing must not advertise it. Hide the operator CTA when the
  // node identifies itself as authority; keep it visible otherwise (and as a
  // fail-safe when node_role is unknown — don't accidentally lock operators
  // out during transient backend errors).
  const { mode: nodeMode } = useNodeMode();
  const hideOperatorCta = nodeMode?.node_role === 'authority';

  return (
    <div style={{
      minHeight: '100vh',
      background: 'linear-gradient(135deg, #0b0c10 0%, #0d1117 60%, #0b1020 100%)',
      color: '#e0e2e8',
      fontFamily: 'var(--font-family, system-ui, sans-serif)',
      overflowX: 'hidden',
      position: 'relative',
    }}>

      {/* Ambient particle field — behind all content (zIndex 0 < 1). */}
      <ParticlesBackground />

      <div style={{ position: 'relative', zIndex: 1 }}>

      {/* ─── Nav ─────────────────────────────────────────────────────────── */}
      <nav style={{
        display: 'flex', alignItems: 'center', justifyContent: 'space-between',
        padding: '20px 48px', position: 'sticky', top: 0, zIndex: 100,
        backdropFilter: 'blur(12px)',
        borderBottom: '1px solid rgba(255,255,255,0.05)',
        background: 'rgba(11,12,16,0.85)',
      }}>
        <span style={{ display: 'flex', alignItems: 'center', gap: 10, fontSize: 22, fontWeight: 700, letterSpacing: '-0.5px', color: '#fff' }}>
          <img src="/logo.svg" alt="CONFIDIS" width={32} height={32} style={{ display: 'block' }} />
          <span><span style={{ color: '#45f3ff' }}>CY</span>BOU</span>
        </span>
        <div style={{ display: 'flex', gap: 32, alignItems: 'center', fontSize: 14 }}>
          <a href="#features" style={{ color: '#9aa0a6', textDecoration: 'none' }}>Fonctionnalités</a>
          <a href="#how" style={{ color: '#9aa0a6', textDecoration: 'none' }}>Fonctionnement</a>
          <a href="#faq" style={{ color: '#9aa0a6', textDecoration: 'none' }}>FAQ</a>
          <a href={GITHUB_URL} target="_blank" rel="noreferrer" style={{ color: '#9aa0a6', textDecoration: 'none' }}>GitHub</a>
          <a href={RELEASES_URL} target="_blank" rel="noreferrer" style={{ color: '#9aa0a6', textDecoration: 'none' }}>Télécharger .deb</a>
          <Link
            to="/user"
            style={{
              background: '#45f3ff22', color: '#45f3ff', border: '1px solid #45f3ff55',
              padding: '7px 18px', borderRadius: 8, textDecoration: 'none', fontWeight: 600, fontSize: 13,
            }}
          >
            Espace utilisateur →
          </Link>
          {hideOperatorCta ? null : (
            <Link
              to="/operator"
              style={{
                background: 'transparent', color: '#9aa0a6', border: '1px solid rgba(255,255,255,0.15)',
                padding: '7px 18px', borderRadius: 8, textDecoration: 'none', fontWeight: 600, fontSize: 13,
              }}
            >
              Espace opérateur →
            </Link>
          )}
        </div>
      </nav>

      {/* ─── Node mode strip ─────────────────────────────────────────────── */}
      {/* Phase 1c — tells visitors at a glance which kind of node they are
          looking at (authority vs company-node) and who would pay. */}
      <div style={{
        display: 'flex', justifyContent: 'center', padding: '12px 24px 0',
      }}>
        <RoleBadge />
      </div>

      {/* ─── Hero ────────────────────────────────────────────────────────── */}
      <section style={{ textAlign: 'center', padding: '60px 24px 80px' }}>
        <div style={{
          display: 'inline-block', background: 'rgba(69,243,255,0.1)',
          border: '1px solid rgba(69,243,255,0.25)', borderRadius: 20,
          padding: '5px 16px', fontSize: 12, fontWeight: 600,
          color: '#45f3ff', letterSpacing: 1, marginBottom: 28, textTransform: 'uppercase',
        }}>
          Appliance Debian self-hosted
        </div>
        <h1 style={{
          fontSize: 'clamp(2.2rem, 5vw, 3.8rem)', fontWeight: 700,
          lineHeight: 1.15, margin: '0 auto 24px', maxWidth: 740,
          background: 'linear-gradient(135deg, #fff 0%, #45f3ff 100%)',
          WebkitBackgroundClip: 'text', WebkitTextFillColor: 'transparent',
        }}>
          CONFIDIS OS<br />Cellules chiffrées temporaires
        </h1>
        <p style={{ maxWidth: 560, margin: '0 auto 40px', color: '#9aa0a6', fontSize: 17, lineHeight: 1.7 }}>
          Une appliance open-source pour organisations qui veulent exploiter des Cellules personnelles temporaires chiffrées, avec fédération de noeuds de confiance et preuves d’exploitation.
        </p>
        <div style={{ display: 'flex', gap: 14, justifyContent: 'center', flexWrap: 'wrap' }}>
          <a
            href="/livre-blanc.md"
            download
            style={{
              background: '#45f3ff', color: '#0b0c10', padding: '13px 28px',
              borderRadius: 10, fontWeight: 700, fontSize: 14, textDecoration: 'none',
              display: 'inline-flex', alignItems: 'center', gap: 8,
            }}
          >
            Télécharger le livre blanc <ArrowRight size={16} />
          </a>
          <a
            href="#how"
            style={{
              background: 'transparent', color: '#e0e2e8',
              border: '1px solid rgba(255,255,255,0.15)',
              padding: '13px 28px', borderRadius: 10, fontWeight: 500,
              fontSize: 14, textDecoration: 'none',
            }}
          >
            Comprendre le fonctionnement
          </a>
        </div>
      </section>

      {/* ─── Features ────────────────────────────────────────────────────── */}
      <section id="features" style={{ padding: '80px 24px', maxWidth: 1100, margin: '0 auto' }}>
        <h2 style={{ textAlign: 'center', fontSize: 28, fontWeight: 700, marginBottom: 48 }}>
          Conçu pour l’exploitation locale et la fédération de confiance
        </h2>
        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(280px, 1fr))', gap: 24 }}>
          {FEATURES.map(f => (
            <div key={f.title} style={{
              background: 'rgba(255,255,255,0.03)',
              border: '1px solid rgba(255,255,255,0.07)',
              borderRadius: 14, padding: '32px 28px',
              transition: 'border-color 0.2s',
            }}>
              <div style={{ marginBottom: 16 }}>{f.icon}</div>
              <h3 style={{ margin: '0 0 12px', fontSize: 17, fontWeight: 600 }}>{f.title}</h3>
              <p style={{ margin: 0, color: '#9aa0a6', fontSize: 14, lineHeight: 1.7 }}>{f.body}</p>
            </div>
          ))}
        </div>
      </section>

      {/* ─── How it works ────────────────────────────────────────────────── */}
      <section id="how" style={{ padding: '80px 24px', background: 'rgba(255,255,255,0.015)' }}>
        <div style={{ maxWidth: 700, margin: '0 auto', textAlign: 'center' }}>
          <h2 style={{ fontSize: 28, fontWeight: 700, marginBottom: 48 }}>Fonctionnement en 3 étapes</h2>
          <div style={{ display: 'flex', justifyContent: 'center', gap: 8, marginBottom: 36 }}>
            {STEPS.map((s, i) => (
              <button key={i} onClick={() => setStep(i)} style={{
                width: 36, height: 36, borderRadius: '50%', border: 'none',
                background: step === i ? '#45f3ff' : 'rgba(255,255,255,0.08)',
                color: step === i ? '#0b0c10' : '#888',
                fontWeight: 700, fontSize: 13, cursor: 'pointer',
              }}>{i + 1}</button>
            ))}
          </div>
          <div style={{
            background: 'rgba(255,255,255,0.03)', border: '1px solid rgba(255,255,255,0.07)',
            borderRadius: 16, padding: '40px 36px', minHeight: 160,
          }}>
            <div style={{ fontSize: 48, fontWeight: 800, color: 'rgba(69,243,255,0.15)', marginBottom: 12 }}>
              {STEPS[step].num}
            </div>
            <h3 style={{ margin: '0 0 14px', fontSize: 20, fontWeight: 600 }}>{STEPS[step].title}</h3>
            <p style={{ margin: 0, color: '#9aa0a6', fontSize: 15, lineHeight: 1.7 }}>{STEPS[step].body}</p>
          </div>
          <div style={{ display: 'flex', justifyContent: 'space-between', marginTop: 16 }}>
            <button onClick={() => setStep(s => Math.max(0, s - 1))} disabled={step === 0}
              style={{ background: 'none', border: '1px solid rgba(255,255,255,0.1)', color: '#888', padding: '8px 18px', borderRadius: 8, cursor: step === 0 ? 'default' : 'pointer' }}>
              ← Précédent
            </button>
            <button onClick={() => setStep(s => Math.min(STEPS.length - 1, s + 1))} disabled={step === STEPS.length - 1}
              style={{ background: 'none', border: '1px solid rgba(255,255,255,0.1)', color: '#888', padding: '8px 18px', borderRadius: 8, cursor: step === STEPS.length - 1 ? 'default' : 'pointer' }}>
              Suivant →
            </button>
          </div>
        </div>
      </section>

      {/* ─── FAQ ─────────────────────────────────────────────────────────── */}
      <section id="faq" style={{ padding: '80px 24px', maxWidth: 720, margin: '0 auto' }}>
        <h2 style={{ textAlign: 'center', fontSize: 28, fontWeight: 700, marginBottom: 40 }}>
          Questions fréquentes
        </h2>
        {FAQS.map(f => <FaqItem key={f.q} q={f.q} a={f.a} />)}
      </section>

      {/* ─── CTA bottom ──────────────────────────────────────────────────── */}
      <section style={{ padding: '80px 24px', textAlign: 'center' }}>
        <div style={{
          maxWidth: 580, margin: '0 auto',
          background: 'linear-gradient(135deg, rgba(69,243,255,0.06), rgba(255,42,122,0.04))',
          border: '1px solid rgba(69,243,255,0.15)',
          borderRadius: 20, padding: '52px 40px',
        }}>
          <h2 style={{ margin: '0 0 16px', fontSize: 26, fontWeight: 700 }}>
            Prêt pour des données personnelles contrôlées par l’utilisateur ?
          </h2>
          <p style={{ color: '#9aa0a6', margin: '0 0 32px', fontSize: 15, lineHeight: 1.7 }}>
            Lisez le livre blanc pour comprendre l’architecture CONFIDIS OS, le cycle de vie des Cellules, les quotas et la fédération de noeuds de confiance.
          </p>
          <a
            href="/livre-blanc.md"
            download
            style={{
              background: '#45f3ff', color: '#0b0c10', padding: '13px 28px',
              borderRadius: 10, fontWeight: 700, fontSize: 14, textDecoration: 'none',
              display: 'inline-flex', alignItems: 'center', gap: 8,
            }}
          >
            Télécharger le livre blanc <ArrowRight size={16} />
          </a>
        </div>
      </section>

      {/* ─── Footer ──────────────────────────────────────────────────────── */}
      <footer style={{
        borderTop: '1px solid rgba(255,255,255,0.06)',
        padding: '28px 48px',
        display: 'flex', justifyContent: 'space-between', alignItems: 'center',
        flexWrap: 'wrap', gap: 12,
        color: '#9aa0a6', fontSize: 13,
      }}>
        <span>© 2026 CONFIDIS. Tous droits réservés.</span>
        <div style={{ display: 'flex', gap: 24 }}>
          <a href={GITHUB_URL} target="_blank" rel="noreferrer"
            style={{ color: '#9aa0a6', textDecoration: 'none' }}>GitHub</a>
          <a href={RELEASES_URL} target="_blank" rel="noreferrer"
            style={{ color: '#9aa0a6', textDecoration: 'none' }}>Télécharger le .deb</a>
          <a href="/livre-blanc.md" download style={{ color: '#9aa0a6', textDecoration: 'none' }}>Livre Blanc</a>
          <Link to="/user" style={{ color: '#45f3ff', textDecoration: 'none' }}>Espace utilisateur</Link>
          <Link to="/operator" style={{ color: '#9aa0a6', textDecoration: 'none' }}>Espace opérateur</Link>
        </div>
      </footer>
      </div>
    </div>
  );
}
