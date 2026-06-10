import { lazy, Suspense, useEffect, useState } from 'react';
import { BrowserRouter as Router, Routes, Route, Link, Navigate, useLocation } from 'react-router-dom';
import { LayoutDashboard, Wallet, Database, Settings, Activity, BookOpen, Server, HelpCircle, Building2, Flame, KeyRound } from 'lucide-react';
import { ToastProvider } from './components/Toast';
import { NodeModeProvider } from './components/NodeModeContext';
import ErrorBoundary from './components/ErrorBoundary';
import { fetchHealth } from './api';

const DashboardOverview = lazy(() => import('./components/DashboardOverview'));
const CellulesManager = lazy(() => import('./components/CellulesManager'));
const NetworkManager = lazy(() => import('./components/NetworkManager'));
const SettingsManager = lazy(() => import('./components/SettingsManager'));
const DocsUser = lazy(() => import('./components/DocsUser'));
const DocsAdmin = lazy(() => import('./components/DocsAdmin'));
const FAQ = lazy(() => import('./components/FAQ'));
const VaultPanel = lazy(() => import('./components/VaultPanel'));
const OperatorPanel = lazy(() => import('./components/OperatorPanel'));
const FirewallGuide = lazy(() => import('./components/FirewallGuide'));
const MarketingPage = lazy(() => import('./components/MarketingPage'));

// Authority controls may be useful in local development only. A production
// bundle must never render a form that sends authority private keys.
const AuthorityPanel = import.meta.env.DEV && import.meta.env.VITE_ENABLE_AUTHORITY_UI === 'true'
  ? lazy(() => import('./components/AuthorityPanel'))
  : null;
const ENABLE_AUTHORITY_UI = Boolean(AuthorityPanel);

// Two separate spaces with their own navigation. The end-user space is
// deliberately minimal (the user is less technical); the operator space holds
// node operations and (optionally) authority controls.
const USER_NAV = [
  { path: '/user', label: 'Vue d’ensemble', icon: LayoutDashboard },
  { path: '/user/cellules', label: 'Mes Cellules', icon: Database },
  { path: '/user/wallet', label: 'Mon identité', icon: Wallet },
];
const USER_DOCS = [
  { path: '/user/docs', label: 'Guide utilisateur', icon: <BookOpen size={20} /> },
  { path: '/user/faq', label: 'FAQ', icon: <HelpCircle size={20} /> },
];

const OPERATOR_NAV = [
  { path: '/operator', label: 'Vue d’ensemble', icon: LayoutDashboard },
  { path: '/operator/node', label: 'Noeud', icon: Building2 },
  { path: '/operator/network', label: 'Réseau', icon: Activity },
  { path: '/operator/wallet', label: 'Accès destinataire', icon: Wallet },
  ...(ENABLE_AUTHORITY_UI ? [{ path: '/operator/authority', label: 'Autorité', icon: KeyRound }] : []),
  { path: '/operator/settings', label: 'Paramètres', icon: Settings },
];
const OPERATOR_DOCS = [
  { path: '/operator/docs', label: 'Docs admin', icon: <Server size={20} /> },
  { path: '/operator/faq', label: 'FAQ opérateur', icon: <HelpCircle size={20} /> },
  { path: '/operator/firewall', label: 'Configuration pare-feu', icon: <Flame size={20} /> },
];

function spaceFromPath(pathname) {
  if (pathname === '/operator' || pathname.startsWith('/operator/')) return 'operator';
  if (pathname === '/user' || pathname.startsWith('/user/')) return 'user';
  return null;
}

function isDashboardRoute(pathname) {
  return spaceFromPath(pathname) !== null;
}

function navFor(space) {
  return space === 'operator'
    ? { nav: OPERATOR_NAV, docs: OPERATOR_DOCS, title: 'Espace opérateur' }
    : { nav: USER_NAV, docs: USER_DOCS, title: 'Espace utilisateur' };
}

function nodeStatusFromHealth(health, error) {
  if (error) return { label: 'Noeud injoignable', detail: 'API locale indisponible', color: 'var(--accent-secondary)', glow: 'none' };
  if (!health) return { label: 'Vérification du noeud…', detail: 'Lecture de la santé locale', color: '#fb923c', glow: 'none' };
  if (health.node_banned) return { label: 'Noeud en quarantaine', detail: 'Cette clé de noeud est suspendue', color: 'var(--accent-secondary)', glow: 'none' };
  if (health.public_ui_only) return { label: 'Surface publique isolée', detail: 'Administration disponible hors interface publique', color: '#4ade80', glow: '0 0 8px #4ade80' };
  if (!health.ui_auth_required) return { label: 'Mode dev local', detail: 'Le jeton UI n’est pas configuré', color: '#fb923c', glow: 'none' };
  if (!health.ban_verification_enabled) return { label: 'Quarantaine non vérifiée', detail: 'Flux de suspension non configuré', color: '#fb923c', glow: 'none' };
  if (!health.ui_cors_restricted) return { label: 'Jeton uniquement', detail: 'Restreindre le CORS avant usage public', color: '#fb923c', glow: 'none' };
  return { label: 'Noeud en ligne', detail: health.trust_root_source || 'API locale protégée', color: '#4ade80', glow: '0 0 8px #4ade80' };
}

function useNodeStatus() {
  const [health, setHealth] = useState(null);
  const [error, setError] = useState(false);

  useEffect(() => {
    let cancelled = false;
    async function refresh() {
      try {
        const nodeHealth = await fetchHealth();
        if (!cancelled) {
          setHealth(nodeHealth);
          setError(false);
        }
      } catch {
        if (!cancelled) setError(true);
      }
    }
    refresh();
    const id = setInterval(refresh, 10000);
    return () => { cancelled = true; clearInterval(id); };
  }, []);

  return nodeStatusFromHealth(health, error);
}

// Whether the served node exposes the operator space. Authority nodes and
// every production public surface serve the end-user Web UI only; operator
// actions there are CLI/local-only until signed operator authentication
// exists. Start hidden while posture is being loaded.
function useOperatorEnabled() {
  const [enabled, setEnabled] = useState(false);
  useEffect(() => {
    let cancelled = false;
    fetchHealth()
      .then(h => {
        if (!cancelled && h && typeof h.operator_ui_enabled === 'boolean') {
          setEnabled(h.operator_ui_enabled);
        }
      })
      .catch(() => {});
    return () => { cancelled = true; };
  }, []);
  return enabled;
}

function Sidebar() {
  const location = useLocation();
  const space = spaceFromPath(location.pathname) || 'user';
  const { nav, docs, title } = navFor(space);
  const nodeStatus = useNodeStatus();
  const operatorEnabled = useOperatorEnabled();
  const other = space === 'operator'
    ? { to: '/user', label: 'Passer à l’espace utilisateur', Icon: Wallet }
    : { to: '/operator', label: 'Passer à l’espace opérateur', Icon: Building2 };

  const active = (path) => location.pathname === path;
  const linkStyle = (path) => ({
    display: 'flex', alignItems: 'center', gap: '0.75rem',
    padding: '0.75rem 1rem', borderRadius: '8px',
    color: active(path) ? 'var(--accent-primary)' : 'var(--text-secondary)',
    background: active(path) ? 'rgba(69, 243, 255, 0.1)' : 'transparent',
    textDecoration: 'none', fontWeight: 500, transition: 'var(--transition)',
  });

  return (
    <aside className="sidebar">
      <Link to="/" style={{ display: 'flex', alignItems: 'center', gap: '0.75rem', fontSize: '1.5rem', fontWeight: 700, marginBottom: '0.5rem', color: 'var(--text-primary)', textDecoration: 'none' }}>
        <img src="/logo.svg" alt="CONFIDIS" width={32} height={32} style={{ display: 'block' }} />
        CONFIDIS
      </Link>
      <p style={{ fontSize: '0.7rem', color: 'var(--accent-primary)', textTransform: 'uppercase', letterSpacing: '0.1em', fontWeight: 700, padding: '0 1rem', marginBottom: '1.5rem' }}>{title}</p>

      <nav style={{ display: 'flex', flexDirection: 'column', gap: '0.5rem' }}>
        {nav.map(item => {
          const Icon = item.icon;
          return (
            <Link key={item.path} to={item.path} style={linkStyle(item.path)}>
              <Icon size={20} />
              {item.label}
            </Link>
          );
        })}
      </nav>

      <div style={{ marginTop: '1.5rem' }}>
        <p style={{ fontSize: '0.7rem', color: 'var(--text-secondary)', textTransform: 'uppercase', letterSpacing: '0.1em', fontWeight: 600, padding: '0 1rem', marginBottom: '0.5rem' }}>Documentation</p>
        <nav style={{ display: 'flex', flexDirection: 'column', gap: '0.5rem' }}>
          {docs.map(item => (
            <Link key={item.path} to={item.path} style={linkStyle(item.path)}>
              {item.icon}
              {item.label}
            </Link>
          ))}
        </nav>
      </div>

      {operatorEnabled && (
        <div style={{ marginTop: '1.5rem' }}>
          <Link to={other.to} style={{ ...linkStyle(other.to), border: '1px solid var(--border-color)', color: 'var(--text-primary)' }}>
            <other.Icon size={20} />
            {other.label}
          </Link>
        </div>
      )}

      <div style={{ marginTop: 'auto', padding: '1.5rem', background: 'rgba(255, 255, 255, 0.03)', borderRadius: '12px', border: '1px solid var(--border-color)' }}>
        <p style={{ fontSize: '0.75rem', color: 'var(--text-secondary)', marginBottom: '0.5rem' }}>État du noeud</p>
        <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', color: nodeStatus.color, fontSize: '0.875rem', fontWeight: 700 }}>
          <div style={{ width: '8px', height: '8px', borderRadius: '50%', background: nodeStatus.color, boxShadow: nodeStatus.glow, flexShrink: 0 }} />
          {nodeStatus.label}
        </div>
        <p style={{ marginTop: '0.35rem', color: 'var(--text-secondary)', fontSize: '0.72rem', lineHeight: 1.35 }}>{nodeStatus.detail}</p>
      </div>

    </aside>
  );
}

function BottomNav() {
  const location = useLocation();
  const space = spaceFromPath(location.pathname) || 'user';
  const { nav } = navFor(space);
  return (
    <nav className="bottom-nav" aria-label="Navigation principale">
      <div className="bottom-nav-inner">
        {nav.map(item => {
          const Icon = item.icon;
          const active = location.pathname === item.path;
          return (
            <Link key={item.path} to={item.path} className={`bottom-nav-item${active ? ' active' : ''}`}>
              <Icon size={22} />
              <span>{item.label}</span>
            </Link>
          );
        })}
      </div>
    </nav>
  );
}

function DashboardShell({ children }) {
  return (
    <div className="app-layout">
      <Sidebar />
      <main className="main-content">{children}</main>
      <BottomNav />
    </div>
  );
}

function LoadingScreen() {
  return (
    <div style={{ padding: '2rem', color: 'var(--text-secondary)' }}>
      Chargement…
    </div>
  );
}

function GuardedRoute({ label, children }) {
  return (
    <ErrorBoundary label={label}>
      <Suspense fallback={<LoadingScreen />}>{children}</Suspense>
    </ErrorBoundary>
  );
}

function AppRoutes() {
  const location = useLocation();
  const isDash = isDashboardRoute(location.pathname);
  const operatorEnabled = useOperatorEnabled();

  if (!isDash) {
    // Public / marketing routes + legacy → space redirects (no sidebar chrome).
    return (
      <Suspense fallback={<LoadingScreen />}>
        <Routes>
          <Route path="/" element={<MarketingPage />} />
          <Route path="/dashboard" element={<Navigate to="/user" replace />} />
          <Route path="/cellules" element={<Navigate to="/user/cellules" replace />} />
          <Route path="/wallet" element={<Navigate to="/user/wallet" replace />} />
          <Route path="/docs/user" element={<Navigate to="/user/docs" replace />} />
          <Route path="/faq" element={<Navigate to="/user/faq" replace />} />
          <Route path="/network" element={<Navigate to="/operator/network" replace />} />
          <Route path="/settings" element={<Navigate to="/operator/settings" replace />} />
          <Route path="/docs/admin" element={<Navigate to="/operator/docs" replace />} />
          <Route path="/firewall" element={<Navigate to="/operator/firewall" replace />} />
          <Route path="/authority" element={<Navigate to="/operator/authority" replace />} />
          <Route path="*" element={<MarketingPage />} />
        </Routes>
      </Suspense>
    );
  }

  // Authority and production public nodes serve the end-user space only.
  // Redirect any operator route to /user.
  if (!operatorEnabled && spaceFromPath(location.pathname) === 'operator') {
    return <Navigate to="/user" replace />;
  }

  return (
    <DashboardShell>
      <Routes>
        {/* ── User space (minimal, for the less-technical end user) ── */}
        <Route path="/user" element={<GuardedRoute label="Vue d’ensemble"><DashboardOverview /></GuardedRoute>} />
        <Route path="/user/cellules" element={<GuardedRoute label="Mes Cellules"><CellulesManager /></GuardedRoute>} />
        <Route path="/user/wallet" element={<GuardedRoute label="Mon identité"><VaultPanel role="end-user" /></GuardedRoute>} />
        <Route path="/user/docs" element={<GuardedRoute label="Guide utilisateur"><DocsUser /></GuardedRoute>} />
        <Route path="/user/faq" element={<GuardedRoute label="FAQ utilisateur"><FAQ audience="user" /></GuardedRoute>} />

        {/* ── Operator space (node operations) ── */}
        <Route path="/operator" element={<GuardedRoute label="Vue d’ensemble"><DashboardOverview /></GuardedRoute>} />
        <Route path="/operator/node" element={<GuardedRoute label="Noeud"><OperatorPanel /></GuardedRoute>} />
        <Route path="/operator/network" element={<GuardedRoute label="Réseau"><NetworkManager /></GuardedRoute>} />
        <Route path="/operator/wallet" element={<GuardedRoute label="Accès destinataire"><VaultPanel role="operator" /></GuardedRoute>} />
        {ENABLE_AUTHORITY_UI && (
          <Route path="/operator/authority" element={<GuardedRoute label="Autorité"><AuthorityPanel /></GuardedRoute>} />
        )}
        <Route path="/operator/settings" element={<GuardedRoute label="Paramètres"><SettingsManager /></GuardedRoute>} />
        <Route path="/operator/docs" element={<GuardedRoute label="Docs admin"><DocsAdmin /></GuardedRoute>} />
        <Route path="/operator/faq" element={<GuardedRoute label="FAQ opérateur"><FAQ audience="operator" /></GuardedRoute>} />
        <Route path="/operator/firewall" element={<GuardedRoute label="Configuration pare-feu"><FirewallGuide /></GuardedRoute>} />

        <Route path="*" element={<div style={{ padding: '2rem' }}>Module en développement…</div>} />
      </Routes>
    </DashboardShell>
  );
}

function AppContent() {
  return (
    <Router>
      <ToastProvider>
        <NodeModeProvider>
          <AppRoutes />
        </NodeModeProvider>
      </ToastProvider>
    </Router>
  );
}

function App() {
  return <AppContent />;
}

export default App;
