import { useState } from 'react';
import { ShieldCheck, X } from 'lucide-react';

/**
 * KeyPolicyNotice — dismissible banner reminding users that private keys
 * entered in this panel are held in React state only and never sent to any
 * server or written to localStorage.
 *
 * Usage: place once at the top of any panel that accepts a private key.
 */
export default function KeyPolicyNotice() {
  const [dismissed, setDismissed] = useState(false);
  if (dismissed) return null;

  return (
    <div style={{
      display: 'flex', alignItems: 'flex-start', justifyContent: 'space-between', gap: '0.75rem',
      padding: '0.75rem 1rem', borderRadius: '10px', marginBottom: '1rem',
      background: 'rgba(69,243,255,0.05)', border: '1px solid rgba(69,243,255,0.18)',
    }}>
      <div style={{ display: 'flex', gap: '0.6rem', alignItems: 'flex-start', fontSize: '0.78rem', color: 'var(--text-secondary)', lineHeight: 1.5 }}>
        <ShieldCheck size={14} color="var(--accent-primary)" style={{ flexShrink: 0, marginTop: '0.1rem' }} />
        <span>
          <strong style={{ color: 'var(--text-primary)' }}>Politique des clés : </strong>
          Les clés privées saisies ici ne sont conservées que dans l’état React — elles ne sont <em>jamais</em> envoyées à un serveur et sont
          effacées à la fermeture de ce panneau. Ne copiez jamais une clé dans <code style={{ background: 'rgba(255,255,255,0.07)', padding: '0 0.3rem', borderRadius: '3px' }}>localStorage</code> ou la console du navigateur.
        </span>
      </div>
      <button onClick={() => setDismissed(true)}
        style={{ background: 'transparent', border: 'none', color: 'var(--text-secondary)', cursor: 'pointer', padding: '0.1rem', flexShrink: 0 }}
        title="Masquer">
        <X size={14} />
      </button>
    </div>
  );
}
