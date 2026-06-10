import { useState, useEffect } from 'react';
import { Shield, Terminal, Copy, CheckCircle, ExternalLink } from 'lucide-react';
import { fetchHealth } from '../api';

function CodeBlock({ code, label }) {
  const [copied, setCopied] = useState(false);

  function copy() {
    navigator.clipboard.writeText(code).then(() => {
      setCopied(true);
      setTimeout(() => setCopied(false), 2000);
    });
  }

  return (
    <div style={{ marginBottom: 12 }}>
      {label && <div style={{ fontSize: 12, color: '#888', marginBottom: 4 }}>{label}</div>}
      <div style={{ display: 'flex', alignItems: 'flex-start', gap: 8 }}>
        <pre style={{
          flex: 1, background: '#0d1117', color: '#e6edf3', borderRadius: 6,
          padding: '10px 14px', fontSize: 13, overflowX: 'auto', margin: 0,
          fontFamily: 'ui-monospace, SFMono-Regular, monospace',
        }}>{code}</pre>
        <button
          onClick={copy}
          title="Copier"
          style={{
            border: 'none', background: 'none', cursor: 'pointer',
            padding: 6, color: copied ? '#3fb950' : '#888',
          }}
        >
          {copied ? <CheckCircle size={16} /> : <Copy size={16} />}
        </button>
      </div>
    </div>
  );
}

function Section({ title, children }) {
  return (
    <section style={{ marginBottom: 28 }}>
      <h3 style={{ margin: '0 0 12px', fontSize: 15, fontWeight: 600 }}>{title}</h3>
      {children}
    </section>
  );
}

export default function FirewallGuide({ listenPort: propPort }) {
  const [os, setOs] = useState('ufw');
  const [listenPort, setListenPort] = useState(propPort ?? 4433);

  useEffect(() => {
    if (propPort) return;
    fetchHealth()
      .then(h => { if (h.listen_port) setListenPort(h.listen_port); })
      .catch(() => {});
  }, [propPort]);

  return (
    <div style={{ maxWidth: 680, margin: '0 auto', padding: '24px 16px', fontFamily: 'system-ui, sans-serif' }}>
      <div style={{ display: 'flex', alignItems: 'center', gap: 10, marginBottom: 20 }}>
        <Shield size={22} color="#f85149" />
        <h2 style={{ margin: 0, fontSize: 18 }}>Guide de configuration du pare-feu</h2>
      </div>

      <p style={{ color: '#888', marginTop: 0, marginBottom: 24, fontSize: 14, lineHeight: 1.6 }}>
        Votre noeud CONFIDIS écoute sur le port <strong>{listenPort}</strong>.
        Pour rejoindre le réseau et servir l’interface web, ce port doit être joignable depuis internet.
        Choisissez votre outil de pare-feu ci-dessous.
      </p>

      {/* OS selector */}
      <div style={{ display: 'flex', gap: 8, marginBottom: 24 }}>
        {[
          { id: 'ufw', label: 'UFW (Ubuntu/Debian)' },
          { id: 'firewalld', label: 'firewalld (RHEL/Rocky)' },
          { id: 'iptables', label: 'iptables (manual)' },
          { id: 'hetzner', label: 'Hetzner Cloud' },
        ].map(({ id, label }) => (
          <button
            key={id}
            onClick={() => setOs(id)}
            style={{
              padding: '6px 14px', borderRadius: 6, fontSize: 13, cursor: 'pointer',
              border: `1px solid ${os === id ? '#1f6feb' : '#30363d'}`,
              background: os === id ? '#1f6feb22' : 'transparent',
              color: os === id ? '#58a6ff' : '#c9d1d9',
              fontWeight: os === id ? 600 : 400,
            }}
          >{label}</button>
        ))}
      </div>

      {os === 'ufw' && (
        <>
          <Section title="1. Autoriser le port du noeud">
            <CodeBlock code={`sudo ufw allow ${listenPort}/tcp`} label="Autoriser le TCP entrant" />
            <CodeBlock code={`sudo ufw status`} label="Vérifier" />
          </Section>
          <Section title="2. Activer UFW s’il n’est pas déjà actif">
            <CodeBlock code={`sudo ufw enable`} />
          </Section>
          <Section title="3. Garder SSH ouvert (si ce n’est pas déjà fait)">
            <CodeBlock code={`sudo ufw allow OpenSSH`} />
          </Section>
        </>
      )}

      {os === 'firewalld' && (
        <>
          <Section title="1. Ouvrir le port de façon permanente">
            <CodeBlock
              code={`sudo firewall-cmd --permanent --add-port=${listenPort}/tcp\nsudo firewall-cmd --reload`}
              label="Ajouter la règle et recharger"
            />
          </Section>
          <Section title="2. Vérifier">
            <CodeBlock code={`sudo firewall-cmd --list-ports`} />
          </Section>
        </>
      )}

      {os === 'iptables' && (
        <>
          <Section title="1. Insérer la règle">
            <CodeBlock
              code={`sudo iptables -I INPUT -p tcp --dport ${listenPort} -j ACCEPT`}
            />
          </Section>
          <Section title="2. La rendre persistante (Debian/Ubuntu)">
            <CodeBlock
              code={`sudo apt install iptables-persistent\nsudo netfilter-persistent save`}
            />
          </Section>
          <Section title="2. La rendre persistante (RHEL/Rocky)">
            <CodeBlock
              code={`sudo service iptables save`}
            />
          </Section>
        </>
      )}

      {os === 'hetzner' && (
        <>
          <Section title="Pare-feu Cloud (recommandé)">
            <ol style={{ paddingLeft: 20, fontSize: 14, lineHeight: 2, color: '#c9d1d9' }}>
              <li>Ouvrez la <strong>Hetzner Cloud Console</strong> → <strong>Firewalls</strong></li>
              <li>Créez un nouveau pare-feu (ou modifiez celui attaché à votre serveur)</li>
              <li>Ajoutez une <strong>règle entrante</strong> :
                <CodeBlock
                  code={`Protocole : TCP\nPort : ${listenPort}\nIP sources : 0.0.0.0/0, ::/0  (toutes)`}
                  label="Paramètres de la règle"
                />
              </li>
              <li>Appliquez le pare-feu à votre serveur</li>
            </ol>
          </Section>
          <Section title="Ou : éditez /etc/iptables/rules.v4 directement">
            <CodeBlock
              code={`# Ajouter avant la ligne COMMIT :\n-A INPUT -p tcp --dport ${listenPort} -j ACCEPT`}
            />
          </Section>
        </>
      )}

      <Section title="Tester la connectivité">
        <CodeBlock
          code={`curl -sf https://$(curl -s ifconfig.me):${listenPort}/health | python3 -m json.tool`}
          label="Depuis une autre machine (ou votre terminal local)"
        />
        <p style={{ fontSize: 13, color: '#888', marginTop: 8 }}>
          Une réponse JSON avec <code style={{ background: '#161b22', padding: '1px 4px', borderRadius: 3 }}>"status":"ok"</code> confirme que votre noeud est joignable.
        </p>
      </Section>

      <div style={{
        padding: '12px 16px', borderRadius: 8,
        background: '#161b22', border: '1px solid #30363d',
        fontSize: 13, color: '#888', lineHeight: 1.6,
      }}>
        <Terminal size={14} style={{ verticalAlign: 'middle', marginRight: 6 }} />
        Après avoir ouvert le port, redémarrez le noeud si vous avez modifié <code>listen_addr</code> :
        <CodeBlock code={`sudo systemctl restart confidis`} />
        <span>
          Besoin d’aide ?{' '}
          <a href="https://confidis.eu/docs/firewall" target="_blank" rel="noreferrer"
            style={{ color: '#58a6ff', display: 'inline-flex', alignItems: 'center', gap: 3 }}>
            Documentation complète <ExternalLink size={11} />
          </a>
        </span>
      </div>
    </div>
  );
}
