import { useEffect, useState } from 'react';
import { fetchNodeInfo } from '../api';
import { NodeModeContext } from './NodeModeContextValue';

// NodeModeContext exposes the running node's role metadata to every
// component so banners and operator/user surfaces stay consistent across the UI:
//
//   - node_role: "authority" (isolated authority/signer surface) or
//     "company" (operator-run node — operator pays for clients).
//   - production_profile: whether strict production checks are enforced.
//
// Loading: until `/node-info` resolves, `mode == null`. Components must treat
// an unknown mode as fail-safe — render nothing economically sensitive and
// surface a generic "Mode de noeud inconnu" warning instead of guessing.

export function NodeModeProvider({ children }) {
  const [mode, setMode] = useState(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);

  useEffect(() => {
    let cancelled = false;
    fetchNodeInfo()
      .then((info) => {
        if (cancelled) return;
        setMode(info);
        setError(null);
      })
      .catch((e) => {
        if (cancelled) return;
        setError(e);
      })
      .finally(() => {
        if (cancelled) return;
        setLoading(false);
      });
    return () => {
      cancelled = true;
    };
  }, []);

  return (
    <NodeModeContext.Provider value={{ mode, loading, error }}>
      {children}
    </NodeModeContext.Provider>
  );
}
