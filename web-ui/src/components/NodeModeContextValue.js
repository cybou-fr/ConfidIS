import { createContext, useContext } from 'react';

export const NodeModeContext = createContext({
  mode: null,
  loading: true,
  error: null,
});

export function useNodeMode() {
  return useContext(NodeModeContext);
}
