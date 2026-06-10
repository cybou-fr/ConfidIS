import { defineConfig } from 'vite';
import react from '@vitejs/plugin-react';

// Content-Security-Policy applied both in the dev server (as HTTP headers) and
// baked into index.html (as a <meta> tag) for production.
//
// Key restrictions:
//   script-src 'self' 'wasm-unsafe-eval'  — no inline scripts, no third-party JS; WASM allowed
//   style-src  'self' 'unsafe-inline'     — inline styles needed for React style-prop patterns
//   connect-src 'self' + dev node URL     — restricts fetch/XHR targets
//   worker-src 'self'                     — allows same-origin Worker (signingWorker.js)
//   frame-ancestors 'none'                — clickjacking defence (HTTP header only; ignored in meta)
//   object-src 'none'                     — no Flash / legacy plugins
//   base-uri   'self'                     — prevent base-tag injection

const DEV_NODE_URL = process.env.VITE_NODE_URL || 'http://127.0.0.1:4433';

// Build the policy as a flat string so it can be reused in both the dev server
// header and the meta tag.
const CSP_POLICY = [
  "default-src 'self'",
  "script-src 'self' 'wasm-unsafe-eval'",
  "style-src 'self' 'unsafe-inline'",
  `connect-src 'self' ${DEV_NODE_URL}`,
  "img-src 'self' data:",
  "font-src 'self'",
  "worker-src 'self' blob:",
  "object-src 'none'",
  "frame-ancestors 'none'",
  "form-action 'self'",
  "base-uri 'self'",
].join('; ');

export default defineConfig({
  plugins: [react()],

  // Dev server: inject full CSP as HTTP headers (supports frame-ancestors).
  server: {
    headers: {
      'Content-Security-Policy': CSP_POLICY,
      'X-Content-Type-Options': 'nosniff',
      'X-Frame-Options': 'DENY',
      'Referrer-Policy': 'strict-origin-when-cross-origin',
    },
  },

  // Ensure Workers are bundled as separate entry points with module syntax so
  // `new Worker(url, { type: 'module' })` works in production builds.
  worker: {
    format: 'es',
  },
});
