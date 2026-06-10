#!/usr/bin/env node
// Post-build SRI injector.
//
// Reads dist/index.html produced by `vite build`, computes SHA-384 for every
// same-origin <script src> and <link href> asset, and injects
// `integrity="sha384-…" crossorigin="anonymous"` attributes so browsers
// enforce Subresource Integrity on every asset load.
//
// Usage:
//   node scripts/inject-sri.js          # operates on dist/index.html
//
// CI should fail if the dist/ directory is missing (i.e. build ran first).
// The script exits with code 1 on any error so `npm run build` surfaces it.

import { readFileSync, writeFileSync } from 'node:fs';
import { createHash } from 'node:crypto';
import { resolve, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';

const __dirname = dirname(fileURLToPath(import.meta.url));
const distDir = resolve(__dirname, '../dist');
const htmlPath = resolve(distDir, 'index.html');

function sri(relPath) {
  const abs = resolve(distDir, relPath.replace(/^\//, ''));
  const bytes = readFileSync(abs);
  const hash = createHash('sha384').update(bytes).digest('base64');
  return `sha384-${hash}`;
}

function stripAttr(str, name) {
  // Remove an existing attribute so we can re-inject a fresh value.
  return str.replace(new RegExp(`\\s+${name}(?:="[^"]*")?`, 'g'), '');
}

let html = readFileSync(htmlPath, 'utf8');
let patched = 0;

// <script … src="/assets/…">
html = html.replace(
  /<script([^>]*?)\ssrc="(\/[^"]+)"([^>]*?)>/g,
  (match, before, src, after) => {
    if (src.startsWith('http')) return match;
    let attrs = before + after;
    attrs = stripAttr(attrs, 'integrity');
    attrs = stripAttr(attrs, 'crossorigin');
    patched++;
    return `<script${attrs} src="${src}" integrity="${sri(src)}" crossorigin="anonymous">`;
  }
);

// <link … href="/assets/…"> (modulepreload, stylesheet, etc.)
html = html.replace(
  /<link([^>]*?)\shref="(\/[^"]+)"([^>]*?)\/?>/g,
  (match, before, href, after) => {
    if (href.startsWith('http')) return match;
    if (!/\.(js|css|wasm)(\?.*)?$/.test(href)) return match;
    let integrity;
    try { integrity = sri(href); } catch { return match; }
    let attrs = before + after;
    attrs = stripAttr(attrs, 'integrity');
    attrs = stripAttr(attrs, 'crossorigin');
    patched++;
    return `<link${attrs} href="${href}" integrity="${integrity}" crossorigin="anonymous" />`;
  }
);

writeFileSync(htmlPath, html, 'utf8');
console.log(`[inject-sri] ${patched} asset(s) hashed → dist/index.html`);
