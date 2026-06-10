#!/usr/bin/env node
// Launch the production build through `vite preview` and ask Firefox headless to
// render the public page plus the user workspace, and verify that an
// operator route is redirected away from the production public surface. This is
// intentionally dependency-free: it catches broken bundles, missing public
// assets and CSP/SRI mistakes without pulling a full browser-test framework
// into the UI package.

import { spawn } from 'node:child_process';
import { mkdir, readFile, stat } from 'node:fs/promises';
import { mkdtemp, rm, writeFile } from 'node:fs/promises';
import net from 'node:net';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { setTimeout as sleep } from 'node:timers/promises';
import { inflateSync } from 'node:zlib';

const port = Number(process.env.CONFIDIS_WEBUI_SMOKE_PORT || 4173);
const marionettePort = Number(process.env.CONFIDIS_WEBUI_MARIONETTE_PORT || 2828);
const host = '127.0.0.1';
const baseUrl = `http://${host}:${port}`;
const outputDir = new URL('../dist/', import.meta.url);
const defaultRoutes = [
  ['home', '/'],
  ['user-overview', '/user'],
  ['user-cellules', '/user/cellules'],
  ['user-wallet', '/user/wallet'],
  ['user-docs', '/user/docs'],
  ['operator-blocked', '/operator', '/user'],
];

function smokeRoutes() {
  const configured = process.env.CONFIDIS_WEBUI_SMOKE_ROUTES;
  if (!configured) return defaultRoutes;
  return configured.split(',')
    .map(route => route.trim())
    .filter(Boolean)
    .map(route => {
      const path = route.startsWith('/') ? route : `/${route}`;
      const name = path === '/'
        ? 'home'
        : path.slice(1).replace(/[^a-z0-9]+/gi, '-').replace(/^-|-$/g, '');
      return [name || 'route', path, path];
    });
}

function commandExists(command) {
  return new Promise((resolve) => {
    const child = spawn(command, ['--version'], { stdio: 'ignore' });
    child.on('error', () => resolve(false));
    child.on('exit', (code) => resolve(code === 0));
  });
}

function waitForSocket(portNumber, deadlineMs = 10_000) {
  const deadline = Date.now() + deadlineMs;
  return new Promise((resolve, reject) => {
    async function attempt() {
      const socket = net.createConnection({ host, port: portNumber });
      socket.once('connect', () => {
        socket.end();
        resolve();
      });
      socket.once('error', async (err) => {
        socket.destroy();
        if (Date.now() >= deadline) {
          reject(err);
          return;
        }
        await sleep(250);
        attempt();
      });
    }
    attempt();
  });
}

class MarionetteFirefox {
  constructor() {
    this.profileDir = null;
    this.process = null;
    this.socket = null;
    this.buffer = Buffer.alloc(0);
    this.pending = [];
    this.id = 0;
  }

  async start() {
    this.profileDir = await mkdtemp(join(tmpdir(), 'confidis-webui-smoke-'));
    this.process = spawn(
      'firefox',
      ['--headless', '--marionette', '--new-instance', '--profile', this.profileDir, 'about:blank'],
      { stdio: ['ignore', 'ignore', 'pipe'] },
    );
    this.process.stderr.on('data', (chunk) => {
      const text = chunk.toString().replace(/^Exiting due to channel error\.\n?/gm, '');
      if (text) process.stderr.write(text);
    });
    await waitForSocket(marionettePort);
    this.socket = net.createConnection({ host, port: marionettePort });
    this.socket.on('data', (chunk) => this.onData(chunk));
    this.socket.on('error', (err) => this.rejectNext(err));
    await this.nextMessage();
    await this.send('WebDriver:NewSession', {
      capabilities: { alwaysMatch: { acceptInsecureCerts: true } },
    });
    await this.send('WebDriver:SetWindowRect', { x: 0, y: 0, width: 1440, height: 1000 });
  }

  onData(chunk) {
    this.buffer = Buffer.concat([this.buffer, chunk]);
    while (true) {
      const separator = this.buffer.indexOf(':');
      if (separator < 0) return;
      const length = Number(this.buffer.subarray(0, separator).toString());
      if (this.buffer.length < separator + 1 + length) return;
      const body = this.buffer.subarray(separator + 1, separator + 1 + length).toString();
      this.buffer = this.buffer.subarray(separator + 1 + length);
      this.pending.shift()?.resolve(JSON.parse(body));
    }
  }

  nextMessage() {
    return new Promise((resolve, reject) => this.pending.push({ resolve, reject }));
  }

  rejectNext(err) {
    this.pending.shift()?.reject(err);
  }

  async send(command, params) {
    const id = ++this.id;
    const body = JSON.stringify([0, id, command, params]);
    this.socket.write(`${Buffer.byteLength(body)}:${body}`);
    const response = await this.nextMessage();
    if (response[2]) {
      throw new Error(`${command} failed: ${JSON.stringify(response[2])}`);
    }
    return response[3]?.value ?? response[3];
  }

  async waitUntilRendered(path) {
    const deadline = Date.now() + 15_000;
    let source = '';
    while (Date.now() < deadline) {
      source = await this.send('WebDriver:GetPageSource', {});
      if (!source.includes('Chargement') && !source.includes('Génération')) return;
      await sleep(250);
    }
    throw new Error(`${path} stayed on loading screen`);
  }

  async redactSensitiveContent() {
    await this.send('WebDriver:ExecuteScript', {
      script: `
        for (const el of document.querySelectorAll('[data-smoke-redact]')) {
          el.textContent = '[contenu sensible masqué pour capture]';
        }
      `,
      args: [],
    });
  }

  async waitForPathname(expectedPathname, requestedPath) {
    const deadline = Date.now() + 15_000;
    let actualPathname = '';
    while (Date.now() < deadline) {
      actualPathname = await this.send('WebDriver:ExecuteScript', {
        script: 'return window.location.pathname;',
        args: [],
      });
      if (actualPathname === expectedPathname) return;
      await sleep(250);
    }
    throw new Error(`${requestedPath} did not redirect to ${expectedPathname} (current path: ${actualPathname})`);
  }

  async screenshot(name, path, expectedPath = path) {
    await this.send('WebDriver:Navigate', { url: `${baseUrl}${path}` });
    if (expectedPath !== path) {
      await this.waitForPathname(expectedPath, path);
    }
    await this.waitUntilRendered(expectedPath);
    await this.redactSensitiveContent();
    const base64 = await this.send('WebDriver:TakeScreenshot', { full: false });
    const screenshotPath = new URL(`smoke-${name}.png`, outputDir);
    await writeFile(screenshotPath, Buffer.from(base64, 'base64'));
    return screenshotPath;
  }

  async stop() {
    try {
      try {
        if (this.socket) await this.send('WebDriver:DeleteSession', {});
      } catch {
        // Best-effort cleanup; the process is still terminated below.
      }
      if (this.socket) this.socket.end();
      if (this.process) this.process.kill('SIGTERM');
    } finally {
      if (this.profileDir) {
        await rm(this.profileDir, { recursive: true, force: true });
      }
    }
  }
}

async function waitForPreview(preview) {
  const deadline = Date.now() + 15_000;
  let lastError;
  while (Date.now() < deadline) {
    if (preview.exitCode !== null) {
      throw new Error(`vite preview exited early with code ${preview.exitCode}`);
    }
    try {
      const response = await fetch(`${baseUrl}/`);
      if (response.ok) return;
      lastError = new Error(`HTTP ${response.status}`);
    } catch (err) {
      lastError = err;
    }
    await sleep(250);
  }
  throw new Error(`vite preview did not become ready at ${baseUrl}/: ${lastError?.message || 'timeout'}`);
}

async function assertRouteServed(path) {
  const response = await fetch(`${baseUrl}${path}`);
  if (!response.ok) {
    throw new Error(`route ${path} returned HTTP ${response.status}`);
  }
}

function decodePngRgba(bytes) {
  const signature = '89504e470d0a1a0a';
  if (bytes.subarray(0, 8).toString('hex') !== signature) {
    throw new Error('screenshot is not a PNG');
  }

  let offset = 8;
  let width;
  let height;
  let colorType;
  const idat = [];
  while (offset < bytes.length) {
    const length = bytes.readUInt32BE(offset);
    const type = bytes.subarray(offset + 4, offset + 8).toString('ascii');
    const data = bytes.subarray(offset + 8, offset + 8 + length);
    offset += 12 + length;
    if (type === 'IHDR') {
      width = data.readUInt32BE(0);
      height = data.readUInt32BE(4);
      colorType = data[9];
    } else if (type === 'IDAT') {
      idat.push(data);
    } else if (type === 'IEND') {
      break;
    }
  }

  if (!width || !height || colorType !== 6) {
    throw new Error(`unsupported PNG format in screenshot (colorType=${colorType})`);
  }

  const bytesPerPixel = 4;
  const stride = width * bytesPerPixel;
  const inflated = inflateSync(Buffer.concat(idat));
  const rgba = Buffer.alloc(height * stride);
  let source = 0;
  for (let y = 0; y < height; y += 1) {
    const filter = inflated[source];
    source += 1;
    const rowStart = y * stride;
    for (let x = 0; x < stride; x += 1) {
      const raw = inflated[source + x];
      const left = x >= bytesPerPixel ? rgba[rowStart + x - bytesPerPixel] : 0;
      const up = y > 0 ? rgba[rowStart + x - stride] : 0;
      const upLeft = y > 0 && x >= bytesPerPixel ? rgba[rowStart + x - stride - bytesPerPixel] : 0;
      let value;
      if (filter === 0) value = raw;
      else if (filter === 1) value = raw + left;
      else if (filter === 2) value = raw + up;
      else if (filter === 3) value = raw + Math.floor((left + up) / 2);
      else if (filter === 4) {
        const p = left + up - upLeft;
        const pa = Math.abs(p - left);
        const pb = Math.abs(p - up);
        const pc = Math.abs(p - upLeft);
        value = raw + (pa <= pb && pa <= pc ? left : pb <= pc ? up : upLeft);
      } else {
        throw new Error(`unsupported PNG filter ${filter}`);
      }
      rgba[rowStart + x] = value & 0xff;
    }
    source += stride;
  }
  return { width, height, rgba };
}

function countVisibleContentInMainArea(png) {
  const startX = Math.min(300, Math.floor(png.width * 0.25));
  let visible = 0;
  for (let y = 0; y < png.height; y += 1) {
    for (let x = startX; x < png.width; x += 1) {
      const index = (y * png.width + x) * 4;
      const r = png.rgba[index];
      const g = png.rgba[index + 1];
      const b = png.rgba[index + 2];
      const a = png.rgba[index + 3];
      if (a > 0 && r + g + b > 90) visible += 1;
    }
  }
  return visible;
}

async function main() {
  if (!(await commandExists('firefox'))) {
    throw new Error('missing firefox; install it or skip with CONFIDIS_SKIP_WEBUI_SMOKE=1');
  }

  await mkdir(outputDir, { recursive: true });
  const preview = spawn(
    'npm',
    ['run', 'preview', '--', '--host', host, '--port', String(port), '--strictPort'],
    { cwd: new URL('..', import.meta.url), stdio: ['ignore', 'pipe', 'pipe'] },
  );

  preview.stdout.on('data', (chunk) => process.stdout.write(chunk));
  preview.stderr.on('data', (chunk) => process.stderr.write(chunk));
  const browser = new MarionetteFirefox();

  try {
    await waitForPreview(preview);
    await browser.start();
    const screenshots = [];
    for (const [name, path, expectedPath = path] of smokeRoutes()) {
      await assertRouteServed(path);
      const screenshotPath = await browser.screenshot(name, path, expectedPath);
      const image = await stat(screenshotPath);
      if (image.size < 10_000) {
        throw new Error(`${path} screenshot is unexpectedly small (${image.size} bytes)`);
      }
      const png = await readFile(screenshotPath);
      const visibleContent = countVisibleContentInMainArea(decodePngRgba(png));
      if (visibleContent < 5_000) {
        throw new Error(
          `${path} screenshot has too little rendered content in the main area (${visibleContent} bright pixels)`,
        );
      }
      screenshots.push(screenshotPath.pathname);
    }
    console.log('✓ web-ui smoke screenshots rendered:');
    screenshots.forEach(path => console.log(`  ${path}`));
  } finally {
    await browser.stop();
    preview.kill('SIGTERM');
  }
}

main().catch((err) => {
  console.error(`web-ui smoke failed: ${err.message || err}`);
  process.exit(1);
});
