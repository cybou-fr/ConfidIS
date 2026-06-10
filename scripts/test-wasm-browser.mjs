#!/usr/bin/env node

import { spawn } from 'node:child_process';
import { fileURLToPath } from 'node:url';

const command = 'wasm-pack';
const args = ['test', '--headless', '--firefox', 'crates/confidis-crypto-wasm'];
const graceMs = 5_000;
const timeoutMs = 180_000;
let output = '';
let completed = false;
let resultSeen = false;
let graceTimer;

const child = spawn(command, args, {
  cwd: fileURLToPath(new URL('..', import.meta.url)),
  detached: process.platform !== 'win32',
  stdio: ['ignore', 'pipe', 'pipe'],
});

function stopBrowserTree(signal = 'SIGTERM') {
  try {
    if (process.platform === 'win32') {
      child.kill(signal);
    } else {
      process.kill(-child.pid, signal);
    }
  } catch {
    // The runner may have already performed its own clean shutdown.
  }
}

function finish(code, message) {
  if (completed) return;
  completed = true;
  clearTimeout(graceTimer);
  clearTimeout(hardTimeout);
  if (message) process.stderr.write(`${message}\n`);
  stopBrowserTree();
  setTimeout(() => {
    stopBrowserTree('SIGKILL');
    process.exit(code);
  }, 100).unref();
  process.exitCode = code;
}

function forward(stream, target) {
  stream.on('data', (chunk) => {
    const text = chunk.toString();
    target.write(text);
    output += text;
    if (!resultSeen && /test result: ok\.\s+\d+ passed; 0 failed/.test(output)) {
      resultSeen = true;
      graceTimer = setTimeout(() => {
        finish(
          0,
          '[wasm-browser] Tests passed; closed a Firefox runner that remained alive after completion.',
        );
      }, graceMs);
    }
  });
}

forward(child.stdout, process.stdout);
forward(child.stderr, process.stderr);

child.on('error', (error) => {
  finish(1, `[wasm-browser] Failed to start ${command}: ${error.message}`);
});

child.on('exit', (code, signal) => {
  if (completed) return;
  if (code === 0 && resultSeen) {
    finish(0);
    return;
  }
  finish(
    1,
    `[wasm-browser] Browser test runner exited without a successful result (code=${code}, signal=${signal}).`,
  );
});

const hardTimeout = setTimeout(() => {
  finish(1, `[wasm-browser] Timed out after ${timeoutMs / 1000}s without a passing browser result.`);
}, timeoutMs);

for (const signal of ['SIGINT', 'SIGTERM']) {
  process.on(signal, () => finish(1, `[wasm-browser] Interrupted by ${signal}.`));
}
