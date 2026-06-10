import { useEffect, useRef } from 'react';

// Subtle, dependency-free particle field for the public landing background.
// CSP-safe (no external library, no inline script — bundled same-origin JS,
// canvas only). Deliberately low-contrast: faint accent dots with thin links
// that should read as ambient depth, never as a flashy animation.
//
// Layered behaviour:
//   • free drift (calm) → particles slowly converge into a mathematical
//     structure (forming) → hold the shape briefly → dissolve back to drift.
//   • the structure catalog reflects what CONFIDIS actually uses:
//     cryptographic lattices, hash chains, Reed-Solomon matrices,
//     Ed25519-style elliptic curves, Pascal mod 2 (Sierpiński),
//     golden-angle Fibonacci placement.
//   • everything stays at ~10–15 % accent opacity, only visible if you look.
//   • easter egg: ?math=verbose URL param OR Ctrl+Shift+M shows the
//     current structure name for demos/juries.
//
// Strict constraints:
//   • respects prefers-reduced-motion (renders one static structure, no loop)
//   • device-pixel-ratio aware (crisp on retina)
//   • pauses the RAF loop when the tab is hidden
//   • pointer-events: none so it never blocks the UI underneath
//   • zero external dependencies, plain canvas 2D

// === Structure generators ===
// Each returns { label, targets: [{x,y}], edges: [[i,j], ...] }.

function lattice(width, height) {
  const cx = width / 2;
  const cy = height / 2;
  const cols = 6;
  const rows = 5;
  const step = Math.min(width, height) * 0.07;
  const jitter = step * 0.05;
  const targets = [];
  for (let r = 0; r < rows; r++) {
    for (let c = 0; c < cols; c++) {
      targets.push({
        x: cx + (c - (cols - 1) / 2) * step + (Math.random() - 0.5) * jitter,
        y: cy + (r - (rows - 1) / 2) * step + (Math.random() - 0.5) * jitter,
      });
    }
  }
  const edges = [];
  for (let r = 0; r < rows; r++) {
    for (let c = 0; c < cols; c++) {
      const i = r * cols + c;
      if (c < cols - 1) edges.push([i, i + 1]);
      if (r < rows - 1) edges.push([i, i + cols]);
    }
  }
  return { label: 'treillis cryptographique', targets, edges };
}

function hashChain(width, height) {
  const n = 16;
  const margin = Math.min(width * 0.08, 120);
  const usable = width - 2 * margin;
  const cy = height / 2;
  const amplitude = Math.min(height * 0.12, 90);
  const targets = [];
  for (let i = 0; i < n; i++) {
    const t = i / (n - 1);
    targets.push({
      x: margin + t * usable,
      y: cy + Math.sin(t * Math.PI * 2.4) * amplitude,
    });
  }
  const edges = [];
  for (let i = 0; i < n - 1; i++) edges.push([i, i + 1]);
  return { label: 'chaîne de hash BLAKE3', targets, edges };
}

function rsMatrix(width, height) {
  const cx = width / 2;
  const cy = height / 2;
  const cols = 6;
  const rows = 5;
  const stepX = Math.min(width, height) * 0.075;
  const stepY = Math.min(width, height) * 0.058;
  const targets = [];
  for (let r = 0; r < rows; r++) {
    for (let c = 0; c < cols; c++) {
      targets.push({
        x: cx + (c - (cols - 1) / 2) * stepX,
        y: cy + (r - (rows - 1) / 2) * stepY,
      });
    }
  }
  const edges = [];
  for (let r = 0; r < rows; r++) {
    for (let c = 0; c < cols - 1; c++) {
      edges.push([r * cols + c, r * cols + c + 1]);
    }
  }
  for (let r = 0; r < rows - 1; r++) edges.push([r * cols, (r + 1) * cols]);
  return {
    label: 'matrice Reed-Solomon (Vandermonde 20+10)',
    targets,
    edges,
  };
}

function ed25519Curve(width, height) {
  // y² = x³ - x + 1, sampled symmetrically on both branches.
  const scale = Math.min(width, height) * 0.16;
  const cx = width / 2;
  const cy = height / 2;
  const samples = 28;
  const xs = [];
  for (let i = 0; i < samples; i++) {
    const t = i / (samples - 1);
    const x = -1.5 + t * 3.8;
    const ySq = x * x * x - x + 1;
    if (ySq >= 0) xs.push({ x, y: Math.sqrt(ySq) });
  }
  const targets = [];
  for (const p of xs) targets.push({ x: cx + p.x * scale, y: cy - p.y * scale });
  for (let i = xs.length - 1; i >= 0; i--) {
    targets.push({ x: cx + xs[i].x * scale, y: cy + xs[i].y * scale });
  }
  const edges = [];
  for (let i = 0; i < targets.length - 1; i++) edges.push([i, i + 1]);
  return { label: 'courbe elliptique Ed25519', targets, edges };
}

function pascalMod2(width, height) {
  const rows = 16;
  const step = Math.min(width, height) * 0.035;
  const cx = width / 2;
  const totalH = rows * step * 0.88;
  const cy = height / 2 - totalH / 2;
  const targets = [];
  // C(n,k) mod 2 == 1  ⟺  (k & n) === k  (Lucas / Kummer).
  for (let n = 0; n < rows; n++) {
    for (let k = 0; k <= n; k++) {
      if ((k & n) === k) {
        targets.push({
          x: cx + (k - n / 2) * step,
          y: cy + n * step * 0.88,
        });
      }
    }
  }
  return { label: 'triangle de Pascal mod 2 (Sierpiński)', targets, edges: [] };
}

function fibonacciSpiral(width, height) {
  const phi = (1 + Math.sqrt(5)) / 2;
  const goldenAngle = 2 * Math.PI * (1 - 1 / phi);
  const scale = Math.min(width, height) * 0.024;
  const cx = width / 2;
  const cy = height / 2;
  const n = 55;
  const targets = [];
  for (let i = 1; i <= n; i++) {
    const r = scale * Math.sqrt(i);
    const theta = i * goldenAngle;
    targets.push({ x: cx + r * Math.cos(theta), y: cy + r * Math.sin(theta) });
  }
  const edges = [];
  for (let i = 0; i < n - 1; i++) edges.push([i, i + 1]);
  return { label: "spirale de Fibonacci (angle d'or φ)", targets, edges };
}

const STRUCTURE_BUILDERS = [
  lattice,
  hashChain,
  rsMatrix,
  ed25519Curve,
  pascalMod2,
  fibonacciSpiral,
];

// Phase durations (ms). Long forming + brief hold + long dissolve = ambient,
// never abrupt. Calm period in between keeps the field calm and unsuspicious.
const PHASE_TIMES = {
  CALM: [6000, 11000],
  FORMING: [26000, 42000],
  HOLD: [9000, 14000],
  DISSOLVING: [10000, 18000],
};

function rng(min, max) {
  return min + Math.random() * (max - min);
}

// Greedy nearest-target assignment: for each target, find the unclaimed
// particle closest to it and bind them. Stable enough for the visual; not
// optimal (Hungarian) on purpose — cheap, and the imperfect routing reads
// well during the slow form-up.
function assignTargets(particles, targets) {
  const used = new Array(particles.length).fill(false);
  // Reset previous assignment.
  for (const p of particles) p.targetIndex = -1;
  // Iterate targets and find best particle.
  const limit = Math.min(targets.length, particles.length);
  // To avoid O(N²) per cycle: shuffle target order then take the nearest
  // available particle. Particles count is bounded ≲ 80, structures ≲ 70,
  // so O(N·M) here is fine (< 6000 ops, runs once per cycle).
  const order = Array.from({ length: targets.length }, (_, i) => i);
  for (let i = order.length - 1; i > 0; i--) {
    const j = Math.floor(Math.random() * (i + 1));
    [order[i], order[j]] = [order[j], order[i]];
  }
  let bound = 0;
  for (const ti of order) {
    if (bound >= limit) break;
    const t = targets[ti];
    let bestIdx = -1;
    let bestDist = Infinity;
    for (let pi = 0; pi < particles.length; pi++) {
      if (used[pi]) continue;
      const p = particles[pi];
      const d = (p.x - t.x) * (p.x - t.x) + (p.y - t.y) * (p.y - t.y);
      if (d < bestDist) {
        bestDist = d;
        bestIdx = pi;
      }
    }
    if (bestIdx >= 0) {
      used[bestIdx] = true;
      particles[bestIdx].targetIndex = ti;
      bound++;
    }
  }
}

export default function ParticlesBackground() {
  const canvasRef = useRef(null);

  useEffect(() => {
    const canvas = canvasRef.current;
    if (!canvas) return;
    const ctx = canvas.getContext('2d', { alpha: true });
    if (!ctx) return;

    const reduceMotion = window.matchMedia(
      '(prefers-reduced-motion: reduce)',
    ).matches;

    // Easter egg toggle for structure labels.
    let showLabels = false;
    try {
      const params = new URLSearchParams(window.location.search);
      if (params.get('math') === 'verbose') showLabels = true;
    } catch {
      // ignore — URLSearchParams should exist, but fail closed if not.
    }

    let width = 0;
    let height = 0;
    let dpr = Math.min(window.devicePixelRatio || 1, 2);
    let particles = [];
    let rafId = 0;
    let running = true;

    // Cycle state.
    let phase = 'CALM';
    let phaseStart = performance.now();
    let phaseDuration = rng(...PHASE_TIMES.CALM);
    let structure = null; // { label, targets, edges }
    let structureMix = 0; // 0 = free drift, 1 = locked onto structure
    let lastBuilderIdx = -1;

    function particleCount() {
      const target = Math.round((width * height) / 22000);
      // Floor lifted so even small viewports have enough particles to
      // render a recognizable structure (structures cap around 70 nodes).
      return Math.max(48, Math.min(80, target));
    }

    function makeParticle() {
      return {
        x: Math.random() * width,
        y: Math.random() * height,
        vx: (Math.random() - 0.5) * 0.18,
        vy: (Math.random() - 0.5) * 0.18,
        r: 0.6 + Math.random() * 1.4,
        targetIndex: -1,
      };
    }

    function resize() {
      width = canvas.clientWidth;
      height = canvas.clientHeight;
      dpr = Math.min(window.devicePixelRatio || 1, 2);
      canvas.width = Math.floor(width * dpr);
      canvas.height = Math.floor(height * dpr);
      ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
      particles = Array.from({ length: particleCount() }, makeParticle);
      // Drop current structure if any — coordinates may be stale.
      structure = null;
      structureMix = 0;
      phase = 'CALM';
      phaseStart = performance.now();
      phaseDuration = rng(...PHASE_TIMES.CALM);
    }

    function pickStructure() {
      // Avoid repeating the same builder twice in a row.
      let idx = Math.floor(Math.random() * STRUCTURE_BUILDERS.length);
      if (
        STRUCTURE_BUILDERS.length > 1 &&
        idx === lastBuilderIdx
      ) {
        idx = (idx + 1) % STRUCTURE_BUILDERS.length;
      }
      lastBuilderIdx = idx;
      return STRUCTURE_BUILDERS[idx](width, height);
    }

    function advancePhase(now) {
      if (now - phaseStart < phaseDuration) return;
      if (phase === 'CALM') {
        phase = 'FORMING';
        phaseDuration = rng(...PHASE_TIMES.FORMING);
        structure = pickStructure();
        assignTargets(particles, structure.targets);
      } else if (phase === 'FORMING') {
        phase = 'HOLD';
        phaseDuration = rng(...PHASE_TIMES.HOLD);
      } else if (phase === 'HOLD') {
        phase = 'DISSOLVING';
        phaseDuration = rng(...PHASE_TIMES.DISSOLVING);
      } else {
        phase = 'CALM';
        phaseDuration = rng(...PHASE_TIMES.CALM);
        structure = null;
        for (const p of particles) p.targetIndex = -1;
      }
      phaseStart = now;
    }

    function computeStructureMix(now) {
      const t = (now - phaseStart) / phaseDuration;
      // Smoothstep for soft entry/exit.
      const ss = (u) => {
        const c = Math.max(0, Math.min(1, u));
        return c * c * (3 - 2 * c);
      };
      if (phase === 'CALM') return 0;
      if (phase === 'FORMING') return ss(t);
      if (phase === 'HOLD') return 1;
      if (phase === 'DISSOLVING') return 1 - ss(t);
      return 0;
    }

    const LINK_DIST = 130;
    const ACCENT_DOT_ALPHA = 0.34;
    const ACCENT_LINK_BASE_ALPHA = 0.12;
    const STRUCT_EDGE_BASE_ALPHA = 0.18;

    function draw() {
      ctx.clearRect(0, 0, width, height);

      // 1. Ambient particle-to-particle links (always on, fade as the
      //    structure asserts itself so the field doesn't look noisy).
      const ambientAlphaScale = 1 - structureMix * 0.6;
      if (ambientAlphaScale > 0.05) {
        for (let i = 0; i < particles.length; i++) {
          const p = particles[i];
          for (let j = i + 1; j < particles.length; j++) {
            const q = particles[j];
            const dx = p.x - q.x;
            const dy = p.y - q.y;
            const dist = Math.hypot(dx, dy);
            if (dist < LINK_DIST) {
              const alpha =
                (1 - dist / LINK_DIST) *
                ACCENT_LINK_BASE_ALPHA *
                ambientAlphaScale;
              if (alpha < 0.005) continue;
              ctx.strokeStyle = `rgba(69, 243, 255, ${alpha})`;
              ctx.lineWidth = 1;
              ctx.beginPath();
              ctx.moveTo(p.x, p.y);
              ctx.lineTo(q.x, q.y);
              ctx.stroke();
            }
          }
        }
      }

      // 2. Structure edges (between particles that are assigned to the
      //    edge's endpoints — distortion during forming/dissolving is
      //    a feature, not a bug).
      if (structure && structureMix > 0.02 && structure.edges.length > 0) {
        // Build a quick lookup: target index -> particle index.
        const targetToParticle = new Array(structure.targets.length).fill(-1);
        for (let pi = 0; pi < particles.length; pi++) {
          const ti = particles[pi].targetIndex;
          if (ti >= 0) targetToParticle[ti] = pi;
        }
        const edgeAlpha = STRUCT_EDGE_BASE_ALPHA * structureMix;
        ctx.strokeStyle = `rgba(69, 243, 255, ${edgeAlpha})`;
        ctx.lineWidth = 1;
        for (const [a, b] of structure.edges) {
          const pa = targetToParticle[a];
          const pb = targetToParticle[b];
          if (pa < 0 || pb < 0) continue;
          ctx.beginPath();
          ctx.moveTo(particles[pa].x, particles[pa].y);
          ctx.lineTo(particles[pb].x, particles[pb].y);
          ctx.stroke();
        }
      }

      // 3. The dots themselves (always rendered last, slightly brighter
      //    when locked into a structure so the geometry pops a touch).
      const dotAlpha = ACCENT_DOT_ALPHA + structureMix * 0.18;
      ctx.fillStyle = `rgba(69, 243, 255, ${dotAlpha})`;
      for (const p of particles) {
        ctx.beginPath();
        ctx.arc(p.x, p.y, p.r, 0, Math.PI * 2);
        ctx.fill();
      }

      // 4. Optional structure label (easter egg only).
      if (showLabels && structure && structureMix > 0.4) {
        ctx.font =
          '11px ui-monospace, SFMono-Regular, Menlo, Consolas, monospace';
        ctx.fillStyle = `rgba(69, 243, 255, ${0.45 * structureMix})`;
        ctx.textAlign = 'center';
        ctx.textBaseline = 'bottom';
        ctx.fillText(structure.label, width / 2, height - 18);
      }
    }

    function step(now) {
      if (!running) return;
      advancePhase(now);
      structureMix = computeStructureMix(now);

      for (const p of particles) {
        // Free drift always applies — when structureMix == 1, the spring
        // pull dominates and the drift is invisible, but never gone.
        p.x += p.vx;
        p.y += p.vy;

        if (structure && p.targetIndex >= 0 && structureMix > 0.0) {
          const t = structure.targets[p.targetIndex];
          const dx = t.x - p.x;
          const dy = t.y - p.y;
          // Spring + damping scale with structureMix so calm phases are
          // truly calm and locked phases are tight.
          const k = 0.0011 * structureMix;
          p.vx += dx * k;
          p.vy += dy * k;
          const damp = 1 - 0.04 * structureMix;
          p.vx *= damp;
          p.vy *= damp;
        }

        // Wrap edges so a stray particle never gets stuck off-screen.
        if (p.x < -30) p.x = width + 30;
        else if (p.x > width + 30) p.x = -30;
        if (p.y < -30) p.y = height + 30;
        else if (p.y > height + 30) p.y = -30;
      }

      draw();
      rafId = requestAnimationFrame(step);
    }

    function onVisibility() {
      if (document.hidden) {
        running = false;
        cancelAnimationFrame(rafId);
      } else if (!reduceMotion && !running) {
        running = true;
        // Push phase clock forward so we don't get a long jump on resume.
        phaseStart = performance.now() - Math.min(phaseDuration * 0.25, 1500);
        rafId = requestAnimationFrame(step);
      }
    }

    function onKey(e) {
      // Ctrl+Shift+M toggles labels (useful for demos).
      if (e.ctrlKey && e.shiftKey && (e.key === 'M' || e.key === 'm')) {
        showLabels = !showLabels;
      }
    }

    resize();
    if (reduceMotion) {
      // Reduced motion: pick one structure, lock it at full mix, render
      // a single static frame. No RAF loop.
      structure = pickStructure();
      assignTargets(particles, structure.targets);
      // Snap particles directly onto their targets so the static frame
      // shows the geometry cleanly.
      for (const p of particles) {
        if (p.targetIndex >= 0) {
          const t = structure.targets[p.targetIndex];
          p.x = t.x;
          p.y = t.y;
          p.vx = 0;
          p.vy = 0;
        }
      }
      structureMix = 1;
      phase = 'HOLD';
      draw();
    } else {
      rafId = requestAnimationFrame(step);
    }

    window.addEventListener('resize', resize);
    document.addEventListener('visibilitychange', onVisibility);
    window.addEventListener('keydown', onKey);

    return () => {
      cancelAnimationFrame(rafId);
      window.removeEventListener('resize', resize);
      document.removeEventListener('visibilitychange', onVisibility);
      window.removeEventListener('keydown', onKey);
    };
  }, []);

  return (
    <canvas
      ref={canvasRef}
      aria-hidden="true"
      style={{
        position: 'fixed',
        inset: 0,
        width: '100%',
        height: '100%',
        zIndex: 0,
        pointerEvents: 'none',
        // Keep it understated regardless of section background.
        opacity: 0.7,
      }}
    />
  );
}
