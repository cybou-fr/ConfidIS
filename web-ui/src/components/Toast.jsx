/* eslint-disable react-refresh/only-export-components */
import { createContext, useCallback, useContext, useEffect, useMemo, useState } from 'react';
import { CheckCircle, AlertTriangle, XCircle, Info, X } from 'lucide-react';

// ── Context ─────────────────────────────────────────────────────────────────

const ToastContext = createContext(null);

export function useToast() {
  const ctx = useContext(ToastContext);
  if (!ctx) throw new Error('useToast must be used inside <ToastProvider>');
  return ctx;
}

// ── Provider ─────────────────────────────────────────────────────────────────

let nextId = 0;

export function ToastProvider({ children }) {
  const [toasts, setToasts] = useState([]);

  const dismiss = useCallback((id) => {
    setToasts((prev) => prev.map((t) => (t.id === id ? { ...t, leaving: true } : t)));
    // Remove from DOM after CSS transition completes (300 ms).
    setTimeout(() => setToasts((prev) => prev.filter((t) => t.id !== id)), 320);
  }, []);

  const push = useCallback(
    (type, message, duration = 4000) => {
      const id = ++nextId;
      setToasts((prev) => [...prev, { id, type, message, leaving: false }]);
      if (duration > 0) setTimeout(() => dismiss(id), duration);
      return id;
    },
    [dismiss],
  );

  const api = useMemo(() => ({
    success: (msg, duration) => push('success', msg, duration),
    error: (msg, duration) => push('error', msg, duration),
    warning: (msg, duration) => push('warning', msg, duration),
    info: (msg, duration) => push('info', msg, duration),
    dismiss,
  }), [dismiss, push]);

  return (
    <ToastContext.Provider value={api}>
      {children}
      <ToastContainer toasts={toasts} onDismiss={dismiss} />
    </ToastContext.Provider>
  );
}

// ── Visual component ──────────────────────────────────────────────────────────

const CONFIG = {
  success: {
    Icon: CheckCircle,
    color: '#4ade80',
    bg: 'rgba(74, 222, 128, 0.12)',
    border: 'rgba(74, 222, 128, 0.35)',
  },
  error: {
    Icon: XCircle,
    color: '#f87171',
    bg: 'rgba(248, 113, 113, 0.12)',
    border: 'rgba(248, 113, 113, 0.35)',
  },
  warning: {
    Icon: AlertTriangle,
    color: '#fbbf24',
    bg: 'rgba(251, 191, 36, 0.12)',
    border: 'rgba(251, 191, 36, 0.35)',
  },
  info: {
    Icon: Info,
    color: '#45f3ff',
    bg: 'rgba(69, 243, 255, 0.10)',
    border: 'rgba(69, 243, 255, 0.30)',
  },
};

function ToastItem({ toast, onDismiss }) {
  const { Icon, color, bg, border } = CONFIG[toast.type] || CONFIG.info;
  const [visible, setVisible] = useState(false);

  // Trigger enter animation after mount.
  useEffect(() => {
    const raf = requestAnimationFrame(() => setVisible(true));
    return () => cancelAnimationFrame(raf);
  }, []);

  const opacity = toast.leaving ? 0 : visible ? 1 : 0;
  const transform = toast.leaving
    ? 'translateX(110%)'
    : visible
    ? 'translateX(0)'
    : 'translateX(110%)';

  return (
    <div
      role="alert"
      aria-live="assertive"
      style={{
        display: 'flex',
        alignItems: 'flex-start',
        gap: '0.75rem',
        padding: '0.875rem 1rem',
        borderRadius: '10px',
        background: bg,
        border: `1px solid ${border}`,
        backdropFilter: 'blur(12px)',
        boxShadow: '0 4px 24px rgba(0,0,0,0.35)',
        minWidth: '280px',
        maxWidth: '420px',
        opacity,
        transform,
        transition: 'opacity 0.28s ease, transform 0.28s ease',
        cursor: 'default',
      }}
    >
      <Icon size={18} color={color} style={{ flexShrink: 0, marginTop: '1px' }} />
      <span style={{ flex: 1, fontSize: '0.875rem', color: 'var(--text-primary)', lineHeight: 1.45 }}>
        {toast.message}
      </span>
      <button
        onClick={() => onDismiss(toast.id)}
        aria-label="Dismiss notification"
        style={{
          background: 'none',
          border: 'none',
          padding: '2px',
          cursor: 'pointer',
          color: 'var(--text-secondary)',
          flexShrink: 0,
          lineHeight: 0,
          opacity: 0.7,
        }}
      >
        <X size={14} />
      </button>
    </div>
  );
}

function ToastContainer({ toasts, onDismiss }) {
  if (toasts.length === 0) return null;

  return (
    <div
      aria-label="Notifications"
      style={{
        position: 'fixed',
        bottom: '1.5rem',
        right: '1.5rem',
        zIndex: 9999,
        display: 'flex',
        flexDirection: 'column',
        gap: '0.625rem',
        alignItems: 'flex-end',
        pointerEvents: 'none',
      }}
    >
      {toasts.map((t) => (
        <div key={t.id} style={{ pointerEvents: 'auto' }}>
          <ToastItem toast={t} onDismiss={onDismiss} />
        </div>
      ))}
    </div>
  );
}
