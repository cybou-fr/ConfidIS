import React from 'react';
import { AlertTriangle, RefreshCw } from 'lucide-react';

/**
 * React class-based error boundary that catches rendering errors in its subtree.
 *
 * Usage:
 *   <ErrorBoundary>
 *     <MyComponent />
 *   </ErrorBoundary>
 *
 * Optional `fallback` prop renders instead of the default error card.
 * Optional `label` prop names the section in the error message.
 */
export default class ErrorBoundary extends React.Component {
  constructor(props) {
    super(props);
    this.state = { hasError: false, error: null };
    this.handleReset = this.handleReset.bind(this);
  }

  static getDerivedStateFromError(error) {
    return { hasError: true, error };
  }

  componentDidCatch(error, info) {
    // Surface to console so devtools / error monitoring can capture it.
    console.error('[ErrorBoundary]', this.props.label ?? 'section', error, info.componentStack);
  }

  handleReset() {
    this.setState({ hasError: false, error: null });
  }

  render() {
    if (!this.state.hasError) return this.props.children;

    if (this.props.fallback) return this.props.fallback;

    const label = this.props.label ?? 'Cette section';
    const message = this.state.error?.message ?? 'Erreur inconnue';

    return (
      <div
        role="alert"
        style={{
          display: 'flex',
          flexDirection: 'column',
          alignItems: 'center',
          justifyContent: 'center',
          gap: '1rem',
          padding: '2.5rem 2rem',
          background: 'rgba(255, 42, 122, 0.06)',
          border: '1px solid rgba(255, 42, 122, 0.2)',
          borderRadius: '14px',
          textAlign: 'center',
          color: 'var(--text-secondary)',
          minHeight: '200px',
        }}
      >
        <AlertTriangle size={36} color="#f43f5e" />
        <div>
          <p style={{ fontWeight: 700, color: '#f43f5e', marginBottom: '0.35rem', fontSize: '1rem' }}>
            {label} a planté
          </p>
          <p style={{ fontSize: '0.825rem', maxWidth: '400px', lineHeight: 1.5 }}>
            {message}
          </p>
        </div>
        <button
          onClick={this.handleReset}
          style={{
            display: 'flex',
            alignItems: 'center',
            gap: '0.5rem',
            padding: '0.6rem 1.25rem',
            background: 'rgba(255,42,122,0.12)',
            border: '1px solid rgba(255,42,122,0.3)',
            borderRadius: '8px',
            color: '#f9a8d4',
            cursor: 'pointer',
            fontSize: '0.875rem',
            fontWeight: 600,
          }}
        >
          <RefreshCw size={15} />
          Réessayer
        </button>
      </div>
    );
  }
}
