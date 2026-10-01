import { Component } from 'react';
import type { ErrorInfo, ReactNode } from 'react';

import { ErrorState } from './ui';

/** Catches render errors in a page so one broken screen does not blank the whole console. */
export default class ErrorBoundary extends Component<{ children: ReactNode; resetKey?: string }, { error: Error | null }> {
  state = { error: null as Error | null };

  static getDerivedStateFromError(error: Error) {
    return { error };
  }

  componentDidCatch(error: Error, info: ErrorInfo) {
    console.error('UI render error', error, info.componentStack);
  }

  componentDidUpdate(prev: { resetKey?: string }) {
    // Navigating to another route clears a previous crash.
    if (this.state.error && prev.resetKey !== this.props.resetKey) this.setState({ error: null });
  }

  render() {
    if (this.state.error) {
      return (
        <div className="card">
          <ErrorState
            title="This page hit an unexpected error"
            message={this.state.error.message || 'Unknown error'}
            onRetry={() => this.setState({ error: null })}
          />
        </div>
      );
    }
    return this.props.children;
  }
}
