import { useState } from 'react';
import { Link } from 'react-router-dom';
import { useForm } from 'react-hook-form';
import { zodResolver } from '@hookform/resolvers/zod';
import { z } from 'zod';
import { BellRing, CircleAlert, Eye, EyeOff, Moon, Radar, Radio, ShieldAlert, ShieldCheck, Sun } from 'lucide-react';

import { useAuth } from '../auth/AuthContext';
import { Button, IconButton } from '../components/ui';
import { useTheme } from '../hooks/useTheme';
import '../styles/login.css';

const schema = z.object({
  username: z.string().trim().min(1, 'Username is required'),
  password: z.string().min(1, 'Password is required'),
});
type Form = z.infer<typeof schema>;

// The four objects a SentinelFlow investigation moves through. No numbers, so nothing here needs
// an "illustrative" label.
const FLOW = [
  { icon: Radio, title: 'Event', text: 'A security event arrives' },
  { icon: Radar, title: 'Prediction', text: 'Scored against behavioral baselines' },
  { icon: BellRing, title: 'Alert', text: 'Graded by the alert policy' },
  { icon: ShieldAlert, title: 'Incident', text: 'Related alerts grouped for investigation' },
];

type LoginError = { title: string; text: string };

// Same classification as before (by HTTP status / network failure); only the wording changed so a
// user never sees a raw or technical message.
function describeError(e: unknown): LoginError {
  const err = e as { status?: number; code?: string } | null;
  const status = err?.status;
  if (status === 401) return { title: 'Unable to sign in', text: 'Check your credentials and try again.' };
  if (status === 403) return { title: 'Access denied', text: 'This account is not permitted to use SentinelFlow.' };
  if (status === undefined || status >= 500 || err?.code === 'NETWORK_ERROR') {
    return { title: 'Unable to connect to SentinelFlow', text: 'Please try again.' };
  }
  return { title: 'Unable to sign in', text: 'Something went wrong. Please try again.' };
}

function Brand({ className = '' }: { className?: string }) {
  return (
    <Link to="/" className={`login-brand ${className}`.trim()} aria-label="SentinelFlow home">
      <span className="brand-mark"><ShieldCheck size={17} /></span>
      <span className="brand-text">
        <strong>SentinelFlow</strong>
        <em>Security Operations</em>
      </span>
    </Link>
  );
}

export default function Login() {
  const { login } = useAuth();
  const { theme, toggle } = useTheme();
  const [error, setError] = useState<LoginError | null>(null);
  const [show, setShow] = useState(false);
  const {
    register,
    handleSubmit,
    formState: { errors, isSubmitting },
  } = useForm<Form>({ resolver: zodResolver(schema) });

  const submit = async (v: Form) => {
    setError(null);
    try {
      await login(v.username, v.password);
    } catch (e) {
      setError(describeError(e));
    }
  };

  const describedBy = (fieldError?: string, id?: string) => [fieldError ? id : '', error ? 'login-error' : ''].filter(Boolean).join(' ') || undefined;

  return (
    <div className="login">
      <main className="login-auth" id="main">
        <div className="login-auth-top">
          <Brand className="login-auth-brand" />
          <IconButton
            icon={theme === 'dark' ? Sun : Moon}
            label={theme === 'dark' ? 'Switch to light theme' : 'Switch to dark theme'}
            bordered
            onClick={toggle}
          />
        </div>

        <div className="login-panel">
          <h1 className="login-title">Welcome back</h1>
          <p className="login-sub">Sign in to SentinelFlow</p>

          <form onSubmit={handleSubmit(submit)} className="login-form" noValidate aria-busy={isSubmitting}>
            <div className="login-field">
              <label htmlFor="login-username">Username</label>
              <input
                id="login-username"
                className="login-input"
                autoFocus
                autoComplete="username"
                aria-invalid={errors.username ? true : undefined}
                aria-describedby={describedBy(errors.username?.message, 'login-username-error')}
                {...register('username')}
              />
              {errors.username && <small id="login-username-error" className="login-field-error">{errors.username.message}</small>}
            </div>

            <div className="login-field">
              <label htmlFor="login-password">Password</label>
              <div className="login-input-wrap">
                <input
                  id="login-password"
                  type={show ? 'text' : 'password'}
                  autoComplete="current-password"
                  aria-invalid={errors.password ? true : undefined}
                  aria-describedby={describedBy(errors.password?.message, 'login-password-error')}
                  {...register('password')}
                />
                <IconButton icon={show ? EyeOff : Eye} label={show ? 'Hide password' : 'Show password'} small onClick={() => setShow((s) => !s)} />
              </div>
              {errors.password && <small id="login-password-error" className="login-field-error">{errors.password.message}</small>}
            </div>

            {/* Always in the DOM so screen readers announce the message when it appears. */}
            <div className="login-error-region" role="alert">
              {error && (
                <div className="login-error" id="login-error">
                  <CircleAlert size={18} aria-hidden="true" />
                  <div>
                    <strong>{error.title}</strong>
                    <span>{error.text}</span>
                  </div>
                </div>
              )}
            </div>

            <Button type="submit" size="lg" block loading={isSubmitting}>
              {isSubmitting ? 'Signing in…' : 'Sign In'}
            </Button>
          </form>

          <p className="login-note">Authorized users only. Your session ends when you close this tab.</p>
        </div>
      </main>

      <aside className="login-brand-pane" aria-label="About SentinelFlow">
        <Brand />

        <div>
          <p className="login-eyebrow">Security operations</p>
          <p className="login-tagline">Security signals into actionable context.</p>
          <p className="login-lede">Investigate events, predictions, alerts and incidents in one place.</p>

          <ol className="login-flow" aria-label="From event to incident">
            {FLOW.map((f, i) => (
              <li key={f.title} style={{ ['--i' as string]: i } as React.CSSProperties}>
                <span className="login-node"><f.icon size={16} aria-hidden="true" /></span>
                <div>
                  <strong>{f.title}</strong>
                  <span className="t">{f.text}</span>
                </div>
              </li>
            ))}
          </ol>
        </div>

        <p className="login-copy">© {new Date().getFullYear()} SentinelFlow</p>
      </aside>
    </div>
  );
}
