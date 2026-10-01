import type { ReactNode } from 'react';
import { Lock } from 'lucide-react';

import { useAuth } from '../auth/AuthContext';
import { Card, EmptyState, LinkButton } from './ui';

/**
 * Route guard for screens whose endpoints the backend restricts to ADMIN.
 * The backend still enforces this (403); the guard just avoids a confusing
 * error page for an analyst who follows a link here.
 */
export default function AdminOnly({ children, what }: { children: ReactNode; what: string }) {
  const { isAdmin } = useAuth();

  if (isAdmin) return <>{children}</>;

  return (
    <Card>
      <EmptyState
        icon={Lock}
        title="Administrator access required"
        text={`${what} is restricted to administrators. Sign in with an administrator account to continue.`}
        action={<LinkButton to="/dashboard" variant="secondary" size="sm">Back to dashboard</LinkButton>}
      />
    </Card>
  );
}
