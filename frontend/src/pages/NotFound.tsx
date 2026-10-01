import { Compass } from 'lucide-react';

import { Card, EmptyState, LinkButton, PageHeader } from '../components/ui';

export default function NotFound() {
  return (
    <>
      <PageHeader eyebrow="Error 404" title="Page not found" />
      <Card>
        <EmptyState
          icon={Compass}
          title="Nothing at this address"
          text="The page you opened does not exist, or it has moved."
          action={<LinkButton to="/dashboard" variant="primary" size="sm">Back to dashboard</LinkButton>}
        />
      </Card>
    </>
  );
}
