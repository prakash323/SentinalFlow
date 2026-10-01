import { useQuery } from '@tanstack/react-query';

import { entitiesApi } from '../api/endpoints';
import { Select } from './ui';

/** Backend entityId filters are exact-match, so offer the known entities rather than free text. */
export function useEntities() {
  return useQuery({
    queryKey: ['entities', 'all'],
    queryFn: () => entitiesApi.list({ size: 100 }),
    staleTime: 60000,
  });
}

export default function EntitySelect({
  value,
  onChange,
  placeholder = 'All entities',
}: {
  value: string;
  onChange: (v: string) => void;
  placeholder?: string;
}) {
  const q = useEntities();
  const options = (q.data?.content ?? []).map((e) => ({
    value: e.entityId,
    label: e.displayName ? `${e.entityId} — ${e.displayName}` : e.entityId,
  }));

  // Keep a deep-linked value selectable even if it is not in the first 100.
  if (value && !options.some((o) => o.value === value)) options.unshift({ value, label: value });

  return <Select value={value} onChange={onChange} options={options} placeholder={placeholder} ariaLabel="Filter by entity" />;
}
