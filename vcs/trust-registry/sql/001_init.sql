create table if not exists trust_entries (
  did text primary key,
  trusted boolean not null default false,
  reason text,
  updated_at timestamptz not null default now()
);

create index if not exists trust_entries_updated_at_idx on trust_entries(updated_at);
