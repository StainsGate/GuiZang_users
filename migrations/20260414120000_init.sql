create table if not exists users (
    id uuid primary key,
    email text null,
    email_normalized text null,
    email_verified_at timestamptz null,
    phone text null,
    phone_verified_at timestamptz null,
    display_name text not null,
    avatar_url text null,
    status text not null,
    last_login_at timestamptz null,
    created_at timestamptz not null default now(),
    updated_at timestamptz not null default now(),
    deleted_at timestamptz null,
    created_by uuid null,
    updated_by uuid null,
    row_version bigint not null default 0,
    constraint users_email_or_phone_chk check (email is not null or phone is not null)
);

create unique index if not exists users_email_unique
    on users (email_normalized)
    where deleted_at is null and email_normalized is not null;

create unique index if not exists users_phone_unique
    on users (phone)
    where deleted_at is null and phone is not null;

create index if not exists users_status_idx
    on users (status)
    where deleted_at is null;

create index if not exists users_created_at_idx
    on users (created_at)
    where deleted_at is null;

create table if not exists user_credentials (
    user_id uuid primary key references users (id),
    password_hash text not null,
    password_updated_at timestamptz not null,
    failed_login_count int not null default 0,
    locked_until timestamptz null,
    created_at timestamptz not null default now(),
    updated_at timestamptz not null default now(),
    row_version bigint not null default 0
);

create index if not exists user_credentials_locked_until_idx
    on user_credentials (locked_until);

create table if not exists roles (
    id uuid primary key,
    name text not null,
    description text null,
    created_at timestamptz not null default now(),
    updated_at timestamptz not null default now(),
    deleted_at timestamptz null,
    created_by uuid null,
    updated_by uuid null,
    row_version bigint not null default 0
);

create unique index if not exists roles_name_unique
    on roles (name)
    where deleted_at is null;

create table if not exists permissions (
    id uuid primary key,
    code text not null,
    description text null,
    created_at timestamptz not null default now(),
    updated_at timestamptz not null default now(),
    deleted_at timestamptz null,
    row_version bigint not null default 0
);

create unique index if not exists permissions_code_unique
    on permissions (code)
    where deleted_at is null;

create table if not exists user_roles (
    user_id uuid not null references users (id),
    role_id uuid not null references roles (id),
    created_at timestamptz not null default now(),
    created_by uuid null,
    primary key (user_id, role_id)
);

create index if not exists user_roles_role_id_idx
    on user_roles (role_id);

create table if not exists role_permissions (
    role_id uuid not null references roles (id),
    permission_id uuid not null references permissions (id),
    created_at timestamptz not null default now(),
    created_by uuid null,
    primary key (role_id, permission_id)
);

create index if not exists role_permissions_permission_id_idx
    on role_permissions (permission_id);

create table if not exists refresh_tokens (
    id uuid primary key,
    user_id uuid not null references users (id),
    token_hash text not null,
    issued_at timestamptz not null,
    expires_at timestamptz not null,
    revoked_at timestamptz null,
    replaced_by uuid null references refresh_tokens (id),
    ip text null,
    user_agent text null,
    created_at timestamptz not null default now()
);

create unique index if not exists refresh_tokens_hash_unique
    on refresh_tokens (token_hash);

create index if not exists refresh_tokens_user_expires_idx
    on refresh_tokens (user_id, expires_at);

create index if not exists refresh_tokens_revoked_at_idx
    on refresh_tokens (revoked_at);

create table if not exists idempotency_records (
    scope text not null,
    key text not null,
    request_hash text not null,
    status_code int not null,
    response_body jsonb not null,
    created_at timestamptz not null default now(),
    expires_at timestamptz not null,
    primary key (scope, key)
);

create index if not exists idempotency_records_expires_at_idx
    on idempotency_records (expires_at);

