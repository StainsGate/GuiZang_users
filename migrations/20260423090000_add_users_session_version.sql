alter table users
    add column if not exists session_version bigint not null default 0;

create index if not exists users_session_version_idx
    on users (session_version)
    where deleted_at is null;

