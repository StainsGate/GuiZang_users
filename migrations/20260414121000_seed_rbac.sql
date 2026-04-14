insert into permissions (id, code, description, created_at, updated_at, deleted_at, row_version)
values
    ('00000000-0000-0000-0000-000000000010', 'users.read', 'Read users', now(), now(), null, 0),
    ('00000000-0000-0000-0000-000000000011', 'users.write', 'Create/update/delete users', now(), now(), null, 0),
    ('00000000-0000-0000-0000-000000000012', 'roles.manage', 'Manage roles and bindings', now(), now(), null, 0),
    ('00000000-0000-0000-0000-000000000013', 'permissions.read', 'Read permissions', now(), now(), null, 0)
on conflict (id) do nothing;

insert into roles (id, name, description, created_at, updated_at, deleted_at, created_by, updated_by, row_version)
values
    ('00000000-0000-0000-0000-000000000001', 'admin', 'Bootstrap admin role', now(), now(), null, null, null, 0)
on conflict (id) do nothing;

insert into role_permissions (role_id, permission_id, created_at, created_by)
values
    ('00000000-0000-0000-0000-000000000001', '00000000-0000-0000-0000-000000000010', now(), null),
    ('00000000-0000-0000-0000-000000000001', '00000000-0000-0000-0000-000000000011', now(), null),
    ('00000000-0000-0000-0000-000000000001', '00000000-0000-0000-0000-000000000012', now(), null),
    ('00000000-0000-0000-0000-000000000001', '00000000-0000-0000-0000-000000000013', now(), null)
on conflict do nothing;

