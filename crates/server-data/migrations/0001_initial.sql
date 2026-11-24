-- Initial schema. The server only ever stores ciphertext and opaque client data.
-- Migrations are forward-only and immutable once merged (ADR 0004).

CREATE TABLE users (
    id           uuid PRIMARY KEY,
    email        text        NOT NULL UNIQUE,
    auth_hash    bytea       NOT NULL,
    key_envelope bytea       NOT NULL,
    created_at   timestamptz NOT NULL DEFAULT now()
);

-- One counter per user, bumped on every change to their data.
CREATE TABLE user_revision (
    user_id  uuid   PRIMARY KEY REFERENCES users (id) ON DELETE CASCADE,
    revision bigint NOT NULL CHECK (revision >= 0)
);

CREATE TABLE devices (
    id         uuid PRIMARY KEY,
    user_id    uuid        NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    name       text        NOT NULL,
    revoked    boolean     NOT NULL DEFAULT false,
    created_at timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX devices_user_id_idx ON devices (user_id);

CREATE TABLE folders (
    id      uuid PRIMARY KEY,
    user_id uuid  NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    name    bytea NOT NULL
);
CREATE INDEX folders_user_id_idx ON folders (user_id);

-- A tombstone is a row with deleted = true and no data.
CREATE TABLE ciphers (
    id        uuid PRIMARY KEY,
    user_id   uuid   NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    folder_id uuid,
    data      bytea  NOT NULL,
    revision  bigint NOT NULL CHECK (revision >= 0),
    deleted   boolean NOT NULL DEFAULT false
);
-- Serves "everything of this user after revision N, in order".
CREATE INDEX ciphers_user_revision_idx ON ciphers (user_id, revision);
